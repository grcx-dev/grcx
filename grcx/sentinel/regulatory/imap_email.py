# Copyright (c) 2026 Neil Lowden | GRCX | MIT License
import email
import imaplib
import os
import re
from email.header import decode_header
from html.parser import HTMLParser
from pathlib import Path
from typing import Optional

from rich.console import Console

from grcx.sentinel.regulatory.rss import RegulatoryItem

console = Console()


class _LinkExtractor(HTMLParser):
    """Minimal HTML parser that collects anchor text and hrefs."""

    def __init__(self):
        super().__init__()
        self.links: list[tuple[str, str]] = []  # [(text, href), ...]
        self._current_href: Optional[str] = None
        self._current_text: list[str] = []

    def handle_starttag(self, tag: str, attrs):
        if tag == "a":
            href = dict(attrs).get("href", "")
            # Skip mailto, anchors, and tracker redirects with no real URL
            if href and href.startswith("http"):
                self._current_href = href
                self._current_text = []

    def handle_endtag(self, tag: str):
        if tag == "a" and self._current_href:
            text = "".join(self._current_text).strip()
            if text:
                self.links.append((text, self._current_href))
            self._current_href = None
            self._current_text = []

    def handle_data(self, data: str):
        if self._current_href is not None:
            self._current_text.append(data)


def _decode_header_value(raw: str) -> str:
    parts = decode_header(raw)
    decoded = []
    for chunk, charset in parts:
        if isinstance(chunk, bytes):
            decoded.append(chunk.decode(charset or "utf-8", errors="replace"))
        else:
            decoded.append(chunk)
    return "".join(decoded)


def _extract_html_body(msg: email.message.Message) -> str:
    """Return the first text/html part, falling back to text/plain."""
    plain = ""
    for part in msg.walk():
        ct = part.get_content_type()
        if ct == "text/html":
            payload = part.get_payload(decode=True)
            charset = part.get_content_charset() or "utf-8"
            return payload.decode(charset, errors="replace")
        if ct == "text/plain" and not plain:
            payload = part.get_payload(decode=True)
            charset = part.get_content_charset() or "utf-8"
            plain = payload.decode(charset, errors="replace")
    return plain


def _links_from_html(html: str) -> list[tuple[str, str]]:
    parser = _LinkExtractor()
    parser.feed(html)
    return parser.links


def _links_from_plain(text: str) -> list[tuple[str, str]]:
    """Extract bare URLs from plain text as (url, url) pairs."""
    urls = re.findall(r"https?://\S+", text)
    return [(u, u) for u in urls]


class EmailSentinel:
    """
    Watches an IMAP mailbox for regulatory publication alert emails.

    Connects over SSL, selects INBOX, fetches unseen messages from the
    configured sender, parses HTML bodies for publication links, and returns
    RegulatoryItem objects using the same fingerprint/state-file pattern as
    RssSentinel.

    Password is read from the GRCX_IMAP_PASSWORD environment variable —
    never store credentials in grcx.yaml.
    """

    def __init__(
        self,
        host: str,
        username: str,
        jurisdiction: str,
        sender_filter: str,
        port: int = 993,
        state_dir: str = "grcx-audit",
    ):
        self.host = host
        self.port = port
        self.username = username
        self.jurisdiction = jurisdiction
        self.sender_filter = sender_filter.lower()
        self.state_path = Path(state_dir) / f"seen_{jurisdiction.lower()}_email.txt"
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self._seen = self._load_seen()

    # Expose a .url property so runner.py's audit log line works unchanged
    @property
    def url(self) -> str:
        return f"imap://{self.host}"

    # ------------------------------------------------------------------
    # State helpers
    # ------------------------------------------------------------------

    def _load_seen(self) -> set[str]:
        if self.state_path.exists():
            return set(self.state_path.read_text().splitlines())
        return set()

    def _save_seen(self) -> None:
        self.state_path.write_text("\n".join(self._seen))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def fetch(self) -> list[RegulatoryItem]:
        password = os.environ.get("GRCX_IMAP_PASSWORD")
        if not password:
            console.print(
                f"[red][{self.jurisdiction}] GRCX_IMAP_PASSWORD not set — "
                f"skipping IMAP fetch[/red]"
            )
            return []

        try:
            messages = self._fetch_messages(password)
        except Exception as e:
            console.print(
                f"[red][{self.jurisdiction}] IMAP error: {e}[/red]"
            )
            return []

        items: list[RegulatoryItem] = []
        for msg in messages:
            items.extend(self._parse_message(msg))

        new_items = [i for i in items if i.fingerprint not in self._seen]
        for item in new_items:
            self._seen.add(item.fingerprint)
        self._save_seen()

        return new_items

    # ------------------------------------------------------------------
    # IMAP
    # ------------------------------------------------------------------

    def _fetch_messages(self, password: str) -> list[email.message.Message]:
        with imaplib.IMAP4_SSL(self.host, self.port) as imap:
            imap.login(self.username, password)
            imap.select("INBOX", readonly=True)

            # Search for all messages from the configured sender.
            # We use ALL rather than UNSEEN so we don't miss items if grcx
            # was offline; the fingerprint state file handles deduplication.
            status, data = imap.search(
                None, f'FROM "{self.sender_filter}"'
            )
            if status != "OK" or not data[0]:
                return []

            uids = data[0].split()
            # Only fetch the 50 most recent to bound latency
            uids = uids[-50:]

            messages = []
            for uid in uids:
                status, msg_data = imap.fetch(uid, "(RFC822)")
                if status != "OK":
                    continue
                raw = msg_data[0][1]
                messages.append(email.message_from_bytes(raw))

        return messages

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------

    def _parse_message(
        self, msg: email.message.Message
    ) -> list[RegulatoryItem]:
        subject = _decode_header_value(msg.get("Subject", "")).strip()
        date = msg.get("Date", "").strip()
        sender = msg.get("From", "").strip()

        body = _extract_html_body(msg)
        if body and "<" in body:
            links = _links_from_html(body)
        else:
            links = _links_from_plain(body)

        if not links:
            # Treat the email itself as a single item if there are no links
            return [
                RegulatoryItem(
                    title=subject or "(no subject)",
                    url=f"imap://{self.host}",
                    published=date,
                    summary=subject,
                    jurisdiction=self.jurisdiction,
                    feed_url=self.url,
                )
            ]

        # Link text patterns that indicate boilerplate UI chrome
        _SKIP_TEXT = re.compile(
            r'^(view\s+(in|online|this|\w+\s+browser)|unsubscribe|manage\s+(preferences|subscription)|'
            r'click\s+here|read\s+(more|online)|sign\s+up.*|update|forward|share|'
            r'follow\s+us|contact\s+us|privacy\s+policy|terms|subscribe|'
            r'financial\s+conduct\s+authority|monetary\s+authority|'
            r'securities\s+(and\s+exchange\s+)?(commission|authority))$',
            re.IGNORECASE
        )
        # Skip href patterns that are purely tracking/utility with no content value
        _SKIP_HREF = ("unsubscribe", "preferences", "optout", "mailto:")

        items = []
        seen_hrefs: set[str] = set()
        for text, href in links:
            if any(skip in href.lower() for skip in _SKIP_HREF):
                continue
            # Skip very short link texts that are probably UI chrome
            if len(text) < 15:
                continue
            # Skip bare domain names (e.g. "fca.org.uk", "fca.org.uk/news")
            if re.match(r'^[\w.-]+\.[a-z]{2,}(/[\w/.-]*)?$', text.strip()):
                continue
            # Skip known boilerplate phrases
            if _SKIP_TEXT.match(text.strip()):
                continue
            # Deduplicate by URL
            if href in seen_hrefs:
                continue
            seen_hrefs.add(href)

            items.append(
                RegulatoryItem(
                    title=text,
                    url=href,
                    published=date,
                    summary=f"[Email: {subject}] {text}"[:300],
                    jurisdiction=self.jurisdiction,
                    feed_url=self.url,
                )
            )

        return items
