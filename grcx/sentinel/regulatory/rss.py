# Copyright (c) 2026 Neil Lowden | GRCX | MIT License
import hashlib
import httpx
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional
from rich.console import Console

console = Console()

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; GRCX/0.1; +https://github.com/grcxdev/grcx)"
}


def compute_fingerprint(url: str) -> str:
    # URL-only, always lowercased. Title is excluded so that feed reformats
    # (capitalisation changes, punctuation edits) don't produce a new fingerprint
    # for the same publication. Lowercasing is permanent — do not remove it.
    # WARNING: changing this function invalidates fingerprint-keyed audit log
    # entries. Any change must be paired with a log-derived state rebuild in
    # runner.py so that previously ingested URLs are not re-ingested.
    return hashlib.sha256(url.lower().encode()).hexdigest()[:16]


@dataclass
class RegulatoryItem:
    title: str
    url: str
    published: Optional[str]
    summary: str
    jurisdiction: str
    feed_url: str
    fingerprint: str = field(init=False)

    def __post_init__(self):
        self.fingerprint = compute_fingerprint(self.url)


class RssSentinel:
    """
    Watches an RSS/Atom feed for new regulatory publications.
    Deduplication is log-derived: the caller (runner.py) passes in the set of
    already-ingested source URLs; fetch() returns only items not in that set.
    No seen-file is written or read.
    """

    def __init__(self, url: str, jurisdiction: str):
        self.url = url
        self.jurisdiction = jurisdiction

    def fetch(self, ingested_urls: set[str]) -> list[RegulatoryItem]:
        """Fetch the feed and return items whose source URL has not been ingested."""
        timeout = httpx.Timeout(connect=10.0, read=45.0, write=10.0, pool=10.0)
        for attempt in range(2):
            try:
                response = httpx.get(
                    self.url, timeout=timeout, follow_redirects=True, headers=HEADERS
                )
                response.raise_for_status()
                break
            except Exception as e:
                if attempt == 0:
                    continue
                console.print(f"[red][{self.jurisdiction}] Feed fetch failed: {e}[/red]")
                return []

        items = self._parse(response.text)
        return [i for i in items if i.url not in ingested_urls]

    def _parse(self, xml_text: str) -> list[RegulatoryItem]:
        items = []
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as e:
            console.print(f"[red][{self.jurisdiction}] XML parse error: {e}[/red]")
            return []

        is_atom = "http://www.w3.org/2005/Atom" in root.tag

        if is_atom:
            ns = {"atom": "http://www.w3.org/2005/Atom"}
            entries = root.findall("atom:entry", ns)
            for entry in entries:
                title = entry.findtext("atom:title", "", ns).strip()
                url = ""
                link = entry.find("atom:link", ns)
                if link is not None:
                    url = link.get("href", "")
                published = entry.findtext("atom:published", "", ns)
                summary = entry.findtext("atom:summary", "", ns).strip()
                items.append(RegulatoryItem(
                    title=title, url=url, published=published,
                    summary=summary[:300] if summary else "",
                    jurisdiction=self.jurisdiction, feed_url=self.url
                ))
        else:
            channel = root.find("channel")
            if channel is None:
                return []
            for item in channel.findall("item"):
                title = (item.findtext("title") or "").strip()
                url = (item.findtext("link") or "").strip()
                published = item.findtext("pubDate") or ""
                summary = (item.findtext("description") or "").strip()
                items.append(RegulatoryItem(
                    title=title, url=url, published=published,
                    summary=summary[:300] if summary else "",
                    jurisdiction=self.jurisdiction, feed_url=self.url
                ))

        return items
