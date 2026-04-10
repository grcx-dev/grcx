# Copyright (c) 2026 Neil Lowden | GRCX | MIT License
import hashlib
import httpx
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional
from rich.console import Console

console = Console()

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; GRCX/0.1; +https://github.com/grcxdev/grcx)"
}

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
        self.fingerprint = hashlib.sha256(
            f"{self.url}{self.title}".encode()
        ).hexdigest()[:16]


class RssSentinel:
    """
    Watches an RSS/Atom feed for new regulatory publications.
    Tracks seen items via a local state file to avoid re-alerting.
    """

    def __init__(self, url: str, jurisdiction: str, state_dir: str = "grcx-audit"):
        self.url = url
        self.jurisdiction = jurisdiction
        self.state_path = Path(state_dir) / f"seen_{jurisdiction.lower()}.txt"
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self._seen = self._load_seen()

    def _load_seen(self) -> set:
        if self.state_path.exists():
            return set(self.state_path.read_text().splitlines())
        return set()

    def _save_seen(self):
        self.state_path.write_text("\n".join(self._seen))

    def fetch(self) -> list[RegulatoryItem]:
        """Fetch the feed and return only items we haven't seen before."""
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
        new_items = [i for i in items if i.fingerprint not in self._seen]

        for item in new_items:
            self._seen.add(item.fingerprint)
        self._save_seen()

        return new_items

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
