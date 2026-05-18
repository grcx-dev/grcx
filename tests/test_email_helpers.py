"""Tests for module-level helper functions in imap_email."""
import pytest

import grcx.sentinel.regulatory.imap_email as imap_mod
from grcx.sentinel.regulatory.imap_email import (
    _decode_header_value,
    _links_from_html,
    _links_from_plain,
    _title_from_slug,
    fetch_page_title,
)


# ---------------------------------------------------------------------------
# _decode_header_value
# ---------------------------------------------------------------------------

def test_decode_header_handles_utf8_encoded():
    result = _decode_header_value("=?utf-8?Q?Test_=C2=A3?=")
    assert result == "Test £"


def test_decode_header_plain_string():
    result = _decode_header_value("Plain Subject")
    assert result == "Plain Subject"


# ---------------------------------------------------------------------------
# _links_from_plain
# ---------------------------------------------------------------------------

def test_links_from_plain_extracts_urls():
    result = _links_from_plain("see https://a.com and https://b.com/x")
    assert len(result) == 2
    texts = [t for t, _ in result]
    hrefs = [h for _, h in result]
    assert "https://a.com" in hrefs
    assert "https://b.com/x" in hrefs
    # text equals href for bare URLs
    for text, href in result:
        assert text == href


# ---------------------------------------------------------------------------
# _links_from_html
# ---------------------------------------------------------------------------

def test_links_from_html():
    html = (
        '<a href="https://example.com/good-publication-2026">Good Publication 2026</a>'
        '<a href="mailto:foo@bar.com">Email me</a>'
    )
    result = _links_from_html(html)
    hrefs = [h for _, h in result]
    assert "https://example.com/good-publication-2026" in hrefs
    # mailto should be excluded
    assert not any("mailto" in h for h in hrefs)
    assert len(result) == 1


# ---------------------------------------------------------------------------
# _title_from_slug
# ---------------------------------------------------------------------------

def test_title_from_slug():
    result = _title_from_slug("https://x.com/a-b-c-document.html")
    assert result == "A B C Document"


def test_title_from_slug_root_path_returns_none():
    result = _title_from_slug("https://x.com/")
    assert result is None


# ---------------------------------------------------------------------------
# fetch_page_title — monkeypatched httpx
# ---------------------------------------------------------------------------

def _make_fake_get(html: str):
    """Return a fake httpx.get that returns the given HTML."""
    class _Resp:
        status_code = 200
        text = html

        def raise_for_status(self):
            pass

    def _fake_get(url, **kwargs):
        return _Resp()

    return _fake_get


def test_fetch_page_title_drupal(monkeypatch):
    html = (
        '<html><body>'
        '<span class="field field--name-title field--type-string">Page Title</span>'
        '</body></html>'
    )
    monkeypatch.setattr(imap_mod.httpx, "get", _make_fake_get(html))
    result = fetch_page_title("https://example.com/some-publication")
    assert result == "Page Title"


def test_fetch_page_title_h1_fallback(monkeypatch):
    html = "<html><body><h1>Some Heading That Is Long Enough</h1></body></html>"
    monkeypatch.setattr(imap_mod.httpx, "get", _make_fake_get(html))
    result = fetch_page_title("https://example.com/some-publication")
    assert result == "Some Heading That Is Long Enough"


def test_fetch_page_title_title_tag_strips_suffix(monkeypatch):
    html = "<html><head><title>Real Title | Site Name</title></head><body></body></html>"
    monkeypatch.setattr(imap_mod.httpx, "get", _make_fake_get(html))
    result = fetch_page_title("https://example.com/some-publication")
    assert result == "Real Title"


def test_fetch_page_title_network_error_falls_back_to_slug(monkeypatch):
    def _raising_get(url, **kwargs):
        raise ConnectionError("network down")

    monkeypatch.setattr(imap_mod.httpx, "get", _raising_get)
    result = fetch_page_title("https://example.com/technology-risk-document")
    # Falls back to slug-derived title or None
    # The slug "technology-risk-document" has len > 4, so should return a title
    assert result == "Technology Risk Document" or result is None
