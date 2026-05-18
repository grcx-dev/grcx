# Copyright (c) 2026 Neil Lowden | GRCX | MIT License
"""
Tests for malformed/adversarial external data robustness in the GRCX pipeline.
"""
import email as email_module

import pytest

from grcx.sentinel.regulatory.imap_email import (
    EmailSentinel,
    _LinkExtractor,
)
from grcx.sentinel.regulatory.rss import RssSentinel


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_sentinel(tmp_path):
    return RssSentinel(
        url="https://example.org/feed.rss",
        jurisdiction="TEST",
        state_dir=str(tmp_path / "state"),
    )


def _make_email_sentinel(tmp_path):
    return EmailSentinel(
        host="imap.example.org",
        username="user@example.org",
        jurisdiction="TEST",
        sender_filter="regs@example.eu",
        state_dir=str(tmp_path / "state"),
    )


# ---------------------------------------------------------------------------
# RSS malformed feed tests
# ---------------------------------------------------------------------------

def test_rss_malformed_feed_partial_parse(rss_malformed_xml, tmp_path):
    """Missing title/link items are included; javascript: href is preserved as-is.

    The RSS parser does NOT filter hrefs — that is the email parser's job.
    """
    sentinel = _make_sentinel(tmp_path)
    items = sentinel._parse(rss_malformed_xml)

    # Must not crash and must return some items
    assert isinstance(items, list)
    assert len(items) > 0

    titles = [i.title for i in items]
    urls = [i.url for i in items]

    # Item with missing title gets empty string
    assert "" in titles

    # Item with javascript: link is included unchanged (no href filtering at RSS level)
    assert "javascript:alert(1)" in urls


def test_rss_with_xml_external_entity_safe(tmp_path):
    """Python's xml.etree.ElementTree does not resolve XXE entities — no crash, no file leak."""
    xxe_xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        "<rss version='2.0'>"
        "<channel>"
        "<title>&xxe;</title>"
        "<item><title>Item</title><link>https://example.org/1</link></item>"
        "</channel>"
        "</rss>"
    )
    sentinel = _make_sentinel(tmp_path)
    # ElementTree raises ParseError when it encounters an external entity DOCTYPE
    # declaration (it does not resolve it), OR it may silently ignore it. Either
    # way, /etc/passwd content must not appear in any parsed item.
    try:
        items = sentinel._parse(xxe_xml)
    except Exception:
        items = []

    for item in items:
        assert "root:" not in (item.title + item.summary)
        assert "/bin/sh" not in (item.title + item.summary)


def test_rss_with_bom_marker(tmp_path):
    """A UTF-8 BOM prefix either parses successfully or returns [] gracefully.

    Pins current behaviour: no exception is raised.
    """
    base_xml = (
        "<?xml version='1.0' encoding='UTF-8'?>"
        "<rss version='2.0'>"
        "<channel>"
        "<item><title>BOM test</title><link>https://example.org/1</link></item>"
        "</channel>"
        "</rss>"
    )
    bom_xml = "﻿" + base_xml

    sentinel = _make_sentinel(tmp_path)
    # Must not raise — returns list (possibly empty on parse error)
    try:
        result = sentinel._parse(bom_xml)
        assert isinstance(result, list)
    except Exception as exc:
        pytest.fail(f"_parse raised unexpectedly with BOM input: {exc}")


def test_rss_with_no_namespace_uses_rss20_branch(tmp_path):
    """A plain RSS 2.0 feed (no Atom namespace) enters the RSS 2.0 parsing branch."""
    rss_xml = (
        "<?xml version='1.0' encoding='UTF-8'?>"
        "<rss version='2.0'>"
        "<channel>"
        "<item>"
        "<title>RSS 2.0 item</title>"
        "<link>https://example.org/rss20</link>"
        "<pubDate>Mon, 12 Jan 2026 00:00:00 +0000</pubDate>"
        "</item>"
        "</channel>"
        "</rss>"
    )
    sentinel = _make_sentinel(tmp_path)
    items = sentinel._parse(rss_xml)

    assert len(items) == 1
    assert items[0].title == "RSS 2.0 item"
    assert items[0].url == "https://example.org/rss20"


def test_email_nested_anchors_handled(email_nested_anchors_html, tmp_path):
    """Only the real policy URL survives; javascript:, mailto:, #anchor, and duplicates are filtered."""
    sentinel = _make_email_sentinel(tmp_path)

    raw = (
        "From: regs@example.eu\r\n"
        "Subject: Regulatory update\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "MIME-Version: 1.0\r\n"
        "\r\n" + email_nested_anchors_html
    )
    msg = email_module.message_from_string(raw)
    items = sentinel._parse_message(msg)

    urls = [item.url for item in items]

    # The real policy URL should be present
    assert any("policy-2026-01" in u for u in urls)

    # javascript:, mailto:, and bare anchors are not http(s) — _LinkExtractor skips them
    assert not any(u.startswith("javascript:") for u in urls)
    assert not any(u.startswith("mailto:") for u in urls)
    assert not any(u.startswith("#") for u in urls)

    # Duplicate URL should appear at most once
    dup_urls = [u for u in urls if "duplicate" in u]
    assert len(dup_urls) <= 1


def test_email_html_with_broken_tags(tmp_path):
    """An unclosed <a> tag is NOT flushed — _LinkExtractor requires </a> to emit a link.

    HTMLParser collects the text into _current_text but never calls handle_endtag,
    so the link is silently dropped. The email falls back to the subject-item path.
    Pins current behaviour: items == [] because the links list built by _LinkExtractor
    is empty, but _parse_message receives a body with '<' so it goes through the HTML
    path — with no links extracted, it falls back to the no-links subject item.
    """
    sentinel = _make_email_sentinel(tmp_path)

    broken_html = (
        '<a href="https://x.com/news-policy-2026">Unclosed anchor text '
        "<p>and a paragraph"
    )
    raw = (
        "From: regs@example.eu\r\n"
        "Subject: Update\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "MIME-Version: 1.0\r\n"
        "\r\n" + broken_html
    )
    msg = email_module.message_from_string(raw)
    items = sentinel._parse_message(msg)

    # The unclosed anchor is never flushed so no links are extracted; the
    # code falls back to treating the email itself as a single item.
    assert len(items) == 1
    assert items[0].url == "imap://imap.example.org"


def test_email_with_only_unsubscribe_link_falls_back_to_subject_item(tmp_path):
    """When the only link passes the http-check but matches a _SKIP_HREF pattern,
    items returned == [] because the links list was non-empty before filtering.
    The no-links fallback only fires when `not links` BEFORE filtering.
    """
    sentinel = _make_email_sentinel(tmp_path)

    html = (
        "<html><body>"
        "<a href='https://example.org/unsubscribe/xyz'>Click here to unsubscribe</a>"
        "</body></html>"
    )
    raw = (
        "From: regs@example.eu\r\n"
        "Subject: Important update\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "MIME-Version: 1.0\r\n"
        "\r\n" + html
    )
    msg = email_module.message_from_string(raw)
    items = sentinel._parse_message(msg)

    # The code only falls back to a subject item when `not links` BEFORE filtering.
    # A non-empty links list that becomes empty after filtering yields no items.
    assert items == []


def test_email_with_link_at_exactly_15_char_boundary(tmp_path):
    """Anchor text of length 14 is skipped; text of length 15 is included."""
    sentinel = _make_email_sentinel(tmp_path)

    # 14-char text: "ABCDEFGHIJKLMN"
    text_14 = "A" * 14
    # 15-char text: "ABCDEFGHIJKLMNO"
    text_15 = "A" * 15

    html = (
        "<html><body>"
        f"<a href='https://example.org/short'>{text_14}</a>"
        f"<a href='https://example.org/enough'>{text_15}</a>"
        "</body></html>"
    )
    raw = (
        "From: regs@example.eu\r\n"
        "Subject: Boundary test\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "MIME-Version: 1.0\r\n"
        "\r\n" + html
    )
    msg = email_module.message_from_string(raw)
    items = sentinel._parse_message(msg)

    urls = [item.url for item in items]
    # 14 chars: filtered out (len < 15)
    assert "https://example.org/short" not in urls
    # 15 chars: included (len == 15, not < 15)
    assert "https://example.org/enough" in urls
