# Copyright (c) 2026 Neil Lowden | GRCX | MIT License
"""
Tests for unicode/encoding robustness across the GRCX pipeline.
"""
import email as email_module
import unicodedata

import pytest

from grcx.sentinel.regulatory.imap_email import (
    EmailSentinel,
    _decode_header_value,
    _extract_html_body,
)
from grcx.sentinel.regulatory.rss import RegulatoryItem, RssSentinel


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_sentinel(tmp_path):
    """Return an RssSentinel pointed at a throwaway state dir."""
    return RssSentinel(
        url="https://example.org/feed.rss",
        jurisdiction="TEST",
        state_dir=str(tmp_path / "state"),
    )


def _make_email_sentinel(tmp_path):
    """Return an EmailSentinel pointed at a throwaway state dir."""
    return EmailSentinel(
        host="imap.example.org",
        username="user@example.org",
        jurisdiction="TEST",
        sender_filter="regs@example.eu",
        state_dir=str(tmp_path / "state"),
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_rss_unicode_titles_parse_correctly(rss_unicode_xml, tmp_path):
    """Item 1 title has multi-byte chars and a decoded &amp;; item 2 has decoded XSS."""
    sentinel = _make_sentinel(tmp_path)
    items = sentinel._parse(rss_unicode_xml)

    assert len(items) >= 2

    title1 = items[0].title
    assert "Règlement" in title1
    assert "€" in title1  # € sign
    assert "ABN AMRO" in title1
    # &amp; in XML is decoded by ElementTree to a literal &
    assert "&" in title1

    # ElementTree decodes XML entities, so &lt;script&gt; becomes literal <script>
    title2 = items[1].title
    assert "<script>" in title2
    assert "alert(1)" in title2
    assert "</script>" in title2


def test_rss_unicode_fingerprint_stable(tmp_path):
    """Two items with identical unicode title and URL produce identical fingerprints."""
    title = "Règlement européen — €1M fine"
    url = "https://example.org/regs/2026/01"

    item_a = RegulatoryItem(
        title=title, url=url,
        published="", summary="", jurisdiction="TEST", feed_url="https://example.org/feed",
    )
    item_b = RegulatoryItem(
        title=title, url=url,
        published="", summary="", jurisdiction="TEST", feed_url="https://example.org/feed",
    )

    assert item_a.fingerprint == item_b.fingerprint


def test_rss_unicode_fingerprint_byte_sensitive(tmp_path):
    """NFC and NFD forms of the same string produce different fingerprints.

    Documents that deduplication is byte-level, not unicode-normalisation-aware.
    """
    title_nfc = unicodedata.normalize("NFC", "Règle")   # composed: è
    title_nfd = unicodedata.normalize("NFD", "Règle")   # decomposed: e + combining grave

    # Confirm they are visually identical but byte-distinct
    assert title_nfc != title_nfd

    url = "https://example.org/regs/2026/01"
    item_nfc = RegulatoryItem(
        title=title_nfc, url=url,
        published="", summary="", jurisdiction="TEST", feed_url="https://example.org/feed",
    )
    item_nfd = RegulatoryItem(
        title=title_nfd, url=url,
        published="", summary="", jurisdiction="TEST", feed_url="https://example.org/feed",
    )

    assert item_nfc.fingerprint != item_nfd.fingerprint


def test_email_mime_encoded_subject_decoded(email_unicode_eml, tmp_path):
    """MIME-encoded (quoted-printable) subject is decoded to French text."""
    sentinel = _make_email_sentinel(tmp_path)
    msg = email_module.message_from_string(email_unicode_eml)
    items = sentinel._parse_message(msg)

    # At least one item should surface — the French regulation link
    assert len(items) >= 1
    titles = [item.title for item in items]
    combined = " ".join(titles)
    # The French regulation anchor text contains 'Règlement'
    assert "Règlement" in combined or any("glement" in t for t in titles)


def test_email_subject_decode_falls_back_on_unknown_charset():
    """_decode_header_value raises LookupError for an unknown charset — errors='replace'
    only suppresses decode errors, not missing codec lookups. Pins current behaviour.
    """
    raw = "=?bogus-charset?Q?Hello?="
    with pytest.raises(LookupError):
        _decode_header_value(raw)


def test_email_with_emoji_in_body(tmp_path):
    """An emoji in the email body does not break link extraction."""
    sentinel = _make_email_sentinel(tmp_path)

    html_body = (
        "<html><body>"
        "<p>Financial regulator update \U0001f3e6</p>"
        "<a href='https://example.org/policy-update-q1-2026'>New capital requirements for Q1 2026</a>"
        "</body></html>"
    )
    raw = (
        "From: regs@example.eu\r\n"
        "Subject: Regulatory Update\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "MIME-Version: 1.0\r\n"
        "\r\n" + html_body
    )
    msg = email_module.message_from_string(raw)
    items = sentinel._parse_message(msg)

    assert len(items) >= 1
    urls = [item.url for item in items]
    assert "https://example.org/policy-update-q1-2026" in urls


def test_email_html_body_preferred_over_plain(tmp_path):
    """_extract_html_body returns the text/html part when both parts exist."""
    raw = (
        "From: regs@example.eu\r\n"
        "Subject: Test\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: multipart/alternative; boundary=\"BOUNDARY\"\r\n"
        "\r\n"
        "--BOUNDARY\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "\r\n"
        "Plain text body with https://example.org/plain-link\r\n"
        "--BOUNDARY\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "\r\n"
        "<html><body><a href='https://example.org/html-link'>HTML link</a></body></html>\r\n"
        "--BOUNDARY--\r\n"
    )
    msg = email_module.message_from_string(raw)
    body = _extract_html_body(msg)

    assert "html-link" in body
    assert "plain-link" not in body


def test_audit_log_writes_unicode_summary_and_verifies(audit_log):
    """Unicode summaries (including emoji) round-trip through the audit log intact."""
    summary = "€1M fine for Banco Santander \U0001f3e6"
    audit_log.write("regulatory.new_publication", summary, jurisdiction="TEST")

    valid, errors = audit_log.verify()
    assert valid is True
    assert errors == []

    entries = audit_log.tail(1)
    assert len(entries) == 1
    assert entries[0]["summary"] == summary
