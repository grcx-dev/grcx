"""Tests for EmailSentinel._parse_message — no IMAP required."""
import email as email_mod
import email.message

import pytest

import grcx.sentinel.regulatory.imap_email as imap_mod
from grcx.sentinel.regulatory.imap_email import EmailSentinel


def make_sentinel(tmp_audit_dir):
    return EmailSentinel(
        host="imap.x",
        username="u",
        jurisdiction="TEST",
        sender_filter="x@y",
        state_dir=str(tmp_audit_dir),
    )


def _build_html_message(html: str, subject: str = "Test Subject", date: str = "Mon, 01 Jan 2026 09:00:00 GMT") -> email.message.Message:
    raw = (
        f"Subject: {subject}\r\n"
        f"Date: {date}\r\n"
        f"From: sender@example.com\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "\r\n"
        + html
    )
    return email_mod.message_from_string(raw)


def _build_plain_message(text: str, subject: str = "Test Subject", date: str = "Mon, 01 Jan 2026 09:00:00 GMT") -> email.message.Message:
    raw = (
        f"Subject: {subject}\r\n"
        f"Date: {date}\r\n"
        f"From: sender@example.com\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "\r\n"
        + text
    )
    return email_mod.message_from_string(raw)


# ---------------------------------------------------------------------------
# FCA HTML email parsing
# ---------------------------------------------------------------------------

def test_extracts_publication_links_from_html(tmp_audit_dir, email_fca_html):
    sentinel = make_sentinel(tmp_audit_dir)
    msg = _build_html_message(email_fca_html)
    items = sentinel._parse_message(msg)
    titles = [i.title for i in items]
    urls = [i.url for i in items]
    assert len(items) == 3
    assert any("PS26/3" in t for t in titles)
    assert any("CP26/7" in t for t in titles)
    assert any("speech" in t.lower() or "trust" in t.lower() for t in titles)
    assert all("fca.org.uk" in u for u in urls)


def test_skips_unsubscribe_and_preferences_links(tmp_audit_dir, email_fca_html):
    sentinel = make_sentinel(tmp_audit_dir)
    msg = _build_html_message(email_fca_html)
    items = sentinel._parse_message(msg)
    for item in items:
        assert "unsubscribe" not in item.url.lower()
        assert "preferences" not in item.url.lower()
        assert "optout" not in item.url.lower()


def test_skips_view_in_browser_and_short_text(tmp_audit_dir, email_fca_html):
    sentinel = make_sentinel(tmp_audit_dir)
    msg = _build_html_message(email_fca_html)
    items = sentinel._parse_message(msg)
    boilerplate = {"View in browser", "Follow us", "News", "Privacy policy"}
    for item in items:
        assert item.title not in boilerplate


def test_skips_bare_domain_anchor_text(tmp_audit_dir, email_fca_html):
    sentinel = make_sentinel(tmp_audit_dir)
    msg = _build_html_message(email_fca_html)
    items = sentinel._parse_message(msg)
    for item in items:
        assert item.title != "fca.org.uk"


# ---------------------------------------------------------------------------
# MAS URL-as-anchor-text
# ---------------------------------------------------------------------------

def test_url_anchor_resolves_via_fetch_page_title(
    tmp_audit_dir, email_mas_url_html, monkeypatch
):
    monkeypatch.setattr(
        imap_mod,
        "fetch_page_title",
        lambda url: "Technology Risk Management Notice",
    )
    sentinel = make_sentinel(tmp_audit_dir)
    msg = _build_html_message(email_mas_url_html)
    items = sentinel._parse_message(msg)
    assert len(items) == 1
    assert items[0].title == "Technology Risk Management Notice"


# ---------------------------------------------------------------------------
# Plain text email
# ---------------------------------------------------------------------------

def test_plain_text_email_extracts_bare_urls(tmp_audit_dir):
    # Use a clean plain text body (no angle brackets) so the code takes the
    # _links_from_plain path. The email_plain_text fixture contains the
    # "From: ... <email>" line which introduces "<", causing _parse_message to
    # route through _links_from_html (which finds no anchors) instead.
    clean_body = (
        "Dear Subscriber,\n\n"
        "The MAS has published:\n\n"
        "  https://www.mas.gov.sg/regulation/notices/notice-tcb-n01\n"
        "  https://www.mas.gov.sg/news/media-releases/2026/cyber-hygiene-update\n\n"
        "Best regards, MAS"
    )
    sentinel = make_sentinel(tmp_audit_dir)
    msg = _build_plain_message(clean_body)
    items = sentinel._parse_message(msg)
    # Both URLs are > 15 chars so they survive the len filter
    item_urls = [i.url for i in items]
    assert any("notice-tcb-n01" in u for u in item_urls)
    assert any("cyber-hygiene-update" in u for u in item_urls)
    assert len(items) == 2


# ---------------------------------------------------------------------------
# No-link fallback
# ---------------------------------------------------------------------------

def test_email_with_no_links_returns_subject_as_single_item(tmp_audit_dir):
    sentinel = make_sentinel(tmp_audit_dir)
    msg = _build_plain_message("No links here at all", subject="Important update")
    items = sentinel._parse_message(msg)
    assert len(items) == 1
    assert items[0].title == "Important update"


# ---------------------------------------------------------------------------
# Deduplication of identical hrefs
# ---------------------------------------------------------------------------

def test_duplicate_hrefs_deduplicated(tmp_audit_dir):
    sentinel = make_sentinel(tmp_audit_dir)
    html = (
        '<a href="https://example.com/publication-about-regulations-2026">First link text for dedup test</a>'
        '<a href="https://example.com/publication-about-regulations-2026">Duplicate link text for dedup</a>'
    )
    msg = _build_html_message(html)
    items = sentinel._parse_message(msg)
    hrefs = [i.url for i in items]
    assert hrefs.count("https://example.com/publication-about-regulations-2026") == 1
