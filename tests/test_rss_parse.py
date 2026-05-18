"""Tests for RssSentinel._parse — no network required."""
import pytest

from grcx.sentinel.regulatory.rss import RssSentinel


def make_sentinel(tmp_audit_dir):
    return RssSentinel(
        url="https://x", jurisdiction="TEST", state_dir=str(tmp_audit_dir)
    )


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def test_parses_rss_2_feed(tmp_audit_dir, rss_boe_xml):
    sentinel = make_sentinel(tmp_audit_dir)
    items = sentinel._parse(rss_boe_xml)
    assert len(items) == 3
    first = items[0]
    assert first.title == "Bank Resolution Standards Instrument 2026"
    assert first.url.startswith("https://")
    assert first.published != ""


def test_parses_atom_feed(tmp_audit_dir, atom_esma_xml):
    sentinel = make_sentinel(tmp_audit_dir)
    items = sentinel._parse(atom_esma_xml)
    assert len(items) == 2
    titles = [i.title for i in items]
    assert "ESMA publishes final report on MiCA technical standards" in titles
    assert "Consultation on MiFID II transparency review" in titles
    # Links are extracted from href attribute
    for item in items:
        assert item.url.startswith("https://")


def test_summary_clipped_to_300_chars(tmp_audit_dir):
    long_desc = "A" * 500
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        "<rss version=\"2.0\"><channel>"
        f"<item><title>Test</title><link>https://x.com/item</link>"
        f"<description>{long_desc}</description></item>"
        "</channel></rss>"
    )
    sentinel = make_sentinel(tmp_audit_dir)
    items = sentinel._parse(xml)
    assert len(items) == 1
    assert len(items[0].summary) <= 300


def test_malformed_xml_returns_empty_list(tmp_audit_dir):
    sentinel = make_sentinel(tmp_audit_dir)
    result = sentinel._parse("<not xml")
    assert result == []


def test_rss_without_channel_returns_empty(tmp_audit_dir):
    sentinel = make_sentinel(tmp_audit_dir)
    result = sentinel._parse('<rss version="2.0"></rss>')
    assert result == []


def test_missing_fields_default_to_empty_strings(tmp_audit_dir):
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<rss version="2.0"><channel>'
        "<item><title>Only Title</title></item>"
        "</channel></rss>"
    )
    sentinel = make_sentinel(tmp_audit_dir)
    items = sentinel._parse(xml)
    assert len(items) == 1
    item = items[0]
    assert item.title == "Only Title"
    assert item.url == ""
    assert item.published == ""
    assert item.summary == ""
