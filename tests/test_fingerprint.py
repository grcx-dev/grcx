# Tests for RegulatoryItem.fingerprint (sha256(url+title)[:16])
import hashlib
import pytest

from grcx.sentinel.regulatory.rss import RegulatoryItem


def test_fingerprint_is_deterministic(make_item):
    item1 = make_item(url="https://example.org/pub/1", title="Regulatory Guidance")
    item2 = make_item(url="https://example.org/pub/1", title="Regulatory Guidance")
    assert item1.fingerprint == item2.fingerprint


def test_fingerprint_depends_on_url_and_title(make_item):
    base = make_item(url="https://example.org/pub/base", title="Base Title")

    changed_url = make_item(url="https://example.org/pub/other", title="Base Title")
    assert changed_url.fingerprint != base.fingerprint

    changed_title = make_item(url="https://example.org/pub/base", title="Different Title")
    assert changed_title.fingerprint != base.fingerprint

    # Changes to other fields must NOT affect the fingerprint
    changed_summary = make_item(
        url="https://example.org/pub/base",
        title="Base Title",
        summary="Completely different summary text",
    )
    assert changed_summary.fingerprint == base.fingerprint

    changed_published = make_item(
        url="https://example.org/pub/base",
        title="Base Title",
        published="Mon, 01 Jan 2026 00:00:00 GMT",
    )
    assert changed_published.fingerprint == base.fingerprint

    changed_jurisdiction = make_item(
        url="https://example.org/pub/base",
        title="Base Title",
        jurisdiction="OTHER",
    )
    assert changed_jurisdiction.fingerprint == base.fingerprint

    changed_feed_url = make_item(
        url="https://example.org/pub/base",
        title="Base Title",
        feed_url="https://different.org/feed",
    )
    assert changed_feed_url.fingerprint == base.fingerprint


def test_fingerprint_length_is_16(make_item):
    item = make_item()
    assert len(item.fingerprint) == 16
    assert all(c in "0123456789abcdef" for c in item.fingerprint)


def test_fingerprint_golden_value(make_item):
    """Golden-value test — DO NOT update without intent.
    Changing this hash breaks dedup state for every existing deployment.
    """
    url = "https://example.org/x"
    title = "Test Title"
    expected = hashlib.sha256(b"https://example.org/xTest Title").hexdigest()[:16]
    item = make_item(url=url, title=title)
    assert item.fingerprint == expected
