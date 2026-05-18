"""Tests for RssSentinel.fetch deduplication behaviour — network mocked with respx."""
import httpx
import pytest
import respx

from grcx.sentinel.regulatory.rss import RssSentinel

FEED_URL = "https://feeds.test/boe.xml"


def make_sentinel(tmp_audit_dir):
    return RssSentinel(
        url=FEED_URL, jurisdiction="TEST", state_dir=str(tmp_audit_dir)
    )


def test_first_fetch_returns_all_items(tmp_audit_dir, rss_boe_xml):
    sentinel = make_sentinel(tmp_audit_dir)
    with respx.mock:
        respx.get(FEED_URL).mock(return_value=httpx.Response(200, text=rss_boe_xml))
        items = sentinel.fetch()
    assert len(items) == 3


def test_second_fetch_returns_no_new_items(tmp_audit_dir, rss_boe_xml):
    sentinel = make_sentinel(tmp_audit_dir)
    with respx.mock:
        respx.get(FEED_URL).mock(return_value=httpx.Response(200, text=rss_boe_xml))
        first = sentinel.fetch()
        second = sentinel.fetch()
    assert len(first) == 3
    assert second == []


def test_seen_state_file_written(tmp_audit_dir, rss_boe_xml):
    sentinel = make_sentinel(tmp_audit_dir)
    with respx.mock:
        respx.get(FEED_URL).mock(return_value=httpx.Response(200, text=rss_boe_xml))
        items = sentinel.fetch()

    assert sentinel.state_path.exists()
    contents = sentinel.state_path.read_text().splitlines()
    fingerprints = {i.fingerprint for i in items}
    for fp in fingerprints:
        assert fp in contents


def test_new_item_after_seen(tmp_audit_dir, rss_boe_xml):
    sentinel = make_sentinel(tmp_audit_dir)
    # Parse the feed to get the actual fingerprints
    all_items = sentinel._parse(rss_boe_xml)
    assert len(all_items) == 3
    # Pre-populate seen file with first two fingerprints
    sentinel.state_path.write_text(
        "\n".join([all_items[0].fingerprint, all_items[1].fingerprint])
    )
    sentinel._seen = sentinel._load_seen()

    with respx.mock:
        respx.get(FEED_URL).mock(return_value=httpx.Response(200, text=rss_boe_xml))
        items = sentinel.fetch()

    assert len(items) == 1
    assert items[0].fingerprint == all_items[2].fingerprint


def test_fetch_failure_returns_empty_list(tmp_audit_dir):
    sentinel = make_sentinel(tmp_audit_dir)
    with respx.mock:
        respx.get(FEED_URL).mock(return_value=httpx.Response(500))
        result = sentinel.fetch()
    assert result == []


def test_fetch_retries_once(tmp_audit_dir, rss_boe_xml):
    sentinel = make_sentinel(tmp_audit_dir)
    # First call returns 500, second returns 200 with valid feed
    with respx.mock:
        route = respx.get(FEED_URL)
        route.side_effect = [
            httpx.Response(500),
            httpx.Response(200, text=rss_boe_xml),
        ]
        items = sentinel.fetch()
    assert len(items) == 3
