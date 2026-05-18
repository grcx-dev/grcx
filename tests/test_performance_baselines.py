"""
Performance regression guard-rails for GRCX core components.

These tests use generous thresholds (5-10x above observed behaviour) so they
catch order-of-magnitude regressions without being sensitive to CI runner
variability. They are NOT micro-benchmarks — a test passing here does not
mean performance is good, only that it has not catastrophically regressed.

Run with -v to see the actual measured times printed by each test.
"""
import time

import pytest

from grcx.audit.log import AuditLog
from grcx.sentinel.regulatory.rss import RegulatoryItem, RssSentinel


# ---------------------------------------------------------------------------
# AuditLog write performance
# ---------------------------------------------------------------------------

def test_audit_write_under_50ms(audit_log):
    """Each individual write to the audit log must complete under 50ms."""
    timings = []
    for i in range(10):
        start = time.perf_counter()
        audit_log.write(event_type="perf.test", summary=f"write {i}")
        elapsed = time.perf_counter() - start
        timings.append(elapsed)

    max_ms = max(timings) * 1000
    print(f"\nActual: max single write = {max_ms:.1f}ms over 10 writes")
    for i, t in enumerate(timings):
        assert t < 0.050, (
            f"Write {i} took {t*1000:.1f}ms, which exceeds the 50ms threshold"
        )


# ---------------------------------------------------------------------------
# AuditLog verify performance
# ---------------------------------------------------------------------------

def test_audit_verify_1000_entries_under_5s(tmp_audit_dir):
    """verify() on a 1000-entry log must complete under 5 seconds."""
    log = AuditLog(log_dir=str(tmp_audit_dir))
    for i in range(1000):
        log.write(event_type="perf.bulk", summary=f"entry {i}")

    start = time.perf_counter()
    valid, errors = log.verify()
    elapsed = time.perf_counter() - start

    print(f"\nActual: verify(1000 entries) = {elapsed*1000:.1f}ms")
    assert valid, f"Log failed to verify: {errors}"
    assert elapsed < 5.0, (
        f"verify() took {elapsed:.2f}s on 1000 entries, exceeds 5s threshold"
    )


def test_audit_verify_100_entries_under_500ms(tmp_audit_dir):
    """verify() on a 100-entry log must complete under 500ms."""
    log = AuditLog(log_dir=str(tmp_audit_dir))
    for i in range(100):
        log.write(event_type="perf.medium", summary=f"entry {i}")

    start = time.perf_counter()
    valid, errors = log.verify()
    elapsed = time.perf_counter() - start

    print(f"\nActual: verify(100 entries) = {elapsed*1000:.1f}ms")
    assert valid, f"Log failed to verify: {errors}"
    assert elapsed < 0.500, (
        f"verify() took {elapsed*1000:.1f}ms on 100 entries, exceeds 500ms threshold"
    )


# ---------------------------------------------------------------------------
# RegulatoryItem fingerprint performance
# ---------------------------------------------------------------------------

def test_fingerprint_under_1ms(make_item):
    """RegulatoryItem.__post_init__ (fingerprint computation) must average under 1ms."""
    timings = []
    for i in range(100):
        start = time.perf_counter()
        make_item(title=f"Publication {i}", url=f"https://example.org/pub/{i}")
        elapsed = time.perf_counter() - start
        timings.append(elapsed)

    avg_ms = (sum(timings) / len(timings)) * 1000
    print(f"\nActual: avg fingerprint time = {avg_ms:.3f}ms over 100 items")
    assert avg_ms < 1.0, (
        f"Average fingerprint time {avg_ms:.3f}ms exceeds 1ms threshold"
    )


# ---------------------------------------------------------------------------
# RssSentinel._parse performance
# ---------------------------------------------------------------------------

def _build_rss_feed(n: int) -> str:
    """Build a valid RSS 2.0 XML string with n <item> elements."""
    items = []
    for i in range(n):
        items.append(
            f"    <item>\n"
            f"      <title>Publication {i}</title>\n"
            f"      <link>https://example.org/pub/{i}</link>\n"
            f"      <pubDate>Mon, 01 Jan 2026 00:00:00 GMT</pubDate>\n"
            f"      <description>Description for publication {i}.</description>\n"
            f"    </item>"
        )
    body = "\n".join(items)
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        "<rss version=\"2.0\">\n"
        "  <channel>\n"
        "    <title>Test Feed</title>\n"
        "    <link>https://example.org</link>\n"
        "    <description>Performance test feed</description>\n"
        f"{body}\n"
        "  </channel>\n"
        "</rss>"
    )


def test_rss_parse_100_items_under_200ms(tmp_audit_dir):
    """_parse() on a 100-item RSS feed must complete under 200ms."""
    xml = _build_rss_feed(100)
    sentinel = RssSentinel(
        url="https://example.org/feed",
        jurisdiction="TEST",
        state_dir=str(tmp_audit_dir),
    )

    start = time.perf_counter()
    items = sentinel._parse(xml)
    elapsed = time.perf_counter() - start

    print(f"\nActual: _parse(100 items) = {elapsed*1000:.1f}ms")
    assert len(items) == 100, f"Expected 100 items, got {len(items)}"
    assert elapsed < 0.200, (
        f"_parse() took {elapsed*1000:.1f}ms on 100 items, exceeds 200ms threshold"
    )
