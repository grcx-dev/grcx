# Copyright (c) 2026 Neil Lowden | GRCX | MIT License
"""
Audit log integrity tests under stress and edge conditions.
"""
import json
import time

import pytest

from grcx.audit.log import AuditLog


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fresh_log(tmp_path):
    d = tmp_path / "grcx-audit"
    d.mkdir()
    return AuditLog(log_dir=str(d))


# ---------------------------------------------------------------------------
# Stress tests
# ---------------------------------------------------------------------------

def test_chain_with_1000_entries_verifies(tmp_path):
    """1 000 chained entries verify correctly in under 5 seconds."""
    log = _fresh_log(tmp_path)

    start = time.monotonic()
    for i in range(1000):
        log.write("regulatory.new_publication", f"Entry {i}", jurisdiction="TEST")
    elapsed_write = time.monotonic() - start

    t_verify = time.monotonic()
    valid, errors = log.verify()
    elapsed_verify = time.monotonic() - t_verify

    assert valid is True
    assert errors == []
    assert (elapsed_write + elapsed_verify) < 5.0, (
        f"Total time exceeded 5 s: write={elapsed_write:.2f}s verify={elapsed_verify:.2f}s"
    )


def test_chain_with_1000_entries_then_tamper_caught(tmp_path):
    """Modifying entry 500's summary is detected as a hash mismatch by verify()."""
    log = _fresh_log(tmp_path)

    for i in range(1000):
        log.write("regulatory.new_publication", f"Entry {i}", jurisdiction="TEST")

    # Read the log, tamper line 500 (1-indexed == index 499)
    log_path = log.log_path
    lines = log_path.read_text().splitlines()
    assert len(lines) == 1000

    entry_500 = json.loads(lines[499])
    entry_500["summary"] = "TAMPERED"
    lines[499] = json.dumps(entry_500)

    log_path.write_text("\n".join(lines) + "\n")

    # Re-instantiate to get a fresh _last_hash
    log2 = AuditLog(log_dir=str(log_path.parent))
    valid, errors = log2.verify()

    assert valid is False
    assert len(errors) > 0
    # At least one error should reference line 500 or a hash mismatch
    combined = " ".join(errors)
    assert "500" in combined or "mismatch" in combined.lower() or "tamper" in combined.lower()


def test_chain_with_unicode_summaries_verifies(tmp_path):
    """100 entries with non-ASCII summaries produce a valid chain."""
    log = _fresh_log(tmp_path)

    for i in range(100):
        log.write(
            "regulatory.new_publication",
            f"Réglementation €{i}M — 中文 Arabic: العربية entry #{i}",
            jurisdiction="TEST",
        )

    valid, errors = log.verify()
    assert valid is True
    assert errors == []


def test_chain_with_very_long_summary_verifies(tmp_path):
    """10 entries each with a 10 000-character summary produce a valid chain."""
    log = _fresh_log(tmp_path)
    long_summary = "x" * 10_000

    for i in range(10):
        log.write("regulatory.new_publication", long_summary, jurisdiction="TEST")

    valid, errors = log.verify()
    assert valid is True
    assert errors == []


def test_chain_with_empty_summary(tmp_path):
    """Entries with empty-string summary are chained and verified correctly."""
    log = _fresh_log(tmp_path)

    for _ in range(5):
        log.write("regulatory.new_publication", "", jurisdiction="TEST")

    valid, errors = log.verify()
    assert valid is True
    assert errors == []


def test_chain_with_complex_nested_detail(tmp_path):
    """Deeply nested detail dict is serialised deterministically and verifies."""
    log = _fresh_log(tmp_path)

    detail = {"a": {"b": {"c": [1, 2, [3, 4, {"d": None}]]}}}
    log.write("control.breach", "Nested detail test", detail=detail, jurisdiction="TEST")

    valid, errors = log.verify()
    assert valid is True
    assert errors == []


def test_chain_severity_unknown_value_still_chains(tmp_path):
    """An unrecognised severity value is accepted; the chain is still valid."""
    log = _fresh_log(tmp_path)

    log.write(
        "regulatory.new_publication",
        "Entry with unusual severity",
        severity="bogus-value",
        jurisdiction="TEST",
    )
    log.write(
        "regulatory.new_publication",
        "Follow-up entry",
        severity="info",
        jurisdiction="TEST",
    )

    valid, errors = log.verify()
    assert valid is True
    assert errors == []


def test_tail_returns_correct_count_at_boundary(tmp_path):
    """tail() boundary cases: n==0 returns [], n==1 returns 1, n==5 returns 5, n>total returns all."""
    log = _fresh_log(tmp_path)

    for i in range(5):
        log.write("regulatory.new_publication", f"Entry {i}", jurisdiction="TEST")

    assert len(log.tail(0)) == 0

    assert len(log.tail(1)) == 1
    assert len(log.tail(5)) == 5
    # Asking for more entries than exist returns only what is present
    assert len(log.tail(100)) == 5
