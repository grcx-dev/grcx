"""
Audit log backwards-compatibility tests.

These tests verify that existing log files remain readable and verifiable
after code changes. If a future fix adds new fields (e.g. a `signature`
field for cryptographic signing), entries written without that field must
still pass verify() and be returned correctly by tail().

The helper _compute_hash() below mirrors AuditLog._hash_entry so tests can
build valid hash chains by hand without importing the private method.
"""
import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

from grcx.audit.log import AuditLog


# ---------------------------------------------------------------------------
# Helper: mirrors AuditLog._hash_entry
# ---------------------------------------------------------------------------

def _compute_hash(entry: dict) -> str:
    """Compute SHA-256 of entry content, excluding the entry_hash field itself."""
    hashable = {k: v for k, v in entry.items() if k != "entry_hash"}
    content = json.dumps(hashable, sort_keys=True)
    return hashlib.sha256(content.encode()).hexdigest()


def _make_entry(
    event_type: str,
    summary: str,
    prev_hash: str,
    *,
    severity: str = "info",
    jurisdiction: str = None,
    source: str = None,
    detail: dict = None,
) -> dict:
    """Build a v0-schema entry dict with a correctly computed entry_hash."""
    entry = {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "severity": severity,
        "summary": summary,
        "jurisdiction": jurisdiction,
        "source": source,
        "detail": detail or {},
        "prev_hash": prev_hash,
    }
    entry["entry_hash"] = _compute_hash(entry)
    return entry


def _write_chain(log_path: Path, entries: list[dict]) -> None:
    """Write a list of entry dicts to a JSONL file."""
    with open(log_path, "w") as f:
        for entry in entries:
            f.write(json.dumps(entry) + "\n")


def _build_v0_chain(n: int) -> list[dict]:
    """Build a valid chain of n v0-schema entries."""
    entries = []
    prev = "genesis"
    for i in range(n):
        entry = _make_entry(
            event_type="test.event",
            summary=f"Entry {i}",
            prev_hash=prev,
        )
        entries.append(entry)
        prev = entry["entry_hash"]
    return entries


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_v0_log_without_signature_field_verifies(tmp_audit_dir):
    """A hand-written v0 JSONL file with current schema fields must verify correctly."""
    log_path = tmp_audit_dir / "grcx.log.jsonl"
    entries = _build_v0_chain(3)
    _write_chain(log_path, entries)

    log = AuditLog(log_dir=str(tmp_audit_dir))
    valid, errors = log.verify()

    assert valid, f"v0 log failed to verify. Errors: {errors}"
    assert errors == []


def test_v0_log_tail_works(tmp_audit_dir):
    """tail(2) on a v0 log returns the last 2 entries with all expected fields."""
    log_path = tmp_audit_dir / "grcx.log.jsonl"
    entries = _build_v0_chain(3)
    _write_chain(log_path, entries)

    log = AuditLog(log_dir=str(tmp_audit_dir))
    result = log.tail(2)

    assert len(result) == 2
    # The last two entries from our chain
    assert result[0]["id"] == entries[1]["id"]
    assert result[1]["id"] == entries[2]["id"]

    # Each entry should carry all expected v0 fields
    expected_fields = {
        "id", "timestamp", "event_type", "severity",
        "summary", "jurisdiction", "source", "detail",
        "prev_hash", "entry_hash",
    }
    for returned in result:
        assert expected_fields.issubset(set(returned.keys())), (
            f"Missing fields: {expected_fields - set(returned.keys())}"
        )


def test_v0_log_can_be_appended_to(tmp_audit_dir):
    """AuditLog.write() after a hand-written v0 log correctly chains onto it."""
    log_path = tmp_audit_dir / "grcx.log.jsonl"
    entries = _build_v0_chain(3)
    _write_chain(log_path, entries)

    last_v0_hash = entries[-1]["entry_hash"]

    log = AuditLog(log_dir=str(tmp_audit_dir))
    new_entry = log.write(event_type="append.test", summary="Appended after v0")

    # The new entry's prev_hash must chain from the last v0 entry
    assert new_entry["prev_hash"] == last_v0_hash, (
        f"Expected prev_hash={last_v0_hash}, got {new_entry['prev_hash']}"
    )

    # The full chain (v0 entries + new entry) must verify cleanly
    valid, errors = log.verify()
    assert valid, f"Extended chain failed to verify. Errors: {errors}"
    assert errors == []


def test_log_with_unknown_extra_fields_still_verifies(tmp_audit_dir):
    """
    Entries containing an unknown extra field (included in the hash) must still
    verify. The chain logic checks hash-over-content matches stored hash; it
    does not validate a fixed field schema.
    """
    log_path = tmp_audit_dir / "grcx.log.jsonl"

    entries = []
    prev = "genesis"
    for i in range(3):
        entry = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "test.event",
            "severity": "info",
            "summary": f"Future entry {i}",
            "jurisdiction": None,
            "source": None,
            "detail": {},
            "prev_hash": prev,
            "experimental_field": "future",   # extra field included in hash
        }
        entry["entry_hash"] = _compute_hash(entry)
        entries.append(entry)
        prev = entry["entry_hash"]

    _write_chain(log_path, entries)

    log = AuditLog(log_dir=str(tmp_audit_dir))
    valid, errors = log.verify()

    assert valid, f"Log with extra fields failed to verify. Errors: {errors}"
    assert errors == []


def test_log_with_unicode_summary_verifies(tmp_audit_dir):
    """Entries containing emoji and non-ASCII characters in summary must verify."""
    log_path = tmp_audit_dir / "grcx.log.jsonl"

    unicode_summaries = [
        "Reglementation europeenne",
        "Consultation publique sur la securite des donnees",
        "Mise a jour des lignes directrices",
    ]

    entries = []
    prev = "genesis"
    for summary in unicode_summaries:
        entry = _make_entry(
            event_type="regulatory.publication",
            summary=summary,
            prev_hash=prev,
            jurisdiction="EU",
        )
        entries.append(entry)
        prev = entry["entry_hash"]

    _write_chain(log_path, entries)

    log = AuditLog(log_dir=str(tmp_audit_dir))
    valid, errors = log.verify()

    assert valid, f"Log with unicode summaries failed to verify. Errors: {errors}"
    assert errors == []

    tailed = log.tail(3)
    assert len(tailed) == 3
    assert tailed[0]["summary"] == unicode_summaries[0]
    assert tailed[1]["summary"] == unicode_summaries[1]
    assert tailed[2]["summary"] == unicode_summaries[2]
