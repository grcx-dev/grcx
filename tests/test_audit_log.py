# Tests for grcx.audit.log.AuditLog
import json
import pytest
from pathlib import Path

from grcx.audit.log import AuditLog


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _read_entries(log_path: Path) -> list[dict]:
    lines = log_path.read_text().strip().splitlines()
    return [json.loads(line) for line in lines]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_write_returns_entry_with_required_fields(audit_log):
    entry = audit_log.write(
        event_type="test.event",
        summary="First entry",
    )
    for field in ("id", "timestamp", "event_type", "severity", "summary", "prev_hash", "entry_hash"):
        assert field in entry, f"Missing field: {field}"
    assert entry["prev_hash"] == "genesis"


def test_chain_linkage(audit_log):
    audit_log.write(event_type="test.event", summary="Entry 1")
    audit_log.write(event_type="test.event", summary="Entry 2")
    audit_log.write(event_type="test.event", summary="Entry 3")

    entries = _read_entries(audit_log.log_path)
    assert len(entries) == 3

    assert entries[0]["prev_hash"] == "genesis"
    assert entries[1]["prev_hash"] == entries[0]["entry_hash"]
    assert entries[2]["prev_hash"] == entries[1]["entry_hash"]


def test_verify_clean_log_passes(audit_log):
    audit_log.write(event_type="test.event", summary="A")
    audit_log.write(event_type="test.event", summary="B")
    audit_log.write(event_type="test.event", summary="C")

    is_valid, errors = audit_log.verify()
    assert is_valid is True
    assert errors == []


def test_verify_detects_tampered_summary(audit_log):
    audit_log.write(event_type="test.event", summary="Original summary")
    audit_log.write(event_type="test.event", summary="Second entry")

    # Read entries, tamper with the first one, rewrite the file
    entries = _read_entries(audit_log.log_path)
    entries[0]["summary"] = "TAMPERED summary"
    tampered_lines = "\n".join(json.dumps(e) for e in entries) + "\n"
    audit_log.log_path.write_text(tampered_lines)

    is_valid, errors = audit_log.verify()
    assert is_valid is False
    assert len(errors) >= 1
    combined = " ".join(errors).lower()
    assert "hash mismatch" in combined or "tamper" in combined


def test_verify_detects_broken_chain(audit_log):
    audit_log.write(event_type="test.event", summary="First")
    audit_log.write(event_type="test.event", summary="Second")

    # Change the second entry's prev_hash to something wrong
    entries = _read_entries(audit_log.log_path)
    entries[1]["prev_hash"] = "deadbeef"
    tampered_lines = "\n".join(json.dumps(e) for e in entries) + "\n"
    audit_log.log_path.write_text(tampered_lines)

    is_valid, errors = audit_log.verify()
    assert is_valid is False
    combined = " ".join(errors).lower()
    assert "chain broken" in combined


def test_tail_returns_last_n(audit_log):
    summaries = [f"Summary {i}" for i in range(5)]
    for s in summaries:
        audit_log.write(event_type="test.event", summary=s)

    result = audit_log.tail(2)
    assert len(result) == 2
    assert result[0]["summary"] == summaries[3]
    assert result[1]["summary"] == summaries[4]


def test_tail_on_empty_log(tmp_audit_dir):
    fresh_log = AuditLog(log_dir=str(tmp_audit_dir))
    result = fresh_log.tail(10)
    assert result == []


def test_resumes_last_hash_across_instances(tmp_audit_dir):
    log_a = AuditLog(log_dir=str(tmp_audit_dir))
    entry_a = log_a.write(event_type="test.event", summary="From A")

    log_b = AuditLog(log_dir=str(tmp_audit_dir))
    entry_b = log_b.write(event_type="test.event", summary="From B")

    assert entry_b["prev_hash"] == entry_a["entry_hash"]


def test_verify_empty_log_is_valid(tmp_audit_dir):
    fresh_log = AuditLog(log_dir=str(tmp_audit_dir))
    is_valid, errors = fresh_log.verify()
    assert is_valid is True
    assert errors == []


def test_severity_levels(audit_log):
    for severity in ("info", "warning", "critical"):
        audit_log.write(
            event_type="test.event",
            summary=f"Severity test: {severity}",
            severity=severity,
        )

    is_valid, errors = audit_log.verify()
    assert is_valid is True
    assert errors == []
