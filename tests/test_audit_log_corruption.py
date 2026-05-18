# Tests for corrupted-log recovery paths in AuditLog.
import json
import pytest
from pathlib import Path

from grcx.audit.log import AuditLog


def test_compute_last_hash_on_empty_file_returns_genesis(tmp_audit_dir):
    """An empty log file should cause new entries to chain from 'genesis'."""
    log_path = tmp_audit_dir / "grcx.log.jsonl"
    log_path.touch()

    log = AuditLog(log_dir=str(tmp_audit_dir))
    entry = log.write(
        event_type="test.event",
        summary="First entry after empty file",
    )

    assert entry["prev_hash"] == "genesis"


def test_compute_last_hash_on_corrupt_last_line_returns_genesis(tmp_audit_dir):
    """When the last line of the log is malformed JSON, _compute_last_hash returns 'genesis'."""
    log_path = tmp_audit_dir / "grcx.log.jsonl"
    # Write a valid-looking line followed by a malformed last line
    log_path.write_text("not json at all\n")

    log = AuditLog(log_dir=str(tmp_audit_dir))
    # The internal state should have fallen back to 'genesis'
    assert log._last_hash == "genesis"

    # Any new write should chain from 'genesis'
    entry = log.write(
        event_type="test.event",
        summary="Entry after corrupt last line",
    )
    assert entry["prev_hash"] == "genesis"


def test_verify_with_invalid_json_line_reports_error(tmp_audit_dir):
    """verify() reports an error for lines that are not valid JSON."""
    log = AuditLog(log_dir=str(tmp_audit_dir))
    log.write(
        event_type="test.event",
        summary="Valid entry",
    )

    # Append a malformed line directly to the log file
    with open(log.log_path, "a") as f:
        f.write("not json at all\n")

    valid, errors = log.verify()

    assert valid is False
    assert len(errors) >= 1
    # At least one error should mention "invalid JSON"
    assert any("invalid JSON" in e for e in errors)
