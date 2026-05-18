"""Pending-fix tests for the remaining TEST_REPORT.md and SECURITY_REVIEW.md findings.
Marked xfail(strict=True) for the same reason as the other *_fixes_pending.py files."""
import hashlib
import json
import os
import smtplib
from pathlib import Path

import pytest
from click.testing import CliRunner

from grcx.audit.log import AuditLog
from grcx.cli import cli


# ── Section 1: RSS state file UTF-8 recovery (TEST_REPORT #6) ────────────────

@pytest.mark.xfail(
    strict=True,
    reason="RssSentinel._load_seen raises UnicodeDecodeError on corrupt state file; "
           "fix should open with errors='replace' or 'ignore' and silently recover.",
)
def test_rss_load_seen_recovers_from_corrupt_state_file(tmp_audit_dir):
    """RssSentinel should construct successfully even when the state file contains
    invalid UTF-8 bytes; valid fingerprints should be retained in _seen."""
    from grcx.sentinel.regulatory.rss import RssSentinel

    # Write a state file that mixes valid lines with invalid UTF-8 bytes
    state_file = tmp_audit_dir / "seen_test.txt"
    state_file.write_bytes(b"abc123def\xff\xfe\xfd\nfingerprint2\n")

    # Today this raises UnicodeDecodeError; after fix it should succeed
    sentinel = RssSentinel(url="https://x", jurisdiction="TEST", state_dir=str(tmp_audit_dir))

    # After fix: _seen contains valid/recovered fingerprints, not an exception
    assert isinstance(sentinel._seen, set)
    # "fingerprint2" is valid UTF-8 and should be present (or at minimum the set is non-empty)
    assert "fingerprint2" in sentinel._seen


# ── Section 2: Email charset error handling (TEST_REPORT #7) ─────────────────

@pytest.mark.xfail(
    strict=True,
    reason="_decode_header_value raises LookupError for unrecognised charsets; "
           "fix should catch LookupError and fall back to utf-8/errors=replace.",
)
def test_decode_header_handles_unknown_charset():
    """_decode_header_value should return a fallback string for headers encoded
    with an unknown charset rather than propagating LookupError."""
    from grcx.sentinel.regulatory.imap_email import _decode_header_value

    # Today: raises LookupError: unknown encoding: bogus-charset-xyz
    result = _decode_header_value("=?bogus-charset-xyz?Q?Hi?=")

    # After fix: returns a non-empty string (raw bytes decoded with replacement chars)
    assert isinstance(result, str)
    assert len(result) > 0


# ── Section 3: AuditLog tail(0) (TEST_REPORT #9) ─────────────────────────────

@pytest.mark.xfail(
    strict=True,
    reason="tail(0) uses lines[-0:] which is lines[:], returning all entries; "
           "fix should special-case n==0 and return [].",
)
def test_audit_tail_zero_returns_empty_list(audit_log):
    """AuditLog.tail(0) should return an empty list, not the entire log."""
    for i in range(5):
        audit_log.write(
            event_type="test.event",
            summary=f"Entry {i}",
            severity="info",
        )

    # Today: returns all 5 entries because lines[-0:] == lines[:]
    result = audit_log.tail(0)
    assert result == []


# ── Section 4: Unclosed anchor recovery (TEST_REPORT #10) ────────────────────

@pytest.mark.xfail(
    strict=True,
    reason="_LinkExtractor silently drops anchor text when </a> is missing; "
           "fix should flush the current anchor in handle_endtag or error-tolerance override.",
)
def test_link_extractor_flushes_unclosed_anchor():
    """_LinkExtractor should capture the link text even when the </a> closing
    tag is absent (e.g. in malformed HTML email bodies)."""
    from grcx.sentinel.regulatory.imap_email import _LinkExtractor

    parser = _LinkExtractor()
    # Feed HTML with an unclosed <a> — no </a> tag
    parser.feed('<a href="https://example.com/important">Important publication')
    parser.close()

    # Today: parser.links is empty because handle_endtag never fires
    assert parser.links == [("Important publication", "https://example.com/important")]


# ── Section 5: backfill creates backup (SECURITY_REVIEW #10) ─────────────────

@pytest.mark.xfail(
    strict=True,
    reason="backfill-titles rewrites grcx.log.jsonl in-place with no backup; "
           "fix should create a timestamped backup before overwriting.",
)
def test_backfill_titles_creates_backup_before_rewrite(monkeypatch, tmp_audit_dir):
    """backfill-titles should write a timestamped backup of grcx.log.jsonl
    before performing any in-place rewrite."""
    _url = "https://www.fca.org.uk/publications/policy-statements/ps26-3"
    _old_fp = hashlib.sha256(f"{_url}{_url}".encode()).hexdigest()[:16]

    audit = AuditLog(log_dir=str(tmp_audit_dir))
    audit.write(
        event_type="regulatory.new_publication",
        summary=_url,
        jurisdiction="FCA",
        detail={"feed_url": "imap://imap.x", "fingerprint": _old_fp},
    )

    monkeypatch.setattr(
        "grcx.sentinel.regulatory.imap_email.fetch_page_title",
        lambda url: "Policy Statement PS26/3",
    )

    runner = CliRunner()
    result = runner.invoke(cli, ["backfill-titles", "--log-dir", str(tmp_audit_dir)])
    assert result.exit_code == 0

    # After fix: a backup file matching grcx.log.jsonl.backup-* must exist
    backups = list(tmp_audit_dir.glob("grcx.log.jsonl.backup-*"))
    assert len(backups) >= 1, (
        f"No backup file found in {tmp_audit_dir}; files present: "
        f"{[p.name for p in tmp_audit_dir.iterdir()]}"
    )


# ── Section 6: PII – hardcoded email recipient (SECURITY_REVIEW #8) ──────────

@pytest.mark.xfail(
    strict=True,
    reason="notify_signup hardcodes 'neil.lowden@gmail.com' as the To address; "
           "fix should read it from the GRCX_NOTIFY_TO environment variable.",
)
def test_notify_signup_recipient_from_env_var(monkeypatch):
    """notify_signup should read the notification recipient from the GRCX_NOTIFY_TO
    env var rather than a hardcoded literal."""
    import dashboard.app as app_module

    captured_messages = []

    class _FakeSMTP:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def starttls(self):
            pass

        def login(self, *args):
            pass

        def send_message(self, msg):
            captured_messages.append(msg)

    monkeypatch.setenv("GRCX_NOTIFY_TO", "test@example.com")
    monkeypatch.setattr(smtplib, "SMTP", _FakeSMTP)

    # Today: sends to the hardcoded address; after fix: uses env var
    app_module.notify_signup("Alice", "alice@corp.com", "Corp Ltd")

    assert len(captured_messages) == 1, "Expected exactly one message to be sent"
    to_header = captured_messages[0]["To"]
    assert to_header == "test@example.com", (
        f"Expected To=test@example.com but got To={to_header!r}; "
        "GRCX_NOTIFY_TO env var is not being respected"
    )


# ── Section 7: backfill refuses when lockfile present (SECURITY_REVIEW #10) ──

@pytest.mark.xfail(
    strict=True,
    reason="backfill-titles does not implement a lockfile check; "
           "fix should detect .lock and exit nonzero with an informative message.",
)
def test_backfill_titles_refuses_if_lockfile_present(tmp_audit_dir):
    """backfill-titles should refuse to proceed and exit nonzero when a .lock
    file exists in the audit directory (indicating a concurrent grcx watch run)."""
    _url = "https://www.fca.org.uk/publications/policy-statements/ps26-4"
    _old_fp = hashlib.sha256(f"{_url}{_url}".encode()).hexdigest()[:16]

    audit = AuditLog(log_dir=str(tmp_audit_dir))
    audit.write(
        event_type="regulatory.new_publication",
        summary=_url,
        jurisdiction="FCA",
        detail={"feed_url": "https://example.org/feed", "fingerprint": _old_fp},
    )

    # Create the lockfile that signals a concurrent watch process
    lockfile = tmp_audit_dir / ".lock"
    lockfile.write_text("locked by grcx watch")

    runner = CliRunner()
    result = runner.invoke(cli, ["backfill-titles", "--log-dir", str(tmp_audit_dir)])

    # After fix: nonzero exit with a message about the lock
    assert result.exit_code != 0, (
        "Expected nonzero exit when lockfile is present, but command succeeded"
    )
    output = result.output.lower()
    assert "lock" in output, (
        f"Expected 'lock' in command output but got: {result.output!r}"
    )
