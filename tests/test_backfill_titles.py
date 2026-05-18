# Tests for the backfill-titles CLI command (grcx/cli.py lines ~108-211)
import hashlib
import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from grcx.audit.log import AuditLog
from grcx.cli import cli


_URL = "https://www.fca.org.uk/publications/policy-statements/ps26-3"
_JUNK_URL = "https://example.com/unsubscribe/123"
_FEED_URL = "imap://imap.x"
_JURISDICTION = "FCA"

# The CLI calculates old_fp as sha256(url + url)[:16] when the summary IS the url
_OLD_FP = hashlib.sha256(f"{_URL}{_URL}".encode()).hexdigest()[:16]
_TITLE = "Policy Statement PS26/3"
_NEW_FP = hashlib.sha256(f"{_URL}{_TITLE}".encode()).hexdigest()[:16]

_JUNK_FP = hashlib.sha256(f"{_JUNK_URL}{_JUNK_URL}".encode()).hexdigest()[:16]


def _build_test_log(log_dir: Path) -> AuditLog:
    """Write three seed entries to the audit log and return the AuditLog instance."""
    audit = AuditLog(log_dir=str(log_dir))

    # Entry 1: fixable — URL-as-title, real publication
    audit.write(
        event_type="regulatory.new_publication",
        summary=_URL,
        jurisdiction=_JURISDICTION,
        detail={"feed_url": _FEED_URL, "fingerprint": _OLD_FP},
    )

    # Entry 2: junk — URL contains "unsubscribe"
    junk_fp = hashlib.sha256(f"{_JUNK_URL}{_JUNK_URL}".encode()).hexdigest()[:16]
    audit.write(
        event_type="regulatory.new_publication",
        summary=_JUNK_URL,
        jurisdiction=_JURISDICTION,
        detail={"feed_url": _FEED_URL, "fingerprint": junk_fp},
    )

    # Entry 3: resolver assessment — should not be touched
    audit.write(
        event_type="resolver.assessment",
        summary="A real summary",
        jurisdiction=_JURISDICTION,
        detail={"framework": "iso27001"},
    )

    return audit


def _load_entries(log_dir: Path) -> list[dict]:
    log_path = log_dir / "grcx.log.jsonl"
    if not log_path.exists():
        return []
    return [json.loads(line) for line in log_path.read_text().strip().splitlines() if line.strip()]


# ── dry-run ──────────────────────────────────────────────────────────────────

def test_dry_run_does_not_modify_log(tmp_audit_dir):
    _build_test_log(tmp_audit_dir)
    log_path = tmp_audit_dir / "grcx.log.jsonl"
    before = log_path.read_bytes()

    runner = CliRunner()
    result = runner.invoke(cli, ["backfill-titles", "--log-dir", str(tmp_audit_dir), "--dry-run"])

    assert result.exit_code == 0
    assert log_path.read_bytes() == before
    output = result.output.lower()
    assert "fix" in output or "purge" in output


# ── purge junk, fix real entries ─────────────────────────────────────────────

def test_backfill_purges_junk_entries(monkeypatch, tmp_audit_dir):
    _build_test_log(tmp_audit_dir)
    monkeypatch.setattr(
        "grcx.sentinel.regulatory.imap_email.fetch_page_title",
        lambda url: _TITLE,
    )

    runner = CliRunner()
    result = runner.invoke(cli, ["backfill-titles", "--log-dir", str(tmp_audit_dir)])
    assert result.exit_code == 0

    entries = _load_entries(tmp_audit_dir)

    # Junk entry must be gone
    summaries = [e["summary"] for e in entries]
    assert _JUNK_URL not in summaries

    # Fixable entry should now have the real title
    pub_entries = [e for e in entries if e["event_type"] == "regulatory.new_publication"]
    assert len(pub_entries) == 1
    assert pub_entries[0]["summary"] == _TITLE

    # Resolver entry must be untouched
    resolver_entries = [e for e in entries if e["event_type"] == "resolver.assessment"]
    assert len(resolver_entries) == 1
    assert resolver_entries[0]["summary"] == "A real summary"


# ── chain integrity after rewrite ────────────────────────────────────────────

def test_backfill_preserves_chain_integrity(monkeypatch, tmp_audit_dir):
    _build_test_log(tmp_audit_dir)
    monkeypatch.setattr(
        "grcx.sentinel.regulatory.imap_email.fetch_page_title",
        lambda url: _TITLE,
    )

    runner = CliRunner()
    result = runner.invoke(cli, ["backfill-titles", "--log-dir", str(tmp_audit_dir)])
    assert result.exit_code == 0

    log = AuditLog(log_dir=str(tmp_audit_dir))
    valid, errors = log.verify()
    assert valid is True
    assert errors == []


# ── seen fingerprint file updated ────────────────────────────────────────────

def test_backfill_updates_seen_fingerprint_file(monkeypatch, tmp_audit_dir):
    _build_test_log(tmp_audit_dir)

    # Pre-seed the seen file with the OLD fingerprint
    seen_file = tmp_audit_dir / "seen_fca_email.txt"
    seen_file.write_text(_OLD_FP)

    monkeypatch.setattr(
        "grcx.sentinel.regulatory.imap_email.fetch_page_title",
        lambda url: _TITLE,
    )

    runner = CliRunner()
    result = runner.invoke(cli, ["backfill-titles", "--log-dir", str(tmp_audit_dir)])
    assert result.exit_code == 0

    seen_after = set(seen_file.read_text().splitlines())
    assert _NEW_FP in seen_after
    assert _OLD_FP not in seen_after


# ── no-op when nothing to fix ────────────────────────────────────────────────

def test_backfill_no_op_when_nothing_to_fix(tmp_audit_dir):
    # Write only a resolver.assessment entry (no URL-as-title publications)
    audit = AuditLog(log_dir=str(tmp_audit_dir))
    audit.write(
        event_type="resolver.assessment",
        summary="A real summary",
        jurisdiction="FCA",
        detail={"framework": "iso27001"},
    )

    log_path = tmp_audit_dir / "grcx.log.jsonl"
    before = log_path.read_bytes()

    runner = CliRunner()
    result = runner.invoke(cli, ["backfill-titles", "--log-dir", str(tmp_audit_dir)])
    assert result.exit_code == 0

    output = result.output.lower()
    assert "no url-titled entries found" in output
    assert log_path.read_bytes() == before
