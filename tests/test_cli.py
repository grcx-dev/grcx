# Tests for grcx.cli commands using Click test runner
import pytest
from click.testing import CliRunner
from grcx.cli import cli
from grcx.audit.log import AuditLog


def test_init_creates_config_and_audit_dir():
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(cli, ["init"])
        assert result.exit_code == 0
        from pathlib import Path
        assert Path("grcx.yaml").exists()
        assert "sentinels:" in Path("grcx.yaml").read_text()
        assert Path("grcx-audit").is_dir()


def test_init_skips_existing_config():
    runner = CliRunner()
    with runner.isolated_filesystem():
        from pathlib import Path
        Path("grcx.yaml").write_text("existing")
        result = runner.invoke(cli, ["init"])
        assert result.exit_code == 0
        assert Path("grcx.yaml").read_text() == "existing"
        assert "skipping" in result.output.lower()


def test_audit_verify_on_empty_passes(tmp_audit_dir):
    runner = CliRunner()
    result = runner.invoke(cli, ["audit", "--verify", "--log-dir", str(tmp_audit_dir)])
    assert result.exit_code == 0
    output_lower = result.output.lower()
    assert "verified" in output_lower or "intact" in output_lower


def test_audit_tail_empty_log(tmp_audit_dir):
    runner = CliRunner()
    result = runner.invoke(cli, ["audit", "--log-dir", str(tmp_audit_dir), "--tail", "5"])
    assert result.exit_code == 0
    assert "no audit log entries found" in result.output.lower()


def test_audit_tail_with_entries(tmp_audit_dir):
    log = AuditLog(log_dir=str(tmp_audit_dir))
    log.write(event_type="regulatory.new_publication", summary="First publication", severity="info")
    log.write(event_type="regulatory.new_publication", summary="Second publication", severity="warning")
    log.write(event_type="resolver.assessment", summary="Third assessment", severity="critical")

    runner = CliRunner()
    result = runner.invoke(cli, ["audit", "--log-dir", str(tmp_audit_dir), "--tail", "2"])
    assert result.exit_code == 0
    # Rich truncates long strings in the table; match on visible substrings from either
    # the event_type column (truncated) or the summary text column.
    output = result.output
    assert "resolver.assessm" in output or "Third assessment" in output


def test_watch_missing_config_aborts():
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(cli, ["watch"])
        assert result.exit_code != 0
        assert "config file not found" in result.output.lower()
