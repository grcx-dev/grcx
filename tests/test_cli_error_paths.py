# Tests for CLI error paths and the watch command.
import json
import pytest
from click.testing import CliRunner

from grcx.cli import cli


def test_watch_runs_with_valid_config(monkeypatch, tmp_path):
    """watch invokes runner.run when config is valid."""
    config_path = tmp_path / "grcx.yaml"
    config_path.write_text(
        "sentinels:\n  regulatory: []\ncontrols: {}\nresolver: {}\naudit: {}\n"
    )

    run_calls = []

    def fake_run(cfg, dry_run=False, poll_interval=300):
        run_calls.append(cfg)

    monkeypatch.setattr("grcx.sentinel.runner.run", fake_run)

    runner = CliRunner()
    result = runner.invoke(cli, ["watch", "--config", str(config_path), "--poll", "1"])

    assert result.exit_code == 0
    assert len(run_calls) == 1


def test_watch_config_env_var_substitution(monkeypatch, tmp_path):
    """watch performs os.path.expandvars substitution on the config before parsing."""
    config_path = tmp_path / "grcx.yaml"
    config_path.write_text(
        "sentinels:\n  regulatory: []\ntest_key: ${TEST_VAR_X}\n"
    )

    monkeypatch.setenv("TEST_VAR_X", "substituted_value")

    captured = []

    def fake_run(cfg, dry_run=False, poll_interval=300):
        captured.append(cfg)

    monkeypatch.setattr("grcx.sentinel.runner.run", fake_run)

    runner = CliRunner()
    result = runner.invoke(cli, ["watch", "--config", str(config_path), "--poll", "1"])

    assert result.exit_code == 0
    assert len(captured) == 1
    assert captured[0].get("test_key") == "substituted_value"


def test_backfill_titles_log_file_missing(tmp_path):
    """backfill-titles reports missing log file and exits cleanly when dir has no log."""
    nonexistent_dir = tmp_path / "no-such-audit-dir"
    nonexistent_dir.mkdir()

    runner = CliRunner()
    result = runner.invoke(cli, ["backfill-titles", "--log-dir", str(nonexistent_dir)])

    assert result.exit_code == 0
    assert "Log file not found" in result.output


def test_backfill_titles_handles_json_decode_error_in_log(tmp_path):
    """backfill-titles skips malformed lines and reports nothing to fix."""
    audit_dir = tmp_path / "grcx-audit"
    audit_dir.mkdir()
    log_path = audit_dir / "grcx.log.jsonl"

    # Write one valid non-publication entry and one malformed line.
    # Neither is a fixable URL-titled regulatory.new_publication.
    valid_entry = {
        "id": "abc123",
        "timestamp": "2026-01-01T00:00:00+00:00",
        "event_type": "resolver.assessment",
        "severity": "info",
        "summary": "Some assessment",
        "jurisdiction": "BOE",
        "source": "https://example.org",
        "detail": {"fingerprint": "fp001"},
        "prev_hash": "genesis",
        "entry_hash": "aabbcc",
    }
    log_path.write_text(json.dumps(valid_entry) + "\nnot json at all\n")

    runner = CliRunner()
    result = runner.invoke(
        cli, ["backfill-titles", "--log-dir", str(audit_dir), "--dry-run"]
    )

    assert result.exit_code == 0
    # Should not crash and should say nothing to fix
    assert "No URL-titled entries found" in result.output or "nothing to fix" in result.output.lower()
