"""Tests for the `claude-cli` resolver branch (Option A — subscription auth).

These never spawn a real `claude` subprocess; subprocess.run is mocked.
"""
import json
from unittest.mock import MagicMock, patch

import pytest

from grcx.resolver.resolver import Resolver


def _config(tmp_audit_dir):
    return {
        "controls": {"frameworks": ["iso27001"]},
        "resolver": {"llm": "claude-cli"},
        "audit": {"output": str(tmp_audit_dir)},
    }


def test_claude_cli_routing_flags(tmp_audit_dir, audit_log):
    r = Resolver(config=_config(tmp_audit_dir), audit=audit_log)
    assert r._use_claude_cli is True
    assert r._use_ollama is False
    assert r._use_gemini is False
    # No SDK client created — would have raised if anthropic was constructed
    # without an API key being checked.
    assert not hasattr(r, "client") or r.client is None or getattr(r, "client", None) is None


def test_claude_cli_calls_subprocess_with_correct_args(
    tmp_audit_dir, audit_log, make_item, canned_llm_response
):
    r = Resolver(config=_config(tmp_audit_dir), audit=audit_log)
    envelope = json.dumps({
        "type": "result",
        "subtype": "success",
        "is_error": False,
        "result": canned_llm_response,
    })
    fake = MagicMock(returncode=0, stdout=envelope, stderr="")
    with patch("subprocess.run", return_value=fake) as mock_run:
        results = r.analyse(make_item())

    assert len(results) == 1
    assert results[0].has_implications is True
    assert results[0].severity == "warning"

    args, kwargs = mock_run.call_args
    cmd = args[0]
    assert cmd[0] == "claude"
    assert "-p" in cmd
    assert "--output-format" in cmd
    assert "json" in cmd
    # Prompt must be piped via stdin, not as a CLI arg (avoids arg-length limits
    # and shell escaping issues).
    assert kwargs["input"] is not None and len(kwargs["input"]) > 100
    assert kwargs["text"] is True
    assert kwargs["capture_output"] is True


def test_claude_cli_subprocess_nonzero_exit_logs_resolver_error(
    tmp_audit_dir, audit_log, make_item
):
    r = Resolver(config=_config(tmp_audit_dir), audit=audit_log)
    fake = MagicMock(returncode=1, stdout="", stderr="not authenticated")
    with patch("subprocess.run", return_value=fake):
        results = r.analyse(make_item())

    assert results == []
    entries = (tmp_audit_dir / "grcx.log.jsonl").read_text().strip().splitlines()
    errors = [
        json.loads(e) for e in entries
        if json.loads(e).get("event_type") == "resolver.error"
    ]
    assert len(errors) == 1
    assert "not authenticated" in errors[0]["detail"]["error"]


def test_claude_cli_envelope_is_error_logged_as_resolver_error(
    tmp_audit_dir, audit_log, make_item
):
    r = Resolver(config=_config(tmp_audit_dir), audit=audit_log)
    envelope = json.dumps({
        "type": "result",
        "subtype": "error_during_execution",
        "is_error": True,
        "result": "rate limit exceeded",
    })
    fake = MagicMock(returncode=0, stdout=envelope, stderr="")
    with patch("subprocess.run", return_value=fake):
        results = r.analyse(make_item())

    assert results == []
    entries = (tmp_audit_dir / "grcx.log.jsonl").read_text().strip().splitlines()
    errors = [
        json.loads(e) for e in entries
        if json.loads(e).get("event_type") == "resolver.error"
    ]
    assert len(errors) == 1
    assert "rate limit" in errors[0]["detail"]["error"]


def test_claude_cli_strips_json_code_fence(
    tmp_audit_dir, audit_log, make_item, canned_llm_response
):
    # `claude -p` sometimes wraps JSON output in ```json fences when the prompt
    # asks for JSON. The existing fence-stripping in _analyse_one must handle it.
    fenced = f"```json\n{canned_llm_response}\n```"
    r = Resolver(config=_config(tmp_audit_dir), audit=audit_log)
    envelope = json.dumps({
        "type": "result",
        "is_error": False,
        "result": fenced,
    })
    fake = MagicMock(returncode=0, stdout=envelope, stderr="")
    with patch("subprocess.run", return_value=fake):
        results = r.analyse(make_item())

    assert len(results) == 1
    assert results[0].has_implications is True
