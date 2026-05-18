# End-to-end tests for Resolver.analyse with mocked LLM providers
import json

import pytest

from grcx.resolver.resolver import Resolver


def _build_resolver(config_overrides, audit_log):
    base = {
        "controls": {"frameworks": ["iso27001"]},
        "resolver": {"llm": "claude-haiku-4-5"},
    }
    base.update(config_overrides)
    return Resolver(config=base, audit=audit_log)


def _read_log(tmp_audit_dir):
    log_path = tmp_audit_dir / "grcx.log.jsonl"
    if not log_path.exists():
        return []
    lines = log_path.read_text().strip().splitlines()
    return [json.loads(line) for line in lines if line.strip()]


# ── Core analyse behaviour ───────────────────────────────────────────────────

def test_analyse_writes_audit_entry_when_has_implications_true(
    patch_anthropic, canned_llm_response, make_item, tmp_audit_dir, audit_log
):
    patch_anthropic(canned_llm_response)
    config = {
        "controls": {"frameworks": ["iso27001"]},
        "resolver": {"llm": "claude-haiku-4-5"},
        "audit": {"output": str(tmp_audit_dir)},
    }
    resolver = Resolver(config=config, audit=audit_log)
    item = make_item()
    resolver.analyse(item)

    entries = _read_log(tmp_audit_dir)
    assessment_entries = [e for e in entries if e["event_type"] == "resolver.assessment"]
    assert len(assessment_entries) == 1

    entry = assessment_entries[0]
    assert entry["severity"] == "warning"
    assert entry["detail"]["framework"] == "iso27001"
    assert entry["detail"]["affected_controls"] == ["5.1", "5.2"]


def test_analyse_no_audit_entry_when_has_implications_false(
    patch_anthropic, make_item, tmp_audit_dir, audit_log
):
    no_implications = json.dumps({
        "has_implications": False,
        "severity": "info",
        "affected_controls": [],
        "summary": "No relevance.",
        "recommended_action": "None needed.",
        "rationale": "Not applicable.",
    })
    patch_anthropic(no_implications)

    config = {
        "controls": {"frameworks": ["iso27001"]},
        "resolver": {"llm": "claude-haiku-4-5"},
        "audit": {"output": str(tmp_audit_dir)},
    }
    resolver = Resolver(config=config, audit=audit_log)
    item = make_item()
    resolver.analyse(item)

    entries = _read_log(tmp_audit_dir)
    assessment_entries = [e for e in entries if e["event_type"] == "resolver.assessment"]
    assert len(assessment_entries) == 0


def test_analyse_returns_one_result_per_framework(
    patch_anthropic, canned_llm_response, make_item, tmp_audit_dir, audit_log
):
    patch_anthropic(canned_llm_response)
    config = {
        "controls": {"frameworks": ["iso27001", "soc2", "dora"]},
        "resolver": {"llm": "claude-haiku-4-5"},
        "audit": {"output": str(tmp_audit_dir)},
    }
    resolver = Resolver(config=config, audit=audit_log)
    item = make_item()
    results = resolver.analyse(item)

    assert len(results) == 3


def test_analyse_records_resolver_error_on_invalid_json(
    patch_anthropic, make_item, tmp_audit_dir, audit_log
):
    patch_anthropic("not json at all")

    config = {
        "controls": {"frameworks": ["iso27001"]},
        "resolver": {"llm": "claude-haiku-4-5"},
        "audit": {"output": str(tmp_audit_dir)},
    }
    resolver = Resolver(config=config, audit=audit_log)
    item = make_item()
    results = resolver.analyse(item)

    # Returns empty list (None results are filtered)
    assert results == []

    entries = _read_log(tmp_audit_dir)
    error_entries = [e for e in entries if e["event_type"] == "resolver.error"]
    assert len(error_entries) == 1
    assert error_entries[0]["severity"] == "warning"


# ── Provider-specific paths ──────────────────────────────────────────────────

def test_analyse_with_ollama_provider(
    patch_ollama_httpx, canned_llm_response, make_item, tmp_audit_dir, audit_log
):
    patch_ollama_httpx(canned_llm_response)
    config = {
        "controls": {"frameworks": ["iso27001"]},
        "resolver": {"llm": "llama3.2"},
        "audit": {"output": str(tmp_audit_dir)},
    }
    resolver = Resolver(config=config, audit=audit_log)
    item = make_item()
    resolver.analyse(item)

    entries = _read_log(tmp_audit_dir)
    assessment_entries = [e for e in entries if e["event_type"] == "resolver.assessment"]
    assert len(assessment_entries) == 1


def test_analyse_with_gemini_provider(
    patch_gemini, canned_llm_response, make_item, tmp_audit_dir, audit_log
):
    patch_gemini(canned_llm_response)
    config = {
        "controls": {"frameworks": ["iso27001"]},
        "resolver": {"llm": "gemini-2.5-flash"},
        "audit": {"output": str(tmp_audit_dir)},
    }
    resolver = Resolver(config=config, audit=audit_log)
    item = make_item()
    resolver.analyse(item)

    entries = _read_log(tmp_audit_dir)
    assessment_entries = [e for e in entries if e["event_type"] == "resolver.assessment"]
    assert len(assessment_entries) == 1
