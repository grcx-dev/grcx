# Tests for pure (no-LLM) module-level helpers in grcx/resolver/resolver.py
import json

import pytest

from grcx.resolver.resolver import (
    _build_controls_summary,
    _load_framework,
    Resolver,
    ResolverResult,
)


# ── _load_framework ─────────────────────────────────────────────────────────

def test_load_framework_existing_returns_dict():
    result = _load_framework("iso27001")
    assert isinstance(result, dict)
    assert "id" in result
    assert result["id"] == "iso27001"
    assert "controls" in result


def test_load_framework_missing_returns_empty_dict():
    result = _load_framework("nonexistent_xyz")
    assert result == {}


# ── _build_controls_summary ─────────────────────────────────────────────────

_FAKE_FRAMEWORK = {
    "id": "fake",
    "name": "Fake Framework",
    "controls": [
        {"id": "A.1", "category": "Alpha", "description": "First alpha control"},
        {"id": "A.2", "category": "Alpha", "description": "Second alpha control"},
        {"id": "B.1", "category": "Beta", "description": "First beta control"},
    ],
}


def test_build_controls_summary_groups_by_category():
    summary, example_id = _build_controls_summary(_FAKE_FRAMEWORK)
    assert "Alpha" in summary
    assert "Beta" in summary
    assert "A.1" in summary
    assert "A.2" in summary
    assert "B.1" in summary


def test_build_controls_summary_returns_example_id():
    _, example_id = _build_controls_summary(_FAKE_FRAMEWORK)
    assert example_id == "A.1"


def test_build_controls_summary_empty_framework():
    summary, example_id = _build_controls_summary({})
    assert summary == ""
    assert example_id == "control-id"


# ── fence-stripping in _analyse_one ─────────────────────────────────────────

def _make_resolver(patch_fn, canned_text, tmp_audit_dir, audit_log):
    config = {
        "controls": {"frameworks": ["iso27001"]},
        "resolver": {"llm": "claude-haiku-4-5"},
        "audit": {"output": str(tmp_audit_dir)},
    }
    return Resolver(config=config, audit=audit_log)


def test_resolver_strips_json_code_fence(patch_anthropic, make_item, tmp_audit_dir, audit_log):
    payload = json.dumps({
        "has_implications": True,
        "severity": "warning",
        "affected_controls": ["5.1"],
        "summary": "Fence-stripped response.",
        "recommended_action": "Do something.",
        "rationale": "Because controls.",
    })
    wrapped = f"```json\n{payload}\n```"
    patch_anthropic(wrapped)

    config = {
        "controls": {"frameworks": ["iso27001"]},
        "resolver": {"llm": "claude-haiku-4-5"},
        "audit": {"output": str(tmp_audit_dir)},
    }
    resolver = Resolver(config=config, audit=audit_log)
    item = make_item()
    results = resolver.analyse(item)

    assert len(results) == 1
    assert isinstance(results[0], ResolverResult)
    assert results[0].has_implications is True


def test_resolver_strips_plain_code_fence(patch_anthropic, make_item, tmp_audit_dir, audit_log):
    payload = json.dumps({
        "has_implications": False,
        "severity": "info",
        "affected_controls": [],
        "summary": "Plain fence stripped.",
        "recommended_action": "Nothing needed.",
        "rationale": "No relevance.",
    })
    wrapped = f"```\n{payload}\n```"
    patch_anthropic(wrapped)

    config = {
        "controls": {"frameworks": ["iso27001"]},
        "resolver": {"llm": "claude-haiku-4-5"},
        "audit": {"output": str(tmp_audit_dir)},
    }
    resolver = Resolver(config=config, audit=audit_log)
    item = make_item()
    results = resolver.analyse(item)

    assert len(results) == 1
    assert isinstance(results[0], ResolverResult)
    assert results[0].has_implications is False
