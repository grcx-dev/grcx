# Tests that pin the resolver's tolerance for malformed LLM responses.
#
# These tests document the CURRENT CONTRACT between the resolver and the LLM.
# If a future change adds input validation or coercion, the relevant test will
# need updating — that is intentional, because the test is signalling a
# deliberate behavioural change.
import json

import pytest

from grcx.resolver.resolver import Resolver, ResolverResult


# ─── shared helpers ────────────────────────────────────────────────────────────

def _config(tmp_audit_dir):
    return {
        "controls": {"frameworks": ["iso27001"]},
        "resolver": {"llm": "claude-haiku-4-5"},
        "audit": {"output": str(tmp_audit_dir)},
    }


def _read_log(tmp_audit_dir):
    log_path = tmp_audit_dir / "grcx.log.jsonl"
    if not log_path.exists():
        return []
    lines = log_path.read_text().strip().splitlines()
    return [json.loads(line) for line in lines if line.strip()]


def _valid_response(**overrides):
    """Return a complete, valid resolver JSON string."""
    base = {
        "has_implications": True,
        "severity": "warning",
        "affected_controls": ["5.1"],
        "summary": "Test publication affects information security policy.",
        "recommended_action": "Review and update relevant policies.",
        "rationale": "The publication introduces requirements relevant to controls.",
    }
    base.update(overrides)
    return json.dumps(base)


# ─── tests ─────────────────────────────────────────────────────────────────────

def test_response_missing_has_implications_defaults_to_false(
    tmp_audit_dir, audit_log, make_item, patch_anthropic
):
    """Pin: missing `has_implications` key causes data.get() to default to False.
    Because has_implications is False, no audit assessment entry is written — the
    resolver silently treats the omission as 'no action needed'. This is a latent
    risk: a botched LLM response looks like a clean non-finding."""
    response = json.dumps({
        "severity": "warning",
        "summary": "x",
        "recommended_action": "y",
        "rationale": "z",
        "affected_controls": [],
    })
    patch_anthropic(response)
    r = Resolver(config=_config(tmp_audit_dir), audit=audit_log)
    results = r.analyse(make_item())

    assert len(results) == 1
    assert results[0].has_implications is False

    entries = _read_log(tmp_audit_dir)
    assessment_entries = [e for e in entries if e["event_type"] == "resolver.assessment"]
    assert len(assessment_entries) == 0


def test_response_with_severity_outside_enum(
    tmp_audit_dir, audit_log, make_item, patch_anthropic
):
    """Pin: unknown severity values are passed through as-is — there is no
    validation against the info/warning/critical enum. Dashboard colour-mapping
    falls back to 'white' for unknown values, but the audit entry IS written."""
    response = _valid_response(severity="high")
    patch_anthropic(response)
    r = Resolver(config=_config(tmp_audit_dir), audit=audit_log)
    results = r.analyse(make_item())

    assert len(results) == 1
    assert results[0].severity == "high"

    entries = _read_log(tmp_audit_dir)
    assessment_entries = [e for e in entries if e["event_type"] == "resolver.assessment"]
    assert len(assessment_entries) == 1
    assert assessment_entries[0]["severity"] == "high"


def test_response_with_affected_controls_as_string(
    tmp_audit_dir, audit_log, make_item, patch_anthropic
):
    """Pin: `affected_controls` is passed through as whatever the LLM returns —
    if the LLM emits a plain string instead of a list, the resolver stores that
    string directly in ResolverResult.affected_controls without coercion.
    Callers iterating `result.affected_controls` as a list will receive individual
    characters, not control IDs."""
    response = json.dumps({
        "has_implications": True,
        "severity": "warning",
        "affected_controls": "5.1",
        "summary": "Policy impact.",
        "recommended_action": "Review policies.",
        "rationale": "Relevant to control 5.1.",
    })
    patch_anthropic(response)
    r = Resolver(config=_config(tmp_audit_dir), audit=audit_log)
    results = r.analyse(make_item())

    assert len(results) == 1
    # The resolver does NOT coerce to list — pin the raw pass-through behaviour.
    assert results[0].affected_controls == "5.1"


def test_response_with_extra_unknown_fields_ignored(
    tmp_audit_dir, audit_log, make_item, patch_anthropic
):
    """Pin: extra fields in the JSON response are silently ignored via data.get()
    — the resolver only reads the known keys and discards anything else."""
    response = json.dumps({
        "has_implications": True,
        "severity": "warning",
        "affected_controls": ["5.1"],
        "summary": "Policy impact.",
        "recommended_action": "Review policies.",
        "rationale": "Relevant to control 5.1.",
        "unexpected_field": "some value",
        "another": [1, 2, 3],
        "hallucinated_key": {"nested": True},
    })
    patch_anthropic(response)
    r = Resolver(config=_config(tmp_audit_dir), audit=audit_log)
    results = r.analyse(make_item())

    assert len(results) == 1
    assert isinstance(results[0], ResolverResult)
    assert results[0].has_implications is True
    assert results[0].severity == "warning"
    assert results[0].affected_controls == ["5.1"]


def test_response_with_trailing_text_after_json_fails_gracefully(
    tmp_audit_dir, audit_log, make_item, patch_anthropic
):
    """Pin: trailing prose after the closing brace causes json.loads to raise
    JSONDecodeError — the resolver catches it, returns [], and writes a
    resolver.error audit entry. This means a partially-valid response is
    entirely lost. We are pinning the CURRENT behaviour; a future fix might
    extract the JSON substring first."""
    payload = json.dumps({
        "has_implications": True,
        "severity": "warning",
        "affected_controls": ["5.1"],
        "summary": "Policy impact.",
        "recommended_action": "Review policies.",
        "rationale": "Relevant to control 5.1.",
    })
    response = payload + "\nNote: this is my analysis."
    patch_anthropic(response)
    r = Resolver(config=_config(tmp_audit_dir), audit=audit_log)
    results = r.analyse(make_item())

    assert results == []

    entries = _read_log(tmp_audit_dir)
    error_entries = [e for e in entries if e["event_type"] == "resolver.error"]
    assert len(error_entries) == 1


def test_response_with_text_before_json(
    tmp_audit_dir, audit_log, make_item, patch_anthropic
):
    """Pin: leading prose before the opening brace causes json.loads to fail —
    the fence-stripping logic only runs when raw.startswith('```'), so prefixed
    prose is never trimmed. The resolver returns [] and writes a resolver.error
    entry. If we ever add JSON-extraction logic (e.g. finding the first '{'),
    this test will need to be updated to reflect the new contract."""
    payload = json.dumps({
        "has_implications": True,
        "severity": "warning",
        "affected_controls": ["5.1"],
        "summary": "Policy impact.",
        "recommended_action": "Review policies.",
        "rationale": "Relevant to control 5.1.",
    })
    response = "Here is my analysis:\n" + payload
    patch_anthropic(response)
    r = Resolver(config=_config(tmp_audit_dir), audit=audit_log)
    results = r.analyse(make_item())

    assert results == []

    entries = _read_log(tmp_audit_dir)
    error_entries = [e for e in entries if e["event_type"] == "resolver.error"]
    assert len(error_entries) == 1


def test_response_with_single_quotes_not_double(
    tmp_audit_dir, audit_log, make_item, patch_anthropic
):
    """Pin: Python-dict-style single-quoted JSON is not valid JSON — json.loads
    raises JSONDecodeError and the resolver returns [] with a resolver.error
    audit entry. This is correct JSON-spec behaviour."""
    response = "{'has_implications': true, 'severity': 'warning', 'affected_controls': [], 'summary': 'x', 'recommended_action': 'y', 'rationale': 'z'}"
    patch_anthropic(response)
    r = Resolver(config=_config(tmp_audit_dir), audit=audit_log)
    results = r.analyse(make_item())

    assert results == []

    entries = _read_log(tmp_audit_dir)
    error_entries = [e for e in entries if e["event_type"] == "resolver.error"]
    assert len(error_entries) == 1


def test_response_with_trailing_comma(
    tmp_audit_dir, audit_log, make_item, patch_anthropic
):
    """Pin: trailing commas are valid in JavaScript but not in JSON — json.loads
    raises JSONDecodeError. The resolver returns [] and writes a resolver.error
    entry."""
    response = '{"has_implications": true, "severity": "warning", "affected_controls": [],}'
    patch_anthropic(response)
    r = Resolver(config=_config(tmp_audit_dir), audit=audit_log)
    results = r.analyse(make_item())

    assert results == []

    entries = _read_log(tmp_audit_dir)
    error_entries = [e for e in entries if e["event_type"] == "resolver.error"]
    assert len(error_entries) == 1


def test_response_truncated_mid_json(
    tmp_audit_dir, audit_log, make_item, patch_anthropic
):
    """Pin: a truncated JSON response (e.g. due to max_tokens cutoff) causes
    json.loads to raise JSONDecodeError. The resolver returns [] and writes a
    resolver.error audit entry. This can silently drop real regulatory findings
    if the LLM context window limit cuts the response short."""
    response = '{"has_implications": true, "severity": "warning"'
    patch_anthropic(response)
    r = Resolver(config=_config(tmp_audit_dir), audit=audit_log)
    results = r.analyse(make_item())

    assert results == []

    entries = _read_log(tmp_audit_dir)
    error_entries = [e for e in entries if e["event_type"] == "resolver.error"]
    assert len(error_entries) == 1


def test_response_with_nested_json_block(
    tmp_audit_dir, audit_log, make_item, patch_anthropic
):
    """Pin: ```json fences ARE stripped by the resolver's fence-stripping logic.
    The logic splits on ``` and takes index 1, then strips the leading 'json'
    prefix. This is intentional — many LLMs wrap JSON in markdown fences despite
    the prompt asking them not to."""
    payload = json.dumps({
        "has_implications": True,
        "severity": "warning",
        "affected_controls": ["5.1"],
        "summary": "Policy impact.",
        "recommended_action": "Review policies.",
        "rationale": "Relevant to control 5.1.",
    })
    response = f"```json\n{payload}\n```"
    patch_anthropic(response)
    r = Resolver(config=_config(tmp_audit_dir), audit=audit_log)
    results = r.analyse(make_item())

    assert len(results) == 1
    assert isinstance(results[0], ResolverResult)
    assert results[0].has_implications is True
    assert results[0].severity == "warning"


def test_response_with_just_plain_fence(
    tmp_audit_dir, audit_log, make_item, patch_anthropic
):
    """Pin: plain ``` fences (no 'json' suffix) are also stripped correctly.
    The content between the fences is taken verbatim and parsed as JSON."""
    payload = json.dumps({
        "has_implications": True,
        "severity": "info",
        "affected_controls": [],
        "summary": "Awareness only.",
        "recommended_action": "No action needed.",
        "rationale": "This publication has no direct obligations.",
    })
    response = f"```\n{payload}\n```"
    patch_anthropic(response)
    r = Resolver(config=_config(tmp_audit_dir), audit=audit_log)
    results = r.analyse(make_item())

    assert len(results) == 1
    assert isinstance(results[0], ResolverResult)
    assert results[0].has_implications is True


def test_response_with_hallucinated_control_ids(
    tmp_audit_dir, audit_log, make_item, patch_anthropic
):
    """Pin: the resolver does NOT validate affected_controls against the loaded
    framework's actual control IDs. Bogus/hallucinated IDs are passed through
    verbatim to the audit log and the ResolverResult. If we ever add framework
    validation, this test will fail — that is the desired signal."""
    response = _valid_response(affected_controls=["BOGUS-99", "FAKE-1.1"])
    patch_anthropic(response)
    r = Resolver(config=_config(tmp_audit_dir), audit=audit_log)
    results = r.analyse(make_item())

    assert len(results) == 1
    assert "BOGUS-99" in results[0].affected_controls
    assert "FAKE-1.1" in results[0].affected_controls

    entries = _read_log(tmp_audit_dir)
    assessment_entries = [e for e in entries if e["event_type"] == "resolver.assessment"]
    assert len(assessment_entries) == 1
    assert "BOGUS-99" in assessment_entries[0]["detail"]["affected_controls"]
    assert "FAKE-1.1" in assessment_entries[0]["detail"]["affected_controls"]
