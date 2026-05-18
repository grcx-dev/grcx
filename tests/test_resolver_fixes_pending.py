"""Resolver fix-ready tests. Each asserts post-fix behaviour for findings 1, 3, 4, 5 in
TEST_REPORT.md (consolidated under 'LLM response schema validation'). Marked
xfail(strict=True) so the suite stays green today and automatically signals when a fix
arrives."""

import json

import pytest


# ─── shared helpers ────────────────────────────────────────────────────────────


def _resolver(audit_log, tmp_audit_dir, frameworks=("iso27001",)):
    config = {
        "controls": {"frameworks": list(frameworks)},
        "resolver": {"llm": "claude-haiku-4-5"},
        "audit": {"output": str(tmp_audit_dir)},
    }
    from grcx.resolver.resolver import Resolver
    return Resolver(config=config, audit=audit_log)


def _read_log(tmp_audit_dir):
    log_path = tmp_audit_dir / "grcx.log.jsonl"
    if not log_path.exists():
        return []
    lines = log_path.read_text().strip().splitlines()
    return [json.loads(line) for line in lines if line.strip()]


def _valid_json(**overrides):
    """Return a complete, valid resolver JSON string with optional overrides."""
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


# ─── Section 1: has_implications must be required (finding #1) ─────────────────


@pytest.mark.xfail(
    strict=True,
    reason="Pending fix: TEST_REPORT finding #1: Resolver silently drops findings on missing has_implications",
)
def test_missing_has_implications_raises_or_logs_error(
    tmp_audit_dir, audit_log, make_item, patch_anthropic
):
    """After fix: a response missing the required 'has_implications' key must either raise
    ValueError (caught by the existing except-all and turned into a resolver.error audit
    entry) or directly write a resolver.error entry. Today: silently treats the omission
    as has_implications=False and returns a ResolverResult with no audit entry at all —
    indistinguishable from a genuine 'no compliance implications' outcome.

    This test accepts either outcome as valid post-fix behaviour:
    - raised exception surfaced as a resolver.error audit entry, OR
    - resolver.error entry written directly.
    Either way, no silent drop.
    """
    response = json.dumps({
        "severity": "warning",
        "summary": "Something important.",
        "recommended_action": "Act now.",
        "rationale": "Relevant to several controls.",
        "affected_controls": ["5.1"],
    })
    patch_anthropic(response)
    r = _resolver(audit_log, tmp_audit_dir)

    raised = False
    try:
        r.analyse(make_item())
    except (ValueError, KeyError):
        raised = True

    if not raised:
        entries = _read_log(tmp_audit_dir)
        error_entries = [e for e in entries if e["event_type"] == "resolver.error"]
        assert len(error_entries) >= 1, (
            "Expected either a raised exception or a resolver.error audit entry "
            "when 'has_implications' is absent from the LLM response, but got neither."
        )


# ─── Section 2: control-ID validation (finding #4) ────────────────────────────


@pytest.mark.xfail(
    strict=True,
    reason="Pending fix: TEST_REPORT finding #4: No control-ID validation — hallucinated IDs flow into audit log",
)
def test_hallucinated_control_ids_filtered_out(
    tmp_audit_dir, audit_log, make_item, patch_anthropic
):
    """After fix: affected_controls in the resolver.assessment audit entry should only
    contain IDs that actually exist in the loaded framework. The iso27001 framework
    includes '5.1' but not 'BOGUS-99' or 'TOTALLY-FAKE'. Those two should be stripped
    before the entry is written.
    """
    response = _valid_json(
        affected_controls=["BOGUS-99", "TOTALLY-FAKE", "5.1"],
    )
    patch_anthropic(response)
    r = _resolver(audit_log, tmp_audit_dir)
    r.analyse(make_item())

    entries = _read_log(tmp_audit_dir)
    assessment_entries = [e for e in entries if e["event_type"] == "resolver.assessment"]
    assert len(assessment_entries) == 1, "Expected one resolver.assessment entry."
    assert assessment_entries[0]["detail"]["affected_controls"] == ["5.1"], (
        "Expected only the real control ID '5.1' to survive; hallucinated IDs must be "
        "filtered out."
    )


@pytest.mark.xfail(
    strict=True,
    reason="Pending fix: TEST_REPORT finding #4: No control-ID validation — hallucinated IDs flow into audit log",
)
def test_all_hallucinated_controls_logged_as_warning(
    tmp_audit_dir, audit_log, make_item, patch_anthropic
):
    """After fix: when every control ID returned by the LLM is hallucinated (none exist
    in the framework), the resolver must handle it explicitly rather than silently writing
    a finding with bogus IDs.

    This test accepts any of the following as valid post-fix behaviour:
    (a) The entry is not written at all (all-bogus treated as no-implications), OR
    (b) A resolver.warning or resolver.error entry is written noting the invalid IDs, OR
    (c) The entry is written with an empty affected_controls list.

    What is NOT acceptable (current behaviour): writing the bogus IDs into the
    resolver.assessment entry as if they were legitimate.
    """
    response = _valid_json(affected_controls=["BOGUS-1", "BOGUS-2"])
    patch_anthropic(response)
    r = _resolver(audit_log, tmp_audit_dir)
    r.analyse(make_item())

    entries = _read_log(tmp_audit_dir)
    assessment_entries = [e for e in entries if e["event_type"] == "resolver.assessment"]

    if len(assessment_entries) == 0:
        # Option (a): entry suppressed entirely — acceptable.
        return

    # Option (b) or (c): entry present; affected_controls must be empty or a warning
    # must accompany it.
    bogus_ids = {"BOGUS-1", "BOGUS-2"}
    actual_controls = set(assessment_entries[0]["detail"].get("affected_controls", []))
    if actual_controls & bogus_ids:
        # Bogus IDs still present — not acceptable post-fix.
        all_entries = entries
        warning_entries = [
            e for e in all_entries
            if e["event_type"] in ("resolver.warning", "resolver.error")
        ]
        assert len(warning_entries) >= 1, (
            "Bogus control IDs are still written into the assessment entry with no "
            "accompanying warning. Post-fix: either strip them or emit a warning."
        )
        # If a warning was emitted, the remaining assertion is that affected_controls
        # is empty (since both IDs are bogus).
        assert actual_controls == set(), (
            "With all-bogus IDs and a warning emitted, affected_controls should be empty."
        )


# ─── Section 3: affected_controls type coercion (finding #5) ──────────────────


@pytest.mark.xfail(
    strict=True,
    reason="Pending fix: TEST_REPORT finding #5: affected_controls accepted as string instead of list",
)
def test_affected_controls_string_coerced_to_list(
    tmp_audit_dir, audit_log, make_item, patch_anthropic
):
    """After fix: when the LLM returns affected_controls as a plain string (e.g. '5.1')
    instead of a list, the resolver must coerce it to a single-element list ['5.1'].
    Today it stores the string verbatim, causing ', '.join() to iterate over characters
    and the dashboard to render one badge per character.
    """
    response = json.dumps({
        "has_implications": True,
        "severity": "warning",
        "affected_controls": "5.1",
        "summary": "Policy impact.",
        "recommended_action": "Review policies.",
        "rationale": "Relevant to control 5.1.",
    })
    patch_anthropic(response)
    r = _resolver(audit_log, tmp_audit_dir)
    results = r.analyse(make_item())

    assert len(results) == 1
    assert results[0].affected_controls == ["5.1"], (
        "Expected the string '5.1' to be coerced to the list ['5.1']."
    )

    entries = _read_log(tmp_audit_dir)
    assessment_entries = [e for e in entries if e["event_type"] == "resolver.assessment"]
    assert len(assessment_entries) == 1
    assert assessment_entries[0]["detail"]["affected_controls"] == ["5.1"], (
        "The audit log entry must store the coerced list, not the raw string."
    )


@pytest.mark.xfail(
    strict=True,
    reason="Pending fix: TEST_REPORT finding #5: affected_controls accepted as string instead of list",
)
def test_affected_controls_none_becomes_empty_list(
    tmp_audit_dir, audit_log, make_item, patch_anthropic
):
    """After fix: when the LLM returns affected_controls as null/None, the resolver must
    coerce it to an empty list []. Today the None is passed through to ResolverResult and
    downstream join() / iteration would crash (silently avoided only because no code
    immediately iterates it in the error path).
    """
    response = json.dumps({
        "has_implications": True,
        "severity": "warning",
        "affected_controls": None,
        "summary": "Policy impact.",
        "recommended_action": "Review policies.",
        "rationale": "Relevant to control 5.1.",
    })
    patch_anthropic(response)
    r = _resolver(audit_log, tmp_audit_dir)
    results = r.analyse(make_item())

    assert len(results) == 1
    assert results[0].affected_controls == [], (
        "Expected None affected_controls to be coerced to an empty list []."
    )

    entries = _read_log(tmp_audit_dir)
    assessment_entries = [e for e in entries if e["event_type"] == "resolver.assessment"]
    assert len(assessment_entries) == 1
    assert assessment_entries[0]["detail"]["affected_controls"] == [], (
        "The audit log entry must store [] not None."
    )


# ─── Section 4: tolerant JSON extraction (finding #3) ─────────────────────────


@pytest.mark.xfail(
    strict=True,
    reason="Pending fix: TEST_REPORT finding #3: Brittle JSON parsing — leading prose drops the finding",
)
def test_extracts_json_with_leading_prose(
    tmp_audit_dir, audit_log, make_item, patch_anthropic
):
    """After fix: prose before the JSON object must not prevent parsing. Today the
    fence-stripping only triggers when the response starts with '```', so 'Here is my
    analysis:\\n\\n{...}' hits json.loads directly and fails. Post-fix, the resolver
    should locate the first '{' and extract from there.
    """
    payload = {
        "has_implications": True,
        "severity": "warning",
        "affected_controls": ["5.1"],
        "summary": "s",
        "recommended_action": "a",
        "rationale": "r",
    }
    response = "Here is my analysis:\n\n" + json.dumps(payload)
    patch_anthropic(response)
    r = _resolver(audit_log, tmp_audit_dir)
    results = r.analyse(make_item())

    assert len(results) == 1, "Expected one result; leading prose should not block parsing."

    entries = _read_log(tmp_audit_dir)
    assessment_entries = [e for e in entries if e["event_type"] == "resolver.assessment"]
    assert len(assessment_entries) == 1, "Expected resolver.assessment entry to be written."


@pytest.mark.xfail(
    strict=True,
    reason="Pending fix: TEST_REPORT finding #3: Brittle JSON parsing — trailing prose drops the finding",
)
def test_extracts_json_with_trailing_prose(
    tmp_audit_dir, audit_log, make_item, patch_anthropic
):
    """After fix: prose after the closing brace must not prevent parsing. Today
    json.loads raises JSONDecodeError on any extra characters after the JSON object.
    Post-fix, the resolver should extract only the JSON object and ignore trailing text.
    """
    payload = json.dumps({
        "has_implications": True,
        "severity": "warning",
        "affected_controls": ["5.1"],
        "summary": "s",
        "recommended_action": "a",
        "rationale": "r",
    })
    response = payload + "\n\nNote: this is preliminary."
    patch_anthropic(response)
    r = _resolver(audit_log, tmp_audit_dir)
    results = r.analyse(make_item())

    assert len(results) == 1, "Expected one result; trailing prose should not block parsing."

    entries = _read_log(tmp_audit_dir)
    assessment_entries = [e for e in entries if e["event_type"] == "resolver.assessment"]
    assert len(assessment_entries) == 1, "Expected resolver.assessment entry to be written."


@pytest.mark.xfail(
    strict=True,
    reason="Pending fix: TEST_REPORT finding #3: Brittle JSON parsing — prose + fenced block drops the finding",
)
def test_extracts_json_from_mixed_prose(
    tmp_audit_dir, audit_log, make_item, patch_anthropic
):
    """After fix: a response structured as prose + fenced JSON block + trailing prose must
    parse successfully. The existing fence-stripping only handles responses that START with
    '```'; if there is any leading text before the fence, the logic is skipped and
    json.loads receives the entire string including the fences and prose, causing a
    JSONDecodeError.
    """
    payload = json.dumps({
        "has_implications": True,
        "severity": "warning",
        "affected_controls": ["5.1"],
        "summary": "s",
        "recommended_action": "a",
        "rationale": "r",
    })
    response = f"Analysis:\n\n```json\n{payload}\n```\n\nDone."
    patch_anthropic(response)
    r = _resolver(audit_log, tmp_audit_dir)
    results = r.analyse(make_item())

    assert len(results) == 1, "Expected one result from prose-wrapped fenced JSON block."

    entries = _read_log(tmp_audit_dir)
    assessment_entries = [e for e in entries if e["event_type"] == "resolver.assessment"]
    assert len(assessment_entries) == 1, "Expected resolver.assessment entry to be written."


@pytest.mark.xfail(
    strict=True,
    reason="Pending fix: TEST_REPORT finding #3: Brittle JSON parsing — extra object after main object",
)
def test_extracts_json_handles_extra_object_after(
    tmp_audit_dir, audit_log, make_item, patch_anthropic
):
    """After fix: when the LLM appends a second JSON object after the main one (e.g. a
    debug or metadata object), the resolver should extract only the FIRST valid object and
    ignore the rest. Today the second object causes json.loads to raise JSONDecodeError.
    """
    payload = json.dumps({
        "has_implications": True,
        "severity": "warning",
        "affected_controls": ["5.1"],
        "summary": "s",
        "recommended_action": "a",
        "rationale": "r",
    })
    response = payload + '\n{ "debug": true }'
    patch_anthropic(response)
    r = _resolver(audit_log, tmp_audit_dir)
    results = r.analyse(make_item())

    assert len(results) == 1, "Expected one result; second debug object should be ignored."

    entries = _read_log(tmp_audit_dir)
    assessment_entries = [e for e in entries if e["event_type"] == "resolver.assessment"]
    assert len(assessment_entries) == 1, "Expected resolver.assessment entry to be written."


# ─── Section 5: schema-validation as a layer ──────────────────────────────────


@pytest.mark.xfail(
    strict=True,
    reason="Pending fix: schema-validation layer — severity outside info/warning/critical enum should be normalised or flagged",
)
def test_response_severity_outside_enum_normalised(
    tmp_audit_dir, audit_log, make_item, patch_anthropic
):
    """After fix: a severity value that is not in the allowed enum (info/warning/critical)
    must be either coerced to a known value or cause a resolver.error audit entry. Today
    the invalid value 'very high' is passed through verbatim, silently producing dashboard
    entries with an unrecognised severity that colour-maps to 'white' and breaks any
    downstream severity-based logic.

    This test accepts either outcome as valid post-fix behaviour:
    - severity is coerced to one of 'info', 'warning', or 'critical', OR
    - a resolver.error entry is written.
    """
    response = _valid_json(severity="very high")
    patch_anthropic(response)
    r = _resolver(audit_log, tmp_audit_dir)

    raised = False
    results = []
    try:
        results = r.analyse(make_item())
    except (ValueError, KeyError):
        raised = True

    if raised:
        # Exception counts as a resolver.error outcome — check the audit log if it exists.
        return

    entries = _read_log(tmp_audit_dir)

    # Check if an error was written instead.
    error_entries = [e for e in entries if e["event_type"] == "resolver.error"]
    if error_entries:
        return  # resolver.error is acceptable post-fix behaviour.

    # Otherwise the result must have a normalised severity.
    valid_severities = {"info", "warning", "critical"}
    assert len(results) == 1
    assert results[0].severity in valid_severities, (
        f"Expected severity to be coerced to one of {valid_severities}, "
        f"got '{results[0].severity}'."
    )

    assessment_entries = [e for e in entries if e["event_type"] == "resolver.assessment"]
    assert len(assessment_entries) == 1
    assert assessment_entries[0]["severity"] in valid_severities, (
        "The audit log entry must have a normalised severity value."
    )


def test_response_with_extra_unknown_fields_ignored_safely(
    tmp_audit_dir, audit_log, make_item, patch_anthropic
):
    """Extra fields in the LLM JSON response are silently ignored via data.get() — the
    resolver only reads the known keys. This already works today (current behaviour via
    dict.get()), so this test is NOT marked xfail. It serves as a regression guard
    ensuring that a future Pydantic schema layer uses extra='ignore' and does not break
    the existing safe pass-through.
    """
    response = json.dumps({
        "has_implications": True,
        "severity": "warning",
        "affected_controls": ["5.1"],
        "summary": "Policy impact.",
        "recommended_action": "Review policies.",
        "rationale": "Relevant to control 5.1.",
        "urgent_action": "PANIC",
        "debug_mode": True,
        "extra_list": [1, 2, 3],
    })
    patch_anthropic(response)
    r = _resolver(audit_log, tmp_audit_dir)
    results = r.analyse(make_item())

    assert len(results) == 1
    assert results[0].has_implications is True
    assert results[0].severity == "warning"
    assert results[0].affected_controls == ["5.1"]

    entries = _read_log(tmp_audit_dir)
    assessment_entries = [e for e in entries if e["event_type"] == "resolver.assessment"]
    assert len(assessment_entries) == 1

    detail = assessment_entries[0]["detail"]
    assert "urgent_action" not in detail, "Extra field 'urgent_action' must not appear in audit entry."
    assert "debug_mode" not in detail, "Extra field 'debug_mode' must not appear in audit entry."
