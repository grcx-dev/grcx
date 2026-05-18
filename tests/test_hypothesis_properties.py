# Property-based tests using Hypothesis.
# Each test generates many random inputs and asserts an invariant must always hold.
import json
import os

import pytest
from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st


# ---------------------------------------------------------------------------
# RegulatoryItem.fingerprint properties
# ---------------------------------------------------------------------------

@given(
    url=st.text(min_size=1, max_size=500),
    title=st.text(min_size=0, max_size=500),
)
@settings(max_examples=50, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_fingerprint_is_always_16_lowercase_hex(url, title):
    """fingerprint is always a 16-character lowercase hex string for any url/title."""
    from grcx.sentinel.regulatory.rss import RegulatoryItem

    item = RegulatoryItem(
        title=title, url=url, published="", summary="", jurisdiction="X", feed_url=""
    )
    assert len(item.fingerprint) == 16
    assert all(c in "0123456789abcdef" for c in item.fingerprint)


@given(
    url=st.text(min_size=1, max_size=500),
    title=st.text(min_size=0, max_size=500),
)
@settings(max_examples=50, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_fingerprint_is_deterministic_for_same_inputs(url, title):
    """Same url+title always yields the same fingerprint (pure SHA-256 truncation)."""
    from grcx.sentinel.regulatory.rss import RegulatoryItem

    item_a = RegulatoryItem(
        title=title, url=url, published="", summary="", jurisdiction="X", feed_url=""
    )
    item_b = RegulatoryItem(
        title=title, url=url, published="2026-01-01", summary="different", jurisdiction="Y", feed_url="other"
    )
    assert item_a.fingerprint == item_b.fingerprint


@given(
    url1=st.text(min_size=1, max_size=200),
    url2=st.text(min_size=1, max_size=200),
    title=st.text(min_size=0, max_size=200),
)
@settings(max_examples=50, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_fingerprint_differs_when_url_differs(url1, url2, title):
    """Two items that differ only in URL should (almost always) have different fingerprints."""
    assume(url1 != url2)
    from grcx.sentinel.regulatory.rss import RegulatoryItem

    item_a = RegulatoryItem(
        title=title, url=url1, published="", summary="", jurisdiction="X", feed_url=""
    )
    item_b = RegulatoryItem(
        title=title, url=url2, published="", summary="", jurisdiction="X", feed_url=""
    )
    # SHA-256 truncated to 16 hex chars (64 bits); collision is astronomically
    # unlikely for any two distinct inputs. If hypothesis ever finds a collision
    # here that would be a genuine finding worth reporting.
    assert item_a.fingerprint != item_b.fingerprint


# ---------------------------------------------------------------------------
# AuditLog chain integrity properties
# ---------------------------------------------------------------------------

@given(
    summaries=st.lists(st.text(max_size=200), min_size=0, max_size=50),
)
@settings(
    max_examples=30,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_audit_chain_always_verifies_after_N_writes(tmp_path, summaries):
    """A single AuditLog writing N entries must always produce a valid chain."""
    from grcx.audit.log import AuditLog

    log = AuditLog(log_dir=str(tmp_path / "audit"))
    for s in summaries:
        log.write(event_type="test", summary=s)
    valid, errors = log.verify()
    assert valid
    assert errors == []


@given(
    summaries=st.lists(st.text(max_size=100), min_size=1, max_size=20),
    tamper_seed=st.integers(min_value=0, max_value=2**31 - 1),
)
@settings(
    max_examples=30,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_audit_chain_always_breaks_when_any_entry_tampered(tmp_path, summaries, tamper_seed):
    """Mutating any single entry's summary must cause verify() to return False."""
    from grcx.audit.log import AuditLog

    log = AuditLog(log_dir=str(tmp_path / "audit"))
    for s in summaries:
        log.write(event_type="test", summary=s)

    log_file = log.log_path
    lines = log_file.read_text().splitlines()
    # Derive index from tamper_seed so the strategy is fully deterministic.
    idx = tamper_seed % len(lines)
    entry = json.loads(lines[idx])
    entry["summary"] = entry["summary"] + "__TAMPERED__"
    lines[idx] = json.dumps(entry)
    log_file.write_text("\n".join(lines) + "\n")

    valid, errors = log.verify()
    assert not valid, "verify() should return False after tampering"
    assert len(errors) >= 1


# ---------------------------------------------------------------------------
# RssSentinel._parse robustness property
# ---------------------------------------------------------------------------

@given(xml_text=st.text(min_size=0, max_size=2000))
@settings(max_examples=50, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_rss_parse_does_not_raise_on_any_valid_utf8_text(tmp_path, xml_text):
    """_parse must never raise — it should return an empty list on unparseable input."""
    from grcx.sentinel.regulatory.rss import RssSentinel

    sentinel = RssSentinel(
        url="https://example.com/feed.rss",
        jurisdiction="TEST",
        state_dir=str(tmp_path),
    )
    result = sentinel._parse(xml_text)
    assert isinstance(result, list)


# ---------------------------------------------------------------------------
# Resolver robustness: never raises on arbitrary LLM response text
# ---------------------------------------------------------------------------

@given(llm_response=st.text(min_size=0, max_size=500))
@settings(
    max_examples=30,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
    deadline=None,
)
def test_resolver_json_envelope_never_crashes_on_arbitrary_text(tmp_path, llm_response, monkeypatch):
    """Resolver.analyse must not raise even when the LLM returns arbitrary non-JSON text."""
    import anthropic
    from grcx.audit.log import AuditLog
    from grcx.resolver.resolver import Resolver
    from grcx.sentinel.regulatory.rss import RegulatoryItem

    class _Msg:
        def __init__(self, text):
            self.content = [type("Block", (), {"text": text})()]

    class _Messages:
        def create(self, **kwargs):
            return _Msg(llm_response)

    class _FakeClient:
        def __init__(self, *args, **kwargs):
            self.messages = _Messages()

    monkeypatch.setattr(anthropic, "Anthropic", _FakeClient)

    log = AuditLog(log_dir=str(tmp_path / "audit"))
    config = {
        "resolver": {"llm": "claude-sonnet-4-6", "auto_remediate": "notify_only"},
        "controls": {"frameworks": ["iso27001"]},
    }
    resolver = Resolver(config=config, audit=log)

    item = RegulatoryItem(
        title="Test Item",
        url="https://example.com/item",
        published="2026-01-01",
        summary="A test item",
        jurisdiction="TEST",
        feed_url="https://example.com/feed",
    )

    # Must not raise — should return a list (empty if JSON parse failed) or write
    # a resolver.error entry and return None internally (which means empty list).
    result = resolver.analyse(item)
    assert isinstance(result, list)


# ---------------------------------------------------------------------------
# Fingerprint collision resistance over 500 random pairs
# ---------------------------------------------------------------------------

@given(seed=st.integers(min_value=0, max_value=2**31 - 1))
@settings(
    max_examples=5,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_fingerprint_collision_resistance_on_500_random_pairs(seed):
    """500 distinct URLs derived from a seed must yield at least 499 unique fingerprints."""
    import hashlib as _hashlib
    from grcx.sentinel.regulatory.rss import RegulatoryItem

    # Generate 500 distinct URLs deterministically from the seed so that
    # Hypothesis doesn't need to carry 500 large text values in its entropy budget.
    pairs = [
        (f"https://example.com/pub/{seed}/{i}", f"Title {seed}-{i}")
        for i in range(500)
    ]
    fps = [
        RegulatoryItem(
            title=title, url=url, published="", summary="", jurisdiction="X", feed_url=""
        ).fingerprint
        for url, title in pairs
    ]
    unique_count = len(set(fps))
    # Tolerate at most 1 collision in 500 (SHA-256 truncated to 64 bits makes
    # even 1 collision astronomically unlikely — this is a sanity check that the
    # function is not accidentally constant).
    assert unique_count >= 499, (
        f"Too many collisions: only {unique_count} unique fingerprints from 500 distinct pairs"
    )
