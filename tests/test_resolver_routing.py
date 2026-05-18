# Tests for provider routing in Resolver.__init__
import anthropic
import pytest

from grcx.resolver.resolver import Resolver


def _make_resolver(config, patch_anthropic=None, patch_gemini=None, patch_ollama_httpx=None, tmp_audit_dir=None, audit_log=None):
    """Helper to build a Resolver with mocked providers."""
    return Resolver(config=config, audit=audit_log)


# ── Anthropic / Claude routing ───────────────────────────────────────────────

def test_claude_model_uses_anthropic(patch_anthropic, tmp_audit_dir, audit_log):
    patch_anthropic("{}")
    config = {
        "controls": {"frameworks": ["iso27001"]},
        "resolver": {"llm": "claude-haiku-4-5-20251001"},
        "audit": {"output": str(tmp_audit_dir)},
    }
    resolver = Resolver(config=config, audit=audit_log)
    assert resolver._use_gemini is False
    assert resolver._use_ollama is False
    assert resolver.client is not None


def test_gemini_model_uses_genai(patch_gemini, tmp_audit_dir, audit_log):
    patch_gemini("{}")
    config = {
        "controls": {"frameworks": ["iso27001"]},
        "resolver": {"llm": "gemini-2.5-flash"},
        "audit": {"output": str(tmp_audit_dir)},
    }
    resolver = Resolver(config=config, audit=audit_log)
    assert resolver._use_gemini is True
    assert resolver._use_ollama is False
    assert hasattr(resolver, "gemini")


def test_ollama_model_uses_ollama(patch_anthropic, tmp_audit_dir, audit_log):
    # No LLM client is created for Ollama, but we still patch anthropic to
    # prevent any accidental real client instantiation.
    patch_anthropic("{}")
    config = {
        "controls": {"frameworks": ["iso27001"]},
        "resolver": {"llm": "llama3"},
        "audit": {"output": str(tmp_audit_dir)},
    }
    resolver = Resolver(config=config, audit=audit_log)
    assert resolver._use_gemini is False
    assert resolver._use_ollama is True


def test_default_llm_when_unset(patch_anthropic, tmp_audit_dir, audit_log):
    patch_anthropic("{}")
    # Omit 'llm' key entirely
    config = {
        "controls": {"frameworks": ["iso27001"]},
        "resolver": {},
        "audit": {"output": str(tmp_audit_dir)},
    }
    resolver = Resolver(config=config, audit=audit_log)
    assert resolver.llm == "claude-sonnet-4-6"
    assert resolver._use_gemini is False
    assert resolver._use_ollama is False
    assert resolver.client is not None


# ── Framework loading ────────────────────────────────────────────────────────

def test_frameworks_list_loaded(patch_anthropic, tmp_audit_dir, audit_log):
    patch_anthropic("{}")
    config = {
        "controls": {"frameworks": ["iso27001", "soc2"]},
        "resolver": {"llm": "claude-haiku-4-5"},
        "audit": {"output": str(tmp_audit_dir)},
    }
    resolver = Resolver(config=config, audit=audit_log)
    assert len(resolver._frameworks) == 2
    ids = {f["id"] for f in resolver._frameworks}
    assert ids == {"iso27001", "soc2"}


def test_frameworks_singular_key_supported(patch_anthropic, tmp_audit_dir, audit_log):
    patch_anthropic("{}")
    config = {
        "controls": {"framework": "iso27001"},
        "resolver": {"llm": "claude-haiku-4-5"},
        "audit": {"output": str(tmp_audit_dir)},
    }
    resolver = Resolver(config=config, audit=audit_log)
    assert len(resolver._frameworks) == 1
    assert resolver._frameworks[0]["id"] == "iso27001"


def test_unknown_framework_skipped_with_warning(patch_anthropic, tmp_audit_dir, audit_log):
    patch_anthropic("{}")
    config = {
        "controls": {"frameworks": ["iso27001", "bogus_xyz"]},
        "resolver": {"llm": "claude-haiku-4-5"},
        "audit": {"output": str(tmp_audit_dir)},
    }
    resolver = Resolver(config=config, audit=audit_log)
    assert len(resolver._frameworks) == 1
    assert resolver._frameworks[0]["id"] == "iso27001"
