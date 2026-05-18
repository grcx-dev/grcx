# Shared pytest fixtures for the GRCX test suite.
#
# Naming contract used across the suite:
#   tmp_audit_dir       -> Path to a fresh per-test audit directory
#   audit_log           -> AuditLog instance pointing at tmp_audit_dir
#   rss_boe_xml         -> str of RSS 2.0 sample (BOE-shaped)
#   atom_esma_xml       -> str of Atom sample (ESMA-shaped)
#   email_fca_html      -> str of HTML newsletter sample
#   email_mas_url_html  -> str of HTML email whose anchor text is itself a URL
#   email_plain_text    -> str of plaintext email body
#   make_item           -> factory(**overrides) -> RegulatoryItem
#   patch_anthropic     -> factory(canned_json_str) that monkeypatches the
#                          anthropic.Anthropic constructor used by Resolver
#   patch_gemini        -> factory(canned_json_str) for google.genai.Client
#   patch_ollama_httpx  -> factory(canned_json_str) for the Ollama httpx.post
import json
from pathlib import Path

import pytest

FIXTURE_DIR = Path(__file__).parent / "fixtures"


# ─── filesystem ────────────────────────────────────────────────────────

@pytest.fixture
def tmp_audit_dir(tmp_path):
    d = tmp_path / "grcx-audit"
    d.mkdir()
    return d


@pytest.fixture
def audit_log(tmp_audit_dir):
    from grcx.audit.log import AuditLog
    return AuditLog(log_dir=str(tmp_audit_dir))


# ─── fixture data ──────────────────────────────────────────────────────

@pytest.fixture
def rss_boe_xml():
    return (FIXTURE_DIR / "rss_boe_sample.xml").read_text()


@pytest.fixture
def atom_esma_xml():
    return (FIXTURE_DIR / "atom_esma_sample.xml").read_text()


@pytest.fixture
def email_fca_html():
    return (FIXTURE_DIR / "email_fca_sample.html").read_text()


@pytest.fixture
def email_mas_url_html():
    return (FIXTURE_DIR / "email_mas_url_anchor.html").read_text()


@pytest.fixture
def email_plain_text():
    return (FIXTURE_DIR / "email_plain_sample.txt").read_text()


@pytest.fixture
def rss_unicode_xml():
    return (FIXTURE_DIR / "rss_unicode_sample.xml").read_text()


@pytest.fixture
def rss_malformed_xml():
    return (FIXTURE_DIR / "rss_malformed_sample.xml").read_text()


@pytest.fixture
def email_unicode_eml():
    return (FIXTURE_DIR / "email_unicode_sample.eml").read_text()


@pytest.fixture
def email_nested_anchors_html():
    return (FIXTURE_DIR / "email_nested_anchors.html").read_text()


# ─── recorder for prompts sent to LLM (for prompt-injection tests) ────

@pytest.fixture
def anthropic_prompt_recorder(monkeypatch):
    """Patch anthropic.Anthropic so the resolver records every prompt sent.

    Usage:
        recorder = anthropic_prompt_recorder(canned_response_json)
        resolver.analyse(item)
        assert "malicious content" in recorder.prompts[0]
    """
    import anthropic

    class Recorder:
        def __init__(self):
            self.prompts: list[str] = []

    def _patch(canned_json: str) -> Recorder:
        rec = Recorder()

        class _Msg:
            def __init__(self, text):
                self.content = [type("Block", (), {"text": text})()]

        class _Messages:
            def create(self, **kwargs):
                rec.prompts.append(kwargs["messages"][0]["content"])
                return _Msg(canned_json)

        class _FakeClient:
            def __init__(self, *args, **kwargs):
                self.messages = _Messages()

        monkeypatch.setattr(anthropic, "Anthropic", _FakeClient)
        return rec

    return _patch


# ─── factories ─────────────────────────────────────────────────────────

@pytest.fixture
def make_item():
    """Factory returning a RegulatoryItem with sensible defaults."""
    from grcx.sentinel.regulatory.rss import RegulatoryItem

    def _make(**overrides):
        defaults = dict(
            title="Sample Publication",
            url="https://example.org/pub/sample",
            published="Thu, 12 Feb 2026 10:00:00 GMT",
            summary="A sample regulatory publication for testing.",
            jurisdiction="TEST",
            feed_url="https://example.org/feed",
        )
        defaults.update(overrides)
        return RegulatoryItem(**defaults)

    return _make


# ─── LLM provider patches ──────────────────────────────────────────────
#
# These patch the *attribute lookup* that Resolver.__init__ performs, so the
# Resolver never tries to talk to a real LLM. Each returns a small helper
# that, when called with a JSON string, configures the mock to return that
# string as the LLM response.

@pytest.fixture
def patch_anthropic(monkeypatch):
    """Patch anthropic.Anthropic so resolver gets a fake client.

    Usage:
        client = patch_anthropic('{"has_implications": true, "severity": "warning", ...}')
    """
    import anthropic

    def _patch(canned_json: str):
        class _Msg:
            def __init__(self, text):
                self.content = [type("Block", (), {"text": text})()]

        class _Messages:
            def __init__(self, text):
                self._text = text

            def create(self, **kwargs):
                return _Msg(self._text)

        class _FakeClient:
            def __init__(self, *args, **kwargs):
                self.messages = _Messages(canned_json)

        monkeypatch.setattr(anthropic, "Anthropic", _FakeClient)
        return _FakeClient

    return _patch


@pytest.fixture
def patch_gemini(monkeypatch):
    """Patch google.genai.Client so resolver gets a fake client."""
    from google import genai

    def _patch(canned_json: str):
        class _Resp:
            def __init__(self, text):
                self.text = text

        class _Models:
            def __init__(self, text):
                self._text = text

            def generate_content(self, **kwargs):
                return _Resp(self._text)

        class _FakeClient:
            def __init__(self, *args, **kwargs):
                self.models = _Models(canned_json)

        monkeypatch.setattr(genai, "Client", _FakeClient)
        return _FakeClient

    return _patch


@pytest.fixture
def patch_ollama_httpx(monkeypatch):
    """Patch httpx.post (used by resolver for Ollama) to return canned JSON."""
    import httpx
    from grcx.resolver import resolver as resolver_mod

    def _patch(canned_json: str):
        class _Resp:
            status_code = 200

            def __init__(self, text):
                self._text = text

            def raise_for_status(self):
                pass

            def json(self):
                return {"message": {"content": self._text}}

        def _fake_post(url, **kwargs):
            return _Resp(canned_json)

        monkeypatch.setattr(resolver_mod.httpx, "post", _fake_post)

    return _patch


# ─── canned LLM response ───────────────────────────────────────────────

@pytest.fixture
def canned_llm_response():
    """A reasonable resolver JSON payload for use with the patch_* fixtures."""
    return json.dumps({
        "has_implications": True,
        "severity": "warning",
        "affected_controls": ["5.1", "5.2"],
        "summary": "New consultation paper affects information security policy.",
        "recommended_action": "Review and update relevant policies within 30 days.",
        "rationale": "The publication introduces requirements relevant to controls 5.1 and 5.2.",
    })
