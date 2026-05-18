# Tests for grcx.sentinel.runner.run
import json
import pytest
from grcx.audit.log import AuditLog
from grcx.sentinel.regulatory.rss import RegulatoryItem


def _make_config(tmp_audit_dir, sentinels):
    return {
        "sentinels": {"regulatory": sentinels},
        "controls": {"framework": "iso27001"},
        "resolver": {"llm": "claude-3-5-sonnet", "auto_remediate": "notify_only"},
        "audit": {"output": str(tmp_audit_dir)},
    }


def _read_entries(tmp_audit_dir):
    log_path = tmp_audit_dir / "grcx.log.jsonl"
    if not log_path.exists():
        return []
    return [json.loads(line) for line in log_path.read_text().strip().splitlines() if line.strip()]


def _make_item(jurisdiction="BOE", n=0):
    return RegulatoryItem(
        title=f"Test Publication {n}",
        url=f"https://example.org/pub/{n}",
        published="Thu, 12 Feb 2026 10:00:00 GMT",
        summary="A test regulatory publication.",
        jurisdiction=jurisdiction,
        feed_url="https://example.org/feed",
    )


def test_runner_one_iteration_writes_started_and_publication_entries(
    tmp_audit_dir, monkeypatch, patch_anthropic, canned_llm_response
):
    patch_anthropic(canned_llm_response)

    items = [_make_item("BOE", 0), _make_item("BOE", 1)]

    class FakeRss:
        def __init__(self, *args, **kwargs):
            self.jurisdiction = kwargs.get("jurisdiction", "FAKE")
            self.url = kwargs.get("url", "https://fake")
            self._called = 0

        def fetch(self):
            self._called += 1
            if self._called == 1:
                return items
            return []

    monkeypatch.setattr("grcx.sentinel.runner.RssSentinel", FakeRss)

    call_count = {"n": 0}

    def fake_sleep(seconds):
        call_count["n"] += 1
        raise StopIteration("stop after first poll")

    monkeypatch.setattr("grcx.sentinel.runner.time.sleep", fake_sleep)

    from grcx.sentinel import runner

    config = _make_config(
        tmp_audit_dir,
        [{"type": "rss", "url": "https://fake", "jurisdiction": "BOE"}],
    )

    with pytest.raises(StopIteration):
        runner.run(config, dry_run=False, poll_interval=1)

    entries = _read_entries(tmp_audit_dir)
    event_types = [e["event_type"] for e in entries]

    started = [e for e in entries if e["event_type"] == "grcx.started"]
    publications = [e for e in entries if e["event_type"] == "regulatory.new_publication"]
    assessments = [e for e in entries if e["event_type"] == "resolver.assessment"]

    assert len(started) == 1
    assert len(publications) == 2
    assert len(assessments) == 2


def test_runner_dry_run_skips_resolver(
    tmp_audit_dir, monkeypatch, patch_anthropic, canned_llm_response
):
    patch_anthropic(canned_llm_response)

    items = [_make_item("BOE", 0), _make_item("BOE", 1)]

    class FakeRss:
        def __init__(self, *args, **kwargs):
            self.jurisdiction = kwargs.get("jurisdiction", "FAKE")
            self.url = kwargs.get("url", "https://fake")
            self._called = 0

        def fetch(self):
            self._called += 1
            if self._called == 1:
                return items
            return []

    monkeypatch.setattr("grcx.sentinel.runner.RssSentinel", FakeRss)

    def fake_sleep(seconds):
        raise StopIteration("stop")

    monkeypatch.setattr("grcx.sentinel.runner.time.sleep", fake_sleep)

    from grcx.sentinel import runner

    config = _make_config(
        tmp_audit_dir,
        [{"type": "rss", "url": "https://fake", "jurisdiction": "BOE"}],
    )

    with pytest.raises(StopIteration):
        runner.run(config, dry_run=True, poll_interval=1)

    entries = _read_entries(tmp_audit_dir)
    publications = [e for e in entries if e["event_type"] == "regulatory.new_publication"]
    assessments = [e for e in entries if e["event_type"] == "resolver.assessment"]

    assert len(publications) == 2
    assert len(assessments) == 0


def test_runner_sentinel_error_logged(tmp_audit_dir, monkeypatch):
    class ErrorSentinel:
        def __init__(self, *args, **kwargs):
            self.jurisdiction = kwargs.get("jurisdiction", "FAKE")
            self.url = kwargs.get("url", "https://fake")

        def fetch(self):
            raise RuntimeError("boom")

    monkeypatch.setattr("grcx.sentinel.runner.RssSentinel", ErrorSentinel)

    def fake_sleep(seconds):
        raise StopIteration("stop")

    monkeypatch.setattr("grcx.sentinel.runner.time.sleep", fake_sleep)

    from grcx.sentinel import runner

    config = _make_config(
        tmp_audit_dir,
        [{"type": "rss", "url": "https://fake", "jurisdiction": "BOE"}],
    )

    with pytest.raises(StopIteration):
        runner.run(config, dry_run=False, poll_interval=1)

    entries = _read_entries(tmp_audit_dir)
    error_entries = [e for e in entries if e["event_type"] == "sentinel.error"]

    assert len(error_entries) == 1
    assert error_entries[0]["severity"] == "critical"


def test_runner_no_sentinels_returns_immediately(tmp_audit_dir):
    from grcx.sentinel import runner

    config = _make_config(tmp_audit_dir, [])

    # Should return without entering the infinite loop — no StopIteration needed
    runner.run(config)

    entries = _read_entries(tmp_audit_dir)
    started_entries = [e for e in entries if e["event_type"] == "grcx.started"]
    assert len(started_entries) == 0


def test_runner_imap_sentinel_constructed(tmp_audit_dir, monkeypatch):
    constructor_kwargs = {}

    class FakeEmail:
        def __init__(self, *args, **kwargs):
            constructor_kwargs.update(kwargs)
            self.jurisdiction = kwargs.get("jurisdiction", "FAKE")
            self.url = f"imap://{kwargs.get('host', 'fake')}"
            self._called = 0

        def fetch(self):
            self._called += 1
            return []

    monkeypatch.setattr("grcx.sentinel.runner.EmailSentinel", FakeEmail)

    def fake_sleep(seconds):
        raise StopIteration("stop")

    monkeypatch.setattr("grcx.sentinel.runner.time.sleep", fake_sleep)

    from grcx.sentinel import runner

    config = _make_config(
        tmp_audit_dir,
        [
            {
                "type": "imap",
                "host": "imap.example.com",
                "username": "user@example.com",
                "sender_filter": "regulator@gov.uk",
                "jurisdiction": "FCA",
            }
        ],
    )

    with pytest.raises(StopIteration):
        runner.run(config, dry_run=True, poll_interval=1)

    assert constructor_kwargs.get("host") == "imap.example.com"
    assert constructor_kwargs.get("username") == "user@example.com"
    assert constructor_kwargs.get("sender_filter") == "regulator@gov.uk"
