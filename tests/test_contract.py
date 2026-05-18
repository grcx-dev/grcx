# End-to-end contract test: runner writes audit log, dashboard reads it correctly.
import pytest
from grcx.sentinel.regulatory.rss import RegulatoryItem
from grcx.audit.log import AuditLog


def test_runner_output_renders_in_dashboard(
    tmp_audit_dir, monkeypatch, patch_anthropic, canned_llm_response
):
    """
    Single most important test in the suite.
    Runs one runner iteration, then verifies dashboard.load_data reads it correctly.
    Also verifies the hash chain is intact end-to-end.
    """
    patch_anthropic(canned_llm_response)

    item = RegulatoryItem(
        title="Contract Test Publication",
        url="https://boe.example.org/pub/contract-test",
        published="Thu, 12 Feb 2026 10:00:00 GMT",
        summary="A regulatory publication for the contract test.",
        jurisdiction="BOE",
        feed_url="https://boe.example.org/feed",
    )

    class FakeRss:
        def __init__(self, *args, **kwargs):
            self.jurisdiction = "BOE"
            self.url = "https://boe.example.org/feed"
            self._called = 0

        def fetch(self):
            self._called += 1
            if self._called == 1:
                return [item]
            return []

    monkeypatch.setattr("grcx.sentinel.runner.RssSentinel", FakeRss)

    def fake_sleep(seconds):
        raise StopIteration("stop after first poll")

    monkeypatch.setattr("grcx.sentinel.runner.time.sleep", fake_sleep)

    config = {
        "sentinels": {
            "regulatory": [
                {"type": "rss", "url": "https://boe.example.org/feed", "jurisdiction": "BOE"}
            ]
        },
        "controls": {"framework": "iso27001"},
        "resolver": {"llm": "claude-3-5-sonnet", "auto_remediate": "notify_only"},
        "audit": {"output": str(tmp_audit_dir)},
    }

    from grcx.sentinel import runner

    with pytest.raises(StopIteration):
        runner.run(config, dry_run=False, poll_interval=1)

    # Point dashboard at the same log file
    import dashboard.app as app_module
    monkeypatch.setattr(app_module, "LOG_PATH", tmp_audit_dir / "grcx.log.jsonl")

    data = app_module.load_data()

    # canned response: severity=warning, has_implications=True, controls=["5.1","5.2"]
    assert data["total"] == 1
    assert data["flagged"] == 1
    assert data["critical_count"] == 0  # canned response is "warning", not "critical"

    row = data["rows"][0]
    assert "iso27001" in row["by_framework"]
    assert row["all_controls"] == ["5.1", "5.2"]
    assert row["title"] == item.title

    # Verify the audit chain is intact end-to-end
    audit = AuditLog(log_dir=str(tmp_audit_dir))
    valid, errors = audit.verify()
    assert valid is True
    assert errors == []
