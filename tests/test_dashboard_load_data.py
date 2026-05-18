# Tests for dashboard.app.load_data
import json
import pytest
from pathlib import Path
from datetime import datetime, timezone, timedelta


@pytest.fixture(autouse=True)
def patch_log_path(monkeypatch, tmp_audit_dir):
    """Redirect dashboard LOG_PATH to the tmp audit dir for every test."""
    import dashboard.app as app_module
    monkeypatch.setattr(app_module, "LOG_PATH", tmp_audit_dir / "grcx.log.jsonl")


def _write_raw(tmp_audit_dir, entries):
    """Write raw JSONL entries (used for controlling timestamps exactly)."""
    log_path = tmp_audit_dir / "grcx.log.jsonl"
    with open(log_path, "a") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")


def test_empty_log_returns_empty_dict(tmp_audit_dir):
    import dashboard.app as app_module
    assert app_module.load_data() == {}


def test_publication_without_assessment_appears_as_info(tmp_audit_dir, audit_log):
    audit_log.write(
        event_type="regulatory.new_publication",
        summary="Test Publication",
        severity="warning",
        jurisdiction="BOE",
        source="https://example.org/pub/1",
        detail={
            "fingerprint": "fp001",
            "published": "2026-02-12",
            "summary": "Details here.",
            "feed_url": "https://example.org/feed",
        },
    )

    import dashboard.app as app_module
    data = app_module.load_data()

    assert data["total"] == 1
    assert data["no_implications"] == 1
    assert len(data["rows"]) == 1

    row = data["rows"][0]
    assert row["severity"] == "info"
    assert row["flagged"] is False


def test_publication_with_critical_assessment(tmp_audit_dir, audit_log):
    fp = "fp_crit_001"
    audit_log.write(
        event_type="regulatory.new_publication",
        summary="Critical Pub",
        severity="warning",
        jurisdiction="FCA",
        source="https://example.org/pub/crit",
        detail={
            "fingerprint": fp,
            "published": "2026-02-12",
            "summary": "Critical details.",
            "feed_url": "https://example.org/feed",
        },
    )
    audit_log.write(
        event_type="resolver.assessment",
        summary="Critical finding",
        severity="critical",
        jurisdiction="FCA",
        source="https://example.org/pub/crit",
        detail={
            "framework": "iso27001",
            "affected_controls": ["5.1"],
            "recommended_action": "Act now",
            "rationale": "Urgent.",
            "publication_title": "Critical Pub",
            "fingerprint": fp,
        },
    )

    import dashboard.app as app_module
    data = app_module.load_data()

    assert data["critical_count"] == 1
    row = data["rows"][0]
    assert row["severity"] == "critical"
    assert row["flagged"] is True


def test_publication_with_multiple_assessments_takes_highest_severity(
    tmp_audit_dir, audit_log
):
    fp = "fp_multi_001"
    audit_log.write(
        event_type="regulatory.new_publication",
        summary="Multi Pub",
        severity="warning",
        jurisdiction="SEC",
        detail={
            "fingerprint": fp,
            "published": "2026-02-12",
            "summary": "Multi assessment test.",
            "feed_url": "https://example.org/feed",
        },
    )
    for sev in ("info", "warning", "critical"):
        audit_log.write(
            event_type="resolver.assessment",
            summary=f"Assessment {sev}",
            severity=sev,
            jurisdiction="SEC",
            detail={
                "framework": "iso27001",
                "affected_controls": ["5.1"],
                "recommended_action": "Do something",
                "rationale": "Reason.",
                "publication_title": "Multi Pub",
                "fingerprint": fp,
            },
        )

    import dashboard.app as app_module
    data = app_module.load_data()

    row = data["rows"][0]
    assert row["severity"] == "critical"


def test_assessments_grouped_by_framework(tmp_audit_dir, audit_log):
    fp = "fp_fw_001"
    audit_log.write(
        event_type="regulatory.new_publication",
        summary="Framework Pub",
        severity="info",
        jurisdiction="BOE",
        detail={
            "fingerprint": fp,
            "published": "2026-02-12",
            "summary": "Framework grouping test.",
            "feed_url": "https://example.org/feed",
        },
    )
    for fw in ("iso27001", "soc2"):
        audit_log.write(
            event_type="resolver.assessment",
            summary=f"Assessment for {fw}",
            severity="warning",
            jurisdiction="BOE",
            detail={
                "framework": fw,
                "affected_controls": ["5.1"],
                "recommended_action": "Action",
                "rationale": "Reason.",
                "publication_title": "Framework Pub",
                "fingerprint": fp,
            },
        )

    import dashboard.app as app_module
    data = app_module.load_data()

    row = data["rows"][0]
    assert "iso27001" in row["by_framework"]
    assert "soc2" in row["by_framework"]


def test_jurisdiction_counts(tmp_audit_dir, audit_log):
    for jur in ("BOE", "FCA", "BOE"):
        audit_log.write(
            event_type="regulatory.new_publication",
            summary=f"Pub from {jur}",
            severity="info",
            jurisdiction=jur,
            detail={
                "fingerprint": f"fp_{jur}_{audit_log._last_hash[:4]}",
                "published": "2026-02-12",
                "summary": "Test",
                "feed_url": "https://example.org/feed",
            },
        )

    import dashboard.app as app_module
    data = app_module.load_data()

    assert data["jurisdiction_counts"]["BOE"] == 2
    assert data["jurisdiction_counts"]["FCA"] == 1


def test_rows_sorted_by_timestamp_desc(tmp_audit_dir):
    import uuid, hashlib

    older_ts = "2026-01-01T10:00:00+00:00"
    newer_ts = "2026-03-01T10:00:00+00:00"

    def _make_entry(ts, fp, title):
        e = {
            "id": str(uuid.uuid4()),
            "timestamp": ts,
            "event_type": "regulatory.new_publication",
            "severity": "info",
            "summary": title,
            "jurisdiction": "BOE",
            "source": "https://example.org",
            "detail": {
                "fingerprint": fp,
                "published": ts,
                "summary": "Test",
                "feed_url": "https://example.org/feed",
            },
            "prev_hash": "genesis",
            "entry_hash": hashlib.sha256(fp.encode()).hexdigest(),
        }
        return e

    _write_raw(
        tmp_audit_dir,
        [
            _make_entry(older_ts, "fp_old_001", "Older publication"),
            _make_entry(newer_ts, "fp_new_001", "Newer publication"),
        ],
    )

    import dashboard.app as app_module
    data = app_module.load_data()

    rows = data["rows"]
    assert len(rows) == 2
    assert rows[0]["timestamp"] > rows[-1]["timestamp"]
    assert rows[0]["title"] == "Newer publication"


def test_all_controls_aggregated_unique_sorted(tmp_audit_dir, audit_log):
    fp = "fp_ctrl_001"
    audit_log.write(
        event_type="regulatory.new_publication",
        summary="Controls Pub",
        severity="info",
        jurisdiction="BOE",
        detail={
            "fingerprint": fp,
            "published": "2026-02-12",
            "summary": "Controls aggregation test.",
            "feed_url": "https://example.org/feed",
        },
    )
    audit_log.write(
        event_type="resolver.assessment",
        summary="Assessment 1",
        severity="warning",
        jurisdiction="BOE",
        detail={
            "framework": "iso27001",
            "affected_controls": ["5.1", "5.2"],
            "recommended_action": "Action",
            "rationale": "Reason.",
            "publication_title": "Controls Pub",
            "fingerprint": fp,
        },
    )
    audit_log.write(
        event_type="resolver.assessment",
        summary="Assessment 2",
        severity="info",
        jurisdiction="BOE",
        detail={
            "framework": "soc2",
            "affected_controls": ["5.2", "5.3"],
            "recommended_action": "Action",
            "rationale": "Reason.",
            "publication_title": "Controls Pub",
            "fingerprint": fp,
        },
    )

    import dashboard.app as app_module
    data = app_module.load_data()

    row = data["rows"][0]
    assert row["all_controls"] == ["5.1", "5.2", "5.3"]
