# Copyright (c) 2026 Neil Lowden | GRCX | MIT License
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, render_template

app = Flask(__name__)

LOG_PATH = Path(__file__).parent.parent / "grcx-audit" / "grcx.log.jsonl"


def _parse_ts(ts: str) -> datetime:
    try:
        return datetime.fromisoformat(ts)
    except Exception:
        return datetime.min.replace(tzinfo=timezone.utc)


def load_data():
    if not LOG_PATH.exists():
        return {}

    publications = {}   # fingerprint -> pub entry (regulatory.new_publication)
    assessments = defaultdict(list)  # fingerprint -> [assessment, ...]

    last_updated = None

    with open(LOG_PATH) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            ts = _parse_ts(entry.get("timestamp", ""))
            if last_updated is None or ts > last_updated:
                last_updated = ts

            event = entry.get("event_type")

            if event == "regulatory.new_publication":
                fp = entry["detail"].get("fingerprint", entry["id"])
                publications[fp] = {
                    "fingerprint": fp,
                    "timestamp": entry.get("timestamp", ""),
                    "jurisdiction": entry.get("jurisdiction", ""),
                    "title": entry.get("summary", ""),
                    "source": entry.get("source", ""),
                    "published": entry["detail"].get("published", ""),
                    "summary": entry["detail"].get("summary", ""),
                }

            elif event == "resolver.assessment":
                fp = entry["detail"].get("fingerprint", "")
                assessments[fp].append({
                    "framework": entry["detail"].get("framework", "iso27001"),
                    "severity": entry.get("severity", "info"),
                    "summary": entry.get("summary", ""),
                    "affected_controls": entry["detail"].get("affected_controls", []),
                    "recommended_action": entry["detail"].get("recommended_action", ""),
                    "rationale": entry["detail"].get("rationale", ""),
                    "source": entry.get("source", ""),
                    "jurisdiction": entry.get("jurisdiction", ""),
                    "timestamp": entry.get("timestamp", ""),
                    "publication_title": entry["detail"].get("publication_title", ""),
                })

    # Build unified rows — one row per publication, with any assessments attached
    rows = []
    for fp, pub in publications.items():
        pub_assessments = assessments.get(fp, [])

        # Derive severity from highest assessment
        sev_order = {"critical": 3, "warning": 2, "info": 1}
        severity = "info"
        if pub_assessments:
            severity = max(pub_assessments, key=lambda a: sev_order.get(a["severity"], 0))["severity"]

        # Group assessments by framework
        by_framework = defaultdict(list)
        for a in pub_assessments:
            by_framework[a["framework"]].append(a)

        rows.append({
            **pub,
            "severity": severity,
            "flagged": bool(pub_assessments),
            "assessments": pub_assessments,
            "by_framework": dict(by_framework),
            "all_controls": sorted({c for a in pub_assessments for c in a["affected_controls"]}),
            "recommended_action": pub_assessments[0]["recommended_action"] if pub_assessments else "",
        })

    # Sort newest first
    rows.sort(key=lambda r: r["timestamp"], reverse=True)

    # Stats
    jurisdictions = ["BOE", "FCA", "MAS", "SEC"]
    jurisdiction_counts = defaultdict(int)
    for r in rows:
        jurisdiction_counts[r["jurisdiction"]] += 1

    flagged = [r for r in rows if r["flagged"]]
    critical = [r for r in rows if r["severity"] == "critical"]

    return {
        "rows": rows,
        "total": len(rows),
        "flagged": len(flagged),
        "no_implications": len(rows) - len(flagged),
        "critical_count": len(critical),
        "jurisdictions": jurisdictions,
        "jurisdiction_counts": dict(jurisdiction_counts),
        "last_updated": last_updated.strftime("%d %b %Y %H:%M UTC") if last_updated else "—",
    }


@app.route("/")
def dashboard():
    data = load_data()
    return render_template("dashboard.html", **data)


if __name__ == "__main__":
    import os
    port = int(os.environ.get("GRCX_DASHBOARD_PORT", "5001"))
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug, port=port)
