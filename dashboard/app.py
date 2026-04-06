# Copyright (c) 2026 Neil Lowden | GRCX | MIT License
import json
import os
from collections import defaultdict
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

import jwt
import requests
from flask import Flask, redirect, render_template, request

app = Flask(__name__)

LOG_PATH = Path(__file__).parent.parent / "grcx-audit" / "grcx.log.jsonl"

# Clerk config
CLERK_SECRET_KEY = os.environ.get("CLERK_SECRET_KEY", "")
CLERK_PUBLISHABLE_KEY = os.environ.get("CLERK_PUBLISHABLE_KEY", "")
CLERK_FRONTEND_API = os.environ.get("CLERK_FRONTEND_API", "")

# Cache JWKS
_jwks_cache = None


def _get_jwks():
    global _jwks_cache
    if _jwks_cache is None:
        resp = requests.get(f"{CLERK_FRONTEND_API}/.well-known/jwks.json")
        resp.raise_for_status()
        _jwks_cache = resp.json()
    return _jwks_cache


def _verify_session(token):
    """Verify a Clerk session JWT. Returns claims dict or None."""
    try:
        jwks = _get_jwks()
        # Get the signing key
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        key = None
        for k in jwks.get("keys", []):
            if k.get("kid") == kid:
                key = jwt.algorithms.RSAAlgorithm.from_jwk(k)
                break
        if not key:
            return None
        claims = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            options={"verify_aud": False},
        )
        return claims
    except Exception:
        return None


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get("__session")
        if not token:
            # Redirect to Clerk hosted sign-in
            sign_in_url = "/sign-in"
            return redirect(sign_in_url)
        claims = _verify_session(token)
        if not claims:
            sign_in_url = "/sign-in"
            return redirect(sign_in_url)
        # Store user info for templates
        request.clerk_user = claims
        return f(*args, **kwargs)
    return decorated


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
    jurisdictions = ["BOE", "FCA", "MAS", "SEC", "ESMA"]
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

@app.route("/sign-in")
def sign_in():
    return render_template("sign-in.html", clerk_publishable_key=CLERK_PUBLISHABLE_KEY)

@app.route("/")
@require_auth
def dashboard():
    data = load_data()
    data["clerk_publishable_key"] = CLERK_PUBLISHABLE_KEY
    data["clerk_frontend_api"] = CLERK_FRONTEND_API
    return render_template("dashboard.html", **data)


if __name__ == "__main__":
    port = int(os.environ.get("GRCX_DASHBOARD_PORT", "5001"))
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug, port=port)