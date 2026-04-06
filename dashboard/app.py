# Copyright (c) 2026 Neil Lowden | GRCX | MIT License
import json
import os
import sqlite3
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, redirect, render_template, request, url_for
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "grcx-change-me-in-production")

LOG_PATH = Path(__file__).parent.parent / "grcx-audit" / "grcx.log.jsonl"
DB_PATH = Path(os.environ.get("GRCX_DB_PATH", Path(__file__).parent.parent / "grcx-audit" / "users.db"))

BLOCKED_DOMAINS = {
    "gmail.com", "googlemail.com", "hotmail.com", "outlook.com",
    "yahoo.com", "yahoo.co.uk", "aol.com", "icloud.com", "me.com",
    "mail.com", "protonmail.com", "proton.me", "live.com", "msn.com",
}

# ── Database ────────────────────────────────────────────────

def get_db():
    db = sqlite3.connect(str(DB_PATH))
    db.row_factory = sqlite3.Row
    return db


def init_db():
    db = get_db()
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            company TEXT NOT NULL DEFAULT '',
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """)
    db.commit()
    db.close()


init_db()

# ── Flask-Login ─────────────────────────────────────────────

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "sign_in"
login_manager.login_message = ""


class User(UserMixin):
    def __init__(self, id, email, name, company):
        self.id = id
        self.email = email
        self.name = name
        self.company = company


@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    db.close()
    if row:
        return User(row["id"], row["email"], row["name"], row["company"])
    return None


# ── Auth routes ─────────────────────────────────────────────

@app.route("/sign-up", methods=["GET", "POST"])
def sign_up():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    error = None
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        name = request.form.get("name", "").strip()
        company = request.form.get("company", "").strip()
        password = request.form.get("password", "")

        if not email or not name or not password:
            error = "All fields are required."
        elif len(password) < 8:
            error = "Password must be at least 8 characters."
        elif not company:
            error = "Company name is required."
        else:
            domain = email.split("@")[-1] if "@" in email else ""
            if domain in BLOCKED_DOMAINS:
                error = "Please use your work email address."
            else:
                db = get_db()
                existing = db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
                if existing:
                    error = "An account with this email already exists."
                else:
                    db.execute(
                        "INSERT INTO users (email, name, company, password_hash) VALUES (?, ?, ?, ?)",
                        (email, name, company, generate_password_hash(password)),
                    )
                    db.commit()
                    row = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
                    user = User(row["id"], row["email"], row["name"], row["company"])
                    login_user(user)
                    db.close()
                    return redirect(url_for("dashboard"))
                db.close()

    return render_template("sign-up.html", error=error)


@app.route("/sign-in", methods=["GET", "POST"])
def sign_in():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    error = None
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        db = get_db()
        row = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        db.close()

        if row and check_password_hash(row["password_hash"], password):
            user = User(row["id"], row["email"], row["name"], row["company"])
            login_user(user, remember=True)
            next_page = request.args.get("next")
            return redirect(next_page or url_for("dashboard"))
        else:
            error = "Invalid email or password."

    return render_template("sign-in.html", error=error)


@app.route("/sign-out")
@login_required
def sign_out():
    logout_user()
    return redirect(url_for("sign_in"))


# ── Data loading ────────────────────────────────────────────

def _parse_ts(ts: str) -> datetime:
    try:
        return datetime.fromisoformat(ts)
    except Exception:
        return datetime.min.replace(tzinfo=timezone.utc)


def load_data():
    if not LOG_PATH.exists():
        return {}

    publications = {}
    assessments = defaultdict(list)
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

    rows = []
    for fp, pub in publications.items():
        pub_assessments = assessments.get(fp, [])
        sev_order = {"critical": 3, "warning": 2, "info": 1}
        severity = "info"
        if pub_assessments:
            severity = max(pub_assessments, key=lambda a: sev_order.get(a["severity"], 0))["severity"]

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

    rows.sort(key=lambda r: r["timestamp"], reverse=True)

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


# ── Dashboard ───────────────────────────────────────────────

@app.route("/")
@login_required
def dashboard():
    data = load_data()
    return render_template("dashboard.html", **data)


if __name__ == "__main__":
    port = int(os.environ.get("GRCX_DASHBOARD_PORT", "5001"))
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug, port=port)
