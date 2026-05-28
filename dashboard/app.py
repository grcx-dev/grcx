# Copyright (c) 2026 Neil Lowden | GRCX | MIT License
import json
import os
import sqlite3
import smtplib
from email.mime.text import MIMEText
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, redirect, render_template, request, send_from_directory, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
_secret_key = os.environ.get("FLASK_SECRET_KEY")
if not _secret_key:
    raise RuntimeError("FLASK_SECRET_KEY environment variable is not set")
app.secret_key = _secret_key
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
csrf = CSRFProtect(app)
limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri="memory://",
    default_limits=[],
)

LOG_PATH = Path(__file__).parent.parent / "grcx-audit" / "grcx.log.jsonl"
DB_PATH = Path(os.environ.get("GRCX_DB_PATH", Path(__file__).parent.parent / "grcx-audit" / "users.db"))

# BLOCKED_DOMAINS = {
#     "gmail.com", "googlemail.com", "hotmail.com", "outlook.com",
#     "yahoo.com", "yahoo.co.uk", "aol.com", "icloud.com", "me.com",
#     "mail.com", "protonmail.com", "proton.me", "live.com", "msn.com",
# }

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

def notify_signup(name, email, company):
    """Send signup notification to founder."""
    try:
        msg = MIMEText(
            f"New GRCX signup:\n\n"
            f"Name: {name}\n"
            f"Email: {email}\n"
            f"Company: {company}\n"
        )
        msg["Subject"] = f"New GRCX signup: {name} ({company})"
        msg["From"] = os.environ.get("GRCX_SMTP_USER", "notifications@grcx.dev")
        msg["To"] = os.environ.get("GRCX_NOTIFY_TO", "neil.lowden@gmail.com")

        with smtplib.SMTP(os.environ.get("GRCX_SMTP_HOST", "mail.grcx.dev"), 587) as s:
            s.starttls()
            s.login(
                os.environ.get("GRCX_SMTP_USER", "notifications@grcx.dev"),
                os.environ.get("GRCX_SMTP_PASS", ""),
            )
            s.send_message(msg)
    except Exception as e:
        app.logger.error(f"Signup notification failed: {e}")

# ── Auth routes ─────────────────────────────────────────────

@app.route("/sign-up", methods=["GET", "POST"])
@limiter.limit("3 per minute", methods=["POST"])
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
            db = get_db()
            existing = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
            if existing:
                # Don't reveal that the account exists — silently sign in if password
                # matches, otherwise show the same generic message either way.
                if check_password_hash(existing["password_hash"], password):
                    user = User(existing["id"], existing["email"], existing["name"], existing["company"])
                    login_user(user)
                    db.close()
                    return redirect(url_for("dashboard"))
                error = "Could not create account. Check your details and try again."
            else:
                db.execute(
                    "INSERT INTO users (email, name, company, password_hash) VALUES (?, ?, ?, ?)",
                    (email, name, company, generate_password_hash(password)),
                )
                db.commit()
                row = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
                user = User(row["id"], row["email"], row["name"], row["company"])
                login_user(user)
                notify_signup(name, email, company)
                db.close()
                return redirect(url_for("dashboard"))
            db.close()
    return render_template("sign-up.html", error=error)


@app.route("/sign-in", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
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

    # Keyed by source URL — the stable canonical identifier for a publication.
    # Historical log entries may carry different fingerprints for the same URL
    # (due to hash-function changes or feed re-emissions); keying on URL
    # collapses them into one row so every displayed stat reflects the honest
    # count of distinct publications, not distinct fingerprints.
    publications = {}
    # fp → url: lets resolver.assessment events (which store fingerprint, not
    # URL) be attributed to the correct URL-keyed row.
    fp_to_url: dict[str, str] = {}
    # url → {framework → latest assessment}. Last-write-wins per (url, fw).
    assessments: dict[str, dict[str, dict]] = defaultdict(dict)
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
                url = entry.get("source", "")
                fp  = entry["detail"].get("fingerprint", entry.get("id", ""))
                key = url or fp  # fp fallback for entries without a source URL
                if fp and url:
                    fp_to_url[fp] = url

                new_entry = {
                    "fingerprint": fp,
                    "timestamp": entry.get("timestamp", ""),
                    "jurisdiction": entry.get("jurisdiction", ""),
                    "title": entry.get("summary", ""),
                    "source": url,
                    "published": entry["detail"].get("published", ""),
                    "summary": entry["detail"].get("summary", ""),
                }
                if key not in publications:
                    publications[key] = new_entry
                else:
                    # Same URL seen again (historical dup fingerprint or re-emit).
                    # Keep earliest ingestion timestamp (true first-seen);
                    # take all other fields from the latest entry so corrected
                    # titles and the newest fingerprint are used.
                    earliest = min(publications[key]["timestamp"], new_entry["timestamp"])
                    publications[key] = {**new_entry, "timestamp": earliest}

            elif event == "resolver.assessment":
                fp  = entry["detail"].get("fingerprint", "")
                url = fp_to_url.get(fp, "")
                key = url or fp  # mirror publications key logic
                fw  = entry["detail"].get("framework", "iso27001")
                assessments[key][fw] = {
                    "framework": fw,
                    "severity": entry.get("severity", "info"),
                    "summary": entry.get("summary", ""),
                    "affected_controls": entry["detail"].get("affected_controls", []),
                    "recommended_action": entry["detail"].get("recommended_action", ""),
                    "rationale": entry["detail"].get("rationale", ""),
                    "source": entry.get("source", ""),
                    "jurisdiction": entry.get("jurisdiction", ""),
                    "timestamp": entry.get("timestamp", ""),
                    "publication_title": entry["detail"].get("publication_title", ""),
                    "resolver_version": entry["detail"].get("resolver_version"),
                    "model_version": entry["detail"].get("model_version"),
                }

    rows = []
    for key, pub in publications.items():
        # One entry per framework — latest assessment for each (url, framework) pair.
        pub_assessments = list(assessments.get(key, {}).values())
        sev_order = {"critical": 3, "warning": 2, "info": 1}
        severity = "info"
        if pub_assessments:
            severity = max(pub_assessments, key=lambda a: sev_order.get(a["severity"], 0))["severity"]

        # Wrap each assessment in a list so the template's `for a in fw_assessments` loop works.
        by_framework = {a["framework"]: [a] for a in pub_assessments}

        rows.append({
            **pub,
            "severity": severity,
            "flagged": bool(pub_assessments),
            "assessments": pub_assessments,
            "by_framework": by_framework,
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


# ── Static helpers ──────────────────────────────────────────

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(app.static_folder, 'favicon.ico',
                               mimetype='image/vnd.microsoft.icon')


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
