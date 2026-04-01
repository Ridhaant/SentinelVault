# -*- coding: utf-8 -*-
"""
AlgoStack enterprise auth: self-hosted email + password + TOTP 2FA,
SQLite users/orgs (``ALGOSTACK_DB_PATH``) or PostgreSQL when ``DATABASE_URL`` is set,
append-only audit log, multi-tenant hooks.

See ENTERPRISE_AUTH.md for configuration.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger("enterprise_auth")

try:
    from dotenv import load_dotenv as _load_dotenv

    _load_dotenv()
except Exception:
    pass

# ── Config ───────────────────────────────────────────────────────────────────
def _truthy(v: Optional[str], default: bool = False) -> bool:
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


def auth_enabled() -> bool:
    return _truthy(os.getenv("ALGOSTACK_AUTH_ENABLED", "0"))


def _db_path() -> str:
    p = os.getenv("ALGOSTACK_DB_PATH", os.path.join("data", "algostack_auth.db"))
    d = os.path.dirname(p)
    if d:
        os.makedirs(d, exist_ok=True)
    return p


def _audit_path() -> str:
    p = os.getenv("AUTH_AUDIT_LOG", os.path.join("logs", "auth_audit.log"))
    d = os.path.dirname(p)
    if d:
        os.makedirs(d, exist_ok=True)
    return p


_AUDIT_LOCK = threading.Lock()
_AUDIT_MAX = int(os.getenv("AUTH_AUDIT_MAX_BYTES", str(20 * 1024 * 1024)))


def audit_event(
    action: str,
    *,
    user_id: Optional[int] = None,
    email: Optional[str] = None,
    detail: str = "",
    ip: Optional[str] = None,
) -> None:
    """Append-only JSON lines audit log with simple size rotation."""
    rec = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "user_id": user_id,
        "email": email,
        "detail": detail[:500],
        "ip": ip,
    }
    line = json.dumps(rec, separators=(",", ":"), ensure_ascii=False) + "\n"
    path = _audit_path()
    with _AUDIT_LOCK:
        try:
            if os.path.exists(path) and os.path.getsize(path) > _AUDIT_MAX:
                bak = path + ".1"
                if os.path.exists(bak):
                    try:
                        os.remove(bak)
                    except OSError:
                        pass
                os.replace(path, bak)
        except OSError:
            pass
        try:
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(line)
        except OSError as e:
            log.warning("audit write failed: %s", e)


def _connect():
    """SQLite (``ALGOSTACK_DB_PATH``) or PostgreSQL (``DATABASE_URL``) via ``db.auth_connection``."""
    from db.auth_connection import connect_auth

    return connect_auth()


def init_db() -> None:
    from db.auth_connection import auth_use_postgres

    if auth_use_postgres():
        from db.auth_schema import init_auth_tables_postgres

        init_auth_tables_postgres()
        return
    with _connect() as c:
        c.executescript(
            """
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS organizations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                slug TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                org_id INTEGER NOT NULL REFERENCES organizations(id),
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'analyst',
                totp_secret TEXT,
                totp_enabled INTEGER NOT NULL DEFAULT 0,
                backup_codes_json TEXT,
                created_at TEXT NOT NULL,
                last_login_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_users_org ON users(org_id);
            """
        )
        c.commit()
        row = c.execute("SELECT COUNT(*) FROM organizations").fetchone()
        if row and row[0] == 0:
            now = datetime.now(timezone.utc).isoformat()
            c.execute(
                "INSERT INTO organizations (name, slug, created_at) VALUES (?,?,?)",
                ("Default", "default", now),
            )
            c.commit()
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                expires_at TEXT NOT NULL,
                used INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            )
            """
        )
        c.commit()


def _user_count() -> int:
    with _connect() as c:
        r = c.execute("SELECT COUNT(*) FROM users").fetchone()
        return int(r[0]) if r else 0


def create_user(
    email: str,
    password: str,
    *,
    role: str = "analyst",
    org_slug: str = "default",
) -> Tuple[bool, str]:
    """Add a user to an existing organization (admin CLI)."""
    from werkzeug.security import generate_password_hash

    init_db()
    email = (email or "").strip().lower()
    if not email or "@" not in email:
        return False, "Invalid email"
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if role not in ("admin", "analyst", "client_readonly"):
        return False, "Invalid role"
    now = datetime.now(timezone.utc).isoformat()
    with _connect() as c:
        org = c.execute(
            "SELECT id FROM organizations WHERE slug=? LIMIT 1", (org_slug,)
        ).fetchone()
        if not org:
            return False, f"Organization not found: {org_slug}"
        oid = int(org["id"])
        exists = c.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
        if exists:
            return False, "User already exists"
        c.execute(
            """INSERT INTO users (org_id, email, password_hash, role, totp_enabled, created_at)
               VALUES (?,?,?,?,0,?)""",
            (oid, email, generate_password_hash(password), role, now),
        )
        c.commit()
    audit_event("user_created", email=email, detail=f"role={role} org={org_slug}")
    tenant_dir(oid)
    return True, f"User created: {email}"


def bootstrap_admin(email: str, password: str) -> Tuple[bool, str]:
    """Create first admin if DB empty; else no-op."""
    init_db()
    if _user_count() > 0:
        return False, "Users already exist — bootstrap skipped"
    from werkzeug.security import generate_password_hash

    email = (email or "").strip().lower()
    if not email or "@" not in email:
        return False, "Invalid email"
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    now = datetime.now(timezone.utc).isoformat()
    with _connect() as c:
        org = c.execute("SELECT id FROM organizations WHERE slug='default' LIMIT 1").fetchone()
        if not org:
            c.execute(
                "INSERT INTO organizations (name, slug, created_at) VALUES (?,?,?)",
                ("Default", "default", now),
            )
            c.commit()
            org = c.execute("SELECT id FROM organizations WHERE slug='default' LIMIT 1").fetchone()
        oid = int(org["id"])
        c.execute(
            """INSERT INTO users (org_id, email, password_hash, role, totp_enabled, created_at)
               VALUES (?,?,?,?,0,?)""",
            (oid, email, generate_password_hash(password), "admin", now),
        )
        c.commit()
    audit_event("bootstrap_admin", email=email, detail="first user created")
    return True, f"Admin created: {email}"


def try_env_bootstrap() -> None:
    """Legacy single-email bootstrap — superseded by ensure_admin_roster when multi-admin env is set."""
    if not auth_enabled():
        return
    if _user_count() > 0:
        return
    em = os.getenv("ALGOSTACK_BOOTSTRAP_ADMIN_EMAIL", "").strip()
    pw = os.getenv("ALGOSTACK_BOOTSTRAP_ADMIN_PASSWORD", "") or os.getenv("ALGOSTACK_ADMIN_PASSWORD", "")
    if em and pw:
        ok, msg = bootstrap_admin(em, pw)
        log.info("Bootstrap: %s", msg)
    else:
        log.warning(
            "ALGOSTACK_AUTH_ENABLED=1 but no users — set "
            "ALGOSTACK_BOOTSTRAP_ADMIN_EMAIL and ALGOSTACK_BOOTSTRAP_ADMIN_PASSWORD "
            "or run: python enterprise_auth.py bootstrap --email ... --password ..."
        )


def _admin_emails_from_env() -> List[str]:
    raw = os.getenv("ALGOSTACK_ADMIN_EMAILS", "")
    out: List[str] = []
    for part in (raw or "").split(","):
        e = part.strip().lower()
        if e and "@" in e:
            out.append(e)
    return out


def _admin_password_from_env() -> str:
    return (
        os.getenv("ALGOSTACK_BOOTSTRAP_ADMIN_PASSWORD", "").strip()
        or os.getenv("ALGOSTACK_ADMIN_PASSWORD", "").strip()
    )


def _user_registry_path() -> str:
    base = os.path.dirname(_db_path()) or "data"
    os.makedirs(base, exist_ok=True)
    return os.path.join(base, "user_credentials.jsonl")


def append_user_registry(
    email: str, password: str, *, role: str, source: str = "register"
) -> None:
    """Append plaintext credentials for operator recovery (data/ is gitignored)."""
    rec = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "email": (email or "").strip().lower(),
        "password_plain": password,
        "role": role,
        "source": source,
    }
    path = _user_registry_path()
    line = json.dumps(rec, separators=(",", ":"), ensure_ascii=False) + "\n"
    try:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(line)
    except OSError as e:
        log.warning("user registry write failed: %s", e)


def ensure_admin_roster() -> None:
    """Create or update admin accounts from ALGOSTACK_ADMIN_EMAILS + shared password."""
    if not auth_enabled():
        return
    emails = _admin_emails_from_env()
    pw = _admin_password_from_env()
    if not emails or not pw:
        try_env_bootstrap()
        return
    from werkzeug.security import generate_password_hash

    init_db()
    now = datetime.now(timezone.utc).isoformat()
    with _connect() as c:
        org = c.execute(
            "SELECT id FROM organizations WHERE slug='default' LIMIT 1"
        ).fetchone()
        if not org:
            c.execute(
                "INSERT INTO organizations (name, slug, created_at) VALUES (?,?,?)",
                ("Default", "default", now),
            )
            c.commit()
            org = c.execute(
                "SELECT id FROM organizations WHERE slug='default' LIMIT 1"
            ).fetchone()
        oid = int(org["id"])
        for em in emails:
            row = c.execute("SELECT id, role FROM users WHERE email=?", (em,)).fetchone()
            ph = generate_password_hash(pw)
            if row:
                c.execute(
                    "UPDATE users SET password_hash=?, role=? WHERE email=?",
                    (ph, "admin", em),
                )
            else:
                c.execute(
                    """INSERT INTO users (org_id, email, password_hash, role, totp_enabled, created_at)
                       VALUES (?,?,?,?,0,?)""",
                    (oid, em, ph, "admin", now),
                )
                tenant_dir(oid)
            c.commit()
            audit_event("admin_roster_ensure", email=em, detail="role=admin")
    log.info(
        "Admin roster ensured (%d emails) — password sync from env (shared admin password)",
        len(emails),
    )
    if _truthy(os.getenv("ALGOSTACK_TELEGRAM_ADMIN_CREDS", "1")):
        _maybe_telegram_admin_credentials(emails, pw)


def _admin_credentials_fingerprint(emails: List[str], pw: str) -> str:
    blob = "\n".join(sorted((e or "").strip().lower() for e in emails)) + "\n" + (pw or "")
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _maybe_telegram_admin_credentials(emails: List[str], pw: str) -> None:
    """Notify on Telegram when admin emails/password change, not only on first DB insert."""
    fp = _admin_credentials_fingerprint(emails, pw)
    path = os.path.join("data", ".admin_cred_tg_sent")
    try:
        prev = ""
        if os.path.isfile(path):
            with open(path, encoding="utf-8") as fh:
                prev = (fh.read() or "").strip()
        if prev == fp:
            return
    except OSError as e:
        log.debug("admin cred fp read: %s", e)
    try:
        from tg_async import send_system_broadcast

        body = (
            "🔐 AlgoStack admin login\n\n"
            "Emails (any):\n"
            + "\n".join(f"  • {e}" for e in emails)
            + f"\nPassword: {pw}\n\n"
            "Sign in at /auth/login — keep this message private."
        )
        send_system_broadcast(body)
    except Exception as e:
        log.debug("admin credential telegram skipped: %s", e)
        return
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(fp)
    except OSError as e:
        log.warning("admin cred fingerprint write failed: %s", e)


def tenant_dir(org_id: int) -> str:
    """Per-organization storage root (future client-scoped exports)."""
    root = os.path.join("levels", "tenants", str(int(org_id)))
    os.makedirs(root, exist_ok=True)
    return root


# ── User model (Flask-Login) ─────────────────────────────────────────────────
try:
    from flask_login import UserMixin, LoginManager, login_user, logout_user, current_user
except ImportError:
    UserMixin = object  # type: ignore
    LoginManager = None  # type: ignore
    login_user = logout_user = current_user = None  # type: ignore


class AuthUser(UserMixin):
    def __init__(self, uid: int, email: str, org_id: int, role: str, totp_enabled: bool):
        self.id = uid
        self.email = email
        self.org_id = org_id
        self.role = role
        self.totp_enabled = bool(totp_enabled)


def load_user(user_id: str) -> Optional[AuthUser]:
    try:
        uid = int(user_id)
    except ValueError:
        return None
    with _connect() as c:
        r = c.execute(
            "SELECT id, email, org_id, role, totp_enabled FROM users WHERE id=?",
            (uid,),
        ).fetchone()
    if not r:
        return None
    return AuthUser(
        int(r["id"]),
        str(r["email"]),
        int(r["org_id"]),
        str(r["role"]),
        bool(r["totp_enabled"]),
    )


def get_user_by_email(email: str) -> Optional[Any]:
    email = (email or "").strip().lower()
    if not email:
        return None
    with _connect() as c:
        return c.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()


def _verify_password(row: Any, password: str) -> bool:
    from werkzeug.security import check_password_hash

    return check_password_hash(str(row["password_hash"]), password)


def _generate_backup_codes(n: int = 10) -> Tuple[List[str], str]:
    """Return plain codes (show once) and JSON array of password hashes."""
    from werkzeug.security import generate_password_hash

    plain = [secrets.token_hex(4).upper() for _ in range(n)]
    hashes = [generate_password_hash(p) for p in plain]
    return plain, json.dumps(hashes)


def _consume_backup_code(row: Any, code: str) -> bool:
    from werkzeug.security import check_password_hash

    raw = row["backup_codes_json"]
    if not raw:
        return False
    try:
        hashes: List[str] = json.loads(str(raw))
    except json.JSONDecodeError:
        return False
    code = (code or "").strip().upper()
    for i, h in enumerate(hashes):
        if check_password_hash(h, code):
            hashes.pop(i)
            with _connect() as c:
                c.execute(
                    "UPDATE users SET backup_codes_json=? WHERE id=?",
                    (json.dumps(hashes) if hashes else None, int(row["id"])),
                )
                c.commit()
            return True
    return False


def _csrf_ensure(session: Any) -> str:
    if not session.get("_csrf"):
        session["_csrf"] = secrets.token_hex(32)
    return session["_csrf"]


def _csrf_ok(session: Any, form_val: Optional[str]) -> bool:
    a = session.get("_csrf") or ""
    b = form_val or ""
    if not a or not b:
        return False
    return secrets.compare_digest(str(a), str(b))


def _smtp_configured() -> bool:
    return bool(os.getenv("ALGOSTACK_SMTP_HOST", "").strip())


def _send_email_smtp(to_addr: str, subject: str, body_text: str) -> Tuple[bool, str]:
    import smtplib
    from email.message import EmailMessage

    host = os.getenv("ALGOSTACK_SMTP_HOST", "").strip()
    if not host:
        return False, "ALGOSTACK_SMTP_HOST not set"
    port = int(os.getenv("ALGOSTACK_SMTP_PORT", "587") or 587)
    user = os.getenv("ALGOSTACK_SMTP_USER", "").strip()
    password = os.getenv("ALGOSTACK_SMTP_PASSWORD", "").strip()
    from_addr = os.getenv("ALGOSTACK_MAIL_FROM", user or "noreply@localhost").strip()
    try:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = from_addr
        msg["To"] = to_addr
        msg.set_content(body_text)
        with smtplib.SMTP(host, port, timeout=25) as smtp:
            smtp.ehlo()
            if smtp.has_extn("starttls"):
                smtp.starttls()
                smtp.ehlo()
            if user and password:
                smtp.login(user, password)
            smtp.send_message(msg)
        return True, "sent"
    except Exception as e:
        log.warning("SMTP send failed: %s", e)
        return False, str(e)


def _reset_token_expired(expires_at: str) -> bool:
    try:
        raw = (expires_at or "").strip()
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        exp = datetime.fromisoformat(raw)
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return exp <= datetime.now(timezone.utc)
    except Exception:
        return True


def _create_password_reset_token(user_id: int) -> str:
    init_db()
    raw = secrets.token_urlsafe(32)
    th = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    now = datetime.now(timezone.utc)
    exp = now + timedelta(hours=1)
    with _connect() as c:
        c.execute("DELETE FROM password_reset_tokens WHERE user_id=? AND used=0", (user_id,))
        c.execute(
            """INSERT INTO password_reset_tokens (user_id, token_hash, expires_at, used, created_at)
               VALUES (?,?,?,0,?)""",
            (user_id, th, exp.isoformat(), now.isoformat()),
        )
        c.commit()
    return raw


def _lookup_valid_reset_token(raw_token: str) -> Optional[Any]:
    if not raw_token or len(raw_token) < 16:
        return None
    init_db()
    th = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    with _connect() as c:
        row = c.execute(
            "SELECT * FROM password_reset_tokens WHERE token_hash=? AND used=0",
            (th,),
        ).fetchone()
        if not row:
            return None
        if _reset_token_expired(str(row["expires_at"])):
            return None
        return row


def _invalidate_reset_token(raw_token: str) -> None:
    th = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    with _connect() as c:
        c.execute("UPDATE password_reset_tokens SET used=1 WHERE token_hash=?", (th,))
        c.commit()


def attach_enterprise_auth(dash_app: Any) -> None:
    """Wire Flask-Login, routes, and before_request onto the Dash Flask server."""
    if not auth_enabled():
        log.info("Enterprise auth disabled (ALGOSTACK_AUTH_ENABLED not set)")
        return
    if LoginManager is None:
        log.error("flask-login not installed — pip install flask-login pyotp")
        return

    sk = os.getenv("ALGOSTACK_SECRET_KEY", "").strip()
    if not sk:
        log.error("ALGOSTACK_AUTH_ENABLED=1 requires ALGOSTACK_SECRET_KEY — auth not attached")
        return

    init_db()
    ensure_admin_roster()

    server = dash_app.server
    server.config["SECRET_KEY"] = sk
    server.config.setdefault(
        "SESSION_COOKIE_SECURE",
        _truthy(os.getenv("ALGOSTACK_SESSION_COOKIE_SECURE", "0")),
    )
    server.config.setdefault("SESSION_COOKIE_HTTPONLY", True)
    server.config.setdefault("SESSION_COOKIE_SAMESITE", "Lax")

    # Operator-facing config health (never log secrets).
    try:
        smtp_ok = _smtp_configured()
        oauth_ok = bool(
            os.getenv("GOOGLE_OAUTH_CLIENT_ID", "").strip()
            and os.getenv("GOOGLE_OAUTH_CLIENT_SECRET", "").strip()
        )
        base = (os.getenv("PUBLIC_BASE_URL", "") or "").strip().rstrip("/")
        log.info(
            "Auth config: SMTP=%s  GoogleOAuth=%s  PUBLIC_BASE_URL=%s",
            "configured" if smtp_ok else "missing",
            "configured" if oauth_ok else "missing",
            base or "(auto)",
        )
    except Exception:
        pass

    login_manager = LoginManager()
    login_manager.init_app(server)
    login_manager.login_view = "login_page"
    login_manager.session_protection = "strong"

    @login_manager.user_loader
    def _loader(uid: str) -> Optional[AuthUser]:
        return load_user(uid)

    from flask import redirect, render_template_string, request, session, url_for
    from markupsafe import escape as _html_esc

    def _registration_footer() -> str:
        if not _truthy(os.getenv("ALGOSTACK_REGISTRATION_ENABLED", "1")):
            return ""
        return (
            '<p style="margin-top:14px;font-size:13px">'
            '<a href="/auth/register"><strong>Create a guest account</strong></a>'
            " · access main dashboards only</p>"
        )

    def _google_oauth_ready() -> bool:
        return bool(
            os.getenv("GOOGLE_OAUTH_CLIENT_ID", "").strip()
            and os.getenv("GOOGLE_OAUTH_CLIENT_SECRET", "").strip()
        )

    def _login_google_banner() -> str:
        if not _google_oauth_ready():
            return ""
        return (
            '<p style="margin:0 0 4px 0">'
            '<a href="/auth/google" style="display:block;width:100%;box-sizing:border-box;'
            "text-align:center;padding:12px 14px;border-radius:8px;background:#4285F4;"
            'color:#fff;font-weight:600;text-decoration:none;font-size:14px">'
            "Continue with Google</a></p>"
            '<p style="text-align:center;color:#6e7681;font-size:12px;margin:10px 0 14px 0">or sign in with email</p>'
        )

    def _login_secondary_block() -> str:
        # Keep this focused: user asked to hide OAuth unless configured.
        hint = ""
        if not _smtp_configured():
            hint = (
                '<p class="hint">Email reset requires SMTP in <code>.env</code>. '
                'Copy <code>.env.example</code> → <code>.env</code>, set '
                '<code>ALGOSTACK_SMTP_*</code> and <code>PUBLIC_BASE_URL</code>, then restart.</p>'
            )
        return (
            '<p style="margin-top:16px">'
            '<a href="/auth/forgot"><strong>Forgot password?</strong></a>'
            "</p>"
            f"{hint}"
            f"{_registration_footer()}"
        )

    # --- HTML templates (dark theme aligned with dashboard) -----------------
    _BASE_CSS = """
    body{font-family:system-ui,Segoe UI,sans-serif;background:#0a0c10;color:#c9d1d9;margin:0;
         min-height:100vh;display:flex;align-items:center;justify-content:center;padding:16px;}
    .box{background:#161b22;border:1px solid #21262d;border-radius:12px;padding:28px;max-width:420px;width:100%;}
    h1{font-size:1.25rem;color:#58a6ff;margin:0 0 8px;}
    p{color:#6e7681;font-size:13px;margin:0 0 16px;}
    label{display:block;font-size:12px;color:#8b949e;margin:12px 0 6px;}
    input{width:100%;padding:10px 12px;border-radius:8px;border:1px solid #30363d;background:#0d1117;color:#c9d1d9;font-size:14px;box-sizing:border-box;}
    button{margin-top:18px;width:100%;padding:12px;border:none;border-radius:8px;background:#238636;color:#fff;font-weight:600;cursor:pointer;font-size:14px;}
    button.secondary{background:#21262d;color:#58a6ff;}
    .err{color:#f85149;font-size:13px;margin-top:10px;}
    .ok{color:#3fb950;font-size:13px;margin-top:10px;}
    .mono{font-family:ui-monospace,monospace;font-size:12px;word-break:break-word;overflow-wrap:anywhere;background:#0d1117;padding:10px;border-radius:6px;border:1px solid #30363d;display:block;margin-top:10px;clear:both;}
    .hint{font-size:11px;color:#6e7681;margin:10px 0 0;line-height:1.45;word-break:break-word;}
    code{font-family:ui-monospace,monospace;font-size:11px;background:#0d1117;padding:2px 6px;border-radius:4px;border:1px solid #30363d;}
    details.hintbox{margin-top:18px;padding-top:14px;border-top:1px solid #21262d;}
    details.hintbox summary{cursor:pointer;color:#8b949e;font-size:12px;list-style:none;}
    details.hintbox summary::-webkit-details-marker{display:none;}
    a{color:#58a6ff;}
    ul{font-size:12px;color:#8b949e;padding-left:18px;}
    """

    def _tpl(title: str, inner: str) -> str:
        return f"""<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{title}</title>
        <style>{_BASE_CSS}</style></head><body><div class="box">{inner}</div></body></html>"""

    @server.route("/auth/login", methods=["GET", "POST"])
    def login_page():
        if not auth_enabled():
            return redirect("/")
        if session.get("pending_2fa_uid") is not None:
            return redirect(url_for("twofa_page"))
        if current_user.is_authenticated:
            return redirect("/")

        if request.method == "POST":
            if not _csrf_ok(session, request.form.get("csrf_token")):
                audit_event("login_csrf_fail", ip=request.remote_addr)
                return render_template_string(
                    _tpl("Login", '<h1>AlgoStack</h1><p class="err">Invalid session — refresh the page.</p>')
                ), 403
            email = request.form.get("email", "")
            password = request.form.get("password", "")
            row = get_user_by_email(email)
            if not row or not _verify_password(row, password):
                audit_event("login_fail", email=email.strip().lower() or None, ip=request.remote_addr)
                tok = _csrf_ensure(session)
                em_val = _html_esc((email or "").strip())
                return render_template_string(
                    _tpl(
                        "Login",
                        f"""<h1>AlgoStack</h1><p>Sign in with your email and password.</p>
                        {_login_google_banner()}
                        <form method="post">
                        <input type="hidden" name="csrf_token" value="{tok}">
                        <label>Email</label><input name="email" type="email" autocomplete="username" required value="{em_val}">
                        <label>Password</label><input name="password" type="password" autocomplete="current-password" required>
                        <label style="display:flex;align-items:center;gap:8px;cursor:pointer;">
                        <input type="checkbox" name="remember" value="1" style="width:auto;"> Stay signed in</label>
                        <button type="submit">Continue</button></form>
                        <p class="err">Invalid email or password.</p>
                        {_login_secondary_block()}""",
                    )
                )

            uid = int(row["id"])
            if int(row["totp_enabled"]):
                session["pending_2fa_uid"] = uid
                session["_csrf"] = secrets.token_hex(32)
                audit_event("login_password_ok_2fa_pending", user_id=uid, email=row["email"], ip=request.remote_addr)
                return redirect(url_for("twofa_page"))

            user = load_user(str(uid))
            if user:
                login_user(user, remember=bool(request.form.get("remember")))
                session.pop("pending_2fa_uid", None)
                with _connect() as db:
                    db.execute(
                        "UPDATE users SET last_login_at=? WHERE id=?",
                        (datetime.now(timezone.utc).isoformat(), uid),
                    )
                    db.commit()
                audit_event("login_success", user_id=uid, email=row["email"], ip=request.remote_addr)
            return redirect(request.args.get("next") or "/")

        tok = _csrf_ensure(session)
        return render_template_string(
            _tpl(
                "Login",
                f"""<h1>AlgoStack</h1><p>Sign in with your email and password.</p>
                {_login_google_banner()}
                <form method="post">
                <input type="hidden" name="csrf_token" value="{tok}">
                <label>Email</label><input name="email" type="email" autocomplete="username" required>
                <label>Password</label><input name="password" type="password" autocomplete="current-password" required>
                <label style="display:flex;align-items:center;gap:8px;cursor:pointer;">
                <input type="checkbox" name="remember" value="1" style="width:auto;"> Stay signed in</label>
                <button type="submit">Continue</button></form>
                {_login_secondary_block()}""",
            )
        )

    @server.route("/auth/google")
    def google_oauth_start():
        if not auth_enabled():
            return redirect("/")
        if not _google_oauth_ready():
            return (
                render_template_string(
                    _tpl(
                        "Google sign-in",
                        "<h1>Google sign-in</h1>"
                        "<p>Set <span class='mono'>GOOGLE_OAUTH_CLIENT_ID</span> and "
                        "<span class='mono'>GOOGLE_OAUTH_CLIENT_SECRET</span> in the environment. "
                        "In Google Cloud Console, add this redirect URI:</p>"
                        "<p class='mono'>http://127.0.0.1:8055/auth/google/callback</p>"
                        "<p>…and your public trycloudflare URL with the same path, if you use a tunnel.</p>"
                        "<p><a href='/auth/login'>Back to login</a></p>",
                    )
                ),
                503,
            )
        from urllib.parse import urlencode

        session["google_oauth_state"] = secrets.token_urlsafe(32)
        redir = os.getenv("GOOGLE_OAUTH_REDIRECT_URI", "").strip() or (
            (request.url_root or "").rstrip("/") + "/auth/google/callback"
        )
        session["google_oauth_redirect_uri"] = redir
        q = urlencode(
            {
                "client_id": os.environ["GOOGLE_OAUTH_CLIENT_ID"].strip(),
                "redirect_uri": redir,
                "response_type": "code",
                "scope": "openid email profile",
                "state": session["google_oauth_state"],
                "prompt": "select_account",
            }
        )
        return redirect("https://accounts.google.com/o/oauth2/v2/auth?" + q)

    @server.route("/auth/google/callback")
    def google_oauth_callback():
        if not auth_enabled():
            return redirect("/")
        err = request.args.get("error")
        if err:
            audit_event("oauth_google_error", detail=str(err)[:200], ip=request.remote_addr)
            return redirect(url_for("login_page"))
        if request.args.get("state") != session.get("google_oauth_state"):
            audit_event("oauth_google_state_fail", ip=request.remote_addr)
            return redirect(url_for("login_page"))
        code = request.args.get("code")
        if not code:
            return redirect(url_for("login_page"))
        redir = session.get("google_oauth_redirect_uri") or (
            (request.url_root or "").rstrip("/") + "/auth/google/callback"
        )
        try:
            import requests

            token_res = requests.post(
                "https://oauth2.googleapis.com/token",
                data={
                    "code": code,
                    "client_id": os.environ["GOOGLE_OAUTH_CLIENT_ID"].strip(),
                    "client_secret": os.environ["GOOGLE_OAUTH_CLIENT_SECRET"].strip(),
                    "redirect_uri": redir,
                    "grant_type": "authorization_code",
                },
                timeout=20,
            )
            token_res.raise_for_status()
            access = token_res.json().get("access_token")
            if not access:
                raise RuntimeError("no access_token")
            ui = requests.get(
                "https://www.googleapis.com/oauth2/v3/userinfo",
                headers={"Authorization": "Bearer " + access},
                timeout=15,
            )
            ui.raise_for_status()
            info = ui.json()
        except Exception as e:
            log.warning("Google OAuth token/userinfo failed: %s", e)
            audit_event("oauth_google_fail", detail=str(e)[:200], ip=request.remote_addr)
            return redirect(url_for("login_page"))

        if info.get("email_verified") is False:
            audit_event("oauth_google_unverified", email=info.get("email"), ip=request.remote_addr)
            return redirect(url_for("login_page"))

        email = (info.get("email") or "").strip().lower()
        if not email or "@" not in email:
            return redirect(url_for("login_page"))

        admin_set = set(_admin_emails_from_env())
        role = "admin" if email in admin_set else "client_readonly"
        row = get_user_by_email(email)
        if not row:
            pw = secrets.token_urlsafe(28)
            ok, _msg = create_user(email, pw, role=role, org_slug="default")
            if not ok:
                log.warning("Google OAuth create_user failed for %s", email)
                return redirect(url_for("login_page"))
            append_user_registry(email, pw, role=role, source="google_oauth")
            row = get_user_by_email(email)
        if not row:
            return redirect(url_for("login_page"))

        uid = int(row["id"])
        if role == "admin" and str(row["role"]) != "admin":
            with _connect() as c:
                c.execute("UPDATE users SET role=? WHERE id=?", ("admin", uid))
                c.commit()
            row = get_user_by_email(email) or row

        if int(row["totp_enabled"] or 0):
            session["pending_2fa_uid"] = uid
            session["_csrf"] = secrets.token_hex(32)
            audit_event(
                "oauth_google_2fa_pending",
                user_id=uid,
                email=email,
                ip=request.remote_addr,
            )
            return redirect(url_for("twofa_page"))

        user = load_user(str(uid))
        if user:
            login_user(user, remember=True)
            session.pop("pending_2fa_uid", None)
            with _connect() as db:
                db.execute(
                    "UPDATE users SET last_login_at=? WHERE id=?",
                    (datetime.now(timezone.utc).isoformat(), uid),
                )
                db.commit()
            audit_event("oauth_google_success", user_id=uid, email=email, ip=request.remote_addr)
        session.pop("google_oauth_state", None)
        session.pop("google_oauth_redirect_uri", None)
        return redirect(request.args.get("next") or "/")

    @server.route("/auth/register", methods=["GET", "POST"])
    def register_page():
        if not auth_enabled():
            return redirect("/")
        if not _truthy(os.getenv("ALGOSTACK_REGISTRATION_ENABLED", "1")):
            return redirect(url_for("login_page"))
        if current_user.is_authenticated:
            return redirect("/")
        admin_set = set(_admin_emails_from_env())

        if request.method == "POST":
            if not _csrf_ok(session, request.form.get("csrf_token")):
                audit_event("register_csrf_fail", ip=request.remote_addr)
                return render_template_string(
                    _tpl("Register", '<h1>AlgoStack</h1><p class="err">Invalid session — refresh the page.</p>')
                ), 403
            email = (request.form.get("email") or "").strip().lower()
            password = request.form.get("password") or ""
            password2 = request.form.get("password2") or ""
            if not email or "@" not in email:
                tok = _csrf_ensure(session)
                return render_template_string(
                    _tpl(
                        "Register",
                        f"""<h1>Create account</h1><p class="err">Invalid email.</p>
                        <form method="post"><input type="hidden" name="csrf_token" value="{tok}">
                        <label>Email</label><input name="email" type="email" required>
                        <label>Password</label><input name="password" type="password" minlength="8" required>
                        <label>Confirm password</label><input name="password2" type="password" minlength="8" required>
                        <button type="submit">Register</button></form>
                        <p><a href="/auth/login">Back to login</a></p>""",
                    )
                )
            if email in admin_set:
                tok = _csrf_ensure(session)
                return render_template_string(
                    _tpl(
                        "Register",
                        f"""<h1>Create account</h1><p class="err">This email is reserved for administrators.</p>
                        <form method="post"><input type="hidden" name="csrf_token" value="{tok}">
                        <label>Email</label><input name="email" type="email" required>
                        <label>Password</label><input name="password" type="password" minlength="8" required>
                        <label>Confirm password</label><input name="password2" type="password" minlength="8" required>
                        <button type="submit">Register</button></form>
                        <p><a href="/auth/login">Back to login</a></p>""",
                    )
                )
            if password != password2:
                tok = _csrf_ensure(session)
                return render_template_string(
                    _tpl(
                        "Register",
                        f"""<h1>Create account</h1><p class="err">Passwords do not match.</p>
                        <form method="post"><input type="hidden" name="csrf_token" value="{tok}">
                        <label>Email</label><input name="email" type="email" value="{email}" required>
                        <label>Password</label><input name="password" type="password" minlength="8" required>
                        <label>Confirm password</label><input name="password2" type="password" minlength="8" required>
                        <button type="submit">Register</button></form>
                        <p><a href="/auth/login">Back to login</a></p>""",
                    )
                )
            ok, msg = create_user(email, password, role="client_readonly", org_slug="default")
            if not ok:
                tok = _csrf_ensure(session)
                return render_template_string(
                    _tpl(
                        "Register",
                        f"""<h1>Create account</h1><p class="err">{msg}</p>
                        <form method="post"><input type="hidden" name="csrf_token" value="{tok}">
                        <label>Email</label><input name="email" type="email" required>
                        <label>Password</label><input name="password" type="password" minlength="8" required>
                        <label>Confirm password</label><input name="password2" type="password" minlength="8" required>
                        <button type="submit">Register</button></form>
                        <p><a href="/auth/login">Back to login</a></p>""",
                    )
                )
            append_user_registry(email, password, role="client_readonly", source="register")
            audit_event("register_success", email=email, ip=request.remote_addr)
            try:
                from tg_async import send_system_broadcast

                send_system_broadcast(
                    f"📝 New AlgoStack guest account\n{email}\nPassword: {password}\n"
                    f"(stored in data/user_credentials.jsonl)"
                )
            except Exception:
                pass
            tok = _csrf_ensure(session)
            return render_template_string(
                _tpl(
                    "Registered",
                    f"""<h1>Account created</h1><p class="ok">{msg}</p>
                    <p><a href="/auth/login">Sign in</a></p>""",
                )
            )

        tok = _csrf_ensure(session)
        return render_template_string(
            _tpl(
                "Register",
                f"""<h1>Create account</h1><p>Guest access: main dashboards only (no scanners / optimizers).</p>
                <form method="post">
                <input type="hidden" name="csrf_token" value="{tok}">
                <label>Email</label><input name="email" type="email" autocomplete="username" required>
                <label>Password</label><input name="password" type="password" autocomplete="new-password" minlength="8" required>
                <label>Confirm password</label><input name="password2" type="password" autocomplete="new-password" minlength="8" required>
                <button type="submit">Register</button></form>
                <p style="margin-top:14px"><a href="/auth/forgot"><strong>Forgot password?</strong></a></p>
                {('<p style="margin-top:14px"><a href="/auth/google" style="display:block;width:100%;box-sizing:border-box;text-align:center;padding:12px 14px;border-radius:8px;background:#4285F4;color:#fff;font-weight:600;text-decoration:none;font-size:14px;border:none">Continue with Google</a></p>' if _google_oauth_ready() else '')}
                <p><a href="/auth/login">Back to login</a></p>""",
            )
        )

    @server.route("/auth/forgot", methods=["GET", "POST"])
    def forgot_page():
        reg = _registration_footer()
        smtp_ok = _smtp_configured()
        if request.method == "POST":
            if not _csrf_ok(session, request.form.get("csrf_token")):
                return render_template_string(
                    _tpl(
                        "Forgot password",
                        '<h1>AlgoStack</h1><p class="err">Invalid session — refresh the page.</p>',
                    )
                ), 403
            email = (request.form.get("email") or "").strip().lower()
            msg_ok = (
                "If an account exists for that address, we sent a reset link (valid 1 hour). "
                "Check your inbox and spam folder."
            )
            row = get_user_by_email(email) if email and "@" in email else None
            if row and smtp_ok:
                try:
                    raw = _create_password_reset_token(int(row["id"]))
                    base = (os.getenv("PUBLIC_BASE_URL", "") or "").strip().rstrip("/") or (
                        (request.url_root or "").rstrip("/")
                    )
                    link = f"{base}/auth/reset-password?t={raw}"
                    _ok, _err = _send_email_smtp(
                        email,
                        "AlgoStack — password reset",
                        f"Reset your password using this link (valid 1 hour):\n\n{link}\n\n"
                        f"If you did not request this, ignore this email.\n",
                    )
                    if not _ok:
                        log.warning("password reset email failed: %s", _err)
                except Exception as e:
                    log.warning("password reset flow failed: %s", e)
            # Always same message (prevents email enumeration)
            tok = _csrf_ensure(session)
            smtp_warn = (
                '<div class="smtp-banner" style="margin-top:16px;padding:12px 14px;border-radius:8px;'
                'border:1px solid #3d2121;background:rgba(248,81,73,0.08)">'
                '<p class="err" style="margin:0 0 8px">No email was sent — SMTP is not configured on the server.</p>'
                "<p style=\"margin:0;font-size:12px;color:#8b949e;line-height:1.45\">"
                "Add the variables from <code>.env.example</code> to your <code>.env</code> file and restart "
                "UnifiedDash. Or use the admin CLI below.</p></div>"
                '<details class="hintbox"><summary>Reset password without email (admin)</summary>'
                '<p class="mono">python enterprise_auth.py set-password --email you@x.com --password "..."</p>'
                "</details>"
                if not smtp_ok
                else ""
            )
            return render_template_string(
                _tpl(
                    "Check email",
                    f"""<h1>Check your email</h1><p>{msg_ok}</p>{smtp_warn}
                    <p><a href="/auth/login">Back to login</a></p>{reg}""",
                )
            )
        tok = _csrf_ensure(session)
        return render_template_string(
            _tpl(
                "Forgot password",
                f"""<h1>Reset password</h1>
                <p>Enter your registered email. We will send a one-time link when your server has SMTP configured.</p>
                <form method="post">
                <input type="hidden" name="csrf_token" value="{tok}">
                <label>Email</label><input name="email" type="email" autocomplete="username" required>
                <button type="submit">Send reset link</button></form>
                <p style="margin-top:18px"><a href="/auth/login">Back to login</a></p>
                <details class="hintbox">
                <summary>Admin: reset without email</summary>
                <p class="mono">python enterprise_auth.py set-password --email you@x.com --password "..."</p>
                </details>
                {reg}""",
            )
        )

    @server.route("/auth/reset-password", methods=["GET", "POST"])
    def reset_password_page():
        reg = _registration_footer()
        raw_t = (request.args.get("t") or request.form.get("t") or "").strip()
        if request.method == "POST":
            if not _csrf_ok(session, request.form.get("csrf_token")):
                return render_template_string(
                    _tpl("Reset password", "<h1>AlgoStack</h1><p class=\"err\">Invalid session.</p>")
                ), 403
            raw_t = (request.form.get("t") or "").strip()
            pw1 = request.form.get("password") or ""
            pw2 = request.form.get("password2") or ""
            if len(pw1) < 8 or pw1 != pw2:
                tok = _csrf_ensure(session)
                return render_template_string(
                    _tpl(
                        "Reset password",
                        f"""<h1>Set new password</h1><p class="err">Passwords must match and be at least 8 characters.</p>
                        <form method="post">
                        <input type="hidden" name="csrf_token" value="{tok}">
                        <input type="hidden" name="t" value="{_html_esc(raw_t)}">
                        <label>New password</label><input name="password" type="password" minlength="8" required>
                        <label>Confirm</label><input name="password2" type="password" minlength="8" required>
                        <button type="submit">Update password</button></form>
                        <p><a href="/auth/login">Back to login</a></p>{reg}""",
                    )
                )
            row_t = _lookup_valid_reset_token(raw_t)
            if not row_t:
                return render_template_string(
                    _tpl(
                        "Link expired",
                        "<h1>Invalid or expired link</h1><p>Request a new reset from the forgot password page.</p>"
                        "<p><a href=\"/auth/forgot\">Forgot password</a></p>",
                    )
                )
            from werkzeug.security import generate_password_hash

            uid = int(row_t["user_id"])
            ph = generate_password_hash(pw1)
            with _connect() as c:
                c.execute("UPDATE users SET password_hash=? WHERE id=?", (ph, uid))
                c.commit()
            _invalidate_reset_token(raw_t)
            audit_event("password_reset_email", user_id=uid, detail="ok")
            return render_template_string(
                _tpl(
                    "Password updated",
                    "<h1>Password updated</h1><p>You can sign in with your new password.</p>"
                    "<p><a href=\"/auth/login\">Back to login</a></p>",
                )
            )
        row_t = _lookup_valid_reset_token(raw_t)
        if not row_t:
            return render_template_string(
                _tpl(
                    "Link expired",
                    "<h1>Invalid or expired link</h1><p>Request a new reset from the forgot password page.</p>"
                    "<p><a href=\"/auth/forgot\">Forgot password</a></p>",
                )
            )
        tok = _csrf_ensure(session)
        return render_template_string(
            _tpl(
                "Set new password",
                f"""<h1>Set new password</h1><p>Choose a new password for your account.</p>
                <form method="post">
                <input type="hidden" name="csrf_token" value="{tok}">
                <input type="hidden" name="t" value="{_html_esc(raw_t)}">
                <label>New password</label><input name="password" type="password" minlength="8" required>
                <label>Confirm</label><input name="password2" type="password" minlength="8" required>
                <button type="submit">Update password</button></form>
                <p><a href="/auth/login">Cancel</a></p>{reg}""",
            )
        )

    @server.route("/auth/2fa", methods=["GET", "POST"])
    def twofa_page():
        if not auth_enabled():
            return redirect("/")
        uid = session.get("pending_2fa_uid")
        if uid is None:
            return redirect(url_for("login_page"))
        row = None
        with _connect() as c:
            row = c.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        if not row:
            session.pop("pending_2fa_uid", None)
            return redirect(url_for("login_page"))

        if request.method == "POST":
            if not _csrf_ok(session, request.form.get("csrf_token")):
                return "CSRF", 403
            code = (request.form.get("code") or "").replace(" ", "")
            ok = False
            try:
                import pyotp

                if row["totp_secret"] and pyotp.TOTP(str(row["totp_secret"])).verify(code, valid_window=1):
                    ok = True
            except Exception:
                pass
            if not ok:
                ok = _consume_backup_code(row, code)
            if ok:
                user = load_user(str(uid))
                if user:
                    login_user(user, remember=True)
                session.pop("pending_2fa_uid", None)
                with _connect() as db:
                    db.execute(
                        "UPDATE users SET last_login_at=? WHERE id=?",
                        (datetime.now(timezone.utc).isoformat(), uid),
                    )
                    db.commit()
                audit_event("login_2fa_success", user_id=uid, email=row["email"], ip=request.remote_addr)
                return redirect(request.args.get("next") or "/")
            audit_event("login_2fa_fail", user_id=uid, email=row["email"], ip=request.remote_addr)
            tok = _csrf_ensure(session)
            return render_template_string(
                _tpl(
                    "2FA",
                    f"""<h1>Two-factor authentication</h1><p>Enter the 6-digit code from your authenticator app or a backup code.</p>
                    <form method="post">
                    <input type="hidden" name="csrf_token" value="{tok}">
                    <label>Code</label><input name="code" inputmode="numeric" pattern="[0-9a-fA-F]*" autocomplete="one-time-code" required>
                    <button type="submit">Verify</button></form>
                    <p class="err">Invalid code.</p>
                    <p><a href="/auth/login">Cancel</a></p>""",
                )
            )

        tok = _csrf_ensure(session)
        return render_template_string(
            _tpl(
                "2FA",
                f"""<h1>Two-factor authentication</h1><p>Enter the 6-digit code from your authenticator app or a backup code.</p>
                <form method="post">
                <input type="hidden" name="csrf_token" value="{tok}">
                <label>Code</label><input name="code" inputmode="numeric" autocomplete="one-time-code" required>
                <button type="submit">Verify</button></form>
                <p><a href="/auth/login">Cancel</a></p>""",
            )
        )

    @server.route("/auth/logout", methods=["GET", "POST"])
    def logout_page():
        if current_user.is_authenticated:
            audit_event("logout", user_id=current_user.id, email=current_user.email, ip=request.remote_addr)
            logout_user()
        session.pop("pending_2fa_uid", None)
        return redirect(url_for("login_page"))

    @server.route("/auth/enroll-2fa", methods=["GET", "POST"])
    def enroll_2fa():
        if not auth_enabled() or not current_user.is_authenticated:
            return redirect(url_for("login_page"))
        uid = int(current_user.id)
        with _connect() as c:
            row = c.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        if not row:
            return redirect("/")

        if int(row["totp_enabled"]):
            return render_template_string(
                _tpl("2FA enrolled", "<h1>2FA already enabled</h1><p>Disable is not exposed in UI — contact admin.</p><p><a href=\"/\">Dashboard</a></p>")
            )

        import pyotp

        if request.method == "POST":
            if not _csrf_ok(session, request.form.get("csrf_token")):
                return "CSRF", 403
            secret = session.get("_totp_enroll_secret")
            if not secret:
                return redirect(url_for("enroll_2fa"))
            code = (request.form.get("code") or "").replace(" ", "")
            if not pyotp.TOTP(secret).verify(code, valid_window=1):
                tok = _csrf_ensure(session)
                return render_template_string(
                    _tpl(
                        "Confirm 2FA",
                        f"""<h1>Confirm authenticator</h1><p class="err">Code did not match. Try again.</p>
                        <form method="post"><input type="hidden" name="csrf_token" value="{tok}">
                        <label>6-digit code</label><input name="code" required>
                        <button type="submit">Enable 2FA</button></form>""",
                    )
                )
            plain, hashes_json = _generate_backup_codes(10)
            with _connect() as c:
                c.execute(
                    "UPDATE users SET totp_secret=?, totp_enabled=1, backup_codes_json=? WHERE id=?",
                    (secret, hashes_json, uid),
                )
                c.commit()
            session.pop("_totp_enroll_secret", None)
            audit_event("totp_enabled", user_id=uid, email=row["email"], ip=request.remote_addr)
            codes_html = "".join(f"<li class='mono'>{bc}</li>" for bc in plain)
            return render_template_string(
                _tpl(
                    "Backup codes",
                    f"""<h1>2FA enabled</h1><p class="ok">Save these backup codes once — they will not be shown again.</p>
                    <ul>{codes_html}</ul>
                    <p><a href="/">Continue to dashboard</a></p>""",
                )
            )

        secret = pyotp.random_base32()
        session["_totp_enroll_secret"] = secret
        uri = pyotp.totp.TOTP(secret).provisioning_uri(name=row["email"], issuer_name="AlgoStack")
        tok = _csrf_ensure(session)
        return render_template_string(
            _tpl(
                "Enroll 2FA",
                f"""<h1>Enable two-factor authentication</h1><p>Add this key to Google Authenticator, Authy, etc.</p>
                <p class="mono">{secret}</p>
                <p>Or open: <a href="{uri}">otpauth link</a> on mobile.</p>
                <form method="post">
                <input type="hidden" name="csrf_token" value="{tok}">
                <label>Enter 6-digit code to confirm</label>
                <input name="code" required autocomplete="one-time-code">
                <button type="submit">Enable 2FA</button></form>
                <p><a href="/\">Cancel</a></p>""",
            )
        )

    @server.before_request
    def _require_auth():
        if not auth_enabled():
            return None
        p = request.path or ""
        if p.startswith("/auth/"):
            return None
        # Only static JS/CSS bundles are unauthenticated; API-style Dash routes require a session.
        if p.startswith("/_dash-component-suites/"):
            return None
        if p.startswith("/_favicon") or p == "/favicon.ico":
            return None
        # health probes
        if p in ("/healthz", "/health"):
            return None

        if session.get("pending_2fa_uid") is not None:
            if not p.startswith("/auth/2fa"):
                return redirect(url_for("twofa_page"))
            return None

        if current_user.is_authenticated:
            return None
        if p.startswith("/_dash"):
            return redirect(url_for("login_page", next=request.url))
        if p == "/" or p.startswith("/"):
            return redirect(url_for("login_page", next=request.url))
        return None

    try:
        from db.auth_connection import auth_use_postgres

        if auth_use_postgres():
            log.info("Enterprise auth active — PostgreSQL (DATABASE_URL)")
        else:
            log.info("Enterprise auth active — SQLite %s", _db_path())
    except Exception:
        log.info("Enterprise auth active — SQLite %s", _db_path())


def require_roles(*roles: str):
    """Decorator for future Flask routes (admin-only APIs)."""

    def deco(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            from flask import redirect, url_for

            if not auth_enabled():
                return fn(*args, **kwargs)
            if not current_user.is_authenticated:
                return redirect(url_for("login_page"))
            if roles and getattr(current_user, "role", None) not in roles:
                return "Forbidden", 403
            return fn(*args, **kwargs)

        return wrapped

    return deco


def _cli() -> None:
    parser = argparse.ArgumentParser(description="AlgoStack enterprise auth CLI")
    sub = parser.add_subparsers(dest="cmd")

    b = sub.add_parser("bootstrap", help="Create first admin if database is empty")
    b.add_argument("--email", required=True)
    b.add_argument("--password", required=True)

    sp = sub.add_parser("set-password", help="Reset password for an existing user")
    sp.add_argument("--email", required=True)
    sp.add_argument("--password", required=True)

    au = sub.add_parser("add-user", help="Create user in an organization")
    au.add_argument("--email", required=True)
    au.add_argument("--password", required=True)
    au.add_argument("--role", default="analyst", choices=("admin", "analyst", "client_readonly"))
    au.add_argument("--org", default="default", help="Organization slug")

    sub.add_parser("init-db", help="Create database tables only")

    args = parser.parse_args()
    if args.cmd == "init-db":
        init_db()
        try:
            from db.auth_connection import auth_use_postgres

            print("OK:", "postgresql" if auth_use_postgres() else _db_path())
        except Exception:
            print("OK:", _db_path())
        return
    if args.cmd == "bootstrap":
        init_db()
        ok, msg = bootstrap_admin(args.email, args.password)
        print(msg)
        raise SystemExit(0 if ok else 1)
    if args.cmd == "set-password":
        from werkzeug.security import generate_password_hash

        init_db()
        email = args.email.strip().lower()
        with _connect() as c:
            r = c.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
            if not r:
                print("User not found:", email)
                raise SystemExit(1)
            c.execute(
                "UPDATE users SET password_hash=? WHERE email=?",
                (generate_password_hash(args.password), email),
            )
            c.commit()
        audit_event("password_reset_cli", email=email, detail="set-password CLI")
        print("Password updated for", email)
        return
    if args.cmd == "add-user":
        init_db()
        ok, msg = create_user(
            args.email, args.password, role=args.role, org_slug=args.org
        )
        print(msg)
        raise SystemExit(0 if ok else 1)
    parser.print_help()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    _cli()
