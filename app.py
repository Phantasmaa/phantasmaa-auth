"""
Phantasmaa SSO — single login for the whole suite (v3, sep-2026).

Authoritative user store: /root/phantasmaa-auth/users_global.db
Apps link to users by email.

SECURITY: All passwords stored as pbkdf2:sha256 (1M iterations, salt >=16 bytes).
NEVER plaintext. Cookie HMAC-SHA256 signed, HttpOnly, SameSite=Lax, Secure over HTTPS.
"""
import hmac
import hashlib
import os
import secrets
import sqlite3
import sys
import time
import urllib.request
import urllib.error
import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import (
    Flask, redirect, render_template, request, jsonify,
    make_response, g,
)
from werkzeug.security import check_password_hash, generate_password_hash


# ─── Config ───────────────────────────────────────────────────────────────

USERS_DB = Path(os.environ.get(
    "PHANTASMAA_USERS_DB", "/root/phantasmaa-auth/users_global.db"
))

SIGNING_SECRET = os.environ.get("PHANTASMAA_AUTH_SECRET",
                          "phantasmaa-dev-secret-CHANGE-IN-PROD-via-env-var-please")

COOKIE_NAME = "phantasmaa_auth"
COOKIE_MAX_AGE = 90 * 24 * 3600  # 90 days


# ─── App factory ──────────────────────────────────────────────────────────

app = Flask(__name__,
            template_folder="/root/phantasmaa-auth/templates",
            static_folder="/root/phantasmaa-auth/static")
app.config["SECRET_KEY"] = SIGNING_SECRET
app.config["JSON_AS_ASCII"] = False


def _db():
    if "db" not in g:
        g.db = sqlite3.connect(str(USERS_DB))
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def _close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


# ─── Schema init ─────────────────────────────────────────────────────────

def init_db():
    con = sqlite3.connect(str(USERS_DB))
    con.executescript("""
    CREATE TABLE IF NOT EXISTS users_global (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        display_name TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        is_admin INTEGER NOT NULL DEFAULT 0,
        must_reset_password INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        last_login TEXT,
        photo_path TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_users_email ON users_global(email);

    CREATE TABLE IF NOT EXISTS user_preferences (
        user_id INTEGER PRIMARY KEY,
        theme TEXT NOT NULL DEFAULT 'midnight',
        accent_hue INTEGER NOT NULL DEFAULT 220,
        accent_sat INTEGER NOT NULL DEFAULT 70,
        accent_light INTEGER NOT NULL DEFAULT 55,
        updated_at TEXT NOT NULL DEFAULT (datetime('now')),
        FOREIGN KEY(user_id) REFERENCES users_global(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS password_resets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        email TEXT NOT NULL,
        code_hash TEXT NOT NULL,           -- PBKDF2 hash del OTP de 6 dígitos
        reset_token_hash TEXT,             -- PBKDF2 hash del token de reset (post-verify)
        expires_at TEXT NOT NULL,          -- ISO datetime, código expira 15 min
        verified_at TEXT,                  -- cuándo el usuario verificó el OTP
        reset_expires_at TEXT,             -- ISO datetime, token de reset expira 10 min
        used_at TEXT,                      -- cuándo se consumió el reset
        request_ip TEXT,                   -- IP que pidió el reset (rate-limit)
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        FOREIGN KEY(user_id) REFERENCES users_global(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_password_resets_email ON password_resets(email);
    CREATE INDEX IF NOT EXISTS idx_password_resets_user_id ON password_resets(user_id);
    """)
    # Migración: agregar photo_path si la tabla ya existía sin esa columna
    cols = [r[1] for r in con.execute("PRAGMA table_info(users_global)").fetchall()]
    if "photo_path" not in cols:
        con.execute("ALTER TABLE users_global ADD COLUMN photo_path TEXT")
    con.commit()
    con.close()


# ─── Token signing ────────────────────────────────────────────────────────

def _make_token(user_id, ttl=None):
    if ttl is None:
        ttl = COOKIE_MAX_AGE
    expires = int(time.time()) + ttl
    payload = f"{user_id}.{expires}".encode()
    sig = hmac.new(SIGNING_SECRET.encode(), payload, hashlib.sha256).hexdigest()
    return f"{user_id}.{expires}.{sig}"


def _verify_token(token):
    if not token or token.count(".") != 2:
        return None
    try:
        uid_s, exp_s, sig = token.split(".")
        uid = int(uid_s)
        exp = int(exp_s)
    except (ValueError, AttributeError):
        return None
    if exp < int(time.time()):
        return None
    expected = hmac.new(
        SIGNING_SECRET.encode(),
        f"{uid}.{exp}".encode(),
        hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return None
    return uid


def _current_user():
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return None
    uid = _verify_token(token)
    if not uid:
        return None
    row = _db().execute(
        "SELECT id, email, display_name, is_admin, must_reset_password, photo_path "
        "FROM users_global WHERE id = ?",
        (uid,)
    ).fetchone()
    if not row:
        return None
    return dict(row)


def _set_cookie(resp, user_id):
    token = _make_token(user_id)
    resp.set_cookie(
        COOKIE_NAME, token,
        max_age=COOKIE_MAX_AGE,
        httponly=True,
        secure=request.is_secure,
        samesite="Lax",
        path="/",
    )
    return resp


def _clear_cookie(resp):
    resp.delete_cookie(COOKIE_NAME, path="/")
    return resp


# ─── Login (browser form) ─────────────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    next_url = request.args.get("next") or request.form.get("next") or "/"
    if not next_url.startswith("/") or next_url.startswith("//"):
        next_url = "/"

    if request.method == "GET":
        user = _current_user()
        if user:
            return redirect(next_url)
        return render_template("login.html", error=None, next=next_url)

    email = (request.form.get("email") or "").strip().lower()
    password = request.form.get("password") or ""

    if not email or not password:
        return render_template("login.html",
                               error="Ingresa email y contraseña.",
                               next=next_url), 400

    row = _db().execute(
        "SELECT id, email, display_name, password_hash, is_admin, must_reset_password, email_verified "
        "FROM users_global WHERE email = ?",
        (email,)
    ).fetchone()

    if not row or not check_password_hash(row["password_hash"], password):
        return render_template("login.html",
                               error="Email o contraseña incorrectos.",
                               next=next_url), 401

    # Bloquear login si el email no está verificado
    if not row["email_verified"]:
        return render_template("login.html",
                               error="Necesitas verificar tu email antes de iniciar sesión. Revisa tu bandeja de entrada.",
                               next=next_url,
                               show_resend_verification=True,
                               unverified_email=row["email"]), 403

    _db().execute(
        "UPDATE users_global SET last_login = datetime('now') WHERE id = ?",
        (row["id"],)
    )
    _db().commit()

    resp = make_response(redirect(next_url))
    _set_cookie(resp, row["id"])
    return resp


# ─── Logout ───────────────────────────────────────────────────────────────

@app.route("/logout", methods=["GET", "POST"])
def logout():
    next_url = request.args.get("next", "/login")
    if not next_url.startswith("/") or next_url.startswith("//"):
        next_url = "/login"
    resp = make_response(redirect(next_url))
    _clear_cookie(resp)
    return resp


# ─── JSON API ─────────────────────────────────────────────────────────────

@app.route("/api/auth/login", methods=["POST"])
def api_auth_login():
    if not request.is_json:
        return jsonify(ok=False, error="expected_json"), 400
    data = request.get_json() or {}
    email = (data.get("email") or data.get("username") or "").strip().lower()
    password = data.get("password") or ""

    if not email or not password:
        return jsonify(ok=False, error="missing_credentials"), 400

    row = _db().execute(
        "SELECT id, email, display_name, password_hash, is_admin, must_reset_password, email_verified "
        "FROM users_global WHERE email = ?",
        (email,)
    ).fetchone()

    if not row or not check_password_hash(row["password_hash"], password):
        return jsonify(ok=False, error="bad_credentials"), 401

    # Bloquear login si el email no está verificado
    if not row["email_verified"]:
        return jsonify(
            ok=False,
            error="email_not_verified",
            message="Necesitas verificar tu email antes de iniciar sesión.",
            verification_required=True,
        ), 403

    _db().execute(
        "UPDATE users_global SET last_login = datetime('now') WHERE id = ?",
        (row["id"],)
    )
    _db().commit()

    token = _make_token(row["id"])
    resp = jsonify(
        ok=True,
        user={
            "id": row["id"],
            "email": row["email"],
            "display_name": row["display_name"],
            "is_admin": bool(row["is_admin"]),
            "must_reset_password": bool(row["must_reset_password"]),
        },
        auth_token=token
    )
    _set_cookie(resp, row["id"])
    return resp, 200


@app.route("/api/auth/logout", methods=["POST"])
def api_auth_logout():
    resp = jsonify(ok=True)
    _clear_cookie(resp)
    return resp, 200


@app.route("/api/auth/change-password", methods=["POST"])
def api_auth_change_password():
    user = _current_user()
    if not user:
        return jsonify(ok=False, error="unauthorized"), 401
    if not request.is_json:
        return jsonify(ok=False, error="expected_json"), 400
    data = request.get_json() or {}
    current_pw = data.get("current_password") or ""
    new_pw = data.get("new_password") or ""
    if len(new_pw) < 8:
        return jsonify(ok=False, error="password_too_short",
                       message="Mínimo 8 caracteres"), 400

    row = _db().execute(
        "SELECT password_hash FROM users_global WHERE id = ?",
        (user["id"],)
    ).fetchone()
    if not check_password_hash(row["password_hash"], current_pw):
        return jsonify(ok=False, error="bad_current_password"), 401

    new_hash = generate_password_hash(
        new_pw, method='pbkdf2:sha256', salt_length=16
    )
    _db().execute(
        "UPDATE users_global SET password_hash = ?, must_reset_password = 0 "
        "WHERE id = ?",
        (new_hash, user["id"])
    )
    _db().commit()
    return jsonify(ok=True)


@app.route("/api/whoami", methods=["GET"])
def whoami():
    user = _current_user()
    if not user:
        return jsonify(authenticated=False), 401
    prefs = _get_prefs(user["id"])
    return jsonify(
        authenticated=True,
        id=user["id"],
        email=user["email"],
        display_name=user["display_name"],
        is_admin=bool(user["is_admin"]),
        must_reset_password=bool(user["must_reset_password"]),
        photo_path=user["photo_path"],  # ruta relativa tipo "avatars/user_1.png" o None
        photo_url=(
            f"/api/auth/avatar/{user['id']}"
            if user["photo_path"] else None
        ),
        preferences=prefs,
    )


# ─── Preferences (theme + accent color) ─────────────────────────────────

def _get_prefs(user_id):
    row = _db().execute(
        "SELECT theme, accent_hue, accent_sat, accent_light "
        "FROM user_preferences WHERE user_id = ?",
        (user_id,)
    ).fetchone()
    if not row:
        # Inicializa defaults
        _db().execute(
            "INSERT OR IGNORE INTO user_preferences (user_id) VALUES (?)",
            (user_id,)
        )
        _db().commit()
        return {"theme": "midnight", "accent_hue": 220,
                "accent_sat": 70, "accent_light": 55}
    return dict(row)


@app.route("/api/auth/preferences", methods=["GET", "POST"])
def api_preferences():
    user = _current_user()
    if not user:
        return jsonify(ok=False, error="unauthorized"), 401

    if request.method == "GET":
        return jsonify(ok=True, preferences=_get_prefs(user["id"]))

    # POST: actualizar
    if not request.is_json:
        return jsonify(ok=False, error="expected_json"), 400
    data = request.get_json() or {}
    theme = (data.get("theme") or "").strip()
    hue = data.get("accent_hue")
    sat = data.get("accent_sat")
    light = data.get("accent_light")

    allowed_themes = ("midnight", "aurora", "sunset", "forest", "ocean")
    if theme and theme not in allowed_themes:
        return jsonify(ok=False, error="bad_theme"), 400
    try:
        if hue is not None: hue = max(0, min(360, int(hue)))
        if sat is not None: sat = max(0, min(100, int(sat)))
        if light is not None: light = max(20, min(80, int(light)))
    except (TypeError, ValueError):
        return jsonify(ok=False, error="bad_color"), 400

    sets = []
    args = []
    if theme:
        sets.append("theme = ?")
        args.append(theme)
    if hue is not None:
        sets.append("accent_hue = ?")
        args.append(hue)
    if sat is not None:
        sets.append("accent_sat = ?")
        args.append(sat)
    if light is not None:
        sets.append("accent_light = ?")
        args.append(light)

    if sets:
        args.append(user["id"])
        _db().execute(
            "UPDATE user_preferences SET "
            + ", ".join(sets) +
            ", updated_at = datetime('now') WHERE user_id = ?",
            args
        )
        _db().commit()
    return jsonify(ok=True, preferences=_get_prefs(user["id"]))


# ─── Account page (cambio de contraseña UI) ─────────────────────────────

@app.route("/account/change-password", methods=["GET", "POST"])
def account_change_password():
    user = _current_user()
    next_url = request.args.get("next") or "/"
    if not next_url.startswith("/") or next_url.startswith("//"):
        next_url = "/"

    if not user:
        return redirect("/login?next=/account/change-password")

    error = None
    if request.method == "POST":
        actual = request.form.get("password_actual") or ""
        nueva = request.form.get("password_nueva") or ""
        confirma = request.form.get("password_confirma") or ""

        if not actual or not nueva or not confirma:
            error = "Completá los tres campos."
        elif len(nueva) < 8:
            error = "La nueva contraseña debe tener al menos 8 caracteres."
        elif nueva != confirma:
            error = "La nueva contraseña y su confirmación no coinciden."
        else:
            row = _db().execute(
                "SELECT password_hash FROM users_global WHERE id = ?",
                (user["id"],)
            ).fetchone()
            if not check_password_hash(row["password_hash"], actual):
                error = "La contraseña actual es incorrecta."
            else:
                new_hash = generate_password_hash(
                    nueva, method='pbkdf2:sha256', salt_length=16
                )
                _db().execute(
                    "UPDATE users_global "
                    "SET password_hash = ?, must_reset_password = 0 "
                    "WHERE id = ?",
                    (new_hash, user["id"])
                )
                _db().commit()
                return render_template(
                    "account_done.html",
                    user=user,
                    next=next_url
                )

    return render_template(
        "change_password.html",
        user=user,
        error=error,
        next=next_url,
    )


@app.route("/account", methods=["GET"])
@app.route("/account/", methods=["GET"])
def account():
    user = _current_user()
    if not user:
        return redirect("/login?next=/account")
    prefs = _get_prefs(user["id"])
    return render_template("account.html", user=user, prefs=prefs)


# ─── nginx auth_request ──────────────────────────────────────────────────

@app.route("/auth/verify")
def auth_verify():
    user = _current_user()
    if not user:
        return make_response("", 401)
    resp = make_response("", 200)
    resp.headers["X-User-Id"] = str(user["id"])
    resp.headers["X-User-Email"] = user["email"]
    resp.headers["X-Username"] = user["display_name"]
    resp.headers["X-Is-Admin"] = "1" if user["is_admin"] else "0"
    resp.headers["X-Must-Reset"] = "1" if user["must_reset_password"] else "0"
    resp.headers["X-User-Photo"] = user["photo_path"] or ""
    return resp


# ─── Health ──────────────────────────────────────────────────────────────

@app.route("/health")
def health():
    return jsonify(ok=True, service="phantasmaa-auth", ts=int(time.time()))


# ─── Register (public, opt-in) ───────────────────────────────────────────

# Cookie que rastrea si ya preguntamos "quieres configurar chIA?" este user
CHIA_PROMPT_COOKIE = "chia_prompt_dismissed"


def _valid_email(email):
    """Quick sanity check — full validation happens when sending email,
    but this stops obvious typos before we waste a hash."""
    if not email or len(email) > 254:
        return False
    if " " in email:
        return False
    # Requisitos mínimos: x@y.z
    if email.count("@") != 1:
        return False
    local, _, domain = email.partition("@")
    if not local or not domain or "." not in domain:
        return False
    return True


def _valid_password(password):
    """Mínimo 8 chars. No exigimos símbolos ni mayúsculas porque eso
    castiga a usuarios con nombres simples (ej. Balya). Mejor largo mínimo."""
    return isinstance(password, str) and len(password) >= 8


@app.route("/register", methods=["GET", "POST"])
def register():
    """Auto-registro: crea cuenta SSO con email + password + nombre.
    Después de registrarse, redirige al portal con un aviso opcional
    preguntando si quiere configurar su perfil nutricional de chIA.
    """
    next_url = request.args.get("next") or request.form.get("next") or "/"
    if not next_url.startswith("/") or next_url.startswith("//"):
        next_url = "/"

    # Si ya está autenticado, redirige al portal
    if request.method == "GET" and _current_user():
        return redirect(next_url)

    error = None
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        display_name = (request.form.get("display_name") or "").strip()

        # Validaciones
        if not email or not password or not display_name:
            error = "Email, contraseña y nombre son obligatorios."
        elif not _valid_email(email):
            error = "Email inválido."
        elif not _valid_password(password):
            error = "La contraseña debe tener al menos 8 caracteres."
        elif len(display_name) > 100:
            error = "Nombre demasiado largo (máximo 100 caracteres)."
        else:
            # ¿Ya existe?
            existing = _db().execute(
                "SELECT id FROM users_global WHERE email = ?", (email,)
            ).fetchone()
            if existing:
                error = "Ya existe una cuenta con ese email. Inicia sesión."
            else:
                # Crear user (email_verified=0 por default; debe verificar antes de login)
                pw_hash = generate_password_hash(password, method="pbkdf2:sha256", salt_length=16)
                # Generar token de verificación (32 bytes hex = 64 chars)
                verification_token = secrets.token_hex(32)
                expires_at = (
                    datetime.now(timezone.utc) + timedelta(hours=24)
                ).isoformat(timespec="seconds")

                cur = _db().execute(
                    "INSERT INTO users_global "
                    "(email, display_name, password_hash, is_admin, must_reset_password, "
                    "email_verified, email_verification_token, email_verification_expires_at) "
                    "VALUES (?, ?, ?, 0, 0, 0, ?, ?)",
                    (email, display_name, pw_hash, verification_token, expires_at),
                )
                new_id = cur.lastrowid
                _db().commit()

                # Inicializar prefs
                _db().execute(
                    "INSERT OR IGNORE INTO user_preferences (user_id) VALUES (?)",
                    (new_id,),
                )
                _db().commit()

                # Mandar email de verificación (no loguear todavía)
                verify_link = (
                    f"{request.scheme}://{request.host}/verify-email"
                    f"?token={verification_token}"
                )
                sent_ok, _err = _send_verification_email(
                    email, verify_link, display_name
                )
                if not sent_ok:
                    log.error(f"Error mandando email de verificación a {email}: {_err}")

                # Mostrar pantalla "revisa tu email" (NO loguear)
                return render_template(
                    "register.html",
                    error=None,
                    next=next_url,
                    just_registered=True,
                    registered_email=email,
                )

    return render_template("register.html", error=error, next=next_url)


@app.route("/api/auth/register", methods=["POST"])
def api_auth_register():
    """JSON variant for API clients / scripts."""
    if not request.is_json:
        return jsonify(ok=False, error="expected_json"), 400
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    display_name = (data.get("display_name") or "").strip()

    if not email or not password or not display_name:
        return jsonify(ok=False, error="missing_fields"), 400
    if not _valid_email(email):
        return jsonify(ok=False, error="invalid_email"), 400
    if not _valid_password(password):
        return jsonify(ok=False, error="weak_password"), 400

    existing = _db().execute(
        "SELECT id FROM users_global WHERE email = ?", (email,)
    ).fetchone()
    if existing:
        return jsonify(ok=False, error="email_taken"), 409

    pw_hash = generate_password_hash(password, method="pbkdf2:sha256", salt_length=16)
    # Generar token de verificación (32 bytes hex = 64 chars)
    verification_token = secrets.token_hex(32)
    expires_at = (
        datetime.now(timezone.utc) + timedelta(hours=24)
    ).isoformat(timespec="seconds")

    cur = _db().execute(
        "INSERT INTO users_global "
        "(email, display_name, password_hash, is_admin, must_reset_password, "
        "email_verified, email_verification_token, email_verification_expires_at) "
        "VALUES (?, ?, ?, 0, 0, 0, ?, ?)",
        (email, display_name, pw_hash, verification_token, expires_at),
    )
    new_id = cur.lastrowid
    _db().commit()
    _db().execute(
        "INSERT OR IGNORE INTO user_preferences (user_id) VALUES (?)",
        (new_id,),
    )
    _db().commit()

    # Mandar email de verificación
    verify_link = (
        f"{request.scheme}://{request.host}/verify-email"
        f"?token={verification_token}"
    )
    sent_ok, _err = _send_verification_email(
        email, verify_link, display_name
    )
    if not sent_ok:
        log.error(f"Error mandando email de verificación a {email}: {_err}")

    # NO logueamos: usuario debe verificar email primero
    return jsonify(
        ok=True,
        message="Cuenta creada. Revisa tu email para activarla.",
        user={
            "id": new_id,
            "email": email,
            "display_name": display_name,
            "email_verified": False,
        },
        verification_required=True,
    ), 201


@app.route("/api/auth/dismiss-chia-prompt", methods=["POST"])
def api_dismiss_chia_prompt():
    """Marca que el user ya vio (y descartó) el prompt de chIA.
    Cookie de 7 días. Aplica solo al user actual."""
    user = _current_user()
    if not user:
        return jsonify(ok=False, error="not_authenticated"), 401
    resp = jsonify(ok=True)
    resp.set_cookie(
        CHIA_PROMPT_COOKIE, "1",
        max_age=7 * 24 * 3600,
        httponly=False,  # JS no lo necesita pero está bien
        samesite="Lax",
        path="/",
    )
    return resp


# ─── Avatar upload ───────────────────────────────────────────────────────

ALLOWED_AVATAR_EXTS = {"png", "jpg", "jpeg", "webp"}
ALLOWED_AVATAR_MIMES = {"image/png", "image/jpeg", "image/webp"}
MAX_AVATAR_BYTES = 2 * 1024 * 1024  # 2 MB


@app.route("/api/auth/avatar", methods=["POST"])
def api_upload_avatar():
    """Upload/replace avatar for the current user. multipart/form-data, field `file`.
    Returns JSON {ok: True, url: "..."}.
    Validates: authenticated user, file present, ≤ 2 MB, image MIME.
    """
    user = _current_user()
    if not user:
        return jsonify(ok=False, error="not_authenticated"), 401

    f = request.files.get("file")
    if not f or not f.filename:
        return jsonify(ok=False, error="no_file"), 400

    # Validate extension
    ext = f.filename.rsplit(".", 1)[-1].lower() if "." in f.filename else ""
    if ext not in ALLOWED_AVATAR_EXTS:
        return jsonify(ok=False, error="bad_extension", allowed=list(ALLOWED_AVATAR_EXTS)), 400

    # Validate MIME (sent by browser)
    mime = (f.mimetype or "").lower()
    if mime not in ALLOWED_AVATAR_MIMES:
        return jsonify(ok=False, error="bad_mime", got=mime), 400

    # Read & size check
    data = f.read()
    if len(data) > MAX_AVATAR_BYTES:
        return jsonify(ok=False, error="too_big", max_bytes=MAX_AVATAR_BYTES), 413
    if len(data) == 0:
        return jsonify(ok=False, error="empty_file"), 400

    # Normalize jpeg → jpg
    ext = "jpg" if ext == "jpeg" else ext

    avatars_dir = Path(__file__).parent / "static" / "avatars"
    avatars_dir.mkdir(parents=True, exist_ok=True)

    # Delete previous avatar file (any extension) for this user
    for old in avatars_dir.glob(f"user_{user['id']}.*"):
        try:
            old.unlink()
        except OSError:
            pass

    rel_path = f"avatars/user_{user['id']}.{ext}"
    abs_path = avatars_dir / f"user_{user['id']}.{ext}"
    abs_path.write_bytes(data)

    # Persist photo_path
    con = _db()
    con.execute("UPDATE users_global SET photo_path = ? WHERE id = ?", (rel_path, user["id"]))
    con.commit()

    return jsonify(ok=True, url=f"/static/{rel_path}")


@app.route("/api/auth/avatar", methods=["DELETE"])
def api_delete_avatar():
    """Remove the avatar for the current user."""
    user = _current_user()
    if not user:
        return jsonify(ok=False, error="not_authenticated"), 401

    con = _db()
    row = con.execute("SELECT photo_path FROM users_global WHERE id = ?", (user["id"],)).fetchone()
    if row and row["photo_path"]:
        abs_path = Path(__file__).parent / "static" / Path(row["photo_path"])
        if abs_path.exists():
            try:
                abs_path.unlink()
            except OSError:
                pass
    con.execute("UPDATE users_global SET photo_path = NULL WHERE id = ?", (user["id"],))
    con.commit()
    return jsonify(ok=True)


@app.route("/api/auth/avatar/<int:user_id>", methods=["GET"])
def api_get_avatar(user_id):
    """Serve the avatar image for a given user. Returns 404 if not set
    (caller should fall back to initial-letter avatar)."""
    con = _db()
    row = con.execute("SELECT photo_path FROM users_global WHERE id = ?", (user_id,)).fetchone()
    if not row or not row["photo_path"]:
        return ("", 404)
    abs_path = Path(__file__).parent / "static" / row["photo_path"]
    if not abs_path.exists():
        return ("", 404)

    ext = abs_path.suffix.lower().lstrip(".")
    mime = {"png": "image/png", "jpg": "image/jpeg", "webp": "image/webp"}.get(ext, "application/octet-stream")

    resp = make_response(abs_path.read_bytes())
    resp.headers["Content-Type"] = mime
    resp.headers["Cache-Control"] = "public, max-age=300"
    return resp


# ─── Password reset (OTP por email) ───────────────────────────────────────

log = logging.getLogger("phantasmaa-auth")
if not log.handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=sys.stderr,
    )

# Config Resend (free tier: 100 emails/día)
RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
RESEND_FROM = os.environ.get(
    "RESEND_FROM", "Phantasma support <onboarding@resend.dev>"
)
RESEND_EMAIL_DEV_MODE = os.environ.get(
    "RESEND_EMAIL_DEV_MODE", "0"
) == "1"  # Si True, loguea el OTP en vez de mandar email real

# TTL y rate limiting
OTP_TTL_SECONDS = 15 * 60        # 15 min para el código de 6 dígitos
RESET_TOKEN_TTL_SECONDS = 10 * 60  # 10 min para el token de reset
RATE_LIMIT_EMAIL_PER_HOUR = 3
RATE_LIMIT_IP_PER_HOUR = 10


def _hash_otp(code: str, salt: bytes = b"") -> tuple[str, bytes]:
    """Hash PBKDF2 para el OTP. Retorna (hash_str, salt_bytes)."""
    if not salt:
        salt = secrets.token_bytes(16)
    hk = hashlib.pbkdf2_hmac(
        "sha256", code.encode(), salt, 200_000
    )
    # formato: pbkdf2$salt-b64$hash-b64
    return (f"pbkdf2${base64_url(salt)}${base64_url(hk)}", salt)


def _verify_otp(code: str, stored: str) -> bool:
    try:
        algo, salt_b64, hash_b64 = stored.split("$")
        if algo != "pbkdf2":
            return False
        salt = hashlib_b64decode(salt_b64)
        expected = hashlib_b64decode(hash_b64)
    except Exception:
        return False
    candidate = hashlib.pbkdf2_hmac(
        "sha256", code.encode(), salt, 200_000
    )
    return hmac.compare_digest(candidate, expected)


def base64_url(data: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def hashlib_b64decode(s: str) -> bytes:
    import base64
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _client_ip() -> str:
    fwd = request.headers.get("X-Forwarded-For", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.remote_addr or ""


def _rate_limit_check(email: str) -> tuple[bool, str]:
    """Check rate limits: 3/hora por email y 10/hora por IP. Returns (ok, msg)."""
    con = _db()
    cutoff = (
        datetime.now(timezone.utc) - timedelta(hours=1)
    ).strftime("%Y-%m-%d %H:%M:%S")
    ip = _client_ip()

    by_email = con.execute(
        "SELECT COUNT(*) FROM password_resets WHERE email = ? AND created_at > ?",
        (email, cutoff)
    ).fetchone()[0]
    if by_email >= RATE_LIMIT_EMAIL_PER_HOUR:
        return False, "Demasiados intentos. Esperá una hora antes de pedir otro código."

    if ip:
        by_ip = con.execute(
            "SELECT COUNT(*) FROM password_resets WHERE request_ip = ? AND created_at > ?",
            (ip, cutoff)
        ).fetchone()[0]
        if by_ip >= RATE_LIMIT_IP_PER_HOUR:
            return False, "Demasiados intentos desde esta IP. Esperá una hora."

    return True, ""


def _send_otp_email(to_email: str, code: str, display_name: str = "") -> tuple[bool, str]:
    """Envía OTP por Resend. Returns (ok, error_message)."""

    # Modo dev: loguea el OTP en lugar de mandar email real
    if RESEND_EMAIL_DEV_MODE or not RESEND_API_KEY:
        if RESEND_EMAIL_DEV_MODE:
            log.warning(f"[DEV MODE] OTP para {to_email}: {code}")
        else:
            log.warning(
                f"[NO RESEND] OTP para {to_email}: {code} "
                f"(RESEND_API_KEY no configurada — seteala para enviar emails reales)"
            )
        return True, ""

    subject = "Tu código de recuperación — phantasma.dev"
    greeting = f"Hola {display_name}" if display_name else "Hola"
    text_body = (
        f"{greeting},\n\n"
        f"Recibimos una solicitud para restablecer la contraseña de tu cuenta "
        f"en phantasma.dev.\n\n"
        f"Tu código de verificación es:\n\n"
        f"    {code}\n\n"
        f"Este código expira en 15 minutos. Si no lo usas, tendrás que pedir "
        f"uno nuevo.\n\n"
        f"Si no pediste este código, puedes ignorar este mensaje — tu cuenta "
        f"está segura.\n\n"
        f"— Equipo phantasma.dev\n"
    )
    html_body = (
        f"<div style='font-family:Inter,Arial,sans-serif;max-width:480px;"
        f"margin:0 auto;padding:2rem;background:#0a0a0a;color:#e0e0e0;"
        f"border-radius:12px;border:1px solid #ff0000;'>"
        f"<h2 style='color:#ff0000;margin:0 0 1rem;'>{greeting},</h2>"
        f"<p style='margin:0 0 1.5rem;'>Recibimos una solicitud para restablecer "
        f"la contraseña de tu cuenta en <strong>phantasma.dev</strong>.</p>"
        f"<div style='background:#1a1a1a;border:2px solid #ff0000;border-radius:8px;"
        f"padding:1.5rem;text-align:center;margin:1.5rem 0;'>"
        f"<span style='font-family:JetBrains Mono,Courier New,monospace;"
        f"font-size:2rem;font-weight:bold;color:#ff0000;letter-spacing:0.5em;'>"
        f"{code}</span>"
        f"</div>"
        f"<p style='margin:1.5rem 0;font-size:0.875rem;color:#999;'>"
        f"Este código expira en <strong>15 minutos</strong>. Si no lo usas, "
        f"tendrás que pedir uno nuevo.</p>"
        f"<p style='margin:1.5rem 0 0;font-size:0.875rem;color:#999;'>"
        f"Si no pediste este código, puedes ignorar este mensaje — tu cuenta "
        f"está segura.</p>"
        f"</div>"
    )

    payload = {
        "from": RESEND_FROM,
        "to": [to_email],
        "subject": subject,
        "text": text_body,
        "html": html_body,
    }

    req = urllib.request.Request(
        "https://api.resend.com/emails",
        data=json.dumps(payload).encode(),
        headers={
            "Authorization": f"Bearer {RESEND_API_KEY}",
            "Content-Type": "application/json",
            "User-Agent": "phantasmaa-auth/1.0 (+https://phantasma.dev)",
        },
        method="POST",
    )
    log.info(f"[resend] POST → {to_email} code={code} (api_key=***)")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode(errors="ignore")[:300]
            if resp.status in (200, 201):
                log.info(f"[resend] OK → {to_email} status={resp.status} body={body}")
                return True, ""
            log.error(f"[resend] NON-2xx → {to_email} status={resp.status} body={body}")
            return False, f"Resend devolvió {resp.status}: {body}"
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="ignore")[:300]
        log.error(f"[resend] HTTPError → {to_email} code={e.code} body={body}")
        return False, f"Resend HTTP {e.code}: {body}"
    except Exception as e:
        return False, f"Error de red: {type(e).__name__}: {e}"


def _send_verification_email(to_email: str, verification_link: str, display_name: str = "") -> tuple[bool, str]:
    """Envía email de verificación de cuenta nueva. Returns (ok, error_message)."""

    if RESEND_EMAIL_DEV_MODE or not RESEND_API_KEY:
        if RESEND_EMAIL_DEV_MODE:
            log.warning(f"[DEV MODE] Verification link para {to_email}: {verification_link}")
        else:
            log.warning(f"[NO RESEND] Verification link para {to_email}: {verification_link}")
        return True, ""

    subject = "Verifica tu email — phantasma.dev"
    greeting = f"Hola {display_name}" if display_name else "Hola"
    text_body = (
        f"{greeting},\n\n"
        f"Para activar tu cuenta en phantasma.dev, hace clic en el siguiente enlace:\n\n"
        f"    {verification_link}\n\n"
        f"Este enlace expira en 24 horas. Si no lo usas, puedes pedir uno nuevo "
        f"desde la pantalla de login.\n\n"
        f"Si no creaste esta cuenta, puedes ignorar este mensaje.\n\n"
        f"— Equipo phantasma.dev\n"
    )
    html_body = (
        f"<div style='font-family:Inter,Arial,sans-serif;max-width:480px;"
        f"margin:0 auto;padding:2rem;background:#0a0a0a;color:#e0e0e0;"
        f"border-radius:12px;border:1px solid #ff0000;'>"
        f"<h2 style='color:#ff0000;margin:0 0 1rem;'>{greeting},</h2>"
        f"<p style='margin:0 0 1.5rem;'>Bienvenido a <strong>phantasma.dev</strong>. "
        f"Para activar tu cuenta, hace clic en el botón:</p>"
        f"<div style='text-align:center;margin:2rem 0;'>"
        f"<a href='{verification_link}' style='display:inline-block;background:#ff0000;"
        f"color:#fff;padding:0.875rem 2rem;border-radius:8px;text-decoration:none;"
        f"font-weight:bold;'>Verificar mi email</a>"
        f"</div>"
        f"<p style='margin:1.5rem 0;font-size:0.875rem;color:#999;'>"
        f"O copia y pega este enlace en tu navegador:</p>"
        f"<p style='margin:0 0 1.5rem;font-family:JetBrains Mono,Courier New,monospace;"
        f"font-size:0.75rem;color:#999;word-break:break-all;'>{verification_link}</p>"
        f"<p style='margin:1.5rem 0;font-size:0.875rem;color:#999;'>"
        f"Este enlace expira en <strong>24 horas</strong>.</p>"
        f"<p style='margin:1.5rem 0 0;font-size:0.875rem;color:#999;'>"
        f"Si no creaste esta cuenta, puedes ignorar este mensaje.</p>"
        f"</div>"
    )

    payload = {
        "from": RESEND_FROM,
        "to": [to_email],
        "subject": subject,
        "text": text_body,
        "html": html_body,
    }

    req = urllib.request.Request(
        "https://api.resend.com/emails",
        data=json.dumps(payload).encode(),
        headers={
            "Authorization": f"Bearer {RESEND_API_KEY}",
            "Content-Type": "application/json",
            "User-Agent": "phantasmaa-auth/1.0 (+https://phantasma.dev)",
        },
        method="POST",
    )
    log.info(f"[resend] POST verify → {to_email} (api_key=***)")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode(errors="ignore")[:300]
            if resp.status in (200, 201):
                log.info(f"[resend] OK verify → {to_email} status={resp.status} body={body}")
                return True, ""
            log.error(f"[resend] NON-2xx verify → {to_email} status={resp.status} body={body}")
            return False, f"Resend devolvió {resp.status}: {body}"
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="ignore")[:300]
        log.error(f"[resend] HTTPError verify → {to_email} code={e.code} body={body}")
        return False, f"Resend HTTP {e.code}: {body}"
    except Exception as e:
        return False, f"Error de red: {type(e).__name__}: {e}"


# ─── Email verification (cuenta nueva) ───────────────────────────────────

@app.route("/verify-email", methods=["GET"])
def verify_email():
    """Página que se abre cuando el usuario hace clic en el link de verificación."""
    token = (request.args.get("token") or "").strip()
    error = None
    success = False

    if not token:
        error = "Falta el token de verificación."
    else:
        row = _db().execute(
            "SELECT id, email, display_name, email_verified, email_verification_expires_at "
            "FROM users_global WHERE email_verification_token = ?",
            (token,),
        ).fetchone()
        if not row:
            error = "Token inválido o ya usado."
        elif row["email_verified"]:
            success = True  # ya estaba verificado
        else:
            try:
                expires_dt = datetime.fromisoformat(row["email_verification_expires_at"])
                # DB guarda naive (asumimos UTC) — agregar timezone si falta
                if expires_dt.tzinfo is None:
                    expires_dt = expires_dt.replace(tzinfo=timezone.utc)
                if expires_dt < datetime.now(timezone.utc):
                    error = "El token expiró. Pide uno nuevo desde la pantalla de login."
            except Exception:
                error = "Token con formato inválido."

            if not error:
                _db().execute(
                    "UPDATE users_global "
                    "SET email_verified = 1, email_verification_token = NULL, "
                    "email_verification_expires_at = NULL WHERE id = ?",
                    (row["id"],),
                )
                _db().commit()
                success = True
                log.info(f"Email verificado: {row['email']} (user_id={row['id']})")

    return render_template(
        "verify_email.html",
        success=success,
        error=error,
    )


@app.route("/api/auth/verify-email", methods=["POST"])
def api_verify_email():
    """JSON variant para API clients."""
    token = ""
    if request.is_json:
        token = (request.get_json() or {}).get("token", "").strip()
    else:
        token = (request.form.get("token") or "").strip()

    if not token:
        return jsonify(ok=False, error="missing_token"), 400

    row = _db().execute(
        "SELECT id, email, email_verified, email_verification_expires_at "
        "FROM users_global WHERE email_verification_token = ?",
        (token,),
    ).fetchone()
    if not row:
        return jsonify(ok=False, error="invalid_token"), 404
    if row["email_verified"]:
        return jsonify(ok=True, message="Email ya estaba verificado"), 200

    try:
        expires_dt = datetime.fromisoformat(row["email_verification_expires_at"])
        # DB guarda naive (asumimos UTC) — agregar timezone si falta
        if expires_dt.tzinfo is None:
            expires_dt = expires_dt.replace(tzinfo=timezone.utc)
        if expires_dt < datetime.now(timezone.utc):
            return jsonify(ok=False, error="token_expired"), 410
    except Exception:
        return jsonify(ok=False, error="invalid_token_format"), 400

    _db().execute(
        "UPDATE users_global "
        "SET email_verified = 1, email_verification_token = NULL, "
        "email_verification_expires_at = NULL WHERE id = ?",
        (row["id"],),
    )
    _db().commit()
    return jsonify(ok=True, message="Email verificado"), 200


@app.route("/api/auth/resend-verification", methods=["POST"])
def api_resend_verification():
    """Reenvía el email de verificación. Anti-enumeration + rate-limited."""
    email = ""
    if request.is_json:
        email = (request.get_json() or {}).get("email", "").strip().lower()
    else:
        email = (request.form.get("email") or "").strip().lower()

    # Mensaje genérico (anti-enumeration)
    generic = jsonify(ok=True, message="Si el email está registrado y pendiente de verificar, recibirás un nuevo link."), 200

    if not _valid_email(email):
        return generic

    row = _db().execute(
        "SELECT id, email, display_name, email_verified FROM users_global WHERE email = ?",
        (email,),
    ).fetchone()

    if not row or row["email_verified"]:
        return generic

    # Rate limit por email
    ok, msg = _rate_limit_check(email)
    if not ok:
        return jsonify(ok=False, error="rate_limited", message=msg), 429

    # Generar nuevo token
    new_token = secrets.token_hex(32)
    new_expires = (
        datetime.now(timezone.utc) + timedelta(hours=24)
    ).isoformat(timespec="seconds")
    _db().execute(
        "UPDATE users_global SET email_verification_token = ?, "
        "email_verification_expires_at = ? WHERE id = ?",
        (new_token, new_expires, row["id"]),
    )
    _db().commit()

    verify_link = (
        f"{request.scheme}://{request.host}/verify-email?token={new_token}"
    )
    sent_ok, _err = _send_verification_email(
        email, verify_link, row["display_name"]
    )
    if not sent_ok:
        log.error(f"Error reenviando email de verificación a {email}: {_err}")
        return jsonify(ok=False, error="send_failed"), 502

    return jsonify(ok=True, message="Email de verificación reenviado."), 200


@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    """Form HTML para 'olvidé mi contraseña' (3 pasos en una sola página)."""
    step = request.args.get("step") or "email"
    email = (request.form.get("email") or request.args.get("email") or "").strip().lower()

    if request.method == "GET":
        return render_template(
            "forgot.html", step=step, email=email,
            error=None, message=None, token=request.args.get("token") or ""
        )

    # POST: depende del paso
    action = request.form.get("action") or ""

    if action == "send_code":
        if not _valid_email(email):
            return render_template(
                "forgot.html", step="email", email="",
                error="Email inválido.", message=None, token=""
            ), 400

        row = _db().execute(
            "SELECT id, display_name FROM users_global WHERE email = ?",
            (email,)
        ).fetchone()

        # Anti-enumeration: solo mandamos código si el email existe
        if row:
            ok, msg = _rate_limit_check(email)
            if not ok:
                return render_template(
                    "forgot.html", step="email", email="",
                    error=msg, message=None, token=""
                ), 429

            # Generar OTP 6 dígitos
            code = f"{secrets.randbelow(1_000_000):06d}"
            code_hash, _salt = _hash_otp(code)
            expires_at = (
                datetime.now(timezone.utc) + timedelta(seconds=OTP_TTL_SECONDS)
            ).strftime("%Y-%m-%d %H:%M:%S")
            ip = _client_ip()

            # Invalidar códigos anteriores no usados
            _db().execute(
                "UPDATE password_resets SET used_at = datetime('now') "
                "WHERE email = ? AND used_at IS NULL AND verified_at IS NULL",
                (email,)
            )
            _db().execute(
                "INSERT INTO password_resets "
                "(user_id, email, code_hash, expires_at, request_ip) "
                "VALUES (?, ?, ?, ?, ?)",
                (row["id"], email, code_hash, expires_at, ip)
            )
            _db().commit()

            sent_ok, err_msg = _send_otp_email(
                email, code, row["display_name"]
            )
            if not sent_ok:
                log.error(f"Error enviando OTP a {email}: {err_msg}")
                # No leak detalle al user; mensaje genérico
                return render_template(
                    "forgot.html", step="email", email="",
                    error="No pudimos enviar el código. Prueba de nuevo en unos minutos.",
                    message=None, token=""
                ), 502

        # Siempre devolvemos éxito (anti-enumeration)
        return render_template(
            "forgot.html", step="code", email=email,
            error=None, message=(
                "Si el email está registrado, te enviamos un código de 6 dígitos. "
                "Revisa tu bandeja de entrada y spam."
            ),
            token=""
        )

    elif action == "verify_code":
        code = (request.form.get("code") or "").strip()
        if not email or not code or len(code) != 6 or not code.isdigit():
            return render_template(
                "forgot.html", step="code", email=email,
                error="Código inválido (6 dígitos).", message=None, token=""
            ), 400

        # Buscar el código más reciente no usado y no expirado
        row = _db().execute(
            "SELECT id, user_id, code_hash, expires_at FROM password_resets "
            "WHERE email = ? AND verified_at IS NULL AND used_at IS NULL "
            "ORDER BY id DESC LIMIT 1",
            (email,)
        ).fetchone()

        if not row or not _verify_otp(code, row["code_hash"]):
            return render_template(
                "forgot.html", step="code", email=email,
                error="Código incorrecto o expirado.", message=None, token=""
            ), 401

        # Verificar expiración
        try:
            exp_dt = datetime.strptime(
                row["expires_at"], "%Y-%m-%d %H:%M:%S"
            ).replace(tzinfo=timezone.utc)
        except ValueError:
            exp_dt = datetime.now(timezone.utc)
        if exp_dt < datetime.now(timezone.utc):
            return render_template(
                "forgot.html", step="code", email=email,
                error="El código expiró. Pide uno nuevo.",
                message=None, token=""
            ), 410

        # Generar reset_token
        token = secrets.token_urlsafe(32)
        token_hash, _salt = _hash_otp(token)
        reset_expires_at = (
            datetime.now(timezone.utc) + timedelta(seconds=RESET_TOKEN_TTL_SECONDS)
        ).strftime("%Y-%m-%d %H:%M:%S")

        _db().execute(
            "UPDATE password_resets SET verified_at = datetime('now'), "
            "reset_token_hash = ?, reset_expires_at = ? WHERE id = ?",
            (token_hash, reset_expires_at, row["id"])
        )
        _db().commit()

        return render_template(
            "forgot.html", step="reset", email=email,
            error=None, message="Código verificado. Define tu nueva contraseña.",
            token=token
        )

    elif action == "reset_password":
        token = (request.form.get("token") or "").strip()
        new_pw = request.form.get("new_password") or ""
        confirm_pw = request.form.get("confirm_password") or ""

        if not email or not token:
            return render_template(
                "forgot.html", step="code", email=email,
                error="Sesión expirada. Empieza de nuevo.",
                message=None, token=""
            ), 401

        if not _valid_password(new_pw):
            return render_template(
                "forgot.html", step="reset", email=email, token=token,
                error="La contraseña debe tener al menos 8 caracteres.",
                message=None
            ), 400
        if new_pw != confirm_pw:
            return render_template(
                "forgot.html", step="reset", email=email, token=token,
                error="Las contraseñas no coinciden.",
                message=None
            ), 400

        # Validar token
        row = _db().execute(
            "SELECT id, user_id, reset_token_hash, reset_expires_at "
            "FROM password_resets WHERE email = ? AND used_at IS NULL "
            "AND reset_token_hash IS NOT NULL "
            "ORDER BY id DESC LIMIT 1",
            (email,)
        ).fetchone()
        if not row or not _verify_otp(token, row["reset_token_hash"]):
            return render_template(
                "forgot.html", step="code", email=email,
                error="Token inválido o expirado. Empieza de nuevo.",
                message=None, token=""
            ), 401

        try:
            exp_dt = datetime.strptime(
                row["reset_expires_at"], "%Y-%m-%d %H:%M:%S"
            ).replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            exp_dt = datetime.now(timezone.utc)
        if exp_dt < datetime.now(timezone.utc):
            return render_template(
                "forgot.html", step="code", email=email,
                error="El token expiró. Pide un código nuevo.",
                message=None, token=""
            ), 410

        # Aplicar cambio
        new_hash = generate_password_hash(
            new_pw, method='pbkdf2:sha256', salt_length=16
        )
        _db().execute(
            "UPDATE users_global SET password_hash = ?, must_reset_password = 0 "
            "WHERE id = ?",
            (new_hash, row["user_id"])
        )
        _db().execute(
            "UPDATE password_resets SET used_at = datetime('now') WHERE id = ?",
            (row["id"],)
        )
        # Invalidar TODOS los resets no usados de ese user (defensive)
        _db().execute(
            "UPDATE password_resets SET used_at = datetime('now') "
            "WHERE user_id = ? AND used_at IS NULL",
            (row["user_id"],)
        )
        _db().commit()

        return render_template(
            "forgot.html", step="done", email=email,
            error=None, message=(
                "Contraseña actualizada. Ya puedes iniciar sesión con tu nueva clave."
            ),
            token=""
        )

    else:
        return render_template(
            "forgot.html", step="email", email="",
            error=None, message=None, token=""
        )


@app.route("/api/auth/forgot", methods=["POST"])
def api_forgot():
    if not request.is_json:
        return jsonify(ok=False, error="expected_json"), 400
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    if not _valid_email(email):
        return jsonify(ok=False, error="invalid_email"), 400

    row = _db().execute(
        "SELECT id, display_name FROM users_global WHERE email = ?",
        (email,)
    ).fetchone()
    if row:
        ok, msg = _rate_limit_check(email)
        if not ok:
            return jsonify(ok=False, error="rate_limited", message=msg), 429

        code = f"{secrets.randbelow(1_000_000):06d}"
        code_hash, _ = _hash_otp(code)
        expires_at = (
            datetime.now(timezone.utc) + timedelta(seconds=OTP_TTL_SECONDS)
        ).strftime("%Y-%m-%d %H:%M:%S")
        ip = _client_ip()

        _db().execute(
            "UPDATE password_resets SET used_at = datetime('now') "
            "WHERE email = ? AND used_at IS NULL AND verified_at IS NULL",
            (email,)
        )
        _db().execute(
            "INSERT INTO password_resets "
            "(user_id, email, code_hash, expires_at, request_ip) "
            "VALUES (?, ?, ?, ?, ?)",
            (row["id"], email, code_hash, expires_at, ip)
        )
        _db().commit()

        sent_ok, err_msg = _send_otp_email(email, code, row["display_name"])
        if not sent_ok:
            log.error(f"Error enviando OTP a {email}: {err_msg}")
            return jsonify(ok=False, error="send_failed"), 502

    return jsonify(ok=True,
                   message="Si el email está registrado, recibirás un código.")


@app.route("/api/auth/forgot/verify", methods=["POST"])
def api_forgot_verify():
    if not request.is_json:
        return jsonify(ok=False, error="expected_json"), 400
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    code = (data.get("code") or "").strip()

    if not email or len(code) != 6 or not code.isdigit():
        return jsonify(ok=False, error="bad_request"), 400

    row = _db().execute(
        "SELECT id, code_hash, expires_at FROM password_resets "
        "WHERE email = ? AND verified_at IS NULL AND used_at IS NULL "
        "ORDER BY id DESC LIMIT 1",
        (email,)
    ).fetchone()
    if not row or not _verify_otp(code, row["code_hash"]):
        return jsonify(ok=False, error="invalid_code"), 401

    try:
        exp_dt = datetime.strptime(
            row["expires_at"], "%Y-%m-%d %H:%M:%S"
        ).replace(tzinfo=timezone.utc)
    except ValueError:
        return jsonify(ok=False, error="invalid_code"), 401
    if exp_dt < datetime.now(timezone.utc):
        return jsonify(ok=False, error="expired"), 410

    token = secrets.token_urlsafe(32)
    token_hash, _ = _hash_otp(token)
    reset_expires_at = (
        datetime.now(timezone.utc) + timedelta(seconds=RESET_TOKEN_TTL_SECONDS)
    ).strftime("%Y-%m-%d %H:%M:%S")
    _db().execute(
        "UPDATE password_resets SET verified_at = datetime('now'), "
        "reset_token_hash = ?, reset_expires_at = ? WHERE id = ?",
        (token_hash, reset_expires_at, row["id"])
    )
    _db().commit()
    return jsonify(ok=True, reset_token=token,
                   expires_in=RESET_TOKEN_TTL_SECONDS)


@app.route("/api/auth/forgot/reset", methods=["POST"])
def api_forgot_reset():
    if not request.is_json:
        return jsonify(ok=False, error="expected_json"), 400
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    token = (data.get("reset_token") or "").strip()
    new_pw = data.get("new_password") or ""

    if not email or not token or not _valid_password(new_pw):
        return jsonify(ok=False, error="bad_request"), 400

    row = _db().execute(
        "SELECT id, user_id, reset_token_hash, reset_expires_at "
        "FROM password_resets WHERE email = ? AND used_at IS NULL "
        "AND reset_token_hash IS NOT NULL "
        "ORDER BY id DESC LIMIT 1",
        (email,)
    ).fetchone()
    if not row or not _verify_otp(token, row["reset_token_hash"]):
        return jsonify(ok=False, error="invalid_token"), 401

    try:
        exp_dt = datetime.strptime(
            row["reset_expires_at"], "%Y-%m-%d %H:%M:%S"
        ).replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return jsonify(ok=False, error="invalid_token"), 401
    if exp_dt < datetime.now(timezone.utc):
        return jsonify(ok=False, error="expired"), 410

    new_hash = generate_password_hash(
        new_pw, method='pbkdf2:sha256', salt_length=16
    )
    _db().execute(
        "UPDATE users_global SET password_hash = ?, must_reset_password = 0 "
        "WHERE id = ?",
        (new_hash, row["user_id"])
    )
    _db().execute(
        "UPDATE password_resets SET used_at = datetime('now') WHERE id = ?",
        (row["id"],)
    )
    _db().execute(
        "UPDATE password_resets SET used_at = datetime('now') "
        "WHERE user_id = ? AND used_at IS NULL",
        (row["user_id"],)
    )
    _db().commit()
    return jsonify(ok=True)


# ─── Run ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 8200))
    app.run(host="127.0.0.1", port=port, debug=False)
