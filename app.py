"""
Phantasmaa SSO — single login for the whole suite.

This service is the auth authority for chordbook, pennypath, pdf-tools,
and any other app behind the nginx front. It exposes three things:

  GET  /login              → login form (or 302 if already authed)
  POST /login              → verify password, set cookie, redirect to ?next
  POST /logout             → clear cookie, redirect to /login
  GET  /api/whoami         → JSON: {authenticated, id, username, is_admin}
  *     /auth/verify       → nginx auth_request endpoint. Always 200 with
                             X-Phantasmaa-User / X-Phantasmaa-Admin headers
                             if the cookie is valid; 401 otherwise.

Auth backend: the SAME `usuarios` table that pennypath (mis-finanzas) owns,
in /root/finanzas/finanzas.db. Single source of truth — change password in
finanzas, it changes here. Register a user, they get access everywhere.

Cookie: HMAC-signed `auth_token` containing `user_id.signature`. Survives
90 days. SameSite=Lax, HttpOnly.
"""
import hmac
import hashlib
import os
from datetime import timedelta, datetime
from pathlib import Path

from flask import (
    Flask, redirect, render_template, request, jsonify,
    make_response, url_for, g,
)
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user
from sqlalchemy import (
    create_engine, Column, Integer, String, Boolean, DateTime,
)
from sqlalchemy.orm import sessionmaker, scoped_session, declarative_base
from werkzeug.security import check_password_hash, generate_password_hash


# ─── Config ───────────────────────────────────────────────────────────────

SHARED_USERS_DB = Path(os.environ.get(
    "FINANZAS_DB", "/root/finanzas/finanzas.db"
))

# One secret to sign auth_token cookies. If you want to rotate, all apps
# must restart at the same time or sessions break. Set PHANTASMAA_AUTH_SECRET
# in the environment (e.g. systemd unit) for production.
SIGNING_SECRET = os.environ.get(
    "PHANTASMAA_AUTH_SECRET",
    "phantasmaa-dev-secret-rotate-me-in-prod"
)


# Cookie name. Apps can read it if they want to identify the user without
# going through nginx.
COOKIE_NAME = "phantasmaa_auth"
COOKIE_MAX_AGE = 90 * 24 * 3600  # 90 days


# ─── Database ─────────────────────────────────────────────────────────────

Base = declarative_base()


class User(UserMixin, Base):
    """Mirror of pennypath's `usuarios` table. Read-only from this side —
    we never INSERT/UPDATE/DELETE here, pennypath owns it."""
    __tablename__ = "usuarios"

    id            = Column(Integer, primary_key=True)
    username      = Column(String(80),  unique=True, nullable=False)
    password_hash = Column(String(200), nullable=False)
    nombre        = Column(String(100))
    email         = Column(String(120))
    is_admin      = Column(Boolean, nullable=False, default=False)
    created_at    = Column(DateTime)


_engine = create_engine(
    f"sqlite:///{SHARED_USERS_DB}",
    connect_args={"check_same_thread": False},
    pool_pre_ping=True,
)
_UsersSession = scoped_session(sessionmaker(bind=_engine, autoflush=False, autocommit=False))


# ─── App factory ──────────────────────────────────────────────────────────

app = Flask(__name__, template_folder="/root/phantasmaa-auth/templates",
            static_folder="/root/phantasmaa-auth/static")
app.config["SECRET_KEY"] = SIGNING_SECRET
app.config["SESSION_COOKIE_NAME"] = "phantasmaa_sso_session"
app.config["REMEMBER_COOKIE_DURATION"] = timedelta(days=90)
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=90)
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_HTTPONLY"] = True

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.login_message = None
login_manager.init_app(app)


@login_manager.user_loader
def _load(uid):
    return _UsersSession().get(User, int(uid))


@app.teardown_appcontext
def _close_session(exc=None):
    _UsersSession.remove()


# ─── Token signing ────────────────────────────────────────────────────────

def _sign(user_id: int) -> str:
    """HMAC-SHA256 of user_id with the SIGNING_SECRET. The token is
    `{user_id}.{sig_hex}`."""
    key = SIGNING_SECRET.encode() if isinstance(SIGNING_SECRET, str) else SIGNING_SECRET
    sig = hmac.new(key, str(user_id).encode(), hashlib.sha256).hexdigest()
    return f"{user_id}.{sig}"


def _verify(token: str):
    """Return (user_id, signature) if the token is well-formed and the
    signature is valid. None otherwise."""
    if not token or "." not in token:
        return None
    user_id_s, sig = token.rsplit(".", 1)
    try:
        user_id = int(user_id_s)
    except ValueError:
        return None
    key = SIGNING_SECRET.encode() if isinstance(SIGNING_SECRET, str) else SIGNING_SECRET
    expected = hmac.new(key, str(user_id).encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return None
    return (user_id, sig)


# ─── Routes ───────────────────────────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    # `next` is the URL the user wanted to reach before being redirected
    # here. After successful login we redirect back to it.
    next_url = request.args.get("next") or request.form.get("next") or "/"

    if request.method == "POST":
        # Form submit (regular browser) or JSON (programmatic)
        if request.is_json:
            data = request.get_json() or {}
            username = (data.get("username") or "").strip()
            password = data.get("password") or ""
        else:
            username = (request.form.get("username") or "").strip()
            password = request.form.get("password") or ""

        if not username or not password:
            if request.headers.get("X-Phantasmaa-Async"):
                return jsonify(ok=False, error="missing_credentials"), 400
            return render_template("login.html", error="Falta usuario o contraseña", next=next_url)

        user = _UsersSession().query(User).filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user, remember=True, duration=timedelta(days=90))
            # Set the auth_token cookie that nginx will validate
            token = _sign(user.id)
            # For JSON clients, return 200 + the token so they can set it
            # themselves (curl, scripts).
            if request.headers.get("X-Phantasmaa-Async") or request.is_json:
                resp = jsonify(ok=True, username=user.username,
                              is_admin=bool(user.is_admin), auth_token=token)
                resp.set_cookie(
                    COOKIE_NAME, token,
                    max_age=COOKIE_MAX_AGE,
                    httponly=True,
                    samesite="Lax",
                    path="/",
                )
                return resp, 200
            # Browser: redirect to ?next
            resp = make_response(redirect(next_url))
            resp.set_cookie(
                COOKIE_NAME, token,
                max_age=COOKIE_MAX_AGE,
                httponly=True,
                samesite="Lax",
                path="/",
            )
            return resp

        if request.headers.get("X-Phantasmaa-Async") or request.is_json:
            return jsonify(ok=False, error="bad_credentials"), 401
        return render_template("login.html", error="Usuario o contraseña incorrectos", next=next_url)

    # GET: show login form. If already authed via token, redirect to next.
    token = request.cookies.get(COOKIE_NAME)
    if token:
        verified = _verify(token)
        if verified:
            user = _UsersSession().get(User, verified[0])
            if user:
                return redirect(next_url)
    return render_template("login.html", error=None, next=next_url)


@app.route("/logout", methods=["GET", "POST"])
def logout():
    next_url = request.args.get("next", "/login")
    logout_user()
    resp = make_response(redirect(next_url))
    resp.delete_cookie(COOKIE_NAME, path="/")
    resp.delete_cookie("phantasmaa_sso_session", path="/")
    return resp


@app.route("/api/whoami")
def whoami():
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return jsonify(authenticated=False), 401
    verified = _verify(token)
    if not verified:
        return jsonify(authenticated=False), 401
    user = _UsersSession().get(User, verified[0])
    if not user:
        return jsonify(authenticated=False), 401
    return jsonify(
        authenticated=True,
        id=user.id,
        username=user.username,
        nombre=user.nombre,
        is_admin=bool(user.is_admin),
    )


# ─── nginx auth_request endpoint ──────────────────────────────────────────

@app.route("/auth/verify")
def auth_verify():
    """Called by nginx BEFORE the request reaches a protected app.

    Returns 200 with X-User-Id, X-Username, X-Is-Admin headers if authed.
    Returns 401 if not authed. The nginx config uses auth_request_set to
    capture these headers and forward them to the upstream app as
    `X-Phantasmaa-User` and `X-Phantasmaa-Admin`."""
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return _unauth()
    verified = _verify(token)
    if not verified:
        return _unauth()
    user = _UsersSession().get(User, verified[0])
    if not user:
        return _unauth()

    resp = make_response("", 200)
    resp.headers["X-User-Id"] = str(user.id)
    resp.headers["X-Username"] = user.username
    resp.headers["X-Is-Admin"] = "1" if user.is_admin else "0"
    return resp


def _unauth():
    resp = make_response(jsonify(error="unauthorized", login_url="/login"), 401)
    return resp


# ─── Health ───────────────────────────────────────────────────────────────

@app.route("/healthz")
def healthz():
    return jsonify(status="ok", time=datetime.utcnow().isoformat())


# ─── Run directly (for dev) ───────────────────────────────────────────────

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8200)
