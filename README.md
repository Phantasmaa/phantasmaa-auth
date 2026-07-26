# Panoplia · Phantasmaa SSO

Single sign-on portal for the entire Phantasmaa suite. Serves the
landing page, authenticates users, and acts as a PWA launcher into
the upstream apps (MeTube, PDF Tools, Chordbook, etc.).

## What it does

- **SSO auth** — HMAC-signed cookies that nginx `auth_request` validates
  for every protected app site.
- **Admin user panel** at `/admin/users` — CRUD on the shared
  `usuarios` table with role toggling, password reset, last-login
  tracking.
- **Self-service account** at `/account` — change your own password.
- **PWA launcher** at `/` — installs as "Panoplia" on Android/iOS home
  screen, opens full-screen, has app shortcuts to MeTube, PDF Tools,
  Chordbook.

## Quick start

```bash
# Dev
python3 -m app    # listens on 127.0.0.1:8200

# Production (systemd)
systemctl status phantasmaa-auth
```

## Install as a phone app

1. Open `http://173.249.3.113:8100/` in Chrome on Android (or Safari
   on iOS).
2. Chrome shows "Add Panoplia to Home screen" in the menu. Tap it.
3. Icon appears on your home screen. Tapping it opens Panoplia
   full-screen — no browser chrome, no address bar.

The same manifest works for iOS Safari (via `apple-touch-icon` meta
tags) and for Windows Edge (via `msapplication-TileColor`).

## Files

```
app.py                  Flask app: auth, admin, account, PWA shortcuts
templates/index.html    Landing page (PWA shell)
templates/login.html    Login form
templates/account.html  Self-service account page
templates/admin/users.html  Admin user management panel
static/manifest.json    PWA manifest (name, icons, shortcuts)
static/sw.js            Service worker (app-shell caching)
static/icons/           PWA icons: 192, 512, 512-maskable, apple-touch, favicon
```

## Endpoints

- `GET /` — landing page (PWA shell)
- `GET /login` — login form
- `POST /login` — JSON or form, sets `phantasmaa_auth` cookie
- `POST /logout` — clears cookie
- `GET /api/whoami` — JSON identity (used by other apps)
- `GET /auth/verify` — nginx auth_request endpoint
- `GET /admin/users` — admin panel (requires is_admin)
- `GET /account` — self-service profile
- `POST /api/account/change-password` — change your own password
- `GET /redirect/<app>` — PWA shortcut target (metube, pdf-tools, chordbook, ...)

## Config

- `FINANZAS_DB` — path to the shared SQLite DB (default `/root/finanzas/finanzas.db`)
- `PHANTASMAA_AUTH_SECRET` — HMAC signing secret (rotate = all sessions break)

## User DB schema

Owned by pennypath. We add one column on top:

```sql
ALTER TABLE usuarios ADD COLUMN last_login_at TIMESTAMP;
```

Login stamps `last_login_at = NOW()` on every successful auth.
