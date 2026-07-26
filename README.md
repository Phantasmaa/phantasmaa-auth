# Phantasmaa SSO

Single login for the whole suite. One cookie, one login form, all apps.

## How it works

```
                    ┌──────────────────┐
                    │  phantasmaa-auth │  (Flask on :8200, exposed :8100)
                    │  /login /logout  │
                    │  /auth/verify    │
                    └────────▲─────────┘
                             │ cookie = phantasmaa_auth
                             │
   ┌──────────┐        ┌──────┴──────┐        ┌──────────┐
   │ chordbook│◀───────│   nginx     │───────▶│ pdf-tools│
   │   :8104  │ auth_  │ :8100 SSO   │ auth_  │   :8101  │
   │          │ request│  :8104 chord│request │          │
   └──────────┘        │  :8101 pdf  │        └──────────┘
                       └─────────────┘
```

1. Browser hits `http://host:8104/`
2. nginx sub-requests `http://127.0.0.1:8200/auth/verify` with the cookie
3. If 200 → nginx forwards request to backend with `X-Phantasmaa-User-Id` etc headers
4. If 401 → nginx redirects to `http://host:8100/login?next=...`
5. User logs in once, gets a cookie valid for 90 days
6. Same cookie works on pdf-tools, chordbook, anything else behind the SSO

## Files

- `app.py` — Flask SSO service (login, logout, whoami, verify)
- `templates/login.html` — login form (dark, mobile-friendly)
- `/etc/nginx/sites-available/phantasmaa-auth` — public nginx (port 8100)
- `/etc/systemd/system/phantasmaa-auth.service` — systemd unit
- `/etc/nginx/sites-enabled/chordbook` — uses auth_request
- `/etc/nginx/sites-enabled/pdf-tools` — uses auth_request

## Add SSO to another app

1. Modify the app to read `X-Phantasmaa-User-Id` from request headers and
   auto-login that user. See `chordbook/app/auth.py` for the pattern.
2. Add an nginx site with the auth_request block (copy from
   `/etc/nginx/sites-enabled/chordbook`).

The pattern:
```nginx
auth_request /verify_8200;
auth_request_set $auth_user_id   $upstream_http_x_user_id;
auth_request_set $auth_username  $upstream_http_x_username;
auth_request_set $auth_is_admin  $upstream_http_x_is_admin;

error_page 401 = /sso_redirect;

location = /sso_redirect {
    internal;
    return 302 http://127.0.0.1:8100/login?next=$scheme://$http_host$request_uri;
}

location = /verify_8200 {
    internal;
    proxy_pass http://127.0.0.1:8200/auth/verify;
    proxy_pass_request_body off;
    proxy_set_header Cookie $http_cookie;
    proxy_set_header Host $host;
}

location / {
    proxy_pass http://127.0.0.1:PORT;
    # ... standard proxy headers ...
    proxy_set_header X-Phantasmaa-User-Id  $auth_user_id;
    proxy_set_header X-Phantasmaa-Username $auth_username;
    proxy_set_header X-Phantasmaa-Is-Admin $auth_is_admin;
}
```

## Users

Read from `/root/finanzas/finanzas.db` `usuarios` table (same as pennypath/mis-finanzas).
Register/login there. Don't add users via SSO.

## Env vars

- `FINANZAS_DB` — path to users DB. Default `/root/finanzas/finanzas.db`
- `PHANTASMAA_AUTH_SECRET` — HMAC signing key. If unset, uses dev fallback.
  Set this in production (e.g. systemd Environment=).

## Service

```sh
systemctl status phantasmaa-auth
systemctl restart phantasmaa-auth
journalctl -u phantasmaa-auth -f
```

Public URL: `http://<vps>:8100/login`
Verify endpoint: `http://127.0.0.1:8200/auth/verify` (internal)
