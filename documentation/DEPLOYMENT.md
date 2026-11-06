# Deploying screensharing.me

## 1. Database

Provision PostgreSQL 14+ with **UTF-8** encoding (mod names and paths contain non-Latin characters; a WIN1252 database rejects them). Create a database and a least-privilege user.

## 2. Website + API

Any Node.js 20+ host works (VM, container, or a platform such as Render/Fly/Railway). Serverless platforms work for the REST API, but long-lived SSE streams need a host that allows streaming responses (Node runtime, no response buffering).

Environment (see `apps/website/.env.example`):

| Variable | Value |
|---|---|
| `DATABASE_URL` | `postgresql://user:pass@host:5432/screensharing?sslmode=require` |
| `APP_SECRET` | 32+ random bytes (base64url) |
| `APP_ORIGIN` | `https://www.screensharing.me` |
| `NODE_ENV` | `production` |
| `TRUST_PROXY` | `1` when behind a reverse proxy that sets `X-Real-IP` / `X-Forwarded-For` |
| `SMTP_URL`, `MAIL_FROM` | SMTP for verification/reset mail (`npm i nodemailer` in apps/website to enable delivery) |
| `ADMIN_BOOTSTRAP_*` | only for the first seed, then remove |
| `PIN_TTL_MINUTES`, `DESKTOP_TOKEN_TTL_MINUTES` | optional |

Build and start:

```bash
cd apps/website && npm ci && npx prisma migrate deploy && npm run db:seed && npm run build && npm start
```

Put it behind TLS (nginx, Caddy or the platform's edge). For nginx, disable buffering for `/api/investigations/*/events` (`proxy_buffering off;`; the app also sends `X-Accel-Buffering: no`) and allow request bodies up to 2 MiB.

## 3. Windows client

```bash
powershell -ExecutionPolicy Bypass -File scripts/build-desktop.ps1 -ServerUrl https://www.screensharing.me -Version 1.0.1
```

* Sign `artifacts/desktop/screensharing.me.exe` with your Authenticode certificate (`signtool sign /fd SHA256 /tr <timestamp-url> /td SHA256 …`).
* Upload it to `apps/website/public/download/` (or a CDN and set the download URL), then register the version and its SHA-256 in **Admin → App versions**. Mark the oldest still-acceptable release as *minimum supported*; untick *active* to block a withdrawn build.

## 4. After go-live

* Sign in at `/admin/login`, change the bootstrap password, and remove `ADMIN_BOOTSTRAP_PASSWORD`.
* Review **Admin → Detection catalog**; disable rules that conflict with your server policy (e.g. Freecam allowed).
* Monitor **Admin → Audit log** for `desktop.pin_claim_failed` and `auth.login_failed` spikes.
* Back up PostgreSQL daily.
