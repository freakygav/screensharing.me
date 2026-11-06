# screensharing.me

PIN-based Minecraft forensic investigations: a website + backend for investigators and a Windows client
(`screensharing.me.exe`) that performs a consent-first, read-only forensic scan and streams tiered,
hashed, explained evidence back in real time.

* **Website & API** — Next.js 16 (App Router, TypeScript, Tailwind 4), Prisma 6, PostgreSQL, Argon2id auth, Server-Sent Events.
* **Windows client** — .NET 10, WPF (MVVM, CommunityToolkit.Mvvm), SQLite (Microsoft.Data.Sqlite) + DPAPI, QuestPDF; single self-contained `screensharing.me.exe`.
* **Scanner engine** — 9 collection modules (installations, mod archives, game-file integrity, game logs, JVM configuration, processes & memory, Prefetch/BAM, Recycle Bin/USN journal, anti-forensics), 110-rule catalog, five evidence tiers.

**Live:** https://screensharing-me-azure.vercel.app · repository: https://github.com/freakygav/screensharing.me (private) ·
hosted on Vercel (project `screensharing-me`, root directory `apps/website`, auto-deploys on every push to `main`) with
Neon PostgreSQL (Vercel Marketplace) and the client EXE on Vercel Blob. Preview deployments currently share the production database.

Desktop screenshots (rendered from the real views with real scan data): [`documentation/screenshots/desktop`](documentation/screenshots/desktop).

## Repository layout

```
apps/
  website/                Next.js app: public site, dashboard, admin console, REST API, SSE
    prisma/               schema + migrations
    scripts/              dev-db.mjs (embedded PostgreSQL), seed.mjs (rules + first admin), reset-rate-limits.mjs
    src/app/api/          route handlers (auth, account, investigations, desktop, admin)
    src/lib/              server logic (auth, PINs, rate limiting, events, reports, validation)
    tests/unit/           vitest unit tests
  desktop/
    src/Screensharing.Scanner/   forensic engine (no UI)
    src/Screensharing.Desktop/   WPF client → screensharing.me.exe
    tests/Screensharing.Scanner.Tests/  fixtures + detection/parsers/engine tests
    tests/Screensharing.Desktop.Tests/  end-to-end (desktop ↔ live API), UI rendering
packages/
  detection-rules/        build-rules.mjs (authoring source) → rules.json (single source of truth)
  shared-types/           design tokens shared by web and desktop; API contract pointer
tests/e2e/                API end-to-end tests (node:test) against a running server
scripts/                  build-desktop.ps1, gen-catalog.mjs, unbundle.py (dev helper)
documentation/            DEPLOYMENT.md, TESTING.md, screenshots/
ARCHITECTURE.md  RESEARCH.md  DETECTION_CATALOG.md  SECURITY.md
```

## Prerequisites

* Node.js 20+ (tested with 24) and npm.
* .NET 10 SDK (only for the Windows client; tested with 10.0.403).
* PostgreSQL 14+ for production. Development uses a bundled PostgreSQL server (`embedded-postgres`), no install needed.

## Run the website and backend locally

The API is part of the Next.js app, so "running the backend" and "running the website" are the same process.

```bash
cd apps/website
npm install
cp .env.example .env
```

Edit `.env`: set `DATABASE_URL="postgresql://ssme:ssme_dev_pw@127.0.0.1:5433/screensharing"`, a random `APP_SECRET` (`node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"`), `APP_ORIGIN="http://localhost:3000"`, and the `ADMIN_BOOTSTRAP_*` values.

```bash
npm run db:start
```

Starts the dev PostgreSQL on port 5433 (UTF-8). Leave it running, then in a second terminal:

```bash
npx prisma migrate deploy
```

```bash
npm run db:seed
```

```bash
npm run dev
```

Open http://localhost:3000. The seed loads the detection catalog, registers app version 1.0.0 and creates the first administrator.

## Initialize the administrator

`npm run db:seed` reads `ADMIN_BOOTSTRAP_EMAIL`, `ADMIN_BOOTSTRAP_USERNAME` and `ADMIN_BOOTSTRAP_PASSWORD`, hashes the password with Argon2id and creates (or promotes) the account. It never overwrites an existing admin password unless `ADMIN_BOOTSTRAP_FORCE_RESET=1`. Sign in at `/admin/login` (website) or via **Admin** in the desktop title bar. Afterwards remove `ADMIN_BOOTSTRAP_PASSWORD` from the environment and change the password in Account settings. See [SECURITY.md](SECURITY.md).

## Build the EXE

```bash
powershell -ExecutionPolicy Bypass -File scripts/build-desktop.ps1
```

Produces `artifacts/desktop/screensharing.me.exe` (self-contained win-x64, ~75 MB), prints its SHA-256 and copies it to `apps/website/public/download/` so the Download page serves it. For production pass `-ServerUrl https://www.screensharing.me -Version 1.0.1`. The server URL is only a default (changeable in Settings); no secrets are embedded.

## Use it

1. Register on the website → **New investigation** → you get a PIN such as `483-921`.
2. On the player's PC run `screensharing.me.exe` → **I have an investigation PIN** → enter the PIN → review the consent screen → optionally **Restart as administrator** (unlocks Prefetch, BAM, USN journal, Security log) → **Begin scan**.
3. The investigation page updates live (connection, version, progress, categories, findings, severity breakdown) and shows the final report with search/filter/sort, expandable evidence, coverage, inventory and chain of custody; export PDF/JSON/CSV.

## Tests

| Suite | Command | Result (2026-11-06) |
|---|---|---|
| Website unit (vitest) | `cd apps/website && npm test` | 19 / 19 passed |
| API end-to-end (live server) | `SSME_ADMIN_PASSWORD=… node --test tests/e2e/api-flow.test.mjs` | 18 / 18 passed |
| Scanner (fixtures, parsers, engine, live machine) | `dotnet test apps/desktop/tests/Screensharing.Scanner.Tests` | 34 / 34 passed |
| Desktop end-to-end + UI rendering | `dotnet test apps/desktop/tests/Screensharing.Desktop.Tests` | 3 passed, 1 opt-in skipped |
| Full real-machine scan → live server | `SSME_E2E_FULL=1 dotnet test … --filter Full_system` | passed: 592 findings, 2,272 mods, manifest verified |
| Production build | `cd apps/website && npx next build` | succeeds |

Details and the false-positive measurement are in [documentation/TESTING.md](documentation/TESTING.md).

## Deploy

See [documentation/DEPLOYMENT.md](documentation/DEPLOYMENT.md).

## Status

**Complete and tested:** registration (username, optional email), login by username or email, email verification, password reset (verified email) and admin-issued reset links (no-email accounts), rate limiting, CSRF/Origin checks, PIN creation/expiry/single-use/brute-force protection, desktop connect/consent/scan/upload with reconnect handling, live SSE updates, findings with evidence/hashes/limitations, integrity manifest, chain of custody, reports (web + desktop PDF/JSON/CSV), investigator dashboard, admin console (users, investigations, sessions/devices, detection catalog editing, app versions, audit log, configuration, mail outbox), desktop admin/staff console, settings, about, single-file EXE.

**Needs further work:** Amcache/SRUM/ShellBags/Jump Lists/Sysmon collectors; SHA-256 fingerprints for specific cheat releases (none shipped — none could be verified); identifiers for closed-source clients; Authenticode signing of the EXE and an auto-updater; SMTP delivery is implemented but only exercised through the outbox; Prefetch/BAM/USN rule paths need administrator-run integration testing on a machine with matching artifacts (parsers are unit-tested); mobile layout of the admin console is functional but not polished.
