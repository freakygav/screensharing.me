# Architecture

```
┌───────────────────────────── apps/website (Next.js 16, TypeScript, Tailwind 4) ─────────────────────────────┐
│  Pages (RSC + client islands)            API route handlers (/api/*)                 lib/ (server-only)          │
│  ├ public: home, features, download,     ├ auth/*  account/*  (cookie session)       ├ auth (Argon2id, sessions) │
│  │ docs, login, register, reset…         ├ investigations/*   (owner or admin)       ├ investigations (PIN, auth,│
│  ├ dashboard/* (investigator)            │  └ [id]/events  ── Server-Sent Events     │  snapshot, verdict)       │
│  └ admin/*  (administrator)              ├ desktop/*  (bearer device / staff token)  ├ events (durable + bus)    │
│                                          └ admin/*    (admin, audited)               ├ ratelimit (PostgreSQL)    │
│                                                                                       └ report (JSON/CSV/PDF)     │
└──────────────────────────────────────────────────────┬──────────────────────────────────────────────────────────┘
                                                       │ Prisma 6
                                               ┌───────▼────────┐
                                               │  PostgreSQL    │  (embedded server for dev: apps/website/scripts/dev-db.mjs)
                                               └────────────────┘
                     HTTPS (HTTP only for localhost), JSON, short-lived bearer tokens
┌────────────────────────────── apps/desktop (.NET 10, WPF, MVVM) ───────────────────────────────────────────────┐
│ Screensharing.Desktop  (screensharing.me.exe)          Screensharing.Scanner (class library, no UI)              │
│  ├ Views/ViewModels: connect, PIN, investigation,       ├ Engine: plan → run, real work-unit progress, custody log  │
│  │ scan, results, evidence, staff/admin, settings,      ├ Discovery: launcher/installation locator                │
│  │ about                                                ├ Analysis: JarAnalyzer, ModuleHeuristics, Aho–Corasick    │
│  ├ Services: ApiClient, InvestigationSession            ├ Modules (9): installations, mods, integrity, logs, jvm,  │
│  │ (queue + retry + idempotent upload), LocalStore      │  processes, execution, deleted, tamper                   │
│  │ (SQLite + DPAPI), ReportExporter (QuestPDF)          ├ Windows: Prefetch(MAM), RecycleBin, USN, memory, WinVerifyTrust│
│                                                         └ Reporting: integrity manifest (shared algorithm)          │
└──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
packages/detection-rules/rules.json — single source of truth: embedded in the scanner (offline fallback) and seeded into the DB.
```

## Investigation workflow (sequence)

1. Investigator `POST /api/investigations` → backend creates `Investigation`, issues a 6-digit PIN: CSPRNG digits, stored as `HMAC-SHA256(APP_SECRET, pin)` for lookup plus an AES-256-GCM sealed copy so the owner can re-display it while pending. TTL 15 min (admin-configurable). Event `investigation.created`.
2. Player opens `screensharing.me.exe` → `GET /api/desktop/version` (supported? update?).
3. Player enters the PIN → `POST /api/desktop/pin/claim`. Rate-limited per IP (10/10 min) plus a global failure circuit breaker (300/min). A single atomic `updateMany … where claimedAt is null` makes the PIN single-use; the sealed PIN is wiped. Returns an **investigation-scoped** device token (32 random bytes; SHA-256 stored), the investigator's display name and the consent text. Event `device.connected`.
4. Player reviews sources and consents → `POST /api/desktop/consent`. Nothing is collected before this. Event `consent.given`.
5. `GET /api/desktop/rules` (live catalog) → `POST /api/desktop/scan/start` with the module list.
6. Scanner plans (counts real work items), runs modules; `InvestigationSession` uploads progress (≤1/s), findings in idempotent batches of 50 (`clientFindingId` = deterministic hash) and a heartbeat every 15 s. Events `scan.progress`, `scan.findings`.
7. `POST /api/desktop/scan/complete` with inventory, coverage, chain of custody and the **integrity manifest** (SHA-256 over canonical finding lines). The server refuses completion if it holds a different number of findings, recomputes the manifest from what it stored and records `manifestVerified`. Event `scan.completed`.
8. The investigator's page receives every event through SSE and re-fetches the snapshot; the report is exportable (PDF/JSON/CSV).

### Reconnect & interruption handling

* Scanning never depends on the network. Findings stay queued in memory until acknowledged; failed uploads back off (0.75 s → 20 s) while the scan continues; completion retries up to ~40 times. Verified by `Upload_survives_a_network_interruption_mid_scan` (6 injected failures).
* The device token slides on heartbeat (2 h, hard cap 12 h after connection). The token and investigation are stored DPAPI-encrypted so "Restart as administrator" or an app restart can **resume**.
* If the desktop stays offline > 45 s the investigator can issue a new PIN, which revokes the old device, marks the partial scan `INTERRUPTED`, and lets a new scan replace it (results are never mixed).
* SSE streams are resumable with `Last-Event-ID`; events are durable rows (`InvestigationEvent`), so updates written by any server instance are delivered (in-process bus only shortens latency).

## Data model (PostgreSQL / Prisma)

`User` (role USER/ADMIN — administrators are users with a role, one auth path and one audit trail) · `Session` (WEB cookie / DESKTOP bearer, hashed tokens) · `EmailToken` (verify/reset, hashed, single-use) · `Investigation` · `InvestigationPin` · `ConnectedDevice` · `Scan` · `ScanCategory` · `Detection` · `Evidence` (ordered by `position`) · `DetectionRule` · `AuditLog` · `ApplicationVersion` · `InvestigationEvent` · `RateLimitBucket` · `SystemConfig` · `MailOutbox`. Schema: `apps/website/prisma/schema.prisma`; migration: `prisma/migrations/20261106000000_init`.

## API contract (summary)

All payloads are validated with strict zod schemas (`apps/website/src/lib/validation.ts`); unknown properties are rejected, sizes are bounded (findings batch ≤ 1 MiB / 100 findings / 25 evidence items; completion ≤ 2 MiB), and every finding must reference an existing catalog rule. Confirmed-artifact findings must carry hashed evidence.

| Endpoint | Auth | Purpose |
|---|---|---|
| `POST /api/auth/register · login · logout`, `GET /api/auth/me` | cookie (+Origin check) | accounts; login by username **or** email; `adminOnly` for admin sign-in |
| `POST /api/auth/verify-email · request-reset · reset-password` | token | email verification, password reset (verified emails only) |
| `POST /api/account/password · email · resend-verification` | cookie | account settings |
| `GET/POST /api/investigations`, `GET /api/investigations/:id`, `POST …/cancel`, `POST …/pin` | owner or admin | create, list, snapshot, cancel, re-issue PIN |
| `GET /api/investigations/:id/events` | owner or admin | SSE live updates |
| `GET /api/investigations/:id/export?format=json\|csv\|pdf` | owner or admin | report export (audited) |
| `GET /api/desktop/version` | public | update/support check |
| `POST /api/desktop/pin/claim` | PIN | exchange PIN for device token |
| `GET /api/desktop/session`, `GET …/rules`, `POST …/consent · heartbeat · scan/start · scan/progress · scan/findings · scan/complete · scan/fail` | device token | scan lifecycle |
| `POST /api/desktop/auth/login · logout`, `GET /api/desktop/staff/investigations[/:id]` | staff bearer (8 h) | desktop staff/admin console |
| `PATCH /api/admin/users/:id`, `POST …/reset-link`, `DELETE /api/admin/sessions/:id · devices/:id`, `POST/PATCH /api/admin/rules[/:id]`, `POST/PATCH /api/admin/versions[/:id]`, `PATCH /api/admin/config` | admin cookie | administration (every call audited) |

## Desktop module contract

`IScanModule { Key, Name, Activity, SkipReason(ctx), Plan(ctx) → work units, RunAsync(ctx) }`. Findings are created only through `ScanContext.Report(ruleId, …)`, which pulls severity/tier/confidence/limitations/false-positive text from the active catalog and **returns nothing if the rule is disabled**. All file access goes through `ScanContext.OpenRead` (read-only, shared) and is recorded in the custody log.

## Why one Next.js service instead of separate api/realtime services

The suggested `services/api` and `services/realtime` live inside the Next.js app as route handlers to keep one deployable unit with one auth implementation. Realtime is SSE backed by a durable table, so it scales horizontally without sticky sessions or a separate WebSocket server. Splitting later is mechanical: `src/lib` has no dependency on React.
