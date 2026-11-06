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
│  ├ Views/ViewModels: connect, PIN, instance selection   ├ Instance: ProcessInspector (WMI + PEB: cwd, JVM env),    │
│  │ + consent, scan, results, evidence, staff/admin,     │  JavaLaunch parser, InstanceResolver → GameInstance       │
│  │ settings, about                                      ├ Engine: ScanScope (hard path guard), InstanceFiles       │
│  ├ Services: ApiClient, InvestigationSession            │  (discovery/classification), plan → run, InspectionLog,  │
│  │ (queue + retry + idempotent upload), LocalStore      │  custody log                                             │
│  │ (SQLite + DPAPI), ReportExporter (QuestPDF)          ├ Analysis: JarAnalyzer, ClassFile (constant pool),        │
│                                                         │  SignatureIndex (Aho–Corasick per scope), EvidenceScoring│
│                                                         │  ModuleHeuristics, PngAlpha                              │
│                                                         ├ Modules (7): launch, mods, gamefiles, files, packs,      │
│                                                         │  logs, process                                           │
│                                                         ├ Windows: memory reader, WinVerifyTrust                   │
│                                                         └ Reporting: integrity manifest (shared algorithm)          │
└──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
packages/detection-rules/signatures/*.json — categorised signature databases → build-rules.mjs validates and compiles them into
rules.json, the single source of truth: embedded in the scanner (offline fallback) and seeded into the DB (admin-editable).
```

## Investigation workflow (sequence)

1. Investigator `POST /api/investigations` → backend creates `Investigation`, issues a 6-digit PIN: CSPRNG digits, stored as `HMAC-SHA256(APP_SECRET, pin)` for lookup plus an AES-256-GCM sealed copy so the owner can re-display it while pending. TTL 15 min (admin-configurable). Event `investigation.created`.
2. Player opens `screensharing.me.exe` → `GET /api/desktop/version` (supported? update?).
3. Player enters the PIN → `POST /api/desktop/pin/claim`. Rate-limited per IP (10/10 min) plus a global failure circuit breaker (300/min). A single atomic `updateMany … where claimedAt is null` makes the PIN single-use; the sealed PIN is wiped. Returns an **investigation-scoped** device token (32 random bytes; SHA-256 stored), the investigator's display name and the consent text. Event `device.connected`.
4. The client lists the **running Minecraft instances** it identified (see *Instance identification*). The player confirms one (choosing when several run) and consents → `POST /api/desktop/consent`. Nothing is collected before this. Right before starting, the selected process is re-identified so a closed or restarted game is never scanned by mistake. Event `consent.given`.
5. `GET /api/desktop/rules` (live catalog) → `POST /api/desktop/scan/start` with the stage list and the selected instance (launcher, name, game directory, version, loader, PID — no account data).
6. Scanner discovers the instance's files inside the scope, plans (counts real work items), runs modules; `InvestigationSession` uploads progress with live file counters (≤1/s), findings in idempotent batches of 50 (`clientFindingId` = deterministic hash) and a heartbeat every 15 s. Events `scan.progress`, `scan.findings`.
7. `POST /api/desktop/scan/complete` with inventory, coverage, chain of custody and the **integrity manifest** (SHA-256 over canonical finding lines). The server refuses completion if it holds a different number of findings, recomputes the manifest from what it stored and records `manifestVerified`. Event `scan.completed`.
8. The investigator's page receives every event through SSE and re-fetches the snapshot; the report is exportable (PDF/JSON/CSV).

### Reconnect & interruption handling

* Scanning never depends on the network. Findings stay queued in memory until acknowledged; failed uploads back off (0.75 s → 20 s) while the scan continues; completion retries up to ~40 times. Verified by `Upload_survives_a_network_interruption_mid_scan` (6 injected failures).
* The device token slides on heartbeat (2 h, hard cap 12 h after connection). The token and investigation are stored DPAPI-encrypted so "Restart as administrator" or an app restart can **resume**.
* If the desktop stays offline > 45 s the investigator can issue a new PIN, which revokes the old device, marks the partial scan `INTERRUPTED`, and lets a new scan replace it (results are never mixed).
* SSE streams are resumable with `Last-Event-ID`; events are durable rows (`InvestigationEvent`), so updates written by any server instance are delivered (in-process bus only shortens latency).

## Data model (PostgreSQL / Prisma)

`Detection` carries `family` (suspected client), `signature` and `location` (instance-relative) since migration `20261106120000_instance_scoped_signatures`; `DetectionRule` carries `scopes`, `weight` and `packages`. Rules that leave the catalog are disabled by the seed, not deleted (old reports reference them).

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

## Instance identification and scope

* **ProcessInspector** enumerates `java.exe`/`javaw.exe` (WMI: command line, parent, start time) and reads, from each process's own parameter block (`NtQueryInformationProcess` → PEB → `RTL_USER_PROCESS_PARAMETERS`), the **working directory** and only the three JVM option variables (`JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS`, `JDK_JAVA_OPTIONS`). Nothing else from the environment is kept.
* **JavaLaunch** splits the command line exactly like the C runtime (`CommandLineToArgvW`) into JVM options, class path, main class (unwrapping launcher wrappers such as Modrinth's `MinecraftLaunch`) and game arguments.
* **InstanceResolver** accepts a process as Minecraft only for known game/loader/launcher main classes or game arguments. The game directory is `--gameDir` (absolute, or relative to the working directory) or, for launchers that start the game in the instance folder without `--gameDir` (Prism/MultiMC `EntryPoint`), the working directory. The directory must exist and contain game markers (`options.txt`, `logs`, `mods`, `config`, `saves`…). The launcher and instance name come from the folder layout (`instance.cfg`, `profiles/<name>`, `minecraftinstance.json`), the launcher brand property and the parent process. **If any of this fails, the instance is returned unresolved with the exact reason and cannot be scanned** — there is no fallback to `.minecraft`.
* **ScanScope** is built from the instance folder and the files the process attests to (class-path jars, their version manifests, `-javaagent` jars, and native modules loaded into the process). Every open, hash, stat and directory enumeration calls `Scope.Demand`; anything else throws `ScopeViolationException`, is recorded and fails that stage loudly. Links inside the instance that lead outside are not followed, except the content folders the game itself loads (`mods`, `config`, `resourcepacks`, `shaderpacks`), which are followed and reported (`SSME-H-LINKED_FOLDER`).
* **InstanceFiles** walks the instance (bounded depth and count), excludes launcher-shared and bulky non-code folders (`saves`, `assets`, `versions`, `libraries`, caches…, each listed in the report) and classifies files by **magic bytes first** (`MZ` → executable, `PK\x03\x04` → archive) and extension second.

## Detection engine

* Signatures live in `packages/detection-rules/signatures/*.json` (one file per category). Rule kinds: `MOD_ID`, `MOD_ID_REGEX`, `PACKAGE_PREFIX`, `STRING` (with scopes `class`, `resource`, `config`, `log`, `script`, `binary`, `memory`), `MEMORY_STRING`, `SHA256`, `INSTANCE_PATH_REGEX`, `EXECUTABLE_REGEX`, `FILE_NAME_REGEX`, `RESOURCEPACK_REGEX`, `SHADERPACK_REGEX`, `FEATURE_NAME`, `MODULE_PACKAGE`, `KNOWN_MOD` (with expected `packages`), `LIBRARY_PACKAGE`, `BUILTIN`. Adding a signature of an existing kind needs no code change.
* **JarAnalyzer** reads metadata, manifest, nested archives (3 levels), and the content of every entry: class files are validated (`CAFEBABE`) and their constant-pool UTF-8 strings matched; text resources and entry names are matched; embedded PE images are recognised regardless of name and matched as binaries. Archives with tampered end-of-central-directory records ("anti-unzip") are normalised in memory.
* **EvidenceScoring** groups indicators per file and suspected family, sums weights and derives the tier (see DETECTION_CATALOG.md → Scoring). Generic indicator families are deferred until Modrinth verification and never reported for verified or genuine known mods.
* Stages: `launch` (agents, JVM option variables) · `mods` (archives, impersonation, encryption, embedded executables, metadata consistency, Modrinth) · `gamefiles` (SHA-1 of class-path jars vs. version manifest; unverifiable jars analysed) · `files` (instance artifacts, configs, scripts, executables, redirected folders) · `packs` (X-ray by content, names, strings) · `logs` (mod lists, crash reports, non-chat strings) · `process` (modules, bounded memory).
* Every file ends with an `InspectionRecord`: *Analyzed*, *NotApplicable* (type not analysed) or a problem (*Unreadable, TooLarge, Encrypted, Corrupt, LinkNotFollowed*). Problems on code-bearing files become *Unable to inspect* findings, so nothing is skipped silently.

## Desktop module contract

`IScanModule { Key, Name, Activity, SkipReason(ctx), Plan(ctx) → work units, RunAsync(ctx) }`. Findings are created only through `ScanContext.Report(ruleId, …)`, which pulls severity/tier/confidence/limitations/false-positive text from the active catalog and **returns nothing if the rule is disabled**. All file access goes through `ScanContext.OpenRead` / `ScopedFileSystem` (scope-checked, read-only, shared) and is recorded in the custody log.

## Why one Next.js service instead of separate api/realtime services

The suggested `services/api` and `services/realtime` live inside the Next.js app as route handlers to keep one deployable unit with one auth implementation. Realtime is SSE backed by a durable table, so it scales horizontally without sticky sessions or a separate WebSocket server. Splitting later is mechanical: `src/lib` has no dependency on React.
