# Testing

All results below were produced on 2026-11-06 on Windows 11 Pro (26200), Node 24.22, .NET SDK 10.0.403, against the local dev server and embedded PostgreSQL 18.

## Website unit tests — 19/19 (`apps/website`, `npm test`)
PIN generation (format, CSPRNG distribution, normalisation, HMAC storage, AES-GCM sealing + tamper detection), reference format, semver ordering, integrity manifest (cross-language reference vector shared with C#, order independence), strict payload validation (unknown keys, enums, ranges, rule-id format, confirmed tier needs hashes), registration policy, rule-pattern validation, JSON export never contains the PIN, CSV formula-injection neutralisation, PDF rendering of non-Latin text and long paths, verdict wording never says "cheater".

## API end-to-end — 18/18 (`tests/e2e/api-flow.test.mjs`)
Registration with/without email (Argon2id hash verified in DB), duplicate/weak rejection, email verification (single-use), login by username and by email, wrong password, cross-origin CSRF rejection, administrator authentication (web + desktop, non-admin refused), PIN creation (not stored in plaintext), authorization (another user gets 404 on snapshot/SSE/export/cancel; 403 on admin API), wrong/malformed PIN, single-use claim, consent required before scanning, invalid token, **SSE delivery** of connected/consent/started/progress events, evidence validation and idempotent retries, completion refused with missing findings, server-recomputed manifest, JSON/CSV/PDF exports, audited admin view, **PIN expiry** + regeneration, **connection interruption** (offline device replaced by new PIN, old token revoked), blocked client versions (426), **PIN brute-force limit** (429).

## Scanner — 34/34 (`apps/desktop/tests/Screensharing.Scanner.Tests`)
Synthetic fixtures are real files built on disk (jars with metadata, classes, manifests, nested jars, version manifests with matching/mismatching SHA-1, Fabric logs, Prism instances). No real cheat binaries are used.

* **Negative cases:** clean Fabric install (Sodium, Lithium, Mod Menu, Fabric API with nested jar, matching logs) → **0 findings**; vanilla install with two versions → **0 findings**; a legitimate mod containing `Reach`/`Speed`/`Fly` classes outside module packages → no structural finding; unrecognised private mod → only an *Inconclusive/INFO* entry.
* **Positive cases:** Meteor (confirmed, corroborated evidence merged), Wurst renamed as `sodium-*.jar` (confirmed + disguise), unknown client with module layout (strong), LiquidBounce hidden in a Jar-in-Jar (confirmed), Java agent manifest, jar with `.txt` extension, obfuscated jar (weak), modified client jar (strong), cheat + removed mod recovered from logs, mod changed after last session (weak), X-ray pack / Freecam / Baritone with policy severities, duplicate mod ids, BleachHack via Forge `mods.toml` in a Prism instance, disabled rules never report.
* **Engine:** monotonic progress from real work units reaching 100%, skipped modules carry reasons, chain of custody records reads and hashes while the evidence file stays byte-identical, deterministic finding ids, manifest identical to the TypeScript implementation, embedded ruleset valid (all regexes compile, all built-ins present), access tokens redacted from command lines.
* **Parsers:** Prefetch v30 uncompressed **and** MAM/XPRESS-Huffman compressed (compressed with Windows' own `RtlCompressBuffer`), volume-path resolution, Recycle Bin `$I` v2, Aho–Corasick, live `ReadProcessMemory` scan.
* **Live machine:** full engine on the development machine completes with no failed module.

## Desktop — 3 passed + 1 opt-in (`apps/desktop/tests/Screensharing.Desktop.Tests`)
* `Pin_connect_scan_upload_and_report_roundtrip` — the desktop's own `ApiClient`/`InvestigationSession` against the live server: version check, PIN claim, consent, live catalog download, scan, upload, server shows COMPLETED with matching counts, verified manifest, confirmed verdict, 9 coverage categories, hashed evidence; desktop staff sign-in lists and loads the report; admin-only sign-in refused for a normal user; desktop PDF/JSON/CSV exports.
* `Upload_survives_a_network_interruption_mid_scan` — 6 consecutive transport failures injected during uploads; the client goes *Reconnecting*, recovers, and the server receives every finding with a verified manifest.
* `Render_all_screens` — loads and lays out all nine screens inside the real `MainWindow` (this test caught a duplicate resource key that would have crashed the app at start-up); with `SSME_UI_SNAPSHOTS=1` it writes the PNGs in `documentation/screenshots/desktop`.
* `Full_system_scan_uploads_and_validates` (opt-in `SSME_E2E_FULL=1`) — scanned this machine and uploaded **592 findings and an inventory of 2,272 mods** in 48 s; manifest verified. This run exposed and fixed two real bugs (WIN1252 database encoding; slow per-row inserts).

The packaged `screensharing.me.exe` was launched and verified to start, stay responsive and load its native SQLite library without errors.

## False-positive measurement on a real machine

Non-elevated scan of a developer machine with **36 Minecraft installations and 2,268 real mod archives** (Modrinth verification on):

| Stage | Disguised archive | Java agent manifest | Java agent argument | Unsigned module | Unrecognised (INFO) |
|---|---|---|---|---|---|
| First run | 22 (all false) | 2 (false) | 1 (false: Modrinth App agent) | 5 (false: voice-chat / JNA natives) | ~2,600 |
| After fixes | **0** | **0** | **0** | **0** | 573 |

Fixes: disguise check only for file names *starting* with a non-library known-mod id, normalised id comparison, Modrinth-verified archives excluded; well-known library agents allowlisted; launcher agents allowlisted **by content**; common library natives allowlisted.

Remaining non-INFO findings on that machine were reviewed manually: Meteor Client (×2), Wurst, Meteor Rejects, two jars with cheat-module layouts (named "…Client"), two Meteor addons (weak), Freecam, five X-ray resource packs, one mod removed after a session, three duplicate ids — i.e. genuine content, plus one name-based X-ray rule hit on a mod called `xray_snitch` (documented false-positive risk of the *Suspicious configuration* tier).

## Not covered by automated tests
Prefetch/BAM/USN rule paths end-to-end (need administrator rights and matching artifacts; parsers are tested), event-log clear / clock change / service / Prefetch-disabled findings (queries run, no matching events on the test machine), `JAVA_TOOL_OPTIONS` injection, memory detection of an actual cheat-loaded JVM, SMTP delivery, browser-driven UI tests of the website (pages were checked manually in a browser, including live SSE updates on the investigation page).
