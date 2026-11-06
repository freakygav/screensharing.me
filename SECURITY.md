# Security

## Threat model (summary)

| Asset / actor | Risk | Control |
|---|---|---|
| Investigation results | A stranger guesses a PIN and reads results | A PIN only lets a desktop **upload** into one investigation. Reading results always requires the owner's or an administrator's authenticated session (404 for everyone else, no existence leak). |
| PIN space (10⁶) | Brute force | 15-min TTL, single use, per-IP limit (10/10 min, DB-backed), global failure circuit breaker (300 failed claims/min pauses claiming), collisions avoided among active PINs, PINs stored as HMAC + AES-GCM (never plaintext). |
| Accounts | Credential stuffing, enumeration | Argon2id (m=19 MiB, t=2, p=1), per-IP and per-identifier login limits, constant-time dummy verification for unknown accounts, identical reset responses, audit of failures. |
| Sessions | Theft, CSRF | 256-bit random tokens, SHA-256 at rest, HttpOnly + SameSite=Lax + Secure (production) cookies, Origin/Sec-Fetch-Site check on every state-changing cookie request, revocation on password change/reset/role change. Admin sessions expire after 8 h. |
| Desktop tokens | Replay, over-privilege | Investigation-scoped, 2 h sliding / 12 h hard cap, revocable by investigator (re-issue PIN) and admin, refused once an investigation is closed (410). Staff desktop tokens are 8 h `DESKTOP` sessions. |
| Uploaded data | Malicious client payloads | Strict schemas (unknown keys rejected), length limits, byte-limited body reader, rule ids must exist, confirmed tier requires hashed evidence, server-side verdicts and counts (never trusted from the client), integrity manifest recomputed server-side. |
| Reports | CSV formula injection, PDF encoding attacks | CSV cells starting with `= + - @` are prefixed; PDF text is re-encoded to WinAnsi. |
| Player privacy | Over-collection | Explicit consent screen listing every source; no browser/credential/launcher-account access; Java command-line tokens redacted; only metadata, hashes and findings uploaded; Modrinth lookup sends only SHA-512 of unrecognised mods and can be disabled. |
| Player system | Damage | Read-only access (`FileShare.ReadWrite|Delete`, never write handles); no code downloaded or executed; asInvoker manifest, elevation only on explicit request. |
| Administration | Abuse | Every admin mutation and every admin view of another user's investigation is written to the append-only audit log; last active admin cannot be demoted/disabled. |

## Secrets and the first administrator

* No secret is compiled into `screensharing.me.exe`. The only build-time value is the default server URL.
* `APP_SECRET` (≥ 32 chars) keys PIN HMAC and sealing; rotate by setting a new value (pending PINs become invalid).
* The first administrator is created by `npm run db:seed` from `ADMIN_BOOTSTRAP_EMAIL`, `ADMIN_BOOTSTRAP_USERNAME`, `ADMIN_BOOTSTRAP_PASSWORD`. The password is hashed with Argon2id; re-running the seed never overwrites an existing administrator's password unless `ADMIN_BOOTSTRAP_FORCE_RESET=1`. **Remove `ADMIN_BOOTSTRAP_PASSWORD` from the environment after bootstrapping and change the password in Account settings.** The development credentials supplied for this project live only in the git-ignored `apps/website/.env`.

## Production checklist

* Serve only over HTTPS; set `APP_ORIGIN` to the public origin; set `NODE_ENV=production` (enables Secure cookies and strict Origin checks).
* Put the app behind a reverse proxy that overwrites `X-Real-IP`/`X-Forwarded-For` and set `TRUST_PROXY=1`, otherwise all clients share one rate-limit bucket.
* Configure `SMTP_URL` so verification/reset mail is delivered (otherwise it is stored in the admin-only outbox).
* Sign `screensharing.me.exe` with an Authenticode certificate and publish its SHA-256 in Admin → App versions.
* Back up PostgreSQL; the audit log is append-only by convention (no delete endpoint exists).

## Reporting a vulnerability

Contact the administrators privately; do not open a public issue with exploit details.
