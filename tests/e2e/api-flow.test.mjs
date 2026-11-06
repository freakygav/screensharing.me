// End-to-end API test against a running website (default http://localhost:3000).
//
//   node --test tests/e2e/api-flow.test.mjs
//
// Uses only real HTTP calls plus direct database access (via the website's Prisma
// client) for test setup that has no API on purpose (expiring a PIN, clearing rate
// limit buckets). Requires the dev database and server to be running.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { createHash, randomBytes } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";

// Version the test client announces; must be a supported release (older versions are blocked with 426).
const CLIENT_VERSION = process.env.SSME_CLIENT_VERSION ?? "1.1.0";
const BASE = process.env.SSME_BASE_URL ?? "http://localhost:3000";
const here = path.dirname(fileURLToPath(import.meta.url));
const websiteDir = path.resolve(here, "../../apps/website");
const require = createRequire(path.join(websiteDir, "package.json"));
process.env.DATABASE_URL ??= "postgresql://ssme:ssme_dev_pw@127.0.0.1:5433/screensharing";
const { PrismaClient } = require("@prisma/client");
const db = new PrismaClient();

const uid = randomBytes(3).toString("hex");
const ADMIN = { identifier: process.env.SSME_ADMIN_ID ?? "admin", password: process.env.SSME_ADMIN_PASSWORD };

class Client {
  constructor() { this.cookie = null; }
  async req(method, p, body, headers = {}) {
    const h = { Origin: BASE, ...headers };
    if (body !== undefined) h["Content-Type"] = "application/json";
    if (this.cookie) h.Cookie = this.cookie;
    const res = await fetch(BASE + p, { method, headers: h, body: body !== undefined ? JSON.stringify(body) : undefined, redirect: "manual" });
    const set = res.headers.get("set-cookie");
    if (set && set.includes("ssme_session=")) {
      const v = set.split(";")[0];
      this.cookie = v.endsWith("=") ? null : v;
    }
    const ct = res.headers.get("content-type") ?? "";
    const data = ct.includes("json") ? await res.json() : Buffer.from(await res.arrayBuffer());
    return { status: res.status, data, headers: res.headers };
  }
}

async function device(method, p, token, body) {
  const res = await fetch(BASE + p, {
    method,
    headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(body !== undefined ? { "Content-Type": "application/json" } : {}) },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  return { status: res.status, data: await res.json().catch(() => null) };
}

// Mirrors Manifest.cs / manifest.ts
function manifest(findings) {
  const ord = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
  const lines = [...findings].sort((a, b) => ord(a.clientFindingId, b.clientFindingId)).map((f) =>
    `${f.clientFindingId}|${f.ruleId}|${f.severity}|${f.tier}|${f.confidence}|${f.evidence.map((e) => `${e.reference}#${e.sha256 ?? ""}`).sort(ord).join(",")}`);
  return createHash("sha256").update(lines.join("\n"), "utf8").digest("hex");
}

const now = () => new Date().toISOString();
const sha = (s) => createHash("sha256").update(s).digest("hex");
function finding(id, extra = {}) {
  return {
    clientFindingId: id, ruleId: "SSME-CL-0001", name: "Meteor Client — mod metadata", description: "Synthetic test finding.",
    category: "Cheat client", categoryKey: "mods", severity: "CRITICAL", tier: "CONFIRMED_ARTIFACT", confidence: 96,
    method: "test", whyItMatters: "test", limitations: "test", falsePositiveNotes: "test", alternativeExplanations: "test",
    detectedAt: now(),
    evidence: [{ kind: "FILE", source: "Mod archive", reference: `C:\\fixture\\mods\\${id}.jar`, sha256: sha(id), sizeBytes: 1234, observedAt: now(), details: { modId: "meteor-client" } }],
    ...extra,
  };
}

const alice = new Client();
const bob = new Client();
const admin = new Client();
const ALICE = { username: `alice_${uid}`, email: `alice_${uid}@example.test`, password: "correct-horse-42" };
const BOB = { username: `bob_${uid}`, password: "battery-staple-77" };
let investigationId, pin, deviceToken;

before(async () => {
  await db.rateLimitBucket.deleteMany({});
});
after(async () => {
  await db.rateLimitBucket.deleteMany({});
  await db.$disconnect();
});

test("registration with and without email", async () => {
  let r = await alice.req("POST", "/api/auth/register", ALICE);
  assert.equal(r.status, 201, JSON.stringify(r.data));
  assert.equal(r.data.emailVerificationSent, true);
  r = await bob.req("POST", "/api/auth/register", BOB);
  assert.equal(r.status, 201);
  r = await new Client().req("POST", "/api/auth/register", { username: ALICE.username, password: "another-pass-99" });
  assert.equal(r.status, 409, "duplicate username rejected");
  r = await new Client().req("POST", "/api/auth/register", { username: `weak_${uid}`, password: "short" });
  assert.equal(r.status, 422, "weak password rejected");
  const u = await db.user.findUnique({ where: { username: ALICE.username } });
  assert.match(u.passwordHash, /^\$argon2id\$/, "password stored as Argon2id hash");
});

test("email verification via outbox link", async () => {
  const mail = await db.mailOutbox.findFirst({ where: { to: ALICE.email }, orderBy: { createdAt: "desc" } });
  const token = mail.body.match(/token=([A-Za-z0-9_-]+)/)[1];
  const r = await alice.req("POST", "/api/auth/verify-email", { token });
  assert.equal(r.status, 200);
  const again = await alice.req("POST", "/api/auth/verify-email", { token });
  assert.equal(again.status, 400, "verification token is single-use");
});

test("login by username and by email; wrong password rejected", async () => {
  const c1 = new Client();
  assert.equal((await c1.req("POST", "/api/auth/login", { identifier: ALICE.username, password: ALICE.password })).status, 200);
  const c2 = new Client();
  assert.equal((await c2.req("POST", "/api/auth/login", { identifier: ALICE.email.toUpperCase(), password: ALICE.password })).status, 200);
  assert.equal((await new Client().req("POST", "/api/auth/login", { identifier: ALICE.username, password: "nope-nope-1" })).status, 401);
  const me = await c2.req("GET", "/api/auth/me");
  assert.equal(me.data.user.username, ALICE.username);
});

test("CSRF: cross-origin state change is rejected", async () => {
  const r = await alice.req("POST", "/api/investigations", { subjectName: "x" }, { Origin: "https://evil.example" });
  assert.equal(r.status, 403);
});

test("administrator authentication", { skip: !ADMIN.password && "set SSME_ADMIN_PASSWORD" }, async () => {
  assert.equal((await new Client().req("POST", "/api/auth/login", { identifier: ALICE.username, password: ALICE.password, adminOnly: true })).status, 403, "non-admin refused at admin login");
  const r = await admin.req("POST", "/api/auth/login", { ...ADMIN, adminOnly: true });
  assert.equal(r.status, 200);
  assert.equal(r.data.user.role, "ADMIN");
  const d = await device("POST", "/api/desktop/auth/login", null, { ...ADMIN, appVersion: CLIENT_VERSION, adminOnly: true });
  assert.equal(d.status, 200, "desktop admin login");
  const list = await device("GET", "/api/desktop/staff/investigations", d.data.token);
  assert.equal(list.status, 200);
});

test("PIN creation and validation", async () => {
  assert.equal((await new Client().req("POST", "/api/investigations", { subjectName: "x" })).status, 401, "anonymous cannot create");
  const r = await alice.req("POST", "/api/investigations", { subjectName: "TestPlayer", serverName: "play.test" });
  assert.equal(r.status, 201);
  assert.match(r.data.pin, /^\d{3}-\d{3}$/);
  investigationId = r.data.id;
  pin = r.data.pin;
  const row = await db.investigationPin.findUnique({ where: { investigationId } });
  assert.ok(!row.lookupHash.includes(pin.replace("-", "")), "PIN not stored in plaintext");
  const snap = await alice.req("GET", `/api/investigations/${investigationId}`);
  assert.equal(snap.data.pin.pin, pin, "owner can re-display pending PIN");
});

test("authorization: other users cannot see the investigation", async () => {
  assert.equal((await bob.req("GET", `/api/investigations/${investigationId}`)).status, 404);
  assert.equal((await bob.req("GET", `/api/investigations/${investigationId}/events`)).status, 404);
  assert.equal((await bob.req("GET", `/api/investigations/${investigationId}/export?format=json`)).status, 404);
  assert.equal((await bob.req("POST", `/api/investigations/${investigationId}/cancel`, {})).status, 404);
  assert.equal((await bob.req("PATCH", `/api/admin/rules/SSME-CL-0001`, { enabled: false })).status, 403, "non-admin cannot use admin API");
});

test("wrong PIN rejected; malformed PIN rejected", async () => {
  const bad = pin === "000-000" ? "000-001" : "000-000";
  let r = await device("POST", "/api/desktop/pin/claim", null, { pin: bad, appVersion: CLIENT_VERSION });
  assert.equal(r.status, 404);
  r = await device("POST", "/api/desktop/pin/claim", null, { pin: "abc", appVersion: CLIENT_VERSION });
  assert.equal(r.status, 404);
});

test("desktop connection: PIN claim is single-use", async () => {
  const r = await device("POST", "/api/desktop/pin/claim", null, { pin, appVersion: CLIENT_VERSION, osVersion: "Windows 11 (test)", elevated: false });
  assert.equal(r.status, 200, JSON.stringify(r.data));
  assert.equal(r.data.investigation.subjectName, "TestPlayer");
  deviceToken = r.data.deviceToken;
  const again = await device("POST", "/api/desktop/pin/claim", null, { pin, appVersion: CLIENT_VERSION });
  assert.equal(again.status, 404, "used PIN cannot be claimed again");
  const snap = await alice.req("GET", `/api/investigations/${investigationId}`);
  assert.equal(snap.data.status, "CONNECTED");
  assert.equal(snap.data.pin, null, "PIN no longer displayed after claim");
  assert.equal(snap.data.device.appVersion, CLIENT_VERSION);
});

test("scan cannot start before consent; invalid token rejected", async () => {
  assert.equal((await device("POST", "/api/desktop/scan/start", "x".repeat(43), { engineVersion: "1.0.0", rulesetVersion: "t", elevated: false, categories: [{ key: "mods", name: "Mods" }] })).status, 401);
  const r = await device("POST", "/api/desktop/scan/start", deviceToken, { engineVersion: "1.0.0", rulesetVersion: "t", elevated: false, categories: [{ key: "mods", name: "Mods" }] });
  assert.equal(r.status, 403);
});

test("live scan updates arrive over SSE", async () => {
  const ac = new AbortController();
  const res = await fetch(`${BASE}/api/investigations/${investigationId}/events`, { headers: { Cookie: alice.cookie }, signal: ac.signal });
  assert.equal(res.status, 200);
  assert.match(res.headers.get("content-type"), /text\/event-stream/);
  const reader = res.body.getReader();
  const seen = new Set();
  const decoder = new TextDecoder();
  const pump = (async () => {
    let buf = "";
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += decoder.decode(value);
      for (const m of buf.matchAll(/"type":"([a-z.]+)"/g)) seen.add(m[1]);
      if (seen.has("scan.progress")) break;
    }
  })();

  assert.equal((await device("POST", "/api/desktop/consent", deviceToken, { accepted: true, consentVersion: "2026-11" })).status, 200);
  const rules = await device("GET", "/api/desktop/rules", deviceToken);
  assert.equal(rules.status, 200);
  assert.ok(rules.data.rules.length > 50, "catalog delivered to desktop");
  const start = await device("POST", "/api/desktop/scan/start", deviceToken, {
    engineVersion: "1.0.0", rulesetVersion: rules.data.version, elevated: false,
    categories: [{ key: "mods", name: "Mod archive analysis" }, { key: "logs", name: "Game logs" }],
  });
  assert.equal(start.status, 201);
  const prog = await device("POST", "/api/desktop/scan/progress", deviceToken, {
    progress: 40, currentActivity: "Examining installed modifications…",
    categories: [{ key: "mods", status: "RUNNING", itemsExamined: 12, findingsCount: 0 }],
  });
  assert.equal(prog.status, 200);
  await Promise.race([pump, new Promise((_, rej) => setTimeout(() => rej(new Error("SSE timeout")), 8000))]);
  ac.abort();
  for (const t of ["device.connected", "consent.given", "scan.started", "scan.progress"]) assert.ok(seen.has(t), `SSE delivered ${t}`);
});

test("evidence transmission: validation, unknown rules, idempotent retries", async () => {
  const bad = await device("POST", "/api/desktop/scan/findings", deviceToken, { findings: [{ ...finding("bad00001"), confidence: 140 }] });
  assert.equal(bad.status, 422, "out-of-range confidence rejected");
  const extra = await device("POST", "/api/desktop/scan/findings", deviceToken, { findings: [{ ...finding("bad00002"), injected: "x" }] });
  assert.equal(extra.status, 422, "unknown fields rejected (strict schema)");
  const unknownRule = await device("POST", "/api/desktop/scan/findings", deviceToken, { findings: [finding("bad00003", { ruleId: "SSME-XX-9999" })] });
  assert.equal(unknownRule.status, 400, "unknown rule rejected");
  const noHash = await device("POST", "/api/desktop/scan/findings", deviceToken, { findings: [finding("bad00004", { evidence: [{ kind: "LOG", source: "x", reference: "y", observedAt: now() }] })] });
  assert.equal(noHash.status, 422, "confirmed tier requires hashed evidence");

  const batch = [finding("good0001"), finding("good0002", { severity: "LOW", tier: "WEAK_INDICATOR", confidence: 30, ruleId: "SSME-H-RECYCLED_ARCHIVE" })];
  const r1 = await device("POST", "/api/desktop/scan/findings", deviceToken, { findings: batch });
  assert.deepEqual(r1.data, { accepted: 2, duplicates: 0 });
  const r2 = await device("POST", "/api/desktop/scan/findings", deviceToken, { findings: batch });
  assert.deepEqual(r2.data, { accepted: 0, duplicates: 2 }, "retry after dropped connection is idempotent");
  globalThis.__batch = batch;
});

test("scan completion with integrity manifest; report generation", async () => {
  const batch = globalThis.__batch;
  const wrongCount = await device("POST", "/api/desktop/scan/complete", deviceToken, completeBody(batch, 5));
  assert.equal(wrongCount.status, 409, "completion refused while findings are missing");
  const r = await device("POST", "/api/desktop/scan/complete", deviceToken, completeBody(batch, 2));
  assert.equal(r.status, 200, JSON.stringify(r.data));
  assert.equal(r.data.manifestVerified, true, "server recomputed identical manifest");

  const snap = (await alice.req("GET", `/api/investigations/${investigationId}`)).data;
  assert.equal(snap.status, "COMPLETED");
  assert.equal(snap.counts.total, 2);
  assert.equal(snap.counts.severity.CRITICAL, 1);
  assert.equal(snap.verdict.level, "confirmed");
  assert.equal(snap.detections[0].evidence[0].sha256, sha("good0001"));

  const json = await alice.req("GET", `/api/investigations/${investigationId}/export?format=json`);
  assert.equal(json.status, 200);
  assert.equal(json.data.reference, snap.reference);
  const csv = await alice.req("GET", `/api/investigations/${investigationId}/export?format=csv`);
  assert.equal(csv.status, 200);
  assert.ok(csv.data.toString("utf8").includes("SSME-CL-0001"));
  const pdf = await alice.req("GET", `/api/investigations/${investigationId}/export?format=pdf`);
  assert.equal(pdf.status, 200);
  assert.equal(pdf.data.subarray(0, 5).toString(), "%PDF-");

  const closed = await device("POST", "/api/desktop/scan/findings", deviceToken, { findings: [finding("late0001")] });
  assert.equal(closed.status, 410, "closed investigation refuses further uploads");
});

function completeBody(batch, count) {
  return {
    manifestSha256: manifest(batch), findingCount: count,
    summary: { installations: [{ launcher: "Official launcher", path: "C:\\fixture\\.minecraft", versions: "1.21.1, fabric-loader-0.16.5-1.21.1", modCount: 2 }], mods: [{ modId: "meteor-client", name: "Meteor Client", classification: "prohibited", fileName: "good0001.jar" }], javaRuntimes: [] },
    coverage: [{ key: "mods", name: "Mod archive analysis", status: "COMPLETED" }, { key: "logs", name: "Game logs", status: "SKIPPED", note: "No logs found" }],
    chainOfCustody: { engineVersion: "1.0.0", rulesetVersion: "t", osVersion: "Windows 11 (test)", elevated: false, startedAt: now(), completedAt: now(), readOnly: true, operations: [{ at: now(), action: "hash", target: "C:\\fixture\\mods\\good0001.jar" }] },
  };
}

test("administrator can inspect any investigation (audited)", { skip: !ADMIN.password && "set SSME_ADMIN_PASSWORD" }, async () => {
  const r = await admin.req("GET", `/api/investigations/${investigationId}`);
  assert.equal(r.status, 200);
  const log = await db.auditLog.findFirst({ where: { action: "admin.investigation_viewed", targetId: investigationId } });
  assert.ok(log, "admin view recorded in audit log");
});

test("PIN expiration", async () => {
  const r = await alice.req("POST", "/api/investigations", { subjectName: "ExpiryPlayer" });
  await db.investigationPin.update({ where: { investigationId: r.data.id }, data: { expiresAt: new Date(Date.now() - 1000) } });
  const claim = await device("POST", "/api/desktop/pin/claim", null, { pin: r.data.pin, appVersion: CLIENT_VERSION });
  assert.equal(claim.status, 404, "expired PIN cannot be claimed");
  const snap = await alice.req("GET", `/api/investigations/${r.data.id}`);
  assert.equal(snap.data.status, "EXPIRED");
  const regen = await alice.req("POST", `/api/investigations/${r.data.id}/pin`, {});
  assert.equal(regen.status, 200);
  assert.notEqual(regen.data.pin, undefined);
  const claim2 = await device("POST", "/api/desktop/pin/claim", null, { pin: regen.data.pin, appVersion: CLIENT_VERSION });
  assert.equal(claim2.status, 200, "regenerated PIN works");
});

test("connection interruption: offline device can be replaced by a new PIN", async () => {
  const r = await alice.req("POST", "/api/investigations", { subjectName: "DropPlayer" });
  const c = await device("POST", "/api/desktop/pin/claim", null, { pin: r.data.pin, appVersion: CLIENT_VERSION });
  const tok = c.data.deviceToken;
  assert.equal((await alice.req("POST", `/api/investigations/${r.data.id}/pin`, {})).status, 409, "cannot re-issue while desktop online");
  await db.connectedDevice.updateMany({ where: { investigationId: r.data.id }, data: { lastHeartbeatAt: new Date(Date.now() - 120_000) } });
  const re = await alice.req("POST", `/api/investigations/${r.data.id}/pin`, {});
  assert.equal(re.status, 200, "re-issue allowed once desktop is offline");
  assert.equal((await device("POST", "/api/desktop/heartbeat", tok, {})).status, 401, "old device token revoked");
  const c2 = await device("POST", "/api/desktop/pin/claim", null, { pin: re.data.pin, appVersion: CLIENT_VERSION });
  assert.equal(c2.status, 200);
  const sess = await device("GET", "/api/desktop/session", c2.data.deviceToken);
  assert.equal(sess.data.investigation.status, "CONNECTED");
});

test("blocked application versions are refused", async () => {
  const r = await device("POST", "/api/desktop/pin/claim", null, { pin: "123-456", appVersion: "0.9.0" });
  assert.equal(r.status, 426, "below minimum supported version");
});

test("PIN brute-force protection (per-IP limit)", async () => {
  await db.rateLimitBucket.deleteMany({});
  let last;
  for (let i = 0; i < 11; i++) last = await device("POST", "/api/desktop/pin/claim", null, { pin: String(100000 + i), appVersion: CLIENT_VERSION });
  assert.equal(last.status, 429);
  await db.rateLimitBucket.deleteMany({});
});
