// Seeds the detection catalog from packages/detection-rules/rules.json and
// bootstraps the first administrator from ADMIN_BOOTSTRAP_* environment variables.
//
//   npm run db:seed
//
// The administrator password is hashed with Argon2id; it is never stored in
// plaintext and never compiled into the desktop executable. Re-running the seed
// does NOT overwrite an existing administrator's password unless
// ADMIN_BOOTSTRAP_FORCE_RESET=1 is set.
import { PrismaClient } from "@prisma/client";
import { hash } from "@node-rs/argon2";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const rulesPath = path.resolve(here, "../../../packages/detection-rules/rules.json");
const db = new PrismaClient();

async function seedRules() {
  const catalog = JSON.parse(fs.readFileSync(rulesPath, "utf8"));
  let created = 0, updated = 0;
  for (const r of catalog.rules) {
    const data = {
      name: r.name, description: r.description, category: r.category, kind: r.kind, pattern: r.pattern,
      family: r.family ?? null, features: r.features ?? [], severity: r.severity, tier: r.tier, confidence: r.confidence,
      classification: r.classification ?? null, falsePositives: r.falsePositives, limitations: r.limitations, references: r.references ?? [],
    };
    const existing = await db.detectionRule.findUnique({ where: { id: r.id } });
    if (!existing) { await db.detectionRule.create({ data: { id: r.id, ...data } }); created++; }
    else if (!existing.updatedById) { await db.detectionRule.update({ where: { id: r.id }, data }); updated++; } // never clobber admin edits
  }
  await db.systemConfig.upsert({ where: { key: "rulesetVersion" }, create: { key: "rulesetVersion", value: catalog.version }, update: { value: catalog.version } });
  console.log(`[seed] rules: ${created} created, ${updated} refreshed (catalog ${catalog.version})`);
}

async function seedAdmin() {
  const email = process.env.ADMIN_BOOTSTRAP_EMAIL?.trim().toLowerCase();
  const username = (process.env.ADMIN_BOOTSTRAP_USERNAME ?? "admin").trim().toLowerCase();
  const password = process.env.ADMIN_BOOTSTRAP_PASSWORD;
  if (!email || !password) {
    console.log("[seed] ADMIN_BOOTSTRAP_EMAIL/PASSWORD not set; skipping administrator bootstrap");
    return;
  }
  const passwordHash = await hash(password, { memoryCost: 19456, timeCost: 2, parallelism: 1, outputLen: 32, algorithm: 2 });
  const existing = await db.user.findFirst({ where: { OR: [{ email }, { username }] } });
  if (existing) {
    const data = { role: "ADMIN", disabled: false, emailVerified: existing.emailVerified ?? new Date() };
    if (process.env.ADMIN_BOOTSTRAP_FORCE_RESET === "1") data.passwordHash = passwordHash;
    await db.user.update({ where: { id: existing.id }, data });
    console.log(`[seed] administrator ${existing.username} ensured${data.passwordHash ? " (password reset)" : ""}`);
  } else {
    const u = await db.user.create({ data: { username, displayName: username, email, emailVerified: new Date(), passwordHash, role: "ADMIN" } });
    await db.auditLog.create({ data: { actorType: "SYSTEM", action: "admin.bootstrap", targetType: "User", targetId: u.id } });
    console.log(`[seed] administrator "${username}" created for ${email}`);
  }
}

async function seedVersion() {
  const v = "1.0.0";
  await db.applicationVersion.upsert({ where: { version: v }, create: { version: v, channel: "stable", minimumSupported: true, notes: "Initial release", downloadUrl: "/download/screensharing.me.exe" }, update: {} });
}

try {
  await seedRules();
  await seedAdmin();
  await seedVersion();
} finally {
  await db.$disconnect();
}
