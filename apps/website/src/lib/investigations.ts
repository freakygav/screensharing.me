import "server-only";
import type { ConnectedDevice, Investigation, Prisma, Severity, EvidenceTier, User } from "@prisma/client";
import { db } from "./db";
import { env } from "./env";
import { formatPin, generatePinDigits, generateReference, hmacHex, randomToken, seal, sha256Hex, unseal } from "./crypto";
import { conflict, forbidden, HttpError, notFound, unauthorized } from "./http";
import { publish } from "./events";
import { getConfig } from "./config";
import { compareSemver } from "./semver";
export { computeManifest, manifestLine } from "./manifest";

export const ONLINE_WINDOW_MS = 45_000;

// ------------------------------------------------------------------ access
/** Returns the investigation only if the user owns it or is an administrator. 404 otherwise (no existence leak). */
export async function getAuthorizedInvestigation(id: string, user: User) {
  const inv = await db.investigation.findUnique({ where: { id } });
  if (!inv || (inv.ownerId !== user.id && user.role !== "ADMIN")) throw notFound("Investigation not found.");
  return inv;
}

// -------------------------------------------------------------------- PINs
async function issuePin(tx: Prisma.TransactionClient, investigationId: string, ttlMinutes: number) {
  // Avoid collisions with any currently-active PIN (6 digits => 1e6 space).
  for (let attempt = 0; attempt < 20; attempt++) {
    const digits = generatePinDigits();
    const lookupHash = hmacHex("pin", digits);
    const clash = await tx.investigationPin.findFirst({
      where: { lookupHash, claimedAt: null, revokedAt: null, expiresAt: { gt: new Date() } },
      select: { id: true },
    });
    if (clash) continue;
    const expiresAt = new Date(Date.now() + ttlMinutes * 60_000);
    await tx.investigationPin.upsert({
      where: { investigationId },
      create: { investigationId, lookupHash, sealed: seal(digits), expiresAt },
      update: { lookupHash, sealed: seal(digits), expiresAt, claimedAt: null, revokedAt: null, createdAt: new Date() },
    });
    return { digits, expiresAt };
  }
  throw new HttpError(503, "pin_space_exhausted", "Could not allocate a unique PIN, please retry.");
}

export async function createInvestigation(owner: User, input: { subjectName: string; serverName?: string; notes?: string }) {
  const cfg = await getConfig();
  return db.$transaction(async (tx) => {
    let reference = generateReference();
    while (await tx.investigation.findUnique({ where: { reference }, select: { id: true } })) reference = generateReference();
    const inv = await tx.investigation.create({
      data: { reference, ownerId: owner.id, subjectName: input.subjectName, serverName: input.serverName || null, notes: input.notes || null },
    });
    const pin = await issuePin(tx, inv.id, cfg.pinTtlMinutes);
    await publish(inv.id, "investigation.created", { reference }, tx);
    return { investigation: inv, pin: formatPin(pin.digits), pinExpiresAt: pin.expiresAt };
  });
}

/**
 * Issues a new PIN. Allowed while waiting/expired, or to recover a lost desktop connection:
 * if the connected device has been offline for longer than the online window, its token is
 * revoked and a partially-complete scan is marked INTERRUPTED (it restarts cleanly on reconnect).
 */
export async function regeneratePin(inv: Investigation) {
  const cfg = await getConfig();
  if (inv.status === "CONNECTED" || inv.status === "SCANNING") {
    const live = await db.connectedDevice.findFirst({
      where: { investigationId: inv.id, revokedAt: null, lastHeartbeatAt: { gt: new Date(Date.now() - ONLINE_WINDOW_MS) } },
      select: { id: true },
    });
    if (live) throw conflict("The desktop application is still connected.");
  } else if (inv.status !== "WAITING" && inv.status !== "EXPIRED") {
    throw conflict("This investigation is closed.");
  }
  return db.$transaction(async (tx) => {
    await tx.connectedDevice.updateMany({ where: { investigationId: inv.id, revokedAt: null }, data: { revokedAt: new Date() } });
    await tx.scan.updateMany({ where: { investigationId: inv.id, status: { in: ["RUNNING", "PENDING"] } }, data: { status: "INTERRUPTED" } });
    const pin = await issuePin(tx, inv.id, cfg.pinTtlMinutes);
    await tx.investigation.update({ where: { id: inv.id }, data: { status: "WAITING", consentedAt: null } });
    await publish(inv.id, "pin.regenerated", {}, tx);
    return { pin: formatPin(pin.digits), pinExpiresAt: pin.expiresAt };
  });
}

/** Lazily transition WAITING investigations whose PIN expired and wipe the sealed PIN. */
export async function expireStalePins(where: Prisma.InvestigationWhereInput = {}) {
  const stale = await db.investigation.findMany({
    where: { ...where, status: "WAITING", pin: { expiresAt: { lt: new Date() }, claimedAt: null } },
    select: { id: true },
    take: 500,
  });
  for (const s of stale) {
    await db.$transaction(async (tx) => {
      const r = await tx.investigation.updateMany({ where: { id: s.id, status: "WAITING" }, data: { status: "EXPIRED" } });
      if (r.count) {
        await tx.investigationPin.update({ where: { investigationId: s.id }, data: { sealed: null } });
        await publish(s.id, "pin.expired", {}, tx);
      }
    });
  }
}

export function displayPin(pin: { sealed: string | null; expiresAt: Date; claimedAt: Date | null; revokedAt: Date | null } | null) {
  if (!pin || !pin.sealed || pin.claimedAt || pin.revokedAt || pin.expiresAt < new Date()) return null;
  const digits = unseal(pin.sealed);
  return digits ? { pin: formatPin(digits), expiresAt: pin.expiresAt } : null;
}

// ------------------------------------------------------------ desktop link
export async function assertAppVersionAllowed(appVersion: string) {
  const versions = await db.applicationVersion.findMany();
  const exact = versions.find((v) => v.version === appVersion);
  if (exact && !exact.active) throw new HttpError(426, "version_blocked", "This version of screensharing.me has been withdrawn. Download the latest version.");
  const minimum = versions.filter((v) => v.minimumSupported).sort((a, b) => compareSemver(b.version, a.version))[0];
  if (minimum && compareSemver(appVersion, minimum.version) < 0)
    throw new HttpError(426, "version_unsupported", `screensharing.me ${minimum.version} or newer is required.`);
}

export async function claimPin(digits: string, meta: { appVersion: string; osVersion?: string; elevated?: boolean; ip: string }) {
  const lookupHash = hmacHex("pin", digits);
  const now = new Date();
  const pinRow = await db.investigationPin.findFirst({
    where: { lookupHash, claimedAt: null, revokedAt: null, expiresAt: { gt: now } },
    include: { investigation: { include: { owner: { select: { displayName: true } } } } },
  });
  if (!pinRow || pinRow.investigation.status !== "WAITING") return null;

  const token = randomToken(32);
  const tokenExpiresAt = new Date(Date.now() + env.desktopTokenTtlMinutes * 60_000);
  const device = await db.$transaction(async (tx) => {
    // Single-use: only one concurrent claimer can flip claimedAt.
    const flipped = await tx.investigationPin.updateMany({
      where: { id: pinRow.id, claimedAt: null, revokedAt: null, expiresAt: { gt: now } },
      data: { claimedAt: now, sealed: null },
    });
    if (flipped.count !== 1) return null;
    await tx.investigation.update({ where: { id: pinRow.investigationId }, data: { status: "CONNECTED", connectedAt: now } });
    const d = await tx.connectedDevice.create({
      data: {
        investigationId: pinRow.investigationId,
        tokenHash: sha256Hex(token),
        tokenExpiresAt,
        appVersion: meta.appVersion,
        osVersion: meta.osVersion,
        elevated: meta.elevated ?? false,
        ip: meta.ip,
      },
    });
    await publish(pinRow.investigationId, "device.connected", { appVersion: meta.appVersion, elevated: meta.elevated ?? false }, tx);
    return d;
  });
  if (!device) return null;
  const inv = pinRow.investigation;
  return {
    device,
    token,
    tokenExpiresAt,
    investigation: {
      id: inv.id,
      reference: inv.reference,
      subjectName: inv.subjectName,
      serverName: inv.serverName,
      requestedBy: inv.owner.displayName,
      createdAt: inv.createdAt,
    },
  };
}

/** Authenticates the desktop's investigation-scoped bearer token. */
export async function requireDevice(req: Request, opts: { allowFinished?: boolean } = {}) {
  const auth = req.headers.get("authorization") ?? "";
  if (!auth.startsWith("Bearer ")) throw unauthorized("Missing device token.");
  const token = auth.slice(7).trim();
  if (token.length < 20 || token.length > 200) throw unauthorized("Invalid device token.");
  const device = await db.connectedDevice.findUnique({ where: { tokenHash: sha256Hex(token) }, include: { investigation: true } });
  if (!device || device.revokedAt || device.tokenExpiresAt < new Date()) throw unauthorized("Device token is invalid or expired.");
  const st = device.investigation.status;
  if (!opts.allowFinished && (st === "CANCELLED" || st === "COMPLETED" || st === "FAILED" || st === "EXPIRED"))
    throw new HttpError(410, "investigation_closed", `This investigation is ${st.toLowerCase()}.`);
  return device as ConnectedDevice & { investigation: Investigation };
}

/** Heartbeat: records liveness and slides the token expiry (bounded to 12h after connection). */
export async function heartbeat(device: ConnectedDevice) {
  const hardCap = device.connectedAt.getTime() + 12 * 3600_000;
  const next = Math.min(Date.now() + env.desktopTokenTtlMinutes * 60_000, hardCap);
  const updated = await db.connectedDevice.update({
    where: { id: device.id },
    data: { lastHeartbeatAt: new Date(), tokenExpiresAt: new Date(next) },
  });
  return updated.tokenExpiresAt;
}

export function assertConsented(inv: Investigation) {
  if (!inv.consentedAt) throw forbidden("The player has not authorised the scan.");
}

// ---------------------------------------------------------------- results
export const SEVERITY_ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
export const TIER_ORDER: EvidenceTier[] = ["CONFIRMED_ARTIFACT", "STRONG_INDICATOR", "SUSPICIOUS_CONFIGURATION", "WEAK_INDICATOR", "INCONCLUSIVE"];

export interface Verdict {
  level: "clear" | "review" | "suspicious" | "strong" | "confirmed";
  title: string;
  explanation: string;
}

/** Evidence-tiered verdict. Deliberately never says "cheater": it describes what the evidence supports. */
export function computeVerdict(counts: Record<EvidenceTier, number>, completed: boolean): Verdict {
  if (!completed) return { level: "review", title: "Scan not complete", explanation: "The verdict is computed when the scan finishes." };
  if (counts.CONFIRMED_ARTIFACT > 0)
    return { level: "confirmed", title: "Confirmed artifact match", explanation: "At least one artifact matched a verified signature of a prohibited modification. Review the evidence and correlate with timing before taking action." };
  if (counts.STRONG_INDICATOR > 0)
    return { level: "strong", title: "Strong forensic indicators", explanation: "Evidence strongly indicates a prohibited modification, but no artifact was matched against a verified signature. Manual review is required." };
  if (counts.SUSPICIOUS_CONFIGURATION > 0)
    return { level: "suspicious", title: "Suspicious configuration", explanation: "The system contains configurations commonly associated with prohibited modifications or concealment. These have legitimate explanations; review each finding." };
  if (counts.WEAK_INDICATOR > 0)
    return { level: "review", title: "Weak indicators only", explanation: "Only weak indicators were found. On their own they do not support a conclusion." };
  return { level: "clear", title: "No indicators found", explanation: "No examined artifact matched a detection rule. This does not prove the absence of modifications outside the examined scope; see coverage." };
}

/** Full state used by the live page, the report page, exports and the desktop staff view. */
export async function buildSnapshot(investigationId: string, opts: { includeDetections?: boolean } = { includeDetections: true }) {
  const inv = await db.investigation.findUnique({
    where: { id: investigationId },
    include: {
      owner: { select: { id: true, username: true, displayName: true } },
      pin: true,
      devices: { orderBy: { connectedAt: "desc" }, take: 1 },
      scan: {
        include: {
          categories: { orderBy: { order: "asc" } },
          detections: { include: { evidence: { orderBy: { position: "asc" } } }, orderBy: [{ detectedAt: "asc" }], take: opts.includeDetections === false ? 0 : undefined },
        },
      },
    },
  });
  if (!inv) throw notFound("Investigation not found.");

  const device = inv.devices[0] ?? null;
  const scan = inv.scan;
  const severityCounts = Object.fromEntries(SEVERITY_ORDER.map((s) => [s, 0])) as Record<Severity, number>;
  const tierCounts = Object.fromEntries(TIER_ORDER.map((t) => [t, 0])) as Record<EvidenceTier, number>;
  let total = 0;
  if (scan) {
    const grouped = await db.detection.groupBy({ by: ["severity", "tier"], where: { scanId: scan.id }, _count: { _all: true } });
    for (const g of grouped) {
      severityCounts[g.severity] += g._count._all;
      tierCounts[g.tier] += g._count._all;
      total += g._count._all;
    }
  }
  const completed = scan?.status === "COMPLETED";
  const detections = scan
    ? [...scan.detections]
        .sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) || b.confidence - a.confidence)
        .map((d) => ({
          id: d.id,
          ruleId: d.ruleId,
          name: d.name,
          description: d.description,
          category: d.category,
          categoryKey: d.categoryKey,
          severity: d.severity,
          tier: d.tier,
          confidence: d.confidence,
          method: d.method,
          whyItMatters: d.whyItMatters,
          limitations: d.limitations,
          falsePositiveNotes: d.falsePositiveNotes,
          alternativeExplanations: d.alternativeExplanations,
          detectedAt: d.detectedAt.toISOString(),
          evidence: d.evidence.map((e) => ({
            id: e.id,
            kind: e.kind,
            source: e.source,
            reference: e.reference,
            sha256: e.sha256,
            sizeBytes: e.sizeBytes === null ? null : Number(e.sizeBytes),
            createdTime: e.createdTime?.toISOString() ?? null,
            modifiedTime: e.modifiedTime?.toISOString() ?? null,
            accessedTime: e.accessedTime?.toISOString() ?? null,
            observedAt: e.observedAt.toISOString(),
            details: (e.details ?? null) as Record<string, string> | null,
          })),
        }))
    : [];

  const lastEvent = await db.investigationEvent.findFirst({ where: { investigationId }, orderBy: { id: "desc" }, select: { id: true } });

  return {
    id: inv.id,
    reference: inv.reference,
    subjectName: inv.subjectName,
    serverName: inv.serverName,
    notes: inv.notes,
    status: inv.status,
    owner: inv.owner,
    createdAt: inv.createdAt.toISOString(),
    connectedAt: inv.connectedAt?.toISOString() ?? null,
    consentedAt: inv.consentedAt?.toISOString() ?? null,
    completedAt: inv.completedAt?.toISOString() ?? null,
    pin: inv.status === "WAITING" ? displayPin(inv.pin) : null,
    pinExpiresAt: inv.pin?.expiresAt.toISOString() ?? null,
    device: device && {
      appVersion: device.appVersion,
      osVersion: device.osVersion,
      elevated: device.elevated,
      connectedAt: device.connectedAt.toISOString(),
      lastHeartbeatAt: device.lastHeartbeatAt.toISOString(),
      online: !device.revokedAt && Date.now() - device.lastHeartbeatAt.getTime() < ONLINE_WINDOW_MS,
    },
    scan: scan && {
      id: scan.id,
      status: scan.status,
      progress: scan.progress,
      currentActivity: scan.currentActivity,
      engineVersion: scan.engineVersion,
      rulesetVersion: scan.rulesetVersion,
      elevated: scan.elevated,
      startedAt: scan.startedAt.toISOString(),
      completedAt: scan.completedAt?.toISOString() ?? null,
      lastUpdateAt: scan.lastUpdateAt.toISOString(),
      failureReason: scan.failureReason,
      manifestSha256: scan.manifestSha256,
      manifestVerified: scan.manifestVerified,
      summary: scan.summary as Record<string, unknown> | null,
      coverage: scan.coverage as unknown[] | null,
      chainOfCustody: scan.chainOfCustody as Record<string, unknown> | null,
      categories: scan.categories.map((c) => ({
        key: c.key,
        name: c.name,
        status: c.status,
        itemsExamined: c.itemsExamined,
        findingsCount: c.findingsCount,
        message: c.message,
        startedAt: c.startedAt?.toISOString() ?? null,
        completedAt: c.completedAt?.toISOString() ?? null,
      })),
    },
    counts: { total, severity: severityCounts, tier: tierCounts },
    verdict: computeVerdict(tierCounts, completed),
    detections,
    lastEventId: lastEvent ? lastEvent.id.toString() : "0",
    generatedAt: new Date().toISOString(),
  };
}

export type InvestigationSnapshot = Awaited<ReturnType<typeof buildSnapshot>>;
