import { randomUUID } from "node:crypto";
import type { Prisma } from "@prisma/client";
import { db } from "@/lib/db";
import { badRequest, conflict, handler, json, readJson } from "@/lib/http";
import { requireDevice } from "@/lib/investigations";
import { findingsBatchSchema } from "@/lib/validation";
import { publish } from "@/lib/events";

export const runtime = "nodejs";

/**
 * Idempotent batch upload of findings. Each finding is keyed by (scanId, clientFindingId)
 * so the desktop can safely retry after a dropped connection. Inserts are done with two
 * bulk statements in one transaction so large batches stay fast.
 */
export const POST = handler(async (req: Request) => {
  const device = await requireDevice(req);
  const body = await readJson(req, findingsBatchSchema, 1024 * 1024);
  const scan = await db.scan.findUnique({ where: { investigationId: device.investigationId } });
  if (!scan || (scan.status !== "RUNNING" && scan.status !== "INTERRUPTED")) throw conflict("No scan is running.");

  // Every finding must reference a rule that exists in the catalog.
  const ruleIds = [...new Set(body.findings.map((f) => f.ruleId))];
  const known = await db.detectionRule.findMany({ where: { id: { in: ruleIds } }, select: { id: true } });
  const missing = ruleIds.filter((r) => !known.some((k) => k.id === r));
  if (missing.length) throw badRequest("Findings reference unknown detection rules.", { unknownRules: missing });

  const existing = await db.detection.findMany({
    where: { scanId: scan.id, clientFindingId: { in: body.findings.map((f) => f.clientFindingId) } },
    select: { clientFindingId: true },
  });
  const seen = new Set(existing.map((e) => e.clientFindingId));
  const fresh = body.findings.filter((f, i, all) => !seen.has(f.clientFindingId) && all.findIndex((x) => x.clientFindingId === f.clientFindingId) === i);

  const detections: Prisma.DetectionCreateManyInput[] = [];
  const evidence: Prisma.EvidenceCreateManyInput[] = [];
  for (const f of fresh) {
    const id = randomUUID();
    detections.push({
      id,
      scanId: scan.id,
      clientFindingId: f.clientFindingId,
      ruleId: f.ruleId,
      name: f.name,
      description: f.description,
      category: f.category,
      categoryKey: f.categoryKey,
      severity: f.severity,
      tier: f.tier,
      confidence: f.confidence,
      method: f.method,
      whyItMatters: f.whyItMatters,
      limitations: f.limitations,
      falsePositiveNotes: f.falsePositiveNotes,
      alternativeExplanations: f.alternativeExplanations,
      detectedAt: new Date(f.detectedAt),
    });
    f.evidence.forEach((e, position) =>
      evidence.push({
        detectionId: id,
        position,
        kind: e.kind,
        source: e.source,
        reference: e.reference,
        sha256: e.sha256 ?? null,
        sizeBytes: e.sizeBytes == null ? null : BigInt(e.sizeBytes),
        createdTime: e.createdTime ? new Date(e.createdTime) : null,
        modifiedTime: e.modifiedTime ? new Date(e.modifiedTime) : null,
        accessedTime: e.accessedTime ? new Date(e.accessedTime) : null,
        observedAt: new Date(e.observedAt),
        details: e.details ?? undefined,
      }),
    );
  }

  await db.$transaction(
    async (tx) => {
      if (detections.length) {
        // skipDuplicates covers a concurrent retry racing this request.
        const created = await tx.detection.createMany({ data: detections, skipDuplicates: true });
        if (created.count !== detections.length) {
          const kept = await tx.detection.findMany({ where: { id: { in: detections.map((d) => d.id!) } }, select: { id: true } });
          const keep = new Set(kept.map((k) => k.id));
          evidence.splice(0, evidence.length, ...evidence.filter((e) => keep.has(e.detectionId)));
        }
        if (evidence.length) await tx.evidence.createMany({ data: evidence });
      }
      await tx.scan.update({ where: { id: scan.id }, data: { lastUpdateAt: new Date() } });
      if (fresh.length) {
        await publish(device.investigationId, "scan.findings", {
          added: fresh.length,
          items: fresh.slice(0, 10).map((f) => ({ name: f.name, severity: f.severity, tier: f.tier })),
        }, tx);
      }
    },
    { timeout: 30_000, maxWait: 10_000 },
  );
  return json({ accepted: fresh.length, duplicates: body.findings.length - fresh.length });
});
