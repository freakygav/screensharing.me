import { db } from "@/lib/db";
import { conflict, handler, json, readJson } from "@/lib/http";
import { requireDevice } from "@/lib/investigations";
import { computeManifest } from "@/lib/manifest";
import { scanCompleteSchema } from "@/lib/validation";
import { publish } from "@/lib/events";
import { audit } from "@/lib/audit";

export const runtime = "nodejs";

export const POST = handler(async (req: Request) => {
  const device = await requireDevice(req);
  const body = await readJson(req, scanCompleteSchema, 2 * 1024 * 1024);
  const scan = await db.scan.findUnique({
    where: { investigationId: device.investigationId },
    include: { detections: { select: { clientFindingId: true, ruleId: true, severity: true, tier: true, confidence: true, evidence: { select: { reference: true, sha256: true } } } } },
  });
  if (!scan || (scan.status !== "RUNNING" && scan.status !== "INTERRUPTED")) throw conflict("No scan is running.");
  if (scan.detections.length !== body.findingCount) {
    throw conflict(`Server holds ${scan.detections.length} findings but the scanner reported ${body.findingCount}. Re-send pending findings before completing.`);
  }
  // Recompute the integrity manifest from what the server actually stored.
  const serverManifest = computeManifest(scan.detections);
  const verified = serverManifest === body.manifestSha256;
  const now = new Date();
  await db.$transaction(async (tx) => {
    await tx.scan.update({
      where: { id: scan.id },
      data: {
        status: "COMPLETED", progress: 100, completedAt: now, lastUpdateAt: now, currentActivity: null,
        summary: body.summary, coverage: body.coverage, chainOfCustody: { ...body.chainOfCustody, serverReceivedAt: now.toISOString(), serverManifestSha256: serverManifest },
        manifestSha256: body.manifestSha256, manifestVerified: verified,
      },
    });
    for (const c of body.coverage) {
      await tx.scanCategory.updateMany({ where: { scanId: scan.id, key: c.key }, data: { status: c.status, message: c.note ?? null, completedAt: now } });
    }
    await tx.investigation.update({ where: { id: device.investigationId }, data: { status: "COMPLETED", completedAt: now } });
    await tx.connectedDevice.update({ where: { id: device.id }, data: { lastHeartbeatAt: now } });
    await publish(device.investigationId, "scan.completed", { findings: scan.detections.length, manifestVerified: verified }, tx);
  }, { timeout: 30_000, maxWait: 10_000 });
  await audit({ actorType: "DEVICE", action: "desktop.scan_completed", targetType: "Scan", targetId: scan.id, details: { findings: scan.detections.length, manifestVerified: verified } });
  return json({ ok: true, manifestVerified: verified, serverManifestSha256: serverManifest });
});
