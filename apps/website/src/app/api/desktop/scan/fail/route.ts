import { db } from "@/lib/db";
import { handler, json, readJson } from "@/lib/http";
import { requireDevice } from "@/lib/investigations";
import { scanFailSchema } from "@/lib/validation";
import { publish } from "@/lib/events";
import { audit } from "@/lib/audit";

export const runtime = "nodejs";

export const POST = handler(async (req: Request) => {
  const device = await requireDevice(req);
  const { reason } = await readJson(req, scanFailSchema, 4096);
  await db.$transaction(async (tx) => {
    await tx.scan.updateMany({ where: { investigationId: device.investigationId, status: { in: ["RUNNING", "INTERRUPTED", "PENDING"] } }, data: { status: "FAILED", failureReason: reason, completedAt: new Date() } });
    await tx.investigation.update({ where: { id: device.investigationId }, data: { status: "FAILED" } });
    await publish(device.investigationId, "scan.failed", { reason }, tx);
  });
  await audit({ actorType: "DEVICE", action: "desktop.scan_failed", targetType: "Investigation", targetId: device.investigationId, details: { reason } });
  return json({ ok: true });
});
