import { db } from "@/lib/db";
import { conflict, handler, json, readJson } from "@/lib/http";
import { assertConsented, requireDevice } from "@/lib/investigations";
import { scanStartSchema } from "@/lib/validation";
import { publish } from "@/lib/events";
import { audit } from "@/lib/audit";

export const runtime = "nodejs";

export const POST = handler(async (req: Request) => {
  const device = await requireDevice(req);
  assertConsented(device.investigation);
  const body = await readJson(req, scanStartSchema, 16 * 1024);
  const existing = await db.scan.findUnique({ where: { investigationId: device.investigationId } });
  if (existing?.status === "COMPLETED") throw conflict("This investigation's scan has already completed.");

  const scan = await db.$transaction(async (tx) => {
    // A restarted scan replaces the previous partial attempt so results are never mixed.
    if (existing) await tx.scan.delete({ where: { id: existing.id } });
    const s = await tx.scan.create({
      data: {
        investigationId: device.investigationId,
        status: "RUNNING",
        engineVersion: body.engineVersion,
        rulesetVersion: body.rulesetVersion,
        elevated: body.elevated,
        categories: { create: body.categories.map((c, i) => ({ key: c.key, name: c.name, order: i })) },
      },
    });
    await tx.investigation.update({ where: { id: device.investigationId }, data: { status: "SCANNING" } });
    await tx.connectedDevice.update({ where: { id: device.id }, data: { elevated: body.elevated, lastHeartbeatAt: new Date() } });
    await publish(device.investigationId, "scan.started", { scanId: s.id, restarted: Boolean(existing) }, tx);
    return s;
  });
  await audit({ actorType: "DEVICE", action: existing ? "desktop.scan_restarted" : "desktop.scan_started", targetType: "Scan", targetId: scan.id });
  return json({ scanId: scan.id }, { status: 201 });
});
