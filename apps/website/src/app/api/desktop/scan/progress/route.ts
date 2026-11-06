import { db } from "@/lib/db";
import { conflict, handler, json, readJson } from "@/lib/http";
import { requireDevice } from "@/lib/investigations";
import { scanProgressSchema } from "@/lib/validation";
import { publish } from "@/lib/events";

export const runtime = "nodejs";

export const POST = handler(async (req: Request) => {
  const device = await requireDevice(req);
  const body = await readJson(req, scanProgressSchema, 32 * 1024);
  const scan = await db.scan.findUnique({ where: { investigationId: device.investigationId }, include: { categories: true } });
  if (!scan || (scan.status !== "RUNNING" && scan.status !== "INTERRUPTED")) throw conflict("No scan is running.");
  const now = new Date();
  await db.$transaction(async (tx) => {
    for (const c of body.categories) {
      const prev = scan.categories.find((x) => x.key === c.key);
      if (!prev) continue; // ignore categories not declared at start
      await tx.scanCategory.update({
        where: { id: prev.id },
        data: {
          status: c.status,
          itemsExamined: c.itemsExamined,
          findingsCount: c.findingsCount,
          message: c.message ?? null,
          startedAt: prev.startedAt ?? (c.status !== "PENDING" ? now : null),
          completedAt: ["COMPLETED", "SKIPPED", "FAILED"].includes(c.status) ? (prev.completedAt ?? now) : null,
        },
      });
    }
    await tx.scan.update({
      where: { id: scan.id },
      data: {
        progress: Math.max(scan.progress, body.progress), currentActivity: body.currentActivity ?? null, lastUpdateAt: now, status: "RUNNING",
        // Live counters are kept next to the selected instance until the final summary replaces them.
        ...(body.files ? { summary: { ...((scan.summary as Record<string, unknown> | null) ?? {}), live: body.files } } : {}),
      },
    });
    await tx.connectedDevice.update({ where: { id: device.id }, data: { lastHeartbeatAt: now } });
    await publish(device.investigationId, "scan.progress", { progress: Math.max(scan.progress, body.progress), activity: body.currentActivity ?? null, files: body.files ?? null }, tx);
  });
  return json({ ok: true });
});
