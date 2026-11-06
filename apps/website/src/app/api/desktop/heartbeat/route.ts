import { handler, json } from "@/lib/http";
import { heartbeat, requireDevice } from "@/lib/investigations";
import { db } from "@/lib/db";
import { publish } from "@/lib/events";

export const runtime = "nodejs";

export const POST = handler(async (req: Request) => {
  const device = await requireDevice(req);
  const wasOffline = Date.now() - device.lastHeartbeatAt.getTime() > 45_000;
  const tokenExpiresAt = await heartbeat(device);
  if (wasOffline) {
    await db.scan.updateMany({ where: { investigationId: device.investigationId, status: "INTERRUPTED" }, data: { status: "RUNNING" } });
    await publish(device.investigationId, "device.heartbeat", { reconnected: true });
  }
  return json({ ok: true, tokenExpiresAt, status: device.investigation.status });
});
