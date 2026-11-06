import { handler, json } from "@/lib/http";
import { heartbeat, requireDevice } from "@/lib/investigations";
import { db } from "@/lib/db";

export const runtime = "nodejs";

/** Used by the desktop to resume after a restart/reconnect. */
export const GET = handler(async (req: Request) => {
  const device = await requireDevice(req, { allowFinished: true });
  const tokenExpiresAt = await heartbeat(device);
  const inv = device.investigation;
  const owner = await db.user.findUnique({ where: { id: inv.ownerId }, select: { displayName: true } });
  const scan = await db.scan.findUnique({ where: { investigationId: inv.id }, select: { id: true, status: true, progress: true, _count: { select: { detections: true } } } });
  return json({
    tokenExpiresAt,
    investigation: {
      id: inv.id, reference: inv.reference, subjectName: inv.subjectName, serverName: inv.serverName,
      requestedBy: owner?.displayName ?? "", createdAt: inv.createdAt, status: inv.status, consentedAt: inv.consentedAt,
    },
    scan: scan && { id: scan.id, status: scan.status, progress: scan.progress, findingsReceived: scan._count.detections },
  });
});
