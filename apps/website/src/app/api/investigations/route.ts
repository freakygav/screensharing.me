import { db } from "@/lib/db";
import type { InvestigationStatus } from "@prisma/client";
import { assertSameOrigin, clientIp, handler, json, readJson } from "@/lib/http";
import { requireUser } from "@/lib/auth/session";
import { createInvestigationSchema } from "@/lib/validation";
import { createInvestigation, expireStalePins } from "@/lib/investigations";
import { enforce } from "@/lib/ratelimit";
import { audit } from "@/lib/audit";

export const runtime = "nodejs";

export const GET = handler(async (req: Request) => {
  const user = await requireUser();
  await expireStalePins({ ownerId: user.id });
  const url = new URL(req.url);
  const scope = url.searchParams.get("scope") ?? "all";
  const statuses: InvestigationStatus[] | null =
    scope === "active" ? ["WAITING", "CONNECTED", "SCANNING"]
    : scope === "history" ? ["COMPLETED", "FAILED", "CANCELLED", "EXPIRED"]
    : null;
  const statusFilter = statuses ? { status: { in: statuses } } : {};
  const rows = await db.investigation.findMany({
    where: { ownerId: user.id, ...statusFilter },
    orderBy: { createdAt: "desc" },
    take: 200,
    include: { scan: { select: { status: true, progress: true, _count: { select: { detections: true } } } } },
  });
  return json({
    investigations: rows.map((r) => ({
      id: r.id, reference: r.reference, subjectName: r.subjectName, serverName: r.serverName, status: r.status,
      createdAt: r.createdAt, completedAt: r.completedAt, progress: r.scan?.progress ?? 0, findings: r.scan?._count.detections ?? 0,
    })),
  });
});

export const POST = handler(async (req: Request) => {
  assertSameOrigin(req);
  const user = await requireUser();
  await enforce(`create-inv:${user.id}`, 30, 3600);
  const body = await readJson(req, createInvestigationSchema);
  const created = await createInvestigation(user, { subjectName: body.subjectName, serverName: body.serverName || undefined, notes: body.notes || undefined });
  await audit({ actorType: user.role === "ADMIN" ? "ADMIN" : "USER", actorId: user.id, action: "investigation.create", targetType: "Investigation", targetId: created.investigation.id, ip: clientIp(req) });
  return json({ id: created.investigation.id, reference: created.investigation.reference, pin: created.pin, pinExpiresAt: created.pinExpiresAt }, { status: 201 });
});
