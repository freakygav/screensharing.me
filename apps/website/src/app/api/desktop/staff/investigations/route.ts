import { db } from "@/lib/db";
import { handler, json } from "@/lib/http";
import { requireDesktopStaff } from "@/lib/auth/session";

export const runtime = "nodejs";

/** Investigations visible to the signed-in staff member (all of them for administrators). */
export const GET = handler(async (req: Request) => {
  const user = await requireDesktopStaff(req);
  const rows = await db.investigation.findMany({
    where: user.role === "ADMIN" ? {} : { ownerId: user.id },
    orderBy: { createdAt: "desc" },
    take: 200,
    include: { owner: { select: { displayName: true } }, scan: { select: { status: true, progress: true, _count: { select: { detections: true } } } } },
  });
  return json({
    investigations: rows.map((r) => ({
      id: r.id, reference: r.reference, subjectName: r.subjectName, serverName: r.serverName, status: r.status,
      owner: r.owner.displayName, createdAt: r.createdAt, completedAt: r.completedAt,
      progress: r.scan?.progress ?? 0, findings: r.scan?._count.detections ?? 0,
    })),
  });
});
