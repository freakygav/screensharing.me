import { handler, json, notFound } from "@/lib/http";
import { requireDesktopStaff } from "@/lib/auth/session";
import { buildSnapshot } from "@/lib/investigations";
import { db } from "@/lib/db";
import { audit } from "@/lib/audit";

export const runtime = "nodejs";

export const GET = handler(async (req: Request, ctx: { params: Promise<{ id: string }> }) => {
  const { id } = await ctx.params;
  const user = await requireDesktopStaff(req);
  const inv = await db.investigation.findUnique({ where: { id }, select: { ownerId: true } });
  if (!inv || (inv.ownerId !== user.id && user.role !== "ADMIN")) throw notFound("Investigation not found.");
  if (user.role === "ADMIN" && inv.ownerId !== user.id) await audit({ actorType: "ADMIN", actorId: user.id, action: "admin.investigation_viewed", targetType: "Investigation", targetId: id, details: { via: "desktop" } });
  return json(await buildSnapshot(id));
});
