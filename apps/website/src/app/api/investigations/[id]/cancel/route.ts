import { db } from "@/lib/db";
import { assertSameOrigin, conflict, handler, json } from "@/lib/http";
import { requireUser } from "@/lib/auth/session";
import { getAuthorizedInvestigation } from "@/lib/investigations";
import { publish } from "@/lib/events";
import { audit } from "@/lib/audit";

export const runtime = "nodejs";

export const POST = handler(async (req: Request, ctx: { params: Promise<{ id: string }> }) => {
  assertSameOrigin(req);
  const { id } = await ctx.params;
  const user = await requireUser();
  const inv = await getAuthorizedInvestigation(id, user);
  if (["COMPLETED", "CANCELLED", "FAILED"].includes(inv.status)) throw conflict("This investigation is already closed.");
  await db.$transaction(async (tx) => {
    await tx.investigation.update({ where: { id }, data: { status: "CANCELLED" } });
    await tx.investigationPin.updateMany({ where: { investigationId: id }, data: { revokedAt: new Date(), sealed: null } });
    await tx.connectedDevice.updateMany({ where: { investigationId: id, revokedAt: null }, data: { revokedAt: new Date() } });
    await tx.scan.updateMany({ where: { investigationId: id, status: { in: ["PENDING", "RUNNING", "INTERRUPTED"] } }, data: { status: "FAILED", failureReason: "Cancelled by investigator" } });
    await publish(id, "investigation.cancelled", {}, tx);
  });
  await audit({ actorType: user.role === "ADMIN" ? "ADMIN" : "USER", actorId: user.id, action: "investigation.cancel", targetType: "Investigation", targetId: id });
  return json({ ok: true });
});
