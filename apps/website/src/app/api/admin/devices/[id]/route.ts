import { db } from "@/lib/db";
import { handler, json, notFound } from "@/lib/http";
import { adminMutation } from "@/lib/admin";

export const runtime = "nodejs";

/** Revokes a connected desktop's investigation token. */
export const DELETE = handler(async (req: Request, ctx: { params: Promise<{ id: string }> }) => {
  const { id } = await ctx.params;
  const { log } = await adminMutation(req);
  const d = await db.connectedDevice.findUnique({ where: { id } });
  if (!d) throw notFound("Device not found.");
  await db.connectedDevice.update({ where: { id }, data: { revokedAt: new Date() } });
  await log("admin.device_revoked", "ConnectedDevice", id, { investigationId: d.investigationId });
  return json({ ok: true });
});
