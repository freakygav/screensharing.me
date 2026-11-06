import { db } from "@/lib/db";
import { handler, json, notFound } from "@/lib/http";
import { adminMutation } from "@/lib/admin";

export const runtime = "nodejs";

export const DELETE = handler(async (req: Request, ctx: { params: Promise<{ id: string }> }) => {
  const { id } = await ctx.params;
  const { log } = await adminMutation(req);
  const s = await db.session.findUnique({ where: { id } });
  if (!s) throw notFound("Session not found.");
  await db.session.update({ where: { id }, data: { revokedAt: new Date() } });
  await log("admin.session_revoked", "Session", id, { userId: s.userId, kind: s.kind });
  return json({ ok: true });
});
