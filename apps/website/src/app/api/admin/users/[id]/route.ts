import { db } from "@/lib/db";
import { badRequest, handler, json, notFound, readJson } from "@/lib/http";
import { adminMutation } from "@/lib/admin";
import { adminUserPatchSchema } from "@/lib/validation";

export const runtime = "nodejs";

export const PATCH = handler(async (req: Request, ctx: { params: Promise<{ id: string }> }) => {
  const { id } = await ctx.params;
  const { admin, log } = await adminMutation(req);
  const body = await readJson(req, adminUserPatchSchema);
  const target = await db.user.findUnique({ where: { id } });
  if (!target) throw notFound("User not found.");
  if (target.id === admin.id && (body.role === "USER" || body.disabled)) throw badRequest("You cannot demote or disable your own account.");
  if (body.role === "USER" && target.role === "ADMIN") {
    const admins = await db.user.count({ where: { role: "ADMIN", disabled: false } });
    if (admins <= 1) throw badRequest("At least one active administrator must remain.");
  }
  const updated = await db.user.update({
    where: { id },
    data: { role: body.role ?? undefined, disabled: body.disabled ?? undefined },
  });
  if (body.disabled || body.revokeSessions || (body.role && body.role !== target.role)) {
    await db.session.updateMany({ where: { userId: id, revokedAt: null }, data: { revokedAt: new Date() } });
  }
  await log("admin.user_updated", "User", id, { before: { role: target.role, disabled: target.disabled }, after: { role: updated.role, disabled: updated.disabled }, revokeSessions: Boolean(body.revokeSessions) });
  return json({ ok: true });
});
