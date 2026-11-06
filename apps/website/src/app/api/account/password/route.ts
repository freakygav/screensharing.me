import { assertSameOrigin, clientIp, handler, HttpError, json, readJson } from "@/lib/http";
import { changePasswordSchema } from "@/lib/validation";
import { getCurrentSession, requireUser } from "@/lib/auth/session";
import { hashPassword, verifyPassword } from "@/lib/auth/password";
import { enforce } from "@/lib/ratelimit";
import { db } from "@/lib/db";
import { audit } from "@/lib/audit";

export const runtime = "nodejs";

export const POST = handler(async (req: Request) => {
  assertSameOrigin(req);
  const user = await requireUser();
  await enforce(`pwchange:${user.id}`, 5, 900);
  const body = await readJson(req, changePasswordSchema);
  if (!(await verifyPassword(user.passwordHash, body.currentPassword))) throw new HttpError(401, "invalid_credentials", "Current password is incorrect.");
  const current = await getCurrentSession();
  const passwordHash = await hashPassword(body.newPassword);
  await db.$transaction([
    db.user.update({ where: { id: user.id }, data: { passwordHash } }),
    db.session.updateMany({ where: { userId: user.id, revokedAt: null, NOT: { id: current?.id ?? "" } }, data: { revokedAt: new Date() } }),
  ]);
  await audit({ actorType: user.role === "ADMIN" ? "ADMIN" : "USER", actorId: user.id, action: "account.password_changed", ip: clientIp(req) });
  return json({ ok: true });
});
