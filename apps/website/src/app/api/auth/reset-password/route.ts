import { assertSameOrigin, badRequest, clientIp, handler, json, readJson } from "@/lib/http";
import { resetPasswordSchema } from "@/lib/validation";
import { consumeEmailToken } from "@/lib/auth/email-tokens";
import { hashPassword } from "@/lib/auth/password";
import { db } from "@/lib/db";
import { audit } from "@/lib/audit";

export const runtime = "nodejs";

export const POST = handler(async (req: Request) => {
  assertSameOrigin(req);
  const body = await readJson(req, resetPasswordSchema);
  const row = await consumeEmailToken(body.token, "RESET_PASSWORD");
  if (!row) throw badRequest("This reset link is invalid or has expired.");
  const passwordHash = await hashPassword(body.password);
  await db.$transaction([
    db.user.update({ where: { id: row.userId }, data: { passwordHash } }),
    db.session.updateMany({ where: { userId: row.userId, revokedAt: null }, data: { revokedAt: new Date() } }),
  ]);
  await audit({ actorType: "USER", actorId: row.userId, action: "account.password_reset", ip: clientIp(req) });
  return json({ ok: true });
});
