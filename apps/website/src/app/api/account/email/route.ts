import { assertSameOrigin, conflict, handler, HttpError, json, readJson } from "@/lib/http";
import { changeEmailSchema } from "@/lib/validation";
import { requireUser } from "@/lib/auth/session";
import { verifyPassword } from "@/lib/auth/password";
import { issueEmailVerification } from "@/lib/auth/email-tokens";
import { enforce } from "@/lib/ratelimit";
import { db } from "@/lib/db";
import { audit } from "@/lib/audit";

export const runtime = "nodejs";

export const POST = handler(async (req: Request) => {
  assertSameOrigin(req);
  const user = await requireUser();
  await enforce(`emailchange:${user.id}`, 5, 3600);
  const body = await readJson(req, changeEmailSchema);
  if (!(await verifyPassword(user.passwordHash, body.currentPassword))) throw new HttpError(401, "invalid_credentials", "Current password is incorrect.");
  const email = body.email ? body.email.toLowerCase() : null;
  const changed = email !== user.email;
  if (email && changed) {
    const taken = await db.user.findUnique({ where: { email }, select: { id: true } });
    if (taken) throw conflict("An account with that email already exists.");
  }
  await db.user.update({ where: { id: user.id }, data: { email, emailVerified: changed ? null : user.emailVerified } });
  if (email && changed) await issueEmailVerification(user.id, email);
  await audit({ actorType: "USER", actorId: user.id, action: email ? "account.email_changed" : "account.email_removed" });
  return json({ ok: true, verificationSent: Boolean(email && changed) });
});
