import { db } from "@/lib/db";
import { assertSameOrigin, clientIp, forbidden, handler, HttpError, json, readJson } from "@/lib/http";
import { loginSchema } from "@/lib/validation";
import { burnPasswordCheck, verifyPassword } from "@/lib/auth/password";
import { createSession, setSessionCookie, toSafeUser } from "@/lib/auth/session";
import { enforce, reset } from "@/lib/ratelimit";
import { audit } from "@/lib/audit";

export const runtime = "nodejs";

export const POST = handler(async (req: Request) => {
  assertSameOrigin(req);
  const ip = clientIp(req);
  const body = await readJson(req, loginSchema);
  const identifier = body.identifier.toLowerCase();
  await enforce(`login-ip:${ip}`, 30, 900);
  await enforce(`login-id:${identifier}`, 8, 900);

  const user = await db.user.findFirst({ where: identifier.includes("@") ? { email: identifier } : { username: identifier } });
  const failAction = body.adminOnly ? "admin.login_failed" : "auth.login_failed";
  if (!user) {
    await burnPasswordCheck(body.password);
    await audit({ actorType: "ANONYMOUS", action: failAction, details: { reason: "unknown_account" }, ip });
    throw new HttpError(401, "invalid_credentials", "Incorrect username/email or password.");
  }
  if (!(await verifyPassword(user.passwordHash, body.password))) {
    await audit({ actorType: "ANONYMOUS", actorId: user.id, action: failAction, details: { reason: "bad_password" }, ip });
    throw new HttpError(401, "invalid_credentials", "Incorrect username/email or password.");
  }
  if (user.disabled) throw forbidden("This account has been disabled.");
  if (body.adminOnly && user.role !== "ADMIN") {
    await audit({ actorType: "USER", actorId: user.id, action: "admin.login_denied", details: { reason: "not_admin" }, ip });
    throw forbidden("This account is not an administrator.");
  }

  await reset(`login-id:${identifier}`);
  await db.user.update({ where: { id: user.id }, data: { lastLoginAt: new Date() } });
  const session = await createSession({
    userId: user.id, role: user.role, kind: "WEB", ip, userAgent: req.headers.get("user-agent"), adminLogin: body.adminOnly,
  });
  await setSessionCookie(session.token, session.expiresAt);
  await audit({ actorType: user.role === "ADMIN" ? "ADMIN" : "USER", actorId: user.id, action: body.adminOnly ? "admin.login" : "auth.login", ip });
  return json({ user: toSafeUser(user) });
});
