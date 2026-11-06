import { db } from "@/lib/db";
import { clientIp, forbidden, handler, HttpError, json, readJson } from "@/lib/http";
import { desktopLoginSchema } from "@/lib/validation";
import { burnPasswordCheck, verifyPassword } from "@/lib/auth/password";
import { createSession, toSafeUser } from "@/lib/auth/session";
import { enforce } from "@/lib/ratelimit";
import { audit } from "@/lib/audit";
import { z } from "zod";

export const runtime = "nodejs";

const schema = desktopLoginSchema.extend({ adminOnly: z.boolean().optional() });

/** Staff / administrator sign-in from the desktop app. Returns a short-lived bearer token (8h). */
export const POST = handler(async (req: Request) => {
  const ip = clientIp(req);
  await enforce(`dlogin-ip:${ip}`, 20, 900);
  const body = await readJson(req, schema, 4096);
  const identifier = body.identifier.toLowerCase();
  await enforce(`login-id:${identifier}`, 8, 900);
  const user = await db.user.findFirst({ where: identifier.includes("@") ? { email: identifier } : { username: identifier } });
  if (!user || !(await verifyPassword(user.passwordHash, body.password))) {
    if (!user) await burnPasswordCheck(body.password);
    await audit({ actorType: "ANONYMOUS", actorId: user?.id, action: body.adminOnly ? "admin.desktop_login_failed" : "desktop.login_failed", ip });
    throw new HttpError(401, "invalid_credentials", "Incorrect username/email or password.");
  }
  if (user.disabled) throw forbidden("This account has been disabled.");
  if (body.adminOnly && user.role !== "ADMIN") {
    await audit({ actorType: "USER", actorId: user.id, action: "admin.desktop_login_denied", ip });
    throw forbidden("This account is not an administrator.");
  }
  const session = await createSession({ userId: user.id, role: user.role, kind: "DESKTOP", ip, userAgent: `desktop/${body.appVersion}` });
  await audit({ actorType: user.role === "ADMIN" ? "ADMIN" : "USER", actorId: user.id, action: body.adminOnly ? "admin.desktop_login" : "desktop.login", ip });
  return json({ token: session.token, expiresAt: session.expiresAt, user: toSafeUser(user) });
});
