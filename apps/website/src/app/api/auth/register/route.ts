import { db } from "@/lib/db";
import { assertSameOrigin, clientIp, conflict, forbidden, handler, json, readJson } from "@/lib/http";
import { registerSchema } from "@/lib/validation";
import { hashPassword } from "@/lib/auth/password";
import { createSession, setSessionCookie, toSafeUser } from "@/lib/auth/session";
import { enforce } from "@/lib/ratelimit";
import { audit } from "@/lib/audit";
import { getConfig } from "@/lib/config";
import { issueEmailVerification } from "@/lib/auth/email-tokens";

export const runtime = "nodejs";

export const POST = handler(async (req: Request) => {
  assertSameOrigin(req);
  const ip = clientIp(req);
  await enforce(`register:${ip}`, 10, 3600);
  const cfg = await getConfig();
  if (!cfg.registrationOpen) throw forbidden("Registration is currently closed.");

  const body = await readJson(req, registerSchema);
  const username = body.username.toLowerCase();
  const email = body.email ? body.email.toLowerCase() : null;

  const existing = await db.user.findFirst({
    where: { OR: [{ username }, ...(email ? [{ email }] : [])] },
    select: { username: true, email: true },
  });
  if (existing?.username === username) throw conflict("That username is taken.");
  if (email && existing?.email === email) throw conflict("An account with that email already exists.");

  const user = await db.user.create({
    data: { username, displayName: body.username, email, passwordHash: await hashPassword(body.password) },
  });
  await audit({ actorType: "USER", actorId: user.id, action: "account.register", targetType: "User", targetId: user.id, ip });
  if (email) await issueEmailVerification(user.id, email);

  const session = await createSession({ userId: user.id, role: user.role, kind: "WEB", ip, userAgent: req.headers.get("user-agent") });
  await setSessionCookie(session.token, session.expiresAt);
  return json({ user: toSafeUser(user), emailVerificationSent: Boolean(email) }, { status: 201 });
});
