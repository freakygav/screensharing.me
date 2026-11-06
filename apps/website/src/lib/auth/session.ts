import "server-only";
import { cookies } from "next/headers";
import type { Role, SessionKind, User } from "@prisma/client";
import { db } from "../db";
import { env } from "../env";
import { randomToken, sha256Hex } from "../crypto";
import { forbidden, unauthorized } from "../http";

export const SESSION_COOKIE = "ssme_session";

export type SafeUser = Pick<User, "id" | "username" | "displayName" | "email" | "emailVerified" | "role" | "createdAt">;

export function toSafeUser(u: User): SafeUser {
  return { id: u.id, username: u.username, displayName: u.displayName, email: u.email, emailVerified: u.emailVerified, role: u.role, createdAt: u.createdAt };
}

export async function createSession(opts: {
  userId: string;
  role: Role;
  kind: SessionKind;
  ip?: string;
  userAgent?: string | null;
  adminLogin?: boolean;
}): Promise<{ token: string; expiresAt: Date }> {
  const token = randomToken(32);
  const ttlMs =
    opts.kind === "DESKTOP"
      ? env.desktopStaffSessionHours * 3600_000
      : opts.adminLogin || opts.role === "ADMIN"
        ? env.adminSessionHours * 3600_000
        : env.webSessionDays * 86400_000;
  const expiresAt = new Date(Date.now() + ttlMs);
  await db.session.create({
    data: {
      tokenHash: sha256Hex(token),
      userId: opts.userId,
      kind: opts.kind,
      expiresAt,
      ip: opts.ip,
      userAgent: opts.userAgent?.slice(0, 300),
    },
  });
  return { token, expiresAt };
}

export async function setSessionCookie(token: string, expiresAt: Date) {
  const jar = await cookies();
  jar.set(SESSION_COOKIE, token, {
    httpOnly: true,
    secure: env.isProduction,
    sameSite: "lax",
    path: "/",
    expires: expiresAt,
  });
}

export async function clearSessionCookie() {
  const jar = await cookies();
  jar.delete(SESSION_COOKIE);
}

async function resolveToken(token: string | undefined, kind: SessionKind) {
  if (!token || token.length < 20 || token.length > 200) return null;
  const session = await db.session.findUnique({ where: { tokenHash: sha256Hex(token) }, include: { user: true } });
  if (!session || session.kind !== kind || session.revokedAt || session.expiresAt < new Date() || session.user.disabled) return null;
  // Touch at most once a minute to avoid write amplification.
  if (Date.now() - session.lastSeenAt.getTime() > 60_000) {
    await db.session.update({ where: { id: session.id }, data: { lastSeenAt: new Date() } });
  }
  return session;
}

/** Current web user from the session cookie, or null. */
export async function getCurrentSession() {
  const jar = await cookies();
  return resolveToken(jar.get(SESSION_COOKIE)?.value, "WEB");
}

export async function getCurrentUser(): Promise<User | null> {
  return (await getCurrentSession())?.user ?? null;
}

export async function requireUser(): Promise<User> {
  const u = await getCurrentUser();
  if (!u) throw unauthorized();
  return u;
}

export async function requireAdmin(): Promise<User> {
  const u = await requireUser();
  if (u.role !== "ADMIN") throw forbidden("Administrator access required.");
  return u;
}

/** Bearer-token session used by the desktop app for staff/admin sign-in. */
export async function requireDesktopStaff(req: Request): Promise<User> {
  const auth = req.headers.get("authorization") ?? "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7).trim() : undefined;
  const session = await resolveToken(token, "DESKTOP");
  if (!session) throw unauthorized("Desktop staff session is invalid or expired.");
  return session.user;
}
