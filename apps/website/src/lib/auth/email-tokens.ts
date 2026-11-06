import "server-only";
import type { TokenPurpose } from "@prisma/client";
import { db } from "../db";
import { env } from "../env";
import { randomToken, sha256Hex } from "../crypto";
import { sendMail } from "../mail";

async function issue(userId: string, email: string, purpose: TokenPurpose, ttlMinutes: number): Promise<string> {
  // Invalidate previous unused tokens of the same purpose.
  await db.emailToken.updateMany({ where: { userId, purpose, usedAt: null }, data: { usedAt: new Date() } });
  const token = randomToken(32);
  await db.emailToken.create({
    data: { userId, purpose, email, tokenHash: sha256Hex(token), expiresAt: new Date(Date.now() + ttlMinutes * 60_000) },
  });
  return token;
}

export async function issueEmailVerification(userId: string, email: string) {
  const token = await issue(userId, email, "VERIFY_EMAIL", 24 * 60);
  await sendMail(
    email,
    "Verify your screensharing.me email",
    `Confirm this address for your screensharing.me account:\n\n${env.appOrigin}/verify-email?token=${token}\n\nThe link expires in 24 hours. If you did not create an account, ignore this message.`,
  );
}

/** Generates a reset link. Returns the URL so an administrator can hand it over for accounts without email. */
export async function issuePasswordReset(userId: string, email: string | null): Promise<string> {
  const token = await issue(userId, email ?? "", "RESET_PASSWORD", 30);
  const url = `${env.appOrigin}/reset-password?token=${token}`;
  if (email) {
    await sendMail(
      email,
      "Reset your screensharing.me password",
      `A password reset was requested for your screensharing.me account:\n\n${url}\n\nThe link expires in 30 minutes and can be used once. If you did not request this, ignore this message.`,
    );
  }
  return url;
}

/** Atomically marks a token used and returns it if valid. */
export async function consumeEmailToken(token: string, purpose: TokenPurpose) {
  const tokenHash = sha256Hex(token);
  const now = new Date();
  const row = await db.emailToken.findUnique({ where: { tokenHash } });
  if (!row || row.purpose !== purpose || row.usedAt || row.expiresAt < now) return null;
  const r = await db.emailToken.updateMany({ where: { id: row.id, usedAt: null }, data: { usedAt: now } });
  return r.count === 1 ? row : null;
}
