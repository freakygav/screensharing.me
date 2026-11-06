import { assertSameOrigin, clientIp, handler, json, readJson } from "@/lib/http";
import { requestResetSchema } from "@/lib/validation";
import { enforce } from "@/lib/ratelimit";
import { db } from "@/lib/db";
import { issuePasswordReset } from "@/lib/auth/email-tokens";
import { audit } from "@/lib/audit";

export const runtime = "nodejs";

export const POST = handler(async (req: Request) => {
  assertSameOrigin(req);
  const ip = clientIp(req);
  await enforce(`reset-ip:${ip}`, 5, 3600);
  const { email } = await readJson(req, requestResetSchema);
  await enforce(`reset-email:${email}`, 3, 3600);
  const user = await db.user.findUnique({ where: { email } });
  // Only verified addresses receive reset links. The response is identical either way (no account enumeration).
  if (user && user.emailVerified && !user.disabled) {
    await issuePasswordReset(user.id, email);
    await audit({ actorType: "USER", actorId: user.id, action: "account.reset_requested", ip });
  }
  return json({ ok: true, message: "If a verified account uses that address, a reset link has been sent." });
});
