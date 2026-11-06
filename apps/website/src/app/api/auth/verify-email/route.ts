import { assertSameOrigin, badRequest, handler, json, readJson } from "@/lib/http";
import { tokenSchema } from "@/lib/validation";
import { consumeEmailToken } from "@/lib/auth/email-tokens";
import { db } from "@/lib/db";
import { audit } from "@/lib/audit";

export const runtime = "nodejs";

export const POST = handler(async (req: Request) => {
  assertSameOrigin(req);
  const { token } = await readJson(req, tokenSchema);
  const row = await consumeEmailToken(token, "VERIFY_EMAIL");
  if (!row) throw badRequest("This verification link is invalid or has expired.");
  const user = await db.user.findUnique({ where: { id: row.userId } });
  if (!user || user.email !== row.email) throw badRequest("The email address on this account changed after the link was sent.");
  await db.user.update({ where: { id: user.id }, data: { emailVerified: new Date() } });
  await audit({ actorType: "USER", actorId: user.id, action: "account.email_verified", targetType: "User", targetId: user.id });
  return json({ ok: true });
});
