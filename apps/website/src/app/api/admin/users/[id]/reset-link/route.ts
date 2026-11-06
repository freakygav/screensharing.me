import { db } from "@/lib/db";
import { handler, json, notFound } from "@/lib/http";
import { adminMutation } from "@/lib/admin";
import { issuePasswordReset } from "@/lib/auth/email-tokens";

export const runtime = "nodejs";

/**
 * Account recovery for users without a verified email: an administrator generates a
 * one-time 30-minute reset link and hands it over through a trusted channel.
 */
export const POST = handler(async (req: Request, ctx: { params: Promise<{ id: string }> }) => {
  const { id } = await ctx.params;
  const { log } = await adminMutation(req);
  const target = await db.user.findUnique({ where: { id } });
  if (!target) throw notFound("User not found.");
  const url = await issuePasswordReset(target.id, null);
  await log("admin.user_reset_link_issued", "User", id);
  return json({ url, expiresInMinutes: 30 });
});
