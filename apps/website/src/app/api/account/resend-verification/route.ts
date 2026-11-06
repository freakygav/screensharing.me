import { assertSameOrigin, badRequest, handler, json } from "@/lib/http";
import { requireUser } from "@/lib/auth/session";
import { issueEmailVerification } from "@/lib/auth/email-tokens";
import { enforce } from "@/lib/ratelimit";

export const runtime = "nodejs";

export const POST = handler(async (req: Request) => {
  assertSameOrigin(req);
  const user = await requireUser();
  if (!user.email) throw badRequest("Add an email address first.");
  if (user.emailVerified) throw badRequest("Your email address is already verified.");
  await enforce(`resend:${user.id}`, 3, 3600);
  await issueEmailVerification(user.id, user.email);
  return json({ ok: true });
});
