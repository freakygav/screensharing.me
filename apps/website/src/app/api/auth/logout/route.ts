import { db } from "@/lib/db";
import { assertSameOrigin, handler, json } from "@/lib/http";
import { clearSessionCookie, getCurrentSession } from "@/lib/auth/session";

export const runtime = "nodejs";

export const POST = handler(async (req: Request) => {
  assertSameOrigin(req);
  const session = await getCurrentSession();
  if (session) await db.session.update({ where: { id: session.id }, data: { revokedAt: new Date() } });
  await clearSessionCookie();
  return json({ ok: true });
});
