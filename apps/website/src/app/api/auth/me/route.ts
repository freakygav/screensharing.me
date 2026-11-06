import { handler, json } from "@/lib/http";
import { getCurrentUser, toSafeUser } from "@/lib/auth/session";

export const runtime = "nodejs";

export const GET = handler(async () => {
  const u = await getCurrentUser();
  return json({ user: u ? toSafeUser(u) : null });
});
