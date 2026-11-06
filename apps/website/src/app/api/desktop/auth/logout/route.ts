import { db } from "@/lib/db";
import { handler, json } from "@/lib/http";
import { sha256Hex } from "@/lib/crypto";

export const runtime = "nodejs";

export const POST = handler(async (req: Request) => {
  const auth = req.headers.get("authorization") ?? "";
  if (auth.startsWith("Bearer ")) {
    await db.session.updateMany({ where: { tokenHash: sha256Hex(auth.slice(7).trim()), kind: "DESKTOP" }, data: { revokedAt: new Date() } });
  }
  return json({ ok: true });
});
