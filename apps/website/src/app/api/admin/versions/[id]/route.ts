import { db } from "@/lib/db";
import { handler, json, notFound, readJson } from "@/lib/http";
import { adminMutation } from "@/lib/admin";
import { z } from "zod";

export const runtime = "nodejs";

const schema = z.object({ active: z.boolean().optional(), minimumSupported: z.boolean().optional(), notes: z.string().max(2000).optional() }).strict();

export const PATCH = handler(async (req: Request, ctx: { params: Promise<{ id: string }> }) => {
  const { id } = await ctx.params;
  const { log } = await adminMutation(req);
  const body = await readJson(req, schema);
  const before = await db.applicationVersion.findUnique({ where: { id } });
  if (!before) throw notFound("Version not found.");
  const v = await db.applicationVersion.update({ where: { id }, data: body });
  await log("admin.version_updated", "ApplicationVersion", id, { version: v.version, before: { active: before.active, minimumSupported: before.minimumSupported }, after: { active: v.active, minimumSupported: v.minimumSupported } });
  return json({ version: v });
});
