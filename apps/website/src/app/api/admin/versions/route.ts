import { db } from "@/lib/db";
import { conflict, handler, json, readJson } from "@/lib/http";
import { adminMutation } from "@/lib/admin";
import { versionSchema } from "@/lib/validation";

export const runtime = "nodejs";

export const POST = handler(async (req: Request) => {
  const { log } = await adminMutation(req);
  const body = await readJson(req, versionSchema);
  if (await db.applicationVersion.findUnique({ where: { version: body.version } })) throw conflict("That version already exists.");
  const v = await db.applicationVersion.create({
    data: { ...body, sha256: body.sha256 || null, downloadUrl: body.downloadUrl || null, notes: body.notes || null },
  });
  await log("admin.version_created", "ApplicationVersion", v.id, { version: v.version, minimumSupported: v.minimumSupported, active: v.active });
  return json({ version: v }, { status: 201 });
});
