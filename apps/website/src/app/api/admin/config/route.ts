import { db } from "@/lib/db";
import { badRequest, handler, json, readJson } from "@/lib/http";
import { adminMutation } from "@/lib/admin";
import { configPatchSchema } from "@/lib/validation";
import { CONFIG_DEFAULTS, getConfig } from "@/lib/config";

export const runtime = "nodejs";

export const PATCH = handler(async (req: Request) => {
  const { log } = await adminMutation(req);
  const body = await readJson(req, configPatchSchema);
  if (typeof body.value !== typeof CONFIG_DEFAULTS[body.key]) throw badRequest(`"${body.key}" expects a ${typeof CONFIG_DEFAULTS[body.key]}.`);
  const before = (await getConfig())[body.key];
  await db.systemConfig.upsert({ where: { key: body.key }, create: { key: body.key, value: body.value }, update: { value: body.value } });
  await log("admin.config_updated", "SystemConfig", body.key, { before, after: body.value });
  return json({ ok: true, config: await getConfig() });
});
