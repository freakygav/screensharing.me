import "server-only";
import { db } from "./db";
import { env } from "./env";

export interface SystemConfigValues {
  registrationOpen: boolean;
  maintenanceMessage: string;
  pinTtlMinutes: number;
  modrinthLookupDefault: boolean;
}

export const CONFIG_DEFAULTS: SystemConfigValues = {
  registrationOpen: true,
  maintenanceMessage: "",
  pinTtlMinutes: env.pinTtlMinutes,
  modrinthLookupDefault: true,
};

export async function getConfig(): Promise<SystemConfigValues> {
  const rows = await db.systemConfig.findMany();
  const out = { ...CONFIG_DEFAULTS } as Record<string, unknown>;
  for (const r of rows) if (r.key in out && typeof r.value === typeof out[r.key]) out[r.key] = r.value;
  return out as unknown as SystemConfigValues;
}

export async function getRulesetVersion(): Promise<string> {
  const row = await db.systemConfig.findUnique({ where: { key: "rulesetVersion" } });
  return typeof row?.value === "string" ? row.value : "unversioned";
}

/** Called whenever an administrator changes the catalog. */
export async function bumpRulesetVersion(): Promise<string> {
  const now = new Date();
  const v = `${now.getUTCFullYear()}.${String(now.getUTCMonth() + 1).padStart(2, "0")}.${String(now.getUTCDate()).padStart(2, "0")}.${now.getTime() % 100000}`;
  await db.systemConfig.upsert({ where: { key: "rulesetVersion" }, create: { key: "rulesetVersion", value: v }, update: { value: v } });
  return v;
}
