import { db } from "@/lib/db";
import { badRequest, handler, json, notFound, readJson } from "@/lib/http";
import { adminMutation } from "@/lib/admin";
import { ruleSchema } from "@/lib/validation";
import { bumpRulesetVersion } from "@/lib/config";
import { z } from "zod";

export const runtime = "nodejs";

const patchSchema = z.union([z.object({ enabled: z.boolean() }).strict(), ruleSchema]);

export const PATCH = handler(async (req: Request, ctx: { params: Promise<{ id: string }> }) => {
  const { id } = await ctx.params;
  const { admin, log } = await adminMutation(req);
  const body = await readJson(req, patchSchema);
  const before = await db.detectionRule.findUnique({ where: { id } });
  if (!before) throw notFound("Rule not found.");
  if ("id" in body && body.id !== id) throw badRequest("Rule ids cannot be changed.");
  const data = "kind" in body
    ? { ...body, id: undefined, family: body.family ?? null, classification: body.classification ?? null }
    : { enabled: body.enabled };
  const rule = await db.detectionRule.update({ where: { id }, data: { ...data, version: { increment: 1 }, updatedById: admin.id } });
  const version = await bumpRulesetVersion();
  await log("admin.rule_updated", "DetectionRule", id, {
    before: { enabled: before.enabled, severity: before.severity, tier: before.tier, pattern: before.pattern },
    after: { enabled: rule.enabled, severity: rule.severity, tier: rule.tier, pattern: rule.pattern },
    rulesetVersion: version,
  });
  return json({ rule, rulesetVersion: version });
});
