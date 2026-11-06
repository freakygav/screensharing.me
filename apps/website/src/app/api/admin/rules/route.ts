import { db } from "@/lib/db";
import { conflict, handler, json, readJson } from "@/lib/http";
import { adminMutation } from "@/lib/admin";
import { ruleSchema } from "@/lib/validation";
import { bumpRulesetVersion } from "@/lib/config";

export const runtime = "nodejs";

export const POST = handler(async (req: Request) => {
  const { admin, log } = await adminMutation(req);
  const body = await readJson(req, ruleSchema);
  if (await db.detectionRule.findUnique({ where: { id: body.id }, select: { id: true } })) throw conflict("A rule with that id already exists.");
  const rule = await db.detectionRule.create({ data: { ...body, family: body.family ?? null, classification: body.classification ?? null, updatedById: admin.id } });
  const version = await bumpRulesetVersion();
  await log("admin.rule_created", "DetectionRule", rule.id, { kind: rule.kind, pattern: rule.pattern, rulesetVersion: version });
  return json({ rule, rulesetVersion: version }, { status: 201 });
});
