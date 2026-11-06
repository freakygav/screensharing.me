import { handler, json } from "@/lib/http";
import { requireDevice } from "@/lib/investigations";
import { db } from "@/lib/db";
import { getRulesetVersion } from "@/lib/config";

export const runtime = "nodejs";

/** Returns the enabled detection catalog to the authenticated desktop scanner. */
export const GET = handler(async (req: Request) => {
  await requireDevice(req);
  const rules = await db.detectionRule.findMany({ where: { enabled: true }, orderBy: { id: "asc" } });
  return json({
    version: await getRulesetVersion(),
    rules: rules.map((r) => ({
      id: r.id, name: r.name, description: r.description, category: r.category, kind: r.kind, pattern: r.pattern,
      family: r.family, features: r.features, severity: r.severity, tier: r.tier, confidence: r.confidence,
      classification: r.classification, falsePositives: r.falsePositives, limitations: r.limitations, references: r.references,
      scopes: r.scopes, weight: r.weight, packages: r.packages,
    })),
  });
});
