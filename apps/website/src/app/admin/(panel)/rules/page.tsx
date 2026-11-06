import { db } from "@/lib/db";
import { PageHeader } from "@/components/app-shell";
import { getRulesetVersion } from "@/lib/config";
import { RulesTable } from "./rules-table";

export default async function AdminRules() {
  const [rules, version, hits] = await Promise.all([
    db.detectionRule.findMany({ orderBy: { id: "asc" } }),
    getRulesetVersion(),
    db.detection.groupBy({ by: ["ruleId"], _count: { _all: true } }),
  ]);
  const hitMap = Object.fromEntries(hits.map((h) => [h.ruleId, h._count._all]));
  return (
    <div>
      <PageHeader title="Detection catalog" subtitle={`Ruleset version ${version}. Changes are delivered to every desktop scan that starts afterwards.`} />
      <div className="p-8"><RulesTable rules={JSON.parse(JSON.stringify(rules))} hits={hitMap} /></div>
    </div>
  );
}
