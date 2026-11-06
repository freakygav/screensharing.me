import Link from "next/link";
import { db } from "@/lib/db";
import { PageHeader, StatCard } from "@/components/app-shell";
import { fmtRelative } from "@/lib/format";
import { expireStalePins } from "@/lib/investigations";
import { SEV_DOT } from "@/components/badges";

export default async function AdminOverview() {
  await expireStalePins();
  const [users, inv, byStatus, sev, topRules, versions, recent] = await Promise.all([
    db.user.count(),
    db.investigation.count(),
    db.investigation.groupBy({ by: ["status"], _count: { _all: true } }),
    db.detection.groupBy({ by: ["severity"], _count: { _all: true } }),
    db.detection.groupBy({ by: ["ruleId"], _count: { _all: true }, orderBy: { _count: { ruleId: "desc" } }, take: 8 }),
    db.connectedDevice.groupBy({ by: ["appVersion"], _count: { _all: true }, orderBy: { _count: { appVersion: "desc" } } }),
    db.auditLog.findMany({ orderBy: { createdAt: "desc" }, take: 12, include: { actor: { select: { username: true } } } }),
  ]);
  const st = (s: string[]) => byStatus.filter((b) => s.includes(b.status)).reduce((a, b) => a + b._count._all, 0);
  const ruleNames = await db.detectionRule.findMany({ where: { id: { in: topRules.map((r) => r.ruleId) } }, select: { id: true, name: true } });
  const totalSev = sev.reduce((a, b) => a + b._count._all, 0) || 1;
  return (
    <div>
      <PageHeader title="Administrator overview" subtitle="Live figures from the production database." />
      <div className="space-y-6 p-8">
        <div className="grid gap-3 sm:grid-cols-4">
          <StatCard label="Total users" value={users} />
          <StatCard label="Total investigations" value={inv} />
          <StatCard label="Active investigations" value={st(["WAITING", "CONNECTED", "SCANNING"])} hint={`${st(["SCANNING"])} scanning now`} />
          <StatCard label="Completed investigations" value={st(["COMPLETED"])} hint={`${st(["FAILED"])} failed · ${st(["CANCELLED", "EXPIRED"])} closed`} />
        </div>
        <div className="grid gap-4 lg:grid-cols-3">
          <div className="card p-5">
            <h2 className="text-sm font-semibold">Detections by severity</h2>
            <div className="mt-4 space-y-3">
              {["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map((s) => {
                const n = sev.find((x) => x.severity === s)?._count._all ?? 0;
                return (
                  <div key={s}>
                    <div className="flex justify-between text-[12.5px]"><span className="text-muted">{s}</span><span className="tabular-nums">{n}</span></div>
                    <div className="mt-1 h-1.5 rounded-full bg-[#151925]"><div className={`h-full rounded-full ${SEV_DOT[s]}`} style={{ width: `${(n / totalSev) * 100}%` }} /></div>
                  </div>
                );
              })}
            </div>
          </div>
          <div className="card p-5">
            <h2 className="text-sm font-semibold">Most frequent rules</h2>
            <div className="mt-3 space-y-2">
              {topRules.length === 0 && <p className="text-[13px] text-dim">No detections yet.</p>}
              {topRules.map((r) => (
                <div key={r.ruleId} className="flex items-center justify-between gap-3 text-[12.5px]">
                  <span className="truncate text-ink-2" title={r.ruleId}>{ruleNames.find((n) => n.id === r.ruleId)?.name ?? r.ruleId}</span>
                  <span className="tabular-nums text-muted">{r._count._all}</span>
                </div>
              ))}
            </div>
          </div>
          <div className="card p-5">
            <h2 className="text-sm font-semibold">Desktop versions in use</h2>
            <div className="mt-3 space-y-2">
              {versions.length === 0 && <p className="text-[13px] text-dim">No connections yet.</p>}
              {versions.map((v) => (<div key={v.appVersion} className="flex justify-between text-[12.5px]"><span className="font-mono text-ink-2">{v.appVersion}</span><span className="text-muted">{v._count._all} connections</span></div>))}
            </div>
          </div>
        </div>
        <div className="card overflow-hidden">
          <div className="flex items-center justify-between border-b border-line px-5 py-3.5"><h2 className="text-sm font-semibold">Recent activity</h2><Link href="/admin/audit" className="text-xs text-muted hover:text-ink">Full audit log</Link></div>
          <table className="table">
            <tbody>
              {recent.map((a) => (
                <tr key={a.id}><td className="w-40 text-dim">{fmtRelative(a.createdAt)}</td><td className="font-mono text-[12px] text-ink">{a.action}</td><td>{a.actor?.username ?? a.actorType.toLowerCase()}</td><td className="font-mono text-[11.5px] text-dim">{a.targetType ? `${a.targetType}:${a.targetId}` : ""}</td></tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
