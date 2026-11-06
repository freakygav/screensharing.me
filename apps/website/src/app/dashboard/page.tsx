import Link from "next/link";
import { db } from "@/lib/db";
import { requireUserPage } from "@/lib/page-auth";
import { PageHeader, StatCard } from "@/components/app-shell";
import { StatusBadge } from "@/components/badges";
import { IconPlus } from "@/components/icons";
import { fmtRelative } from "@/lib/format";
import { expireStalePins } from "@/lib/investigations";
import { ResendVerification } from "./resend-verification";

export default async function Overview({ searchParams }: { searchParams: Promise<{ welcome?: string }> }) {
  const user = await requireUserPage();
  const { welcome } = await searchParams;
  await expireStalePins({ ownerId: user.id });
  const [byStatus, recent, findings] = await Promise.all([
    db.investigation.groupBy({ by: ["status"], where: { ownerId: user.id }, _count: { _all: true } }),
    db.investigation.findMany({ where: { ownerId: user.id }, orderBy: { createdAt: "desc" }, take: 8, include: { scan: { select: { progress: true, _count: { select: { detections: true } } } } } }),
    db.detection.groupBy({ by: ["severity"], where: { scan: { investigation: { ownerId: user.id } } }, _count: { _all: true } }),
  ]);
  const count = (s: string[]) => byStatus.filter((b) => s.includes(b.status)).reduce((a, b) => a + b._count._all, 0);
  const sev = (s: string) => findings.find((f) => f.severity === s)?._count._all ?? 0;
  return (
    <div>
      <PageHeader title={`Welcome, ${user.displayName}`} subtitle="Your investigations at a glance." actions={<Link href="/dashboard/investigations/new" className="btn btn-primary"><IconPlus /> New investigation</Link>} />
      <div className="space-y-6 p-8">
        {user.email && !user.emailVerified && (
          <div className="card-flat flex flex-wrap items-center justify-between gap-3 border-[rgba(245,196,81,.3)] p-4 text-sm">
            <span className="text-ink-2">{welcome === "verify" ? "Account created. " : ""}Verify <b>{user.email}</b> to enable password resets.</span>
            <ResendVerification />
          </div>
        )}
        {!user.email && welcome && (
          <div className="card-flat p-4 text-sm text-ink-2">Account created without an email address. Add one in <Link href="/dashboard/settings" className="text-accent-2">settings</Link> to enable self-service password resets.</div>
        )}
        <div className="grid gap-3 sm:grid-cols-4">
          <StatCard label="Total investigations" value={count(["WAITING", "CONNECTED", "SCANNING", "COMPLETED", "FAILED", "CANCELLED", "EXPIRED"])} />
          <StatCard label="Active" value={count(["WAITING", "CONNECTED", "SCANNING"])} hint="Waiting, connected or scanning" />
          <StatCard label="Completed" value={count(["COMPLETED"])} />
          <StatCard label="Critical / high findings" value={`${sev("CRITICAL")} / ${sev("HIGH")}`} accent={sev("CRITICAL") ? "text-crit" : ""} />
        </div>
        <div className="card overflow-hidden">
          <div className="flex items-center justify-between border-b border-line px-5 py-3.5">
            <h2 className="text-sm font-semibold">Recent investigations</h2>
            <Link href="/dashboard/investigations" className="text-xs text-muted hover:text-ink">View all</Link>
          </div>
          {recent.length === 0 ? (
            <div className="px-5 py-12 text-center text-sm text-muted">No investigations yet. <Link className="text-accent-2" href="/dashboard/investigations/new">Create your first one.</Link></div>
          ) : (
            <table className="table">
              <thead><tr><th>Reference</th><th>Player</th><th>Status</th><th>Findings</th><th>Created</th></tr></thead>
              <tbody>
                {recent.map((r) => (
                  <tr key={r.id}>
                    <td><Link href={`/dashboard/investigations/${r.id}`} className="font-mono text-[12.5px] text-ink hover:text-accent-2">{r.reference}</Link></td>
                    <td className="text-ink">{r.subjectName}{r.serverName && <span className="text-dim"> · {r.serverName}</span>}</td>
                    <td><StatusBadge status={r.status} /></td>
                    <td>{r.scan?._count.detections ?? "—"}</td>
                    <td className="text-dim">{fmtRelative(r.createdAt)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}
