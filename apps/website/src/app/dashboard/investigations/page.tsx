import Link from "next/link";
import { db } from "@/lib/db";
import { requireUserPage } from "@/lib/page-auth";
import { PageHeader } from "@/components/app-shell";
import { StatusBadge } from "@/components/badges";
import { IconPlus } from "@/components/icons";
import { fmtDate } from "@/lib/format";
import { expireStalePins } from "@/lib/investigations";
import type { InvestigationStatus, Prisma } from "@prisma/client";

const SCOPES: Record<string, InvestigationStatus[] | null> = {
  all: null,
  active: ["WAITING", "CONNECTED", "SCANNING"],
  history: ["COMPLETED", "FAILED", "CANCELLED", "EXPIRED"],
};

export default async function Investigations({ searchParams }: { searchParams: Promise<{ scope?: string; q?: string }> }) {
  const user = await requireUserPage();
  const sp = await searchParams;
  const scope = sp.scope && sp.scope in SCOPES ? sp.scope : "all";
  const q = (sp.q ?? "").trim().slice(0, 64);
  await expireStalePins({ ownerId: user.id });
  const where: Prisma.InvestigationWhereInput = {
    ownerId: user.id,
    ...(SCOPES[scope] ? { status: { in: SCOPES[scope]! } } : {}),
    ...(q ? { OR: [{ subjectName: { contains: q, mode: "insensitive" } }, { reference: { contains: q, mode: "insensitive" } }, { serverName: { contains: q, mode: "insensitive" } }] } : {}),
  };
  const rows = await db.investigation.findMany({ where, orderBy: { createdAt: "desc" }, take: 200, include: { scan: { select: { progress: true, status: true, _count: { select: { detections: true } } } } } });
  return (
    <div>
      <PageHeader title={scope === "active" ? "Active investigations" : scope === "history" ? "Investigation history" : "Investigations"} subtitle="Open an investigation to watch it live or review its report." actions={<Link href="/dashboard/investigations/new" className="btn btn-primary"><IconPlus /> New</Link>} />
      <div className="space-y-4 p-8">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex gap-1 rounded-md border border-line bg-bg p-1 text-[13px]">
            {Object.keys(SCOPES).map((s) => (
              <Link key={s} href={`/dashboard/investigations?scope=${s}${q ? `&q=${encodeURIComponent(q)}` : ""}`} className={`rounded-[7px] px-3 py-1.5 capitalize ${scope === s ? "bg-panel-2 font-semibold text-ink" : "text-muted hover:text-ink"}`}>{s}</Link>
            ))}
          </div>
          <form className="w-72"><input type="hidden" name="scope" value={scope} /><input name="q" defaultValue={q} placeholder="Search player, server or reference" className="input h-9" /></form>
        </div>
        <div className="card overflow-hidden">
          {rows.length === 0 ? (
            <div className="px-5 py-14 text-center text-sm text-muted">No investigations match.</div>
          ) : (
            <table className="table">
              <thead><tr><th>Reference</th><th>Player</th><th>Server</th><th>Status</th><th>Progress</th><th>Findings</th><th>Created</th></tr></thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={r.id}>
                    <td><Link href={`/dashboard/investigations/${r.id}`} className="font-mono text-[12.5px] text-ink hover:text-accent-2">{r.reference}</Link></td>
                    <td className="text-ink">{r.subjectName}</td>
                    <td>{r.serverName ?? "—"}</td>
                    <td><StatusBadge status={r.status} /></td>
                    <td>{r.scan ? `${r.scan.progress}%` : "—"}</td>
                    <td>{r.scan?._count.detections ?? "—"}</td>
                    <td className="text-dim">{fmtDate(r.createdAt)}</td>
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
