import Link from "next/link";
import { db } from "@/lib/db";
import { PageHeader } from "@/components/app-shell";
import { StatusBadge } from "@/components/badges";
import { fmtDate } from "@/lib/format";
import type { InvestigationStatus, Prisma } from "@prisma/client";

const STATUSES: InvestigationStatus[] = ["WAITING", "CONNECTED", "SCANNING", "COMPLETED", "FAILED", "CANCELLED", "EXPIRED"];

export default async function AdminInvestigations({ searchParams }: { searchParams: Promise<{ q?: string; status?: string }> }) {
  const sp = await searchParams;
  const q = (sp.q ?? "").trim().slice(0, 64);
  const status = STATUSES.includes(sp.status as InvestigationStatus) ? (sp.status as InvestigationStatus) : null;
  const where: Prisma.InvestigationWhereInput = {
    ...(status ? { status } : {}),
    ...(q ? { OR: [{ subjectName: { contains: q, mode: "insensitive" } }, { reference: { contains: q, mode: "insensitive" } }, { owner: { username: { contains: q, mode: "insensitive" } } }] } : {}),
  };
  const rows = await db.investigation.findMany({ where, orderBy: { createdAt: "desc" }, take: 300, include: { owner: { select: { username: true } }, scan: { select: { progress: true, _count: { select: { detections: true } } } } } });
  return (
    <div>
      <PageHeader title="All investigations" subtitle="Viewing an investigation you do not own is recorded in the audit log." />
      <div className="space-y-4 p-8">
        <form className="flex gap-2">
          <input name="q" defaultValue={q} placeholder="Player, reference or investigator" className="input h-9 w-72" />
          <select name="status" defaultValue={status ?? ""} className="input h-9 w-44"><option value="">Any status</option>{STATUSES.map((s) => <option key={s}>{s}</option>)}</select>
          <button className="btn btn-secondary h-9">Filter</button>
        </form>
        <div className="card overflow-hidden">
          <table className="table">
            <thead><tr><th>Reference</th><th>Player</th><th>Investigator</th><th>Status</th><th>Findings</th><th>Created</th></tr></thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id}>
                  <td><Link className="font-mono text-[12.5px] text-ink hover:text-accent-2" href={`/admin/investigations/${r.id}`}>{r.reference}</Link></td>
                  <td className="text-ink">{r.subjectName}</td><td>{r.owner.username}</td><td><StatusBadge status={r.status} /></td>
                  <td>{r.scan?._count.detections ?? "—"}</td><td className="text-dim">{fmtDate(r.createdAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {rows.length === 0 && <div className="px-5 py-10 text-center text-sm text-muted">No investigations.</div>}
        </div>
      </div>
    </div>
  );
}
