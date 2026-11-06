import Link from "next/link";
import { db } from "@/lib/db";
import { PageHeader } from "@/components/app-shell";
import { fmtDate } from "@/lib/format";
import type { Prisma } from "@prisma/client";

const PAGE = 100;

export default async function AdminAudit({ searchParams }: { searchParams: Promise<{ action?: string; page?: string }> }) {
  const sp = await searchParams;
  const action = (sp.action ?? "").trim().slice(0, 64);
  const page = Math.max(0, Number.parseInt(sp.page ?? "0", 10) || 0);
  const where: Prisma.AuditLogWhereInput = action ? { action: { contains: action } } : {};
  const [rows, total] = await Promise.all([
    db.auditLog.findMany({ where, orderBy: { createdAt: "desc" }, skip: page * PAGE, take: PAGE, include: { actor: { select: { username: true } } } }),
    db.auditLog.count({ where }),
  ]);
  return (
    <div>
      <PageHeader title="Audit log" subtitle={`${total.toLocaleString()} entries. Append-only: entries cannot be edited or deleted from the console.`} />
      <div className="space-y-4 p-8">
        <form className="flex gap-2"><input name="action" defaultValue={action} placeholder="Filter by action (e.g. admin., login_failed)" className="input h-9 w-80" /><button className="btn btn-secondary h-9">Filter</button></form>
        <div className="card overflow-hidden">
          <table className="table">
            <thead><tr><th>Time</th><th>Action</th><th>Actor</th><th>Target</th><th>IP</th><th>Details</th></tr></thead>
            <tbody>{rows.map((r) => (
              <tr key={r.id}>
                <td className="whitespace-nowrap text-[12px] text-dim">{fmtDate(r.createdAt, true)}</td>
                <td className="font-mono text-[12px] text-ink">{r.action}</td>
                <td className="text-[12.5px]">{r.actor?.username ?? "—"} <span className="text-dim">({r.actorType.toLowerCase()})</span></td>
                <td className="font-mono text-[11px]">{r.targetType ? `${r.targetType}:${r.targetId}` : "—"}</td>
                <td className="font-mono text-[11.5px]">{r.ip ?? "—"}</td>
                <td className="max-w-[320px] truncate font-mono text-[11px] text-dim" title={r.details ? JSON.stringify(r.details) : ""}>{r.details ? JSON.stringify(r.details) : ""}</td>
              </tr>
            ))}</tbody>
          </table>
        </div>
        <div className="flex justify-between text-sm">
          {page > 0 ? <Link className="text-accent-2" href={`/admin/audit?page=${page - 1}&action=${encodeURIComponent(action)}`}>← Newer</Link> : <span />}
          {(page + 1) * PAGE < total && <Link className="text-accent-2" href={`/admin/audit?page=${page + 1}&action=${encodeURIComponent(action)}`}>Older →</Link>}
        </div>
      </div>
    </div>
  );
}
