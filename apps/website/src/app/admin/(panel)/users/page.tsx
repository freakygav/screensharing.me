import { db } from "@/lib/db";
import { PageHeader } from "@/components/app-shell";
import { fmtDate } from "@/lib/format";
import { UserActions } from "./user-actions";
import { requireAdminPage } from "@/lib/page-auth";

export default async function AdminUsers({ searchParams }: { searchParams: Promise<{ q?: string }> }) {
  const me = await requireAdminPage();
  const q = ((await searchParams).q ?? "").trim().slice(0, 64);
  const users = await db.user.findMany({
    where: q ? { OR: [{ username: { contains: q, mode: "insensitive" } }, { email: { contains: q, mode: "insensitive" } }] } : {},
    orderBy: { createdAt: "desc" },
    take: 300,
    include: { _count: { select: { investigations: true } } },
  });
  return (
    <div>
      <PageHeader title="Users" subtitle={`${users.length} accounts shown. Role and status changes revoke the user's sessions.`} />
      <div className="space-y-4 p-8">
        <form><input name="q" defaultValue={q} placeholder="Search username or email" className="input h-9 w-72" /></form>
        <div className="card overflow-hidden">
          <table className="table">
            <thead><tr><th>User</th><th>Email</th><th>Role</th><th>Investigations</th><th>Last sign-in</th><th>Created</th><th /></tr></thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.id}>
                  <td><div className="text-ink">{u.displayName}</div><div className="text-[11.5px] text-dim">@{u.username}</div></td>
                  <td>{u.email ? <>{u.email} <span className={`ml-1 text-[11px] ${u.emailVerified ? "text-ok" : "text-med"}`}>{u.emailVerified ? "verified" : "unverified"}</span></> : <span className="text-dim">none</span>}</td>
                  <td><span className={`chip ${u.role === "ADMIN" ? "text-ink" : ""}`}>{u.role}</span>{u.disabled && <span className="chip ml-1 text-crit">DISABLED</span>}</td>
                  <td>{u._count.investigations}</td>
                  <td className="text-dim">{fmtDate(u.lastLoginAt)}</td>
                  <td className="text-dim">{fmtDate(u.createdAt)}</td>
                  <td className="text-right"><UserActions id={u.id} role={u.role} disabled={u.disabled} self={u.id === me.id} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
