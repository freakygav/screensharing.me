import { db } from "@/lib/db";
import { PageHeader } from "@/components/app-shell";
import { fmtDate, fmtRelative } from "@/lib/format";
import { RevokeButton } from "./revoke-button";

export default async function AdminSessions() {
  const now = new Date();
  const [sessions, devices] = await Promise.all([
    db.session.findMany({ where: { revokedAt: null, expiresAt: { gt: now } }, orderBy: { lastSeenAt: "desc" }, take: 300, include: { user: { select: { username: true, role: true } } } }),
    db.connectedDevice.findMany({ where: { revokedAt: null, tokenExpiresAt: { gt: now } }, orderBy: { lastHeartbeatAt: "desc" }, take: 200, include: { investigation: { select: { reference: true, status: true } } } }),
  ]);
  return (
    <div>
      <PageHeader title="Active sessions & devices" subtitle="Revoking takes effect on the next request." />
      <div className="space-y-6 p-8">
        <div className="card overflow-hidden">
          <div className="border-b border-line px-5 py-3 text-sm font-semibold">User sessions ({sessions.length})</div>
          <table className="table">
            <thead><tr><th>User</th><th>Type</th><th>IP</th><th>Client</th><th>Last seen</th><th>Expires</th><th /></tr></thead>
            <tbody>{sessions.map((s) => (
              <tr key={s.id}><td className="text-ink">{s.user.username}{s.user.role === "ADMIN" && <span className="ml-1 text-[11px] text-accent-2">admin</span>}</td><td>{s.kind}</td><td className="font-mono text-[12px]">{s.ip ?? "—"}</td><td className="max-w-[240px] truncate text-[12px]" title={s.userAgent ?? ""}>{s.userAgent ?? "—"}</td><td className="text-dim">{fmtRelative(s.lastSeenAt)}</td><td className="text-dim">{fmtDate(s.expiresAt)}</td><td className="text-right"><RevokeButton path={`/api/admin/sessions/${s.id}`} /></td></tr>
            ))}</tbody>
          </table>
        </div>
        <div className="card overflow-hidden">
          <div className="border-b border-line px-5 py-3 text-sm font-semibold">Connected desktop applications ({devices.length})</div>
          <table className="table">
            <thead><tr><th>Investigation</th><th>Status</th><th>App</th><th>Windows</th><th>Admin</th><th>Last heartbeat</th><th /></tr></thead>
            <tbody>{devices.map((d) => (
              <tr key={d.id}><td className="font-mono text-[12.5px]">{d.investigation.reference}</td><td>{d.investigation.status}</td><td className="font-mono">{d.appVersion}</td><td className="text-[12px]">{d.osVersion ?? "—"}</td><td>{d.elevated ? "yes" : "no"}</td><td className="text-dim">{fmtRelative(d.lastHeartbeatAt)}</td><td className="text-right"><RevokeButton path={`/api/admin/devices/${d.id}`} /></td></tr>
            ))}</tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
