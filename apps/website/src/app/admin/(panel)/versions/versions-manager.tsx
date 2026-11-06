"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";
import { api } from "@/lib/client-api";
import { FormError } from "@/components/form-bits";
import { fmtDate } from "@/lib/format";

interface V { id: string; version: string; channel: string; notes: string | null; sha256: string | null; downloadUrl: string | null; minimumSupported: boolean; active: boolean; releasedAt: string }

export function VersionsManager({ versions, usage }: { versions: V[]; usage: Record<string, number> }) {
  const router = useRouter();
  const [f, setF] = useState({ version: "", notes: "", sha256: "", downloadUrl: "" });
  const [error, setError] = useState<string | null>(null);
  const patch = async (id: string, body: object) => { await api(`/api/admin/versions/${id}`, { method: "PATCH", body }).catch((e) => setError(e.message)); router.refresh(); };
  return (
    <div className="space-y-4">
      <form className="card grid gap-3 p-5 sm:grid-cols-5" onSubmit={async (e) => {
        e.preventDefault(); setError(null);
        try { await api("/api/admin/versions", { body: { ...f, channel: "stable", minimumSupported: false, active: true } }); setF({ version: "", notes: "", sha256: "", downloadUrl: "" }); router.refresh(); }
        catch (err) { setError((err as Error).message); }
      }}>
        <div className="sm:col-span-5"><FormError message={error} /></div>
        <input className="input" placeholder="Version (1.2.0)" value={f.version} onChange={(e) => setF({ ...f, version: e.target.value })} />
        <input className="input sm:col-span-2" placeholder="SHA-256 of executable (optional)" value={f.sha256} onChange={(e) => setF({ ...f, sha256: e.target.value })} />
        <input className="input" placeholder="Release notes" value={f.notes} onChange={(e) => setF({ ...f, notes: e.target.value })} />
        <button className="btn btn-primary">Register version</button>
      </form>
      <div className="card overflow-hidden">
        <table className="table">
          <thead><tr><th>Version</th><th>Released</th><th>Connections</th><th>SHA-256</th><th>Minimum supported</th><th>Active</th></tr></thead>
          <tbody>{versions.map((v) => (
            <tr key={v.id}>
              <td className="font-mono text-ink">{v.version}<div className="font-sans text-[11.5px] text-dim">{v.notes}</div></td>
              <td className="text-dim">{fmtDate(v.releasedAt)}</td>
              <td>{usage[v.version] ?? 0}</td>
              <td className="max-w-[200px] truncate font-mono text-[11px]" title={v.sha256 ?? ""}>{v.sha256 ?? "—"}</td>
              <td><input type="checkbox" checked={v.minimumSupported} onChange={() => patch(v.id, { minimumSupported: !v.minimumSupported })} className="accent-[#4c74e8]" /></td>
              <td><input type="checkbox" checked={v.active} onChange={() => patch(v.id, { active: !v.active })} className="accent-[#4c74e8]" /></td>
            </tr>
          ))}</tbody>
        </table>
      </div>
    </div>
  );
}
