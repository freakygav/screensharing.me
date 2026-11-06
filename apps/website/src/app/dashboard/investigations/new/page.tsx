"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";
import { PageHeaderClient } from "@/components/page-header-client";
import { api } from "@/lib/client-api";
import { FormError, Spinner } from "@/components/form-bits";

export default function NewInvestigation() {
  const router = useRouter();
  const [f, setF] = useState({ subjectName: "", serverName: "", notes: "" });
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  return (
    <div>
      <PageHeaderClient title="New investigation" subtitle="You'll receive a one-time PIN to give to the player." />
      <div className="max-w-xl p-8">
        <form
          className="card space-y-5 p-6"
          onSubmit={async (e) => {
            e.preventDefault();
            setBusy(true); setError(null);
            try {
              const r = await api<{ id: string }>("/api/investigations", { body: f });
              router.push(`/dashboard/investigations/${r.id}`);
            } catch (err) { setError((err as Error).message); setBusy(false); }
          }}
        >
          <FormError message={error} />
          <div>
            <label className="label" htmlFor="subject">Player (Minecraft username)</label>
            <input id="subject" className="input" value={f.subjectName} onChange={(e) => setF({ ...f, subjectName: e.target.value })} maxLength={32} required autoFocus />
          </div>
          <div>
            <label className="label" htmlFor="server">Server <span className="font-normal text-dim">(optional)</span></label>
            <input id="server" className="input" value={f.serverName} onChange={(e) => setF({ ...f, serverName: e.target.value })} maxLength={64} placeholder="play.example.net" />
          </div>
          <div>
            <label className="label" htmlFor="notes">Internal notes <span className="font-normal text-dim">(optional, never shown to the player)</span></label>
            <textarea id="notes" rows={3} className="input" value={f.notes} onChange={(e) => setF({ ...f, notes: e.target.value })} maxLength={1000} />
          </div>
          <button className="btn btn-primary" disabled={busy || !f.subjectName.trim()}>{busy && <Spinner />} Create investigation &amp; PIN</button>
        </form>
      </div>
    </div>
  );
}
