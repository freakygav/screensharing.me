"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";
import { api } from "@/lib/client-api";

export function UserActions({ id, role, disabled, self }: { id: string; role: string; disabled: boolean; self: boolean }) {
  const router = useRouter();
  const [msg, setMsg] = useState<string | null>(null);
  const [link, setLink] = useState<string | null>(null);
  const run = async (body: object) => {
    setMsg(null);
    try { await api(`/api/admin/users/${id}`, { method: "PATCH", body }); router.refresh(); }
    catch (e) { setMsg((e as Error).message); }
  };
  return (
    <div className="flex flex-col items-end gap-1">
      <div className="flex justify-end gap-1">
        {!self && <button className="btn btn-ghost btn-sm" onClick={() => run({ role: role === "ADMIN" ? "USER" : "ADMIN" })}>{role === "ADMIN" ? "Demote" : "Make admin"}</button>}
        {!self && <button className="btn btn-ghost btn-sm" onClick={() => run({ disabled: !disabled })}>{disabled ? "Enable" : "Disable"}</button>}
        <button className="btn btn-ghost btn-sm" onClick={() => run({ revokeSessions: true })}>Sign out</button>
        <button className="btn btn-ghost btn-sm" onClick={async () => {
          if (!window.confirm("Generate a one-time 30-minute password reset link for this user? Only hand it over after verifying their identity.")) return;
          try { const r = await api<{ url: string }>(`/api/admin/users/${id}/reset-link`, { method: "POST", body: {} }); setLink(r.url); }
          catch (e) { setMsg((e as Error).message); }
        }}>Reset link</button>
      </div>
      {link && <input readOnly value={link} className="input h-7 w-80 font-mono text-[11px]" onFocus={(e) => e.currentTarget.select()} />}
      {msg && <span className="text-[11.5px] text-crit">{msg}</span>}
    </div>
  );
}
