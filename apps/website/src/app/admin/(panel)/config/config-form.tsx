"use client";
import { useState } from "react";
import { api } from "@/lib/client-api";
import { FormError, FormSuccess } from "@/components/form-bits";

interface Cfg { registrationOpen: boolean; maintenanceMessage: string; pinTtlMinutes: number; modrinthLookupDefault: boolean }

export function ConfigForm({ initial }: { initial: Cfg }) {
  const [cfg, setCfg] = useState(initial);
  const [msg, setMsg] = useState<{ ok?: string; err?: string }>({});
  const save = async (key: keyof Cfg, value: Cfg[keyof Cfg]) => {
    setMsg({});
    try { const r = await api<{ config: Cfg }>("/api/admin/config", { method: "PATCH", body: { key, value } }); setCfg(r.config); setMsg({ ok: "Saved." }); }
    catch (e) { setMsg({ err: (e as Error).message }); }
  };
  return (
    <div className="card space-y-5 p-5">
      <FormError message={msg.err ?? null} /><FormSuccess message={msg.ok ?? null} />
      <label className="flex items-center justify-between gap-4 text-sm"><span><span className="font-semibold">Registration open</span><span className="block text-[12.5px] text-muted">Allow new accounts to be created.</span></span><input type="checkbox" className="accent-[#4c74e8]" checked={cfg.registrationOpen} onChange={(e) => save("registrationOpen", e.target.checked)} /></label>
      <label className="flex items-center justify-between gap-4 text-sm"><span><span className="font-semibold">Modrinth verification default</span><span className="block text-[12.5px] text-muted">Desktop scanners verify unknown mod hashes against the public Modrinth API.</span></span><input type="checkbox" className="accent-[#4c74e8]" checked={cfg.modrinthLookupDefault} onChange={(e) => save("modrinthLookupDefault", e.target.checked)} /></label>
      <div className="text-sm"><div className="font-semibold">PIN lifetime (minutes)</div><div className="mt-2 flex gap-2"><input type="number" min={1} max={1440} className="input h-9 w-32" value={cfg.pinTtlMinutes} onChange={(e) => setCfg({ ...cfg, pinTtlMinutes: Number(e.target.value) })} /><button className="btn btn-secondary btn-sm h-9" onClick={() => save("pinTtlMinutes", cfg.pinTtlMinutes)}>Save</button></div></div>
      <div className="text-sm"><div className="font-semibold">Maintenance message</div><div className="mt-2 flex gap-2"><input className="input h-9" value={cfg.maintenanceMessage} onChange={(e) => setCfg({ ...cfg, maintenanceMessage: e.target.value })} /><button className="btn btn-secondary btn-sm h-9" onClick={() => save("maintenanceMessage", cfg.maintenanceMessage)}>Save</button></div></div>
    </div>
  );
}
