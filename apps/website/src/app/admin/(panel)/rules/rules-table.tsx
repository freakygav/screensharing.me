"use client";
import { useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { api } from "@/lib/client-api";
import { SeverityBadge, TierBadge } from "@/components/badges";
import { FormError } from "@/components/form-bits";

interface Rule { id: string; name: string; description: string; category: string; kind: string; pattern: string; family: string | null; features: string[]; severity: string; tier: string; confidence: number; classification: string | null; falsePositives: string; limitations: string; references: string[]; enabled: boolean; version: number }

const KINDS = ["MOD_ID", "MOD_ID_REGEX", "PACKAGE_PREFIX", "MEMORY_STRING", "SHA256", "EXECUTABLE_REGEX", "FILE_NAME_REGEX", "RESOURCEPACK_REGEX", "KNOWN_MOD", "BUILTIN"];
const SEVS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const TIERS = ["CONFIRMED_ARTIFACT", "STRONG_INDICATOR", "SUSPICIOUS_CONFIGURATION", "WEAK_INDICATOR", "INCONCLUSIVE"];
const blank: Rule = { id: "SSME-CU-", name: "", description: "", category: "Cheat client", kind: "SHA256", pattern: "", family: "", features: [], severity: "HIGH", tier: "STRONG_INDICATOR", confidence: 80, classification: null, falsePositives: "", limitations: "", references: [], enabled: true, version: 1 };

export function RulesTable({ rules, hits }: { rules: Rule[]; hits: Record<string, number> }) {
  const router = useRouter();
  const [q, setQ] = useState("");
  const [kind, setKind] = useState("ALL");
  const [edit, setEdit] = useState<{ rule: Rule; isNew: boolean } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const list = useMemo(() => rules.filter((r) => (kind === "ALL" || r.kind === kind) && (!q || `${r.id} ${r.name} ${r.pattern} ${r.family ?? ""}`.toLowerCase().includes(q.toLowerCase()))), [rules, q, kind]);

  async function save() {
    if (!edit) return;
    setError(null);
    const r = edit.rule;
    const body = { id: r.id, name: r.name, description: r.description, category: r.category, kind: r.kind, pattern: r.pattern, family: r.family || null, features: r.features, severity: r.severity, tier: r.tier, confidence: Number(r.confidence), classification: r.classification || null, falsePositives: r.falsePositives, limitations: r.limitations, references: r.references, enabled: r.enabled };
    try {
      await api(edit.isNew ? "/api/admin/rules" : `/api/admin/rules/${r.id}`, { method: edit.isNew ? "POST" : "PATCH", body });
      setEdit(null);
      router.refresh();
    } catch (e) { setError((e as Error).message); }
  }

  const set = (k: keyof Rule) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>) =>
    setEdit((s) => s && { ...s, rule: { ...s.rule, [k]: k === "features" || k === "references" ? e.target.value.split("\n").map((x) => x.trim()).filter(Boolean) : e.target.value } });

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <input className="input h-9 w-72" placeholder="Search id, name, pattern, family" value={q} onChange={(e) => setQ(e.target.value)} />
        <select className="input h-9 w-52" value={kind} onChange={(e) => setKind(e.target.value)}><option value="ALL">All kinds</option>{KINDS.map((k) => <option key={k}>{k}</option>)}</select>
        <span className="text-xs text-dim">{list.length} rules</span>
        <button className="btn btn-primary btn-sm ml-auto" onClick={() => setEdit({ rule: { ...blank }, isNew: true })}>Add rule</button>
      </div>
      {edit && (
        <div className="card space-y-3 p-5">
          <div className="text-sm font-semibold">{edit.isNew ? "New rule" : `Edit ${edit.rule.id}`}</div>
          <FormError message={error} />
          <div className="grid gap-3 sm:grid-cols-3">
            <div><label className="label">Rule id</label><input className="input" value={edit.rule.id} onChange={set("id")} disabled={!edit.isNew} /></div>
            <div className="sm:col-span-2"><label className="label">Name</label><input className="input" value={edit.rule.name} onChange={set("name")} /></div>
            <div><label className="label">Kind</label><select className="input" value={edit.rule.kind} onChange={set("kind")}>{KINDS.map((k) => <option key={k}>{k}</option>)}</select></div>
            <div className="sm:col-span-2"><label className="label">Pattern</label><input className="input font-mono" value={edit.rule.pattern} onChange={set("pattern")} /><p className="hint">MOD_ID exact id · PACKAGE_PREFIX like com/example/client/ · SHA256 lowercase hex · *_REGEX .NET regular expression · MEMORY_STRING ≥ 8 chars.</p></div>
            <div><label className="label">Category</label><input className="input" value={edit.rule.category} onChange={set("category")} /></div>
            <div><label className="label">Family</label><input className="input" value={edit.rule.family ?? ""} onChange={set("family")} /></div>
            <div><label className="label">Classification (KNOWN_MOD)</label><input className="input" value={edit.rule.classification ?? ""} onChange={set("classification")} /></div>
            <div><label className="label">Severity</label><select className="input" value={edit.rule.severity} onChange={set("severity")}>{SEVS.map((k) => <option key={k}>{k}</option>)}</select></div>
            <div><label className="label">Evidence tier</label><select className="input" value={edit.rule.tier} onChange={set("tier")}>{TIERS.map((k) => <option key={k}>{k}</option>)}</select></div>
            <div><label className="label">Confidence (0–100)</label><input type="number" min={0} max={100} className="input" value={edit.rule.confidence} onChange={set("confidence")} /></div>
          </div>
          <div><label className="label">Description</label><textarea rows={2} className="input" value={edit.rule.description} onChange={set("description")} /></div>
          <div className="grid gap-3 sm:grid-cols-2">
            <div><label className="label">False positives</label><textarea rows={2} className="input" value={edit.rule.falsePositives} onChange={set("falsePositives")} /></div>
            <div><label className="label">Limitations</label><textarea rows={2} className="input" value={edit.rule.limitations} onChange={set("limitations")} /></div>
            <div><label className="label">Features (one per line)</label><textarea rows={2} className="input" value={edit.rule.features.join("\n")} onChange={set("features")} /></div>
            <div><label className="label">References (URLs, one per line)</label><textarea rows={2} className="input" value={edit.rule.references.join("\n")} onChange={set("references")} /></div>
          </div>
          <div className="flex gap-2"><button className="btn btn-primary btn-sm" onClick={save}>Save rule</button><button className="btn btn-ghost btn-sm" onClick={() => { setEdit(null); setError(null); }}>Cancel</button></div>
        </div>
      )}
      <div className="card overflow-hidden">
        <table className="table">
          <thead><tr><th>Rule</th><th>Kind / pattern</th><th>Severity</th><th>Tier</th><th>Conf.</th><th>Hits</th><th>Enabled</th><th /></tr></thead>
          <tbody>
            {list.map((r) => (
              <tr key={r.id} className={r.enabled ? "" : "opacity-50"}>
                <td><div className="text-ink">{r.name}</div><div className="font-mono text-[11px] text-dim">{r.id} · v{r.version}</div></td>
                <td><div className="text-[11.5px] text-muted">{r.kind}</div><div className="max-w-[260px] truncate font-mono text-[11.5px]" title={r.pattern}>{r.pattern}</div></td>
                <td><SeverityBadge severity={r.severity} /></td>
                <td><TierBadge tier={r.tier} /></td>
                <td className="tabular-nums">{r.confidence}</td>
                <td className="tabular-nums">{hits[r.id] ?? 0}</td>
                <td>
                  <button className={`relative h-5 w-9 rounded-full transition-colors ${r.enabled ? "bg-accent" : "bg-[#2a3145]"}`} aria-label={r.enabled ? "Disable rule" : "Enable rule"} onClick={async () => { await api(`/api/admin/rules/${r.id}`, { method: "PATCH", body: { enabled: !r.enabled } }).catch((e) => alert(e.message)); router.refresh(); }}>
                    <span className={`absolute top-0.5 h-4 w-4 rounded-full bg-white transition-all ${r.enabled ? "left-[18px]" : "left-0.5"}`} />
                  </button>
                </td>
                <td className="text-right"><button className="btn btn-ghost btn-sm" onClick={() => { setError(null); setEdit({ rule: { ...r, family: r.family ?? "" }, isNew: false }); }}>Edit</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
