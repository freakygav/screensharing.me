"use client";
import { useMemo, useState } from "react";
import type { DetectionView, SnapshotView } from "@/lib/snapshot-types";
import { SEV_DOT, SeverityBadge, TierBadge } from "./badges";
import { IconChevron, IconDownload, IconSearch } from "./icons";
import { fmtBytes, fmtDate } from "@/lib/format";

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const SEV_RANK: Record<string, number> = Object.fromEntries(SEVERITIES.map((s, i) => [s, i]));
const VERDICT_STYLE: Record<string, string> = {
  confirmed: "border-[rgba(255,77,106,.4)] bg-[rgba(255,77,106,.07)]",
  strong: "border-[rgba(255,138,76,.38)] bg-[rgba(255,138,76,.06)]",
  suspicious: "border-[rgba(245,196,81,.32)] bg-[rgba(245,196,81,.05)]",
  review: "border-line bg-[#0c0e14]",
  clear: "border-[rgba(61,220,151,.3)] bg-[rgba(61,220,151,.05)]",
};

type Tab = "findings" | "inventory" | "coverage" | "custody";

export function ReportView({ snap }: { snap: SnapshotView }) {
  const [tab, setTab] = useState<Tab>("findings");
  const done = snap.scan?.status === "COMPLETED";
  return (
    <div className="space-y-4">
      {done && (
        <div className={`card-flat flex flex-wrap items-center justify-between gap-4 p-5 ${VERDICT_STYLE[snap.verdict.level]}`}>
          <div className="max-w-3xl">
            <div className="text-xs font-semibold uppercase tracking-[0.14em] text-muted">Overall result</div>
            <div className="mt-1.5 text-lg font-bold">{snap.verdict.title}</div>
            <p className="mt-1 text-[13px] leading-relaxed text-ink-2">{snap.verdict.explanation}</p>
          </div>
          <div className="flex gap-2">
            {(["pdf", "json", "csv"] as const).map((f) => (
              <a key={f} href={`/api/investigations/${snap.id}/export?format=${f}`} className="btn btn-secondary btn-sm uppercase"><IconDownload size={13} /> {f}</a>
            ))}
          </div>
        </div>
      )}
      {done && snap.scan && (
        <div className="grid gap-3 sm:grid-cols-4 lg:grid-cols-7">
          <Mini label="Total findings" value={snap.counts.total} />
          <Mini label="Critical" value={snap.counts.severity.CRITICAL} tone="text-crit" />
          <Mini label="High" value={snap.counts.severity.HIGH} tone="text-high" />
          <Mini label="Medium" value={snap.counts.severity.MEDIUM} tone="text-med" />
          <Mini label="Low" value={snap.counts.severity.LOW} tone="text-low" />
          <Mini label="Inconclusive" value={snap.counts.tier.INCONCLUSIVE} />
          <Mini label="Integrity" value={snap.scan.manifestVerified ? "Verified" : "Unverified"} tone={snap.scan.manifestVerified ? "text-ok" : "text-crit"} small />
        </div>
      )}
      <div className="flex gap-1 border-b border-line text-[13.5px]">
        {([["findings", `Findings (${snap.detections.length})`], ["inventory", "Inventory"], ["coverage", "Coverage"], ["custody", "Chain of custody"]] as [Tab, string][]).map(([k, l]) => (
          <button key={k} onClick={() => setTab(k)} className={`-mb-px border-b-2 px-3 py-2.5 ${tab === k ? "border-accent font-semibold text-ink" : "border-transparent text-muted hover:text-ink"}`}>{l}</button>
        ))}
      </div>
      {tab === "findings" && <Findings detections={snap.detections} />}
      {tab === "inventory" && <Inventory snap={snap} />}
      {tab === "coverage" && <Coverage snap={snap} />}
      {tab === "custody" && <Custody snap={snap} />}
    </div>
  );
}

function Mini({ label, value, tone, small }: { label: string; value: React.ReactNode; tone?: string; small?: boolean }) {
  return (
    <div className="card px-4 py-3">
      <div className="text-[11.5px] text-muted">{label}</div>
      <div className={`mt-1 font-bold tabular-nums ${small ? "text-[15px]" : "text-xl"} ${tone ?? ""}`}>{value}</div>
    </div>
  );
}

function Findings({ detections }: { detections: DetectionView[] }) {
  const [q, setQ] = useState("");
  const [sev, setSev] = useState<string>("ALL");
  const [cat, setCat] = useState<string>("ALL");
  const [sort, setSort] = useState<"severity" | "confidence" | "time">("severity");
  const [open, setOpen] = useState<Set<string>>(new Set());
  const categories = useMemo(() => [...new Set(detections.map((d) => d.category))].sort(), [detections]);

  const list = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return detections
      .filter((d) => sev === "ALL" || d.severity === sev)
      .filter((d) => cat === "ALL" || d.category === cat)
      .filter((d) => !needle || [d.name, d.description, d.ruleId, d.category, ...d.evidence.map((e) => e.reference), ...d.evidence.map((e) => e.sha256 ?? "")].some((t) => t.toLowerCase().includes(needle)))
      .sort((a, b) =>
        sort === "confidence" ? b.confidence - a.confidence
        : sort === "time" ? a.detectedAt.localeCompare(b.detectedAt)
        : SEV_RANK[a.severity] - SEV_RANK[b.severity] || b.confidence - a.confidence);
  }, [detections, q, sev, cat, sort]);

  const toggle = (id: string) => setOpen((s) => { const n = new Set(s); if (n.has(id)) n.delete(id); else n.add(id); return n; });

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap gap-2">
        <div className="relative min-w-60 flex-1">
          <IconSearch className="absolute left-3 top-1/2 -translate-y-1/2 text-dim" size={14} />
          <input className="input h-9 pl-8" placeholder="Search findings, rules, paths, hashes…" value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
        <select className="input h-9 w-40" value={sev} onChange={(e) => setSev(e.target.value)} aria-label="Filter by severity">
          <option value="ALL">All severities</option>
          {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <select className="input h-9 w-48" value={cat} onChange={(e) => setCat(e.target.value)} aria-label="Filter by category">
          <option value="ALL">All categories</option>
          {categories.map((c) => <option key={c} value={c}>{c}</option>)}
        </select>
        <select className="input h-9 w-44" value={sort} onChange={(e) => setSort(e.target.value as typeof sort)} aria-label="Sort">
          <option value="severity">Sort: severity</option>
          <option value="confidence">Sort: confidence</option>
          <option value="time">Sort: detection time</option>
        </select>
        <button className="btn btn-ghost btn-sm h-9" onClick={() => setOpen(open.size ? new Set() : new Set(list.map((d) => d.id)))}>{open.size ? "Collapse all" : "Expand all"}</button>
      </div>
      {list.length === 0 && <div className="card-flat px-5 py-10 text-center text-sm text-muted">{detections.length ? "No findings match the filters." : "No findings. No examined artifact matched a detection rule."}</div>}
      {list.map((d) => <FindingCard key={d.id} d={d} open={open.has(d.id)} onToggle={() => toggle(d.id)} />)}
    </div>
  );
}

function FindingCard({ d, open, onToggle }: { d: DetectionView; open: boolean; onToggle: () => void }) {
  return (
    <div className="card overflow-hidden">
      <button className="flex w-full items-center gap-4 px-5 py-4 text-left hover:bg-white/[0.015]" onClick={onToggle} aria-expanded={open}>
        <span className={`h-2 w-2 shrink-0 rounded-full ${SEV_DOT[d.severity]}`} />
        <div className="min-w-0 flex-1">
          <div className="truncate text-[14px] font-semibold">{d.name}</div>
          <div className="mt-0.5 truncate text-[12px] text-dim">{d.category} · {d.ruleId} · {d.evidence[0]?.reference}</div>
        </div>
        <TierBadge tier={d.tier} />
        <SeverityBadge severity={d.severity} />
        <span className="w-12 text-right text-[13px] font-semibold tabular-nums text-ink-2">{d.confidence}%</span>
        <IconChevron className={`shrink-0 text-dim transition-transform ${open ? "rotate-90" : ""}`} />
      </button>
      {open && (
        <div className="fade-up border-t border-line px-5 py-5">
          <p className="text-[13.5px] leading-relaxed text-ink-2">{d.description}</p>
          <div className="mt-4 grid gap-4 md:grid-cols-2">
            <Block title="Why this matters">{d.whyItMatters}</Block>
            <Block title="Detection method">{d.method}</Block>
            <Block title="Limitations — what this does not establish">{d.limitations}</Block>
            <Block title="Alternative legitimate explanations">{d.alternativeExplanations}</Block>
          </div>
          <Block title="False-positive considerations" className="mt-4">{d.falsePositiveNotes}</Block>
          <div className="mt-5 text-xs font-semibold uppercase tracking-wider text-dim">Evidence ({d.evidence.length})</div>
          <div className="mt-2 space-y-2">
            {d.evidence.map((e) => (
              <div key={e.id} className="rounded-[10px] border border-line bg-[#090b10] p-3.5">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="chip h-5 text-[10.5px]">{e.kind}</span>
                  <span className="text-[12px] text-muted">{e.source}</span>
                </div>
                <div className="mt-2 break-all font-mono text-[12px] text-ink">{e.reference}</div>
                <dl className="mt-2 grid gap-x-6 gap-y-1 font-mono text-[11.5px] text-muted sm:grid-cols-2">
                  {e.sha256 && <div className="sm:col-span-2 break-all"><span className="text-dim">sha256 </span>{e.sha256}</div>}
                  {e.sizeBytes != null && <div><span className="text-dim">size </span>{fmtBytes(e.sizeBytes)} ({e.sizeBytes} B)</div>}
                  {e.createdTime && <div><span className="text-dim">created </span>{fmtDate(e.createdTime, true)}</div>}
                  {e.modifiedTime && <div><span className="text-dim">modified </span>{fmtDate(e.modifiedTime, true)}</div>}
                  <div><span className="text-dim">observed </span>{fmtDate(e.observedAt, true)}</div>
                  {e.details && Object.entries(e.details).map(([k, v]) => <div key={k} className="sm:col-span-2 break-all"><span className="text-dim">{k} </span>{v}</div>)}
                </dl>
              </div>
            ))}
          </div>
          <div className="mt-4 text-[11.5px] text-dim">Detected {fmtDate(d.detectedAt, true)}</div>
        </div>
      )}
    </div>
  );
}

function Block({ title, children, className = "" }: { title: string; children: React.ReactNode; className?: string }) {
  return (
    <div className={className}>
      <div className="text-xs font-semibold uppercase tracking-wider text-dim">{title}</div>
      <p className="mt-1.5 text-[13px] leading-relaxed text-ink-2">{children}</p>
    </div>
  );
}

function Inventory({ snap }: { snap: SnapshotView }) {
  const s = snap.scan?.summary;
  if (!s) return <div className="card-flat px-5 py-10 text-center text-sm text-muted">The inventory is available when the scan completes.</div>;
  const mods = (s.mods ?? []) as Record<string, string | number | boolean | null>[];
  return (
    <div className="space-y-4">
      <div className="card overflow-hidden">
        <div className="border-b border-line px-5 py-3 text-sm font-semibold">Minecraft installations ({s.installations?.length ?? 0})</div>
        <table className="table">
          <thead><tr><th>Launcher / client</th><th>Path</th><th>Loaders &amp; versions</th><th>Mods</th></tr></thead>
          <tbody>
            {(s.installations ?? []).map((i, idx) => (
              <tr key={idx}><td className="text-ink">{String(i.launcher ?? "")}</td><td className="break-all font-mono text-[11.5px]">{String(i.path ?? "")}</td><td className="text-[12.5px]">{String(i.versions ?? "")}</td><td>{String(i.modCount ?? 0)}</td></tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="card overflow-hidden">
        <div className="border-b border-line px-5 py-3 text-sm font-semibold">Installed modifications ({mods.length})</div>
        <div className="max-h-[520px] overflow-y-auto">
          <table className="table">
            <thead><tr><th>Mod</th><th>Version</th><th>Loader</th><th>Classification</th><th>Verified source</th><th>File</th></tr></thead>
            <tbody>
              {mods.map((m, idx) => (
                <tr key={idx}>
                  <td><div className="text-ink">{String(m.name ?? m.modId ?? "?")}</div><div className="font-mono text-[11px] text-dim">{String(m.modId ?? "")}</div></td>
                  <td className="text-[12.5px]">{String(m.version ?? "—")}</td>
                  <td className="text-[12.5px]">{String(m.loader ?? "—")}</td>
                  <td><span className={`chip ${m.classification === "prohibited" ? "text-crit" : m.classification === "unrecognised" ? "text-med" : ""}`}>{String(m.classification ?? "—")}</span></td>
                  <td className="text-[12.5px]">{m.modrinthProject ? `Modrinth: ${m.modrinthProject}` : "—"}</td>
                  <td className="max-w-[260px] truncate font-mono text-[11px]" title={String(m.path ?? "")}>{String(m.fileName ?? "")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
      <div className="card overflow-hidden">
        <div className="border-b border-line px-5 py-3 text-sm font-semibold">Java runtimes ({s.javaRuntimes?.length ?? 0})</div>
        <table className="table">
          <thead><tr><th>Path</th><th>Version</th><th>Source</th></tr></thead>
          <tbody>{(s.javaRuntimes ?? []).map((j, idx) => (<tr key={idx}><td className="break-all font-mono text-[11.5px]">{String(j.path ?? "")}</td><td>{String(j.version ?? "—")}</td><td>{String(j.source ?? "")}</td></tr>))}</tbody>
        </table>
      </div>
    </div>
  );
}

function Coverage({ snap }: { snap: SnapshotView }) {
  const cov = snap.scan?.coverage ?? snap.scan?.categories.map((c) => ({ key: c.key, name: c.name, status: c.status, note: c.message })) ?? [];
  return (
    <div className="card overflow-hidden">
      <table className="table">
        <thead><tr><th>Module</th><th>Status</th><th>Notes</th></tr></thead>
        <tbody>
          {cov.map((c) => (
            <tr key={c.key}><td className="text-ink">{c.name}</td><td><span className={`chip ${c.status === "COMPLETED" ? "text-ok" : c.status === "SKIPPED" ? "text-med" : c.status === "FAILED" ? "text-crit" : ""}`}>{c.status}</span></td><td className="text-[12.5px]">{c.note ?? "—"}</td></tr>
          ))}
        </tbody>
      </table>
      <div className="border-t border-line px-5 py-3 text-xs text-dim">Skipped modules mean the evidence was not examined — not that it was clean.</div>
    </div>
  );
}

function Custody({ snap }: { snap: SnapshotView }) {
  const c = snap.scan?.chainOfCustody;
  if (!c) return <div className="card-flat px-5 py-10 text-center text-sm text-muted">The chain-of-custody record is finalised when the scan completes.</div>;
  const ops = c.operations ?? [];
  const meta = Object.entries(c).filter(([k]) => k !== "operations");
  return (
    <div className="space-y-4">
      <div className="card p-5">
        <dl className="grid gap-x-8 gap-y-2 text-[13px] sm:grid-cols-2">
          {meta.map(([k, v]) => (<div key={k} className="flex justify-between gap-4"><dt className="text-dim">{k}</dt><dd className="break-all text-right font-mono text-[12px] text-ink-2">{String(v)}</dd></div>))}
          <div className="flex justify-between gap-4"><dt className="text-dim">manifestSha256</dt><dd className="break-all text-right font-mono text-[12px] text-ink-2">{snap.scan?.manifestSha256}</dd></div>
        </dl>
      </div>
      <div className="card overflow-hidden">
        <div className="border-b border-line px-5 py-3 text-sm font-semibold">Collection log ({ops.length} read-only operations)</div>
        <div className="max-h-[480px] overflow-y-auto">
          <table className="table">
            <thead><tr><th>Time</th><th>Operation</th><th>Target</th></tr></thead>
            <tbody>{ops.map((o, i) => (<tr key={i}><td className="whitespace-nowrap font-mono text-[11.5px]">{o.at}</td><td className="text-[12.5px]">{o.action}</td><td className="break-all font-mono text-[11.5px]">{o.target}</td></tr>))}</tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
