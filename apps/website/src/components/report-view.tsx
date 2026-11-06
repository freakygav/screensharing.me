"use client";
import { Fragment, useMemo, useState } from "react";
import type { DetectionView, SnapshotView } from "@/lib/snapshot-types";
import { OUTCOME_LABEL, OutcomeBadge, SEV_DOT, SeverityBadge, TIER_LABEL } from "./badges";
import { IconChevron, IconDownload, IconSearch } from "./icons";
import { fmtBytes, fmtDate } from "@/lib/format";

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const SEV_RANK: Record<string, number> = Object.fromEntries(SEVERITIES.map((s, i) => [s, i]));
const OUTCOMES = ["CONFIRMED", "HIGH_CONFIDENCE", "LOW_CONFIDENCE", "UNABLE_TO_INSPECT", "INFORMATIONAL"] as const;
const OUTCOME_RANK: Record<string, number> = Object.fromEntries(OUTCOMES.map((o, i) => [o, i]));
const VERDICT_BAR: Record<string, string> = {
  confirmed: "bg-crit",
  strong: "bg-high",
  suspicious: "bg-med",
  review: "bg-med",
  clear: "bg-ok",
};

type Tab = "findings" | "uninspected" | "inventory" | "coverage" | "custody";

export function ReportView({ snap }: { snap: SnapshotView }) {
  const [tab, setTab] = useState<Tab>("findings");
  const done = snap.scan?.status === "COMPLETED";
  const s = snap.scan?.summary;
  const inspection = s?.inspection;
  const instance = s?.instance ?? s?.installations?.[0];
  const outcomes = useMemo(() => Object.fromEntries(OUTCOMES.map((o) => [o, snap.detections.filter((d) => d.outcome === o).length])), [snap.detections]);
  const uninspected = inspection?.uninspected ?? [];
  return (
    <div className="space-y-4">
      {done && (
        <div className="card-flat relative overflow-hidden">
          <div className={`absolute inset-y-0 left-0 w-1 ${VERDICT_BAR[snap.verdict.level]}`} />
          <div className="flex flex-wrap items-start justify-between gap-4 py-4 pl-6 pr-5">
            <div className="max-w-3xl">
              <div className="eyebrow">Result</div>
              <div className="mt-1 text-[17px] font-semibold">{snap.verdict.title}</div>
              <p className="mt-1 text-[13px] leading-relaxed text-ink-2">{snap.verdict.explanation}</p>
            </div>
            <div className="flex gap-1.5">
              {(["pdf", "json", "csv"] as const).map((f) => (
                <a key={f} href={`/api/investigations/${snap.id}/export?format=${f}`} className="btn btn-secondary btn-sm uppercase"><IconDownload size={13} /> {f}</a>
              ))}
            </div>
          </div>
          <div className="grid grid-cols-2 border-t border-line sm:grid-cols-5">
            {OUTCOMES.map((o) => (
              <div key={o} className="border-line px-5 py-3 [&:not(:last-child)]:border-r">
                <div className="text-[11.5px] text-muted">{OUTCOME_LABEL[o]}</div>
                <div className={`mt-0.5 text-lg font-semibold tabular-nums ${outcomes[o] ? (o === "CONFIRMED" ? "text-crit" : o === "HIGH_CONFIDENCE" ? "text-high" : o === "LOW_CONFIDENCE" ? "text-med" : "text-ink") : "text-dim"}`}>{outcomes[o]}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {done && (instance || inspection) && (
        <div className="card grid gap-x-8 gap-y-3 px-5 py-4 text-[12.5px] md:grid-cols-[1.4fr_1fr]">
          <div className="min-w-0">
            <div className="eyebrow">Examined instance</div>
            <div className="mt-1 text-[14px] font-semibold text-ink">{String(instance?.name ?? instance?.launcher ?? "—")}</div>
            <div className="mt-0.5 text-muted">{String(instance?.launcher ?? "")}{instance?.versions && instance.versions !== "—" ? ` · Minecraft ${String(instance.versions)}` : ""}{instance?.loader ? ` · ${String(instance.loader)}` : ""}{instance?.processId ? ` · PID ${String(instance.processId)}` : ""}</div>
            <div className="mono mt-1.5 break-all text-[11.5px] text-ink-2">{String(instance?.path ?? "")}</div>
            {instance?.source ? <div className="mt-1 text-[11.5px] text-dim">Identified from the {String(instance.source)} of the running game.</div> : null}
          </div>
          {inspection && (
            <dl className="grid grid-cols-3 gap-x-4 gap-y-2 self-center">
              <Stat label="Files examined" value={inspection.examined} />
              <Stat label="Analysed" value={inspection.analyzed} />
              <Stat label="Skipped" value={inspection.skipped} />
              <Stat label="Unable to inspect" value={inspection.unableToInspect} tone={inspection.unableToInspect ? "text-med" : undefined} />
              <Stat label="Signatures" value={s?.statistics?.signatures ?? "—"} />
              <Stat label="Integrity" value={snap.scan?.manifestVerified ? "Verified" : "Unverified"} tone={snap.scan?.manifestVerified ? "text-ok" : "text-crit"} />
            </dl>
          )}
        </div>
      )}

      <div className="flex gap-1 border-b border-line text-[13px]">
        {([["findings", `Findings (${snap.detections.length})`], ["uninspected", `Not inspected (${uninspected.length})`], ["inventory", "Inventory"], ["coverage", "Coverage"], ["custody", "Chain of custody"]] as [Tab, string][]).map(([k, l]) => (
          <button key={k} onClick={() => setTab(k)} className={`-mb-px border-b-2 px-3 py-2.5 ${tab === k ? "border-accent font-semibold text-ink" : "border-transparent text-muted hover:text-ink"}`}>{l}</button>
        ))}
      </div>
      {tab === "findings" && <Findings detections={snap.detections} />}
      {tab === "uninspected" && <Uninspected snap={snap} />}
      {tab === "inventory" && <Inventory snap={snap} />}
      {tab === "coverage" && <Coverage snap={snap} />}
      {tab === "custody" && <Custody snap={snap} />}
    </div>
  );
}

function Stat({ label, value, tone }: { label: string; value: React.ReactNode; tone?: string }) {
  return (
    <div>
      <dt className="text-[11px] text-dim">{label}</dt>
      <dd className={`text-[14px] font-semibold tabular-nums ${tone ?? "text-ink"}`}>{typeof value === "number" ? value.toLocaleString() : value}</dd>
    </div>
  );
}

function Findings({ detections }: { detections: DetectionView[] }) {
  const [q, setQ] = useState("");
  const [outcome, setOutcome] = useState<string>("ALL");
  const [sev, setSev] = useState<string>("ALL");
  const [open, setOpen] = useState<Set<string>>(new Set());

  const list = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return detections
      .filter((d) => outcome === "ALL" || d.outcome === outcome)
      .filter((d) => sev === "ALL" || d.severity === sev)
      .filter((d) => !needle || [d.name, d.description, d.ruleId, d.category, d.family ?? "", d.signature ?? "", d.location ?? "", ...d.evidence.map((e) => e.reference), ...d.evidence.map((e) => e.sha256 ?? "")].some((t) => t.toLowerCase().includes(needle)))
      .sort((a, b) => OUTCOME_RANK[a.outcome] - OUTCOME_RANK[b.outcome] || SEV_RANK[a.severity] - SEV_RANK[b.severity] || b.confidence - a.confidence);
  }, [detections, q, outcome, sev]);

  const toggle = (id: string) => setOpen((s) => { const n = new Set(s); if (n.has(id)) n.delete(id); else n.add(id); return n; });

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap gap-2">
        <div className="relative min-w-60 flex-1">
          <IconSearch className="absolute left-3 top-1/2 -translate-y-1/2 text-dim" size={14} />
          <input className="input pl-8" placeholder="Search detections, clients, paths, signatures, hashes…" value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
        <select className="input w-48" value={outcome} onChange={(e) => setOutcome(e.target.value)} aria-label="Filter by status">
          <option value="ALL">All statuses</option>
          {OUTCOMES.map((o) => <option key={o} value={o}>{OUTCOME_LABEL[o]}</option>)}
        </select>
        <select className="input w-40" value={sev} onChange={(e) => setSev(e.target.value)} aria-label="Filter by severity">
          <option value="ALL">All severities</option>
          {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
      </div>
      {list.length === 0 ? (
        <div className="card-flat px-5 py-10 text-center text-[13px] text-muted">{detections.length ? "No findings match the filters." : "No findings. Nothing in the examined instance matched a signature or heuristic."}</div>
      ) : (
        <div className="card overflow-x-auto">
          <table className="table min-w-[820px] table-fixed">
            <thead>
              <tr><th className="w-8" /><th className="w-[28%]">Detection</th><th className="w-[14%]">Suspected client</th><th className="w-[19%]">Location</th><th className="w-[19%]">Signature / indicator</th><th className="w-14 text-right">Conf.</th><th className="w-24">Severity</th><th className="w-32">Status</th></tr>
            </thead>
            <tbody>
              {list.map((d) => (
                <Fragment key={d.id}>
                  <tr className="cursor-pointer" onClick={() => toggle(d.id)} aria-expanded={open.has(d.id)}>
                    <td className="pr-0"><IconChevron className={`text-dim transition-transform ${open.has(d.id) ? "rotate-90" : ""}`} size={14} /></td>
                    <td><div className="flex items-center gap-2"><span className={`h-1.5 w-1.5 shrink-0 rounded-full ${SEV_DOT[d.severity]}`} /><span className="truncate font-medium text-ink" title={d.name}>{d.name}</span></div><div className="truncate pl-3.5 text-[11.5px] text-dim">{d.category}</div></td>
                    <td className="truncate" title={d.family ?? ""}>{d.family ?? <span className="text-dim">—</span>}</td>
                    <td className="mono truncate text-[11.5px]" title={d.location ?? d.evidence[0]?.reference}>{d.location ?? d.evidence[0]?.reference}</td>
                    <td className="mono truncate text-[11.5px]" title={d.signature ?? ""}>{d.signature ?? <span className="text-dim">—</span>}</td>
                    <td className="text-right tabular-nums">{d.confidence}%</td>
                    <td><SeverityBadge severity={d.severity} /></td>
                    <td className="whitespace-nowrap"><OutcomeBadge outcome={d.outcome} />{d.outcome !== "CONFIRMED" && d.outcome !== "INFORMATIONAL" && d.outcome !== "UNABLE_TO_INSPECT" && <div className="mt-0.5 text-[10.5px] text-dim">manual review</div>}</td>
                  </tr>
                  {open.has(d.id) && (
                    <tr><td colSpan={8} className="bg-bg-raised p-0"><FindingDetail d={d} /></td></tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function FindingDetail({ d }: { d: DetectionView }) {
  return (
    <div className="fade-up px-6 py-5">
      <p className="text-[13px] leading-relaxed text-ink">{d.description}</p>
      <div className="mt-2 text-[11.5px] text-dim">{d.ruleId} · {TIER_LABEL[d.tier] ?? d.tier} · detected {fmtDate(d.detectedAt, true)}</div>
      <div className="mt-4 grid gap-4 md:grid-cols-2">
        <Block title="Why this matters">{d.whyItMatters}</Block>
        <Block title="Detection method">{d.method}</Block>
        <Block title="What this does not establish">{d.limitations}</Block>
        <Block title="Alternative legitimate explanations">{d.alternativeExplanations}</Block>
      </div>
      <Block title="False-positive considerations" className="mt-4">{d.falsePositiveNotes}</Block>
      <div className="eyebrow mt-5">Evidence ({d.evidence.length})</div>
      <div className="mt-2 space-y-2">
        {d.evidence.map((e) => (
          <div key={e.id} className="rounded-md border border-line bg-bg p-3">
            <div className="flex flex-wrap items-center gap-2">
              <span className="chip">{e.kind}</span>
              <span className="text-[12px] text-muted">{e.source}</span>
            </div>
            <div className="mono mt-2 break-all text-[12px] text-ink">{e.reference}</div>
            <dl className="mono mt-2 grid gap-x-6 gap-y-1 text-[11.5px] text-muted sm:grid-cols-2">
              {e.sha256 && <div className="break-all sm:col-span-2"><span className="text-dim">sha256 </span>{e.sha256}</div>}
              {e.sizeBytes != null && <div><span className="text-dim">size </span>{fmtBytes(e.sizeBytes)} ({e.sizeBytes} B)</div>}
              {e.createdTime && <div><span className="text-dim">created </span>{fmtDate(e.createdTime, true)}</div>}
              {e.modifiedTime && <div><span className="text-dim">modified </span>{fmtDate(e.modifiedTime, true)}</div>}
              <div><span className="text-dim">observed </span>{fmtDate(e.observedAt, true)}</div>
              {e.details && Object.entries(e.details).map(([k, v]) => <div key={k} className="break-all sm:col-span-2"><span className="text-dim">{k} </span>{v}</div>)}
            </dl>
          </div>
        ))}
      </div>
    </div>
  );
}

function Block({ title, children, className = "" }: { title: string; children: React.ReactNode; className?: string }) {
  return (
    <div className={className}>
      <div className="eyebrow">{title}</div>
      <p className="mt-1.5 text-[13px] leading-relaxed text-ink-2">{children}</p>
    </div>
  );
}

function Uninspected({ snap }: { snap: SnapshotView }) {
  const s = snap.scan?.summary;
  const list = s?.inspection?.uninspected ?? [];
  const excluded = s?.excludedLocations ?? [];
  return (
    <div className="space-y-4">
      <div className="card overflow-hidden">
        <div className="border-b border-line px-5 py-3 text-[13px] font-semibold">Files that could not be inspected ({list.length})</div>
        {list.length === 0 ? (
          <div className="px-5 py-6 text-[13px] text-muted">Every relevant file of the instance was inspected.</div>
        ) : (
          <table className="table">
            <thead><tr><th>Location</th><th>Reason</th></tr></thead>
            <tbody>{list.map((u, i) => (<tr key={i}><td className="mono break-all text-[11.5px] text-ink">{u.location}</td><td className="text-[12.5px]">{u.reason ?? u.status}</td></tr>))}</tbody>
          </table>
        )}
      </div>
      {excluded.length > 0 && (
        <div className="card overflow-hidden">
          <div className="border-b border-line px-5 py-3 text-[13px] font-semibold">Excluded from the scan</div>
          <ul className="divide-y divide-line">{excluded.map((e, i) => <li key={i} className="mono px-5 py-2 text-[11.5px] text-ink-2">{e}</li>)}</ul>
        </div>
      )}
      <p className="text-[12px] text-dim">Only the selected Minecraft instance is examined. Nothing outside it — other instances, documents, browsers or Windows records — is read.</p>
    </div>
  );
}

function Inventory({ snap }: { snap: SnapshotView }) {
  const s = snap.scan?.summary;
  if (!s) return <div className="card-flat px-5 py-10 text-center text-[13px] text-muted">The inventory is available when the scan completes.</div>;
  const mods = (s.mods ?? []) as Record<string, string | number | boolean | null>[];
  return (
    <div className="space-y-4">
      <div className="card overflow-hidden">
        <div className="border-b border-line px-5 py-3 text-[13px] font-semibold">Archives in the instance ({mods.length})</div>
        <div className="max-h-[560px] overflow-y-auto">
          <table className="table">
            <thead><tr><th>Mod</th><th>Version</th><th>Loader</th><th>Classification</th><th>Verified source</th><th>Location</th></tr></thead>
            <tbody>
              {mods.map((m, idx) => (
                <tr key={idx}>
                  <td><div className="text-ink">{String(m.name ?? m.modId ?? "?")}</div><div className="mono text-[11px] text-dim">{String(m.modId ?? "")}</div></td>
                  <td className="text-[12.5px]">{String(m.version ?? "—")}</td>
                  <td className="text-[12.5px]">{String(m.loader ?? "—")}</td>
                  <td><span className={`chip ${m.classification === "prohibited" || m.classification === "suspicious" ? "text-crit" : String(m.classification).startsWith("unrecognised") ? "text-med" : ""}`}>{String(m.classification ?? "—")}</span></td>
                  <td className="text-[12.5px]">{m.modrinthProject ? `Modrinth: ${m.modrinthProject}` : "—"}</td>
                  <td className="mono max-w-[300px] truncate text-[11px]" title={String(m.path ?? "")}>{String(m.location ?? m.fileName ?? "")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
      {(s.installations ?? []).length > 0 && (
        <div className="card overflow-hidden">
          <div className="border-b border-line px-5 py-3 text-[13px] font-semibold">Instance details</div>
          <dl className="grid gap-x-8 gap-y-1.5 px-5 py-4 text-[12.5px] sm:grid-cols-2">
            {Object.entries((s.installations ?? [])[0]).map(([k, v]) => (<div key={k} className="flex justify-between gap-4"><dt className="text-dim">{k}</dt><dd className="mono break-all text-right text-[11.5px] text-ink-2">{String(v ?? "—")}</dd></div>))}
          </dl>
        </div>
      )}
    </div>
  );
}

function Coverage({ snap }: { snap: SnapshotView }) {
  const cov = snap.scan?.coverage ?? snap.scan?.categories.map((c) => ({ key: c.key, name: c.name, status: c.status, note: c.message })) ?? [];
  return (
    <div className="card overflow-hidden">
      <table className="table">
        <thead><tr><th>Stage</th><th>Status</th><th>Notes</th></tr></thead>
        <tbody>
          {cov.map((c) => (
            <tr key={c.key}><td className="text-ink">{c.name}</td><td><span className={`chip ${c.status === "COMPLETED" ? "text-ok" : c.status === "SKIPPED" ? "text-med" : c.status === "FAILED" ? "text-crit" : ""}`}>{c.status}</span></td><td className="text-[12.5px]">{c.note ?? "—"}</td></tr>
          ))}
        </tbody>
      </table>
      <div className="border-t border-line px-5 py-3 text-[12px] text-dim">A skipped stage means that evidence was not examined — not that it was clean.</div>
    </div>
  );
}

function Custody({ snap }: { snap: SnapshotView }) {
  const c = snap.scan?.chainOfCustody;
  if (!c) return <div className="card-flat px-5 py-10 text-center text-[13px] text-muted">The chain-of-custody record is finalised when the scan completes.</div>;
  const ops = c.operations ?? [];
  const meta = Object.entries(c).filter(([k]) => k !== "operations");
  return (
    <div className="space-y-4">
      <div className="card p-5">
        <dl className="grid gap-x-8 gap-y-2 text-[13px] sm:grid-cols-2">
          {meta.map(([k, v]) => (<div key={k} className="flex justify-between gap-4"><dt className="text-dim">{k}</dt><dd className="mono break-all text-right text-[12px] text-ink-2">{String(v)}</dd></div>))}
          <div className="flex justify-between gap-4"><dt className="text-dim">manifestSha256</dt><dd className="mono break-all text-right text-[12px] text-ink-2">{snap.scan?.manifestSha256}</dd></div>
        </dl>
      </div>
      <div className="card overflow-hidden">
        <div className="border-b border-line px-5 py-3 text-[13px] font-semibold">Collection log ({ops.length} read-only operations)</div>
        <div className="max-h-[480px] overflow-y-auto">
          <table className="table">
            <thead><tr><th>Time</th><th>Operation</th><th>Target</th></tr></thead>
            <tbody>{ops.map((o, i) => (<tr key={i}><td className="mono whitespace-nowrap text-[11.5px]">{o.at}</td><td className="text-[12.5px]">{o.action}</td><td className="mono break-all text-[11.5px]">{o.target}</td></tr>))}</tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
