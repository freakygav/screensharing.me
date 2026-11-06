"use client";
import { useCallback, useEffect, useRef, useState } from "react";
import Link from "next/link";
import type { SnapshotView } from "@/lib/snapshot-types";
import { api } from "@/lib/client-api";
import { StatusBadge } from "./badges";
import { CopyButton, FormError, Spinner } from "./form-bits";
import { IconCheck, IconChevron, IconMonitor, IconX, IconAlert } from "./icons";
import { fmtDate, fmtRelative } from "@/lib/format";
import { ReportView } from "./report-view";

type Conn = "live" | "reconnecting" | "offline";

export function InvestigationLive({ initial, backHref }: { initial: SnapshotView; backHref: string }) {
  const [snap, setSnap] = useState<SnapshotView>(initial);
  const [conn, setConn] = useState<Conn>("live");
  const [feed, setFeed] = useState<{ at: string; text: string }[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const refetchTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [, forceTick] = useState(0);

  const refetch = useCallback(async () => {
    try {
      const s = await api<SnapshotView>(`/api/investigations/${initial.id}`);
      setSnap(s);
    } catch (e) {
      setError((e as Error).message);
    }
  }, [initial.id]);

  // Live updates via Server-Sent Events; the browser reconnects automatically with Last-Event-ID.
  useEffect(() => {
    const es = new EventSource(`/api/investigations/${initial.id}/events?after=${initial.lastEventId}`);
    es.addEventListener("open", () => setConn("live"));
    es.addEventListener("error", () => setConn(es.readyState === EventSource.CLOSED ? "offline" : "reconnecting"));
    es.addEventListener("update", (ev) => {
      setConn("live");
      try {
        const msg = JSON.parse((ev as MessageEvent).data) as { type: string; payload: Record<string, unknown>; at: string };
        const text = describe(msg.type, msg.payload);
        if (text) setFeed((f) => [{ at: msg.at, text }, ...f].slice(0, 40));
      } catch { /* ignore malformed */ }
      if (refetchTimer.current) clearTimeout(refetchTimer.current);
      refetchTimer.current = setTimeout(refetch, 250);
    });
    return () => es.close();
  }, [initial.id, initial.lastEventId, refetch]);

  // Re-render every 5s so "online" / relative timestamps stay honest; refresh device liveness every 20s.
  useEffect(() => {
    const t = setInterval(() => forceTick((n) => n + 1), 5000);
    const r = setInterval(() => { if (["CONNECTED", "SCANNING"].includes(snap.status)) refetch(); }, 20000);
    return () => { clearInterval(t); clearInterval(r); };
  }, [snap.status, refetch]);

  const deviceOnline = snap.device ? Date.now() - new Date(snap.device.lastHeartbeatAt).getTime() < 45_000 : false;
  const open = ["WAITING", "CONNECTED", "SCANNING", "EXPIRED"].includes(snap.status);

  async function action(path: string) {
    setBusy(true); setError(null);
    try { await api(path, { method: "POST", body: {} }); await refetch(); }
    catch (e) { setError((e as Error).message); }
    finally { setBusy(false); }
  }

  return (
    <div>
      <div className="flex flex-wrap items-end justify-between gap-4 border-b border-line px-8 pb-6 pt-8">
        <div>
          <Link href={backHref} className="text-xs text-muted hover:text-ink">← Investigations</Link>
          <h1 className="mt-2 flex items-center gap-3 text-[22px] font-bold tracking-tight">
            {snap.subjectName}
            <StatusBadge status={snap.status} />
          </h1>
          <p className="mt-1 text-sm text-muted">
            <span className="font-mono">{snap.reference}</span>{snap.serverName ? ` · ${snap.serverName}` : ""} · created {fmtDate(snap.createdAt)} by {snap.owner.displayName}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className={`chip ${conn === "live" ? "text-ok" : "text-med"}`}>
            <span className={`h-1.5 w-1.5 rounded-full ${conn === "live" ? "bg-ok pulse-dot" : "bg-med"}`} />
            {conn === "live" ? "Live" : conn === "reconnecting" ? "Reconnecting…" : "Offline"}
          </span>
          {open && snap.status !== "EXPIRED" && (
            <button className="btn btn-danger btn-sm" disabled={busy} onClick={() => confirmThen("Cancel this investigation? The PIN and any connected desktop are revoked.", () => action(`/api/investigations/${snap.id}/cancel`))}>Cancel</button>
          )}
        </div>
      </div>

      <div className="space-y-6 p-8">
        <FormError message={error} />

        {(snap.status === "WAITING" || snap.status === "EXPIRED") && (
          <PinPanel snap={snap} busy={busy} onRegenerate={() => action(`/api/investigations/${snap.id}/pin`)} />
        )}

        {snap.status !== "WAITING" && snap.status !== "EXPIRED" && (
          <div className="grid gap-4 lg:grid-cols-[1fr_340px]">
            <ProgressPanel snap={snap} deviceOnline={deviceOnline} />
            <div className="space-y-4">
              <DevicePanel snap={snap} online={deviceOnline} busy={busy} onReissue={() => action(`/api/investigations/${snap.id}/pin`)} />
              <ActivityFeed feed={feed} />
            </div>
          </div>
        )}

        {snap.scan && (snap.detections.length > 0 || snap.scan.status === "COMPLETED") && <ReportView snap={snap} />}
      </div>
    </div>
  );
}

function confirmThen(message: string, fn: () => void) {
  if (window.confirm(message)) fn();
}

function describe(type: string, p: Record<string, unknown>): string | null {
  switch (type) {
    case "device.connected": return `Desktop connected (v${p.appVersion}${p.elevated ? ", administrator" : ""})`;
    case "consent.given": return "Player authorised the scan";
    case "scan.started": return p.restarted ? "Scan restarted" : "Scan started";
    case "scan.progress": return p.activity ? `${p.progress}% · ${p.activity}` : null;
    case "scan.findings": return `${p.added} new finding${p.added === 1 ? "" : "s"} received`;
    case "scan.completed": return `Scan completed · ${p.findings} findings · manifest ${p.manifestVerified ? "verified" : "NOT verified"}`;
    case "scan.failed": return `Scan failed: ${p.reason}`;
    case "investigation.cancelled": return "Investigation cancelled";
    case "pin.regenerated": return "New PIN issued";
    case "pin.expired": return "PIN expired";
    case "device.heartbeat": return p.reconnected ? "Desktop reconnected" : null;
    default: return null;
  }
}

function PinPanel({ snap, busy, onRegenerate }: { snap: SnapshotView; busy: boolean; onRegenerate: () => void }) {
  const expired = snap.status === "EXPIRED" || !snap.pin;
  const remaining = snap.pin ? Math.max(0, new Date(snap.pin.expiresAt).getTime() - Date.now()) : 0;
  const mm = Math.floor(remaining / 60000), ss = Math.floor((remaining % 60000) / 1000);
  return (
    <div className="card relative overflow-hidden px-8 py-12 text-center">
      <div className="relative">
        <div className="text-xs font-semibold uppercase tracking-[0.18em] text-muted">Your investigation PIN</div>
        {expired ? (
          <>
            <div className="mt-5 font-mono text-5xl font-bold tracking-[0.2em] text-dim">––– –––</div>
            <p className="mt-5 text-sm text-muted">This PIN has expired. Issue a new one to continue.</p>
            <button className="btn btn-primary mt-5" disabled={busy} onClick={onRegenerate}>{busy && <Spinner />} Issue new PIN</button>
          </>
        ) : (
          <>
            <div className="kbd-pin mt-5 text-[64px] font-bold leading-none text-ink">{snap.pin!.pin}</div>
            <div className="mt-5 flex items-center justify-center gap-2"><CopyButton value={snap.pin!.pin.replace("-", "")} label="Copy PIN" /></div>
            <div className="mt-6 inline-flex items-center gap-2.5 text-sm text-ink-2">
              <Spinner className="border-white/15 border-t-accent" />
              Waiting for desktop application…
            </div>
            <p className="mt-2 text-xs text-dim">Single use · expires in {mm}:{String(ss).padStart(2, "0")}</p>
            <div className="mx-auto mt-8 max-w-md text-left text-[13px] leading-relaxed text-muted">
              <div className="font-semibold text-ink-2">Send the player these steps</div>
              <ol className="mt-2 list-decimal space-y-1 pl-5">
                <li>Start the Minecraft instance you play on and leave it running.</li>
                <li>Download screensharing.me.exe from <span className="font-mono text-ink-2">/download</span>, open it and enter PIN <span className="font-mono text-ink-2">{snap.pin!.pin}</span>.</li>
                <li>Confirm the instance the scanner found and review the consent screen.</li>
              </ol>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

const CAT_ICON: Record<string, React.ReactNode> = {
  COMPLETED: <IconCheck size={14} className="text-ok" />,
  FAILED: <IconX size={14} className="text-crit" />,
  SKIPPED: <IconChevron size={14} className="text-dim" />,
};

function ProgressPanel({ snap, deviceOnline }: { snap: SnapshotView; deviceOnline: boolean }) {
  const scan = snap.scan;
  const pct = scan?.progress ?? 0;
  const running = scan?.status === "RUNNING";
  return (
    <div className="card p-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="text-xs font-semibold uppercase tracking-[0.14em] text-muted">
            {!scan ? (snap.consentedAt ? "Starting scan" : "Awaiting player consent") : scan.status === "COMPLETED" ? "Investigation complete" : scan.status === "FAILED" ? "Scan failed" : "Investigation in progress"}
          </div>
          <div className="mt-2 text-sm text-ink-2">
            {!scan
              ? snap.consentedAt ? "Consent recorded. The scanner is preparing." : "The player is reviewing what will be examined."
              : scan.status === "FAILED" ? scan.failureReason
              : scan.currentActivity ?? (scan.status === "COMPLETED" ? `Completed ${fmtDate(scan.completedAt)}` : "Working…")}
          </div>
        </div>
        <div className="text-right">
          <div className="text-3xl font-bold tabular-nums tracking-tight">{pct}%</div>
          <div className="text-xs text-dim">{snap.counts.total} findings</div>
        </div>
      </div>
      {(() => {
        const inst = scan?.summary?.instance;
        const live = scan?.summary?.live ?? scan?.summary?.inspection;
        if (!inst && !live) return null;
        return (
          <div className="mt-4 grid gap-3 rounded-md border border-line bg-bg px-4 py-3 text-[12.5px] sm:grid-cols-[1.3fr_1fr]">
            {inst ? (
              <div className="min-w-0">
                <div className="eyebrow">Instance</div>
                <div className="mt-0.5 truncate font-medium text-ink">{String(inst.name ?? "")} <span className="font-normal text-muted">· {String(inst.launcher ?? "")}</span></div>
                <div className="mono truncate text-[11.5px] text-dim" title={String(inst.path ?? "")}>{String(inst.path ?? "")}</div>
              </div>
            ) : <div />}
            {live && (
              <div className="grid grid-cols-4 gap-2 text-center">
                {([["Examined", live.examined], ["Analysed", live.analyzed], ["Skipped", live.skipped], ["Not inspected", live.unableToInspect]] as [string, number][]).map(([l, v]) => (
                  <div key={l}><div className="text-[14px] font-semibold tabular-nums text-ink">{(v ?? 0).toLocaleString()}</div><div className="text-[10.5px] text-dim">{l}</div></div>
                ))}
              </div>
            )}
          </div>
        );
      })()}
      <div className={`relative mt-5 h-1.5 overflow-hidden rounded-full bg-panel-2 ${running && deviceOnline ? "progress-sweep" : ""}`}>
        <div className="h-full rounded-full bg-accent transition-[width] duration-500" style={{ width: `${pct}%` }} />
      </div>
      {running && !deviceOnline && (
        <div className="mt-4 flex items-center gap-2 rounded-md border border-[rgba(217,165,58,.3)] bg-[rgba(217,165,58,.07)] px-3 py-2 text-[13px] text-[#efd9a6]">
          <IconAlert size={14} /> Connection to the desktop was lost. Findings are queued on the player&apos;s machine and will upload when it reconnects.
        </div>
      )}
      {scan && (
        <div className="mt-6 grid gap-2 sm:grid-cols-2">
          {scan.categories.map((c) => (
            <div key={c.key} className="flex items-center gap-3 rounded-md border border-line bg-bg px-3 py-2.5">
              <div className="flex h-6 w-6 shrink-0 items-center justify-center">
                {c.status === "RUNNING" ? <Spinner className="border-white/15 border-t-accent" /> : CAT_ICON[c.status] ?? <span className="h-1.5 w-1.5 rounded-full bg-dim" />}
              </div>
              <div className="min-w-0 flex-1">
                <div className={`truncate text-[13px] ${c.status === "PENDING" ? "text-dim" : "text-ink"}`}>{c.name}</div>
                <div className="truncate text-[11.5px] text-dim">{c.status === "SKIPPED" || c.status === "FAILED" ? c.message : c.status === "PENDING" ? "Pending" : `${c.itemsExamined.toLocaleString()} examined · ${c.findingsCount} findings`}</div>
              </div>
            </div>
          ))}
        </div>
      )}
      <div className="mt-6 grid grid-cols-5 gap-2">
        {(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const).map((s) => (
          <div key={s} className="rounded-md border border-line bg-bg px-3 py-2.5">
            <div className="text-[10.5px] font-semibold tracking-wider text-dim">{s}</div>
            <div className={`mt-1 text-lg font-bold tabular-nums ${s === "CRITICAL" && snap.counts.severity[s] ? "text-crit" : s === "HIGH" && snap.counts.severity[s] ? "text-high" : ""}`}>{snap.counts.severity[s] ?? 0}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

function DevicePanel({ snap, online, busy, onReissue }: { snap: SnapshotView; online: boolean; busy: boolean; onReissue: () => void }) {
  const d = snap.device;
  const recoverable = !online && (snap.status === "CONNECTED" || snap.status === "SCANNING");
  return (
    <div className="card p-5">
      <div className="flex items-center gap-2 text-sm font-semibold"><IconMonitor size={15} className="text-accent-2" /> Desktop application</div>
      {d ? (
        <dl className="mt-4 space-y-2 text-[13px]">
          <Row k="Connection" v={<span className={online ? "text-ok" : "text-med"}>{online ? "Online" : `Offline · last seen ${fmtRelative(d.lastHeartbeatAt)}`}</span>} />
          <Row k="App version" v={<span className="font-mono">{d.appVersion}</span>} />
          <Row k="Windows" v={d.osVersion ?? "—"} />
          <Row k="Administrator" v={d.elevated ? "Yes" : "No — not required"} />
          <Row k="Connected" v={fmtDate(d.connectedAt)} />
          <Row k="Consent" v={snap.consentedAt ? fmtDate(snap.consentedAt) : "Pending"} />
        </dl>
      ) : <p className="mt-3 text-[13px] text-muted">No device connected.</p>}
      {recoverable && (
        <button className="btn btn-secondary btn-sm mt-4 w-full" disabled={busy} onClick={() => confirmThen("Revoke the disconnected desktop and issue a new PIN? Partial results will be replaced by a new scan.", onReissue)}>
          Issue new PIN for reconnection
        </button>
      )}
    </div>
  );
}

function Row({ k, v }: { k: string; v: React.ReactNode }) {
  return <div className="flex justify-between gap-3"><dt className="text-dim">{k}</dt><dd className="text-right text-ink-2">{v}</dd></div>;
}

function ActivityFeed({ feed }: { feed: { at: string; text: string }[] }) {
  return (
    <div className="card p-5">
      <div className="text-sm font-semibold">Live activity</div>
      <div className="mt-3 max-h-64 space-y-2 overflow-y-auto">
        {feed.length === 0 ? <p className="text-[12.5px] text-dim">Updates appear here as they happen.</p> : feed.map((f, i) => (
          <div key={i} className="fade-up flex gap-2 text-[12.5px]"><span className="shrink-0 font-mono text-dim">{new Date(f.at).toLocaleTimeString()}</span><span className="text-ink-2">{f.text}</span></div>
        ))}
      </div>
    </div>
  );
}
