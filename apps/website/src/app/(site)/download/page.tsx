import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { db } from "@/lib/db";
import { IconDownload, IconMonitor } from "@/components/icons";
import { fmtBytes } from "@/lib/format";

export const metadata = { title: "Download" };
export const dynamic = "force-dynamic";

const EXE = path.join(process.cwd(), "public", "download", "screensharing.me.exe");
let cache: { mtime: number; sha: string; size: number } | null = null;

function exeInfo() {
  try {
    const st = fs.statSync(EXE);
    if (!cache || cache.mtime !== st.mtimeMs) {
      cache = { mtime: st.mtimeMs, size: st.size, sha: createHash("sha256").update(fs.readFileSync(EXE)).digest("hex") };
    }
    return cache;
  } catch {
    return null;
  }
}

export default async function Download() {
  const info = exeInfo();
  const latest = await db.applicationVersion.findFirst({ where: { active: true, channel: "stable" }, orderBy: { releasedAt: "desc" } });
  return (
    <div className="relative">
      <div className="glow-top pointer-events-none absolute inset-x-0 top-0 h-80" />
      <div className="relative mx-auto max-w-3xl px-5 py-20 text-center">
        <div className="mx-auto mb-6 inline-flex h-12 w-12 items-center justify-center rounded-xl border border-[rgba(124,92,255,.3)] bg-[rgba(124,92,255,.12)] text-accent-2"><IconMonitor size={22} /></div>
        <h1 className="text-4xl font-extrabold tracking-tight">Download screensharing.me</h1>
        <p className="mx-auto mt-3 max-w-lg text-muted">For Windows 10 and 11 (x64). Self-contained — no .NET installation required. Run it when an investigator gives you a PIN.</p>
        {info ? (
          <>
            <a href="/download/screensharing.me.exe" download className="btn btn-primary mt-8 h-11 px-6"><IconDownload /> Download v{latest?.version ?? "1.0.0"} · {fmtBytes(info.size)}</a>
            <div className="card-flat mx-auto mt-6 max-w-xl p-4 text-left">
              <div className="text-xs font-semibold uppercase tracking-wider text-dim">SHA-256</div>
              <div className="mt-1 break-all font-mono text-[12.5px] text-ink-2">{info.sha}</div>
              <div className="mt-3 text-xs text-dim">Verify with: <span className="font-mono">Get-FileHash .\screensharing.me.exe</span></div>
            </div>
          </>
        ) : (
          <div className="card-flat mx-auto mt-8 max-w-md p-5 text-sm text-muted">
            The executable has not been published to this server yet. Build it with <span className="font-mono text-ink-2">scripts/build-desktop.ps1</span>.
          </div>
        )}
        <div className="mx-auto mt-14 grid max-w-2xl gap-3 text-left sm:grid-cols-3">
          {[
            ["Read-only", "Never modifies your files or Minecraft installation."],
            ["Consent first", "Nothing is collected until you approve the listed sources."],
            ["Run as admin (optional)", "Administrator rights unlock Prefetch, BAM and the change journal. Without them those checks are reported as skipped."],
          ].map(([t, d]) => (
            <div key={t} className="card p-4"><div className="text-sm font-semibold">{t}</div><p className="mt-1.5 text-[12.5px] leading-relaxed text-muted">{d}</p></div>
          ))}
        </div>
      </div>
    </div>
  );
}
