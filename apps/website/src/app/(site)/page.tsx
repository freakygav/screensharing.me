import Link from "next/link";
import { db } from "@/lib/db";
import { IconDownload, IconSearch, IconShield, IconSpark, IconLock, IconFile } from "@/components/icons";
import { getCurrentUser } from "@/lib/auth/session";
import { getRulesetVersion } from "@/lib/config";

export const dynamic = "force-dynamic";

async function stats() {
  // Real numbers from this deployment's database — never marketing placeholders.
  const [scans, rules, latest, avg] = await Promise.all([
    db.scan.count({ where: { status: "COMPLETED" } }),
    db.detectionRule.count({ where: { enabled: true, kind: { not: "KNOWN_MOD" } } }),
    db.applicationVersion.findFirst({ where: { active: true, channel: "stable" }, orderBy: { releasedAt: "desc" } }),
    db.$queryRaw<{ avg: number | null }[]>`SELECT AVG(EXTRACT(EPOCH FROM ("completedAt" - "startedAt")))::float AS avg FROM "Scan" WHERE status = 'COMPLETED'`,
  ]);
  return { scans, rules, version: latest?.version ?? "1.0.0", avgSeconds: avg[0]?.avg ? Math.round(avg[0].avg) : null };
}

export default async function Home() {
  const [s, user, ruleset] = await Promise.all([stats(), getCurrentUser(), getRulesetVersion()]);
  return (
    <div className="relative overflow-hidden">
      <div className="grid-bg pointer-events-none absolute inset-0" />
      <div className="glow-top pointer-events-none absolute inset-x-0 top-0 h-[420px]" />
      <section className="relative mx-auto max-w-6xl px-5 pb-16 pt-20 text-center sm:pt-28">
        <div className="chip mx-auto mb-7 h-7 px-3 text-[12px]">
          <span className="h-1.5 w-1.5 rounded-full bg-ok" />
          Scanner v{s.version} · ruleset {ruleset}
        </div>
        <h1 className="mx-auto max-w-3xl text-[44px] font-extrabold leading-[1.05] tracking-[-0.03em] sm:text-[64px]">
          Screenshares that take <br className="hidden sm:block" />
          <span className="gradient-text">minutes, not hours.</span>
        </h1>
        <p className="mx-auto mt-5 max-w-xl text-[15.5px] leading-relaxed text-muted">
          Create an investigation, hand the player a six-digit PIN, and watch real forensic evidence from their
          Minecraft installation arrive live — tiered, hashed and explained.
        </p>
        <div className="mt-9 flex flex-wrap items-center justify-center gap-3">
          <Link href={user ? "/dashboard/investigations/new" : "/register"} className="btn btn-primary h-11 px-5">
            Start an investigation
          </Link>
          <Link href="/download" className="btn btn-secondary h-11 px-5">
            <IconDownload /> Download the client
          </Link>
        </div>

        <div className="mx-auto mt-16 grid max-w-4xl grid-cols-2 gap-3 sm:grid-cols-4">
          {[
            [s.scans.toLocaleString(), "Scans completed"],
            [String(s.rules), "Active detection rules"],
            [s.avgSeconds ? `~${s.avgSeconds}s` : "—", "Average scan time"],
            ["5", "Evidence tiers"],
          ].map(([v, l]) => (
            <div key={l} className="card px-4 py-5">
              <div className="text-2xl font-bold tracking-tight">{v}</div>
              <div className="mt-1 text-xs text-muted">{l}</div>
            </div>
          ))}
        </div>
      </section>

      <section className="relative mx-auto grid max-w-6xl gap-4 px-5 pb-20 sm:grid-cols-3">
        {[
          { icon: <IconSearch />, t: "Deep Minecraft analysis", d: "Every mod archive is opened: metadata, class packages, agent manifests and obfuscation. Game jars and libraries are verified against Mojang's published hashes." },
          { icon: <IconShield />, t: "Tamper & concealment checks", d: "Prefetch, BAM, the NTFS change journal, the Recycle Bin, cleared event logs, disabled services and clock changes are correlated with game logs." },
          { icon: <IconSpark />, t: "Evidence, not guesses", d: "Each finding carries a tier, confidence, SHA-256 evidence, the exact rule, why it matters and what it does not prove." },
        ].map((f) => (
          <div key={f.t} className="card p-6">
            <div className="mb-4 inline-flex h-9 w-9 items-center justify-center rounded-[10px] border border-[rgba(124,92,255,.3)] bg-[rgba(124,92,255,.12)] text-accent-2">{f.icon}</div>
            <h3 className="text-[15px] font-semibold">{f.t}</h3>
            <p className="mt-2 text-sm leading-relaxed text-muted">{f.d}</p>
          </div>
        ))}
      </section>

      <section className="relative mx-auto max-w-6xl px-5 pb-24">
        <div className="card grid gap-8 p-8 sm:grid-cols-4">
          {[
            ["01", "Create", "Create an investigation in your dashboard. You receive a one-time PIN valid for 15 minutes."],
            ["02", "Connect", "The player opens screensharing.me.exe and enters the PIN. You see them connect instantly."],
            ["03", "Consent & scan", "The player reviews exactly what will be read and authorises the read-only scan."],
            ["04", "Review", "Findings stream into your dashboard live. Export the final report as PDF, JSON or CSV."],
          ].map(([n, t, d]) => (
            <div key={n}>
              <div className="font-mono text-xs text-accent-2">{n}</div>
              <div className="mt-2 font-semibold">{t}</div>
              <p className="mt-1.5 text-[13px] leading-relaxed text-muted">{d}</p>
            </div>
          ))}
        </div>
        <div className="mt-4 grid gap-4 sm:grid-cols-2">
          <div className="card-flat flex gap-4 p-6">
            <IconLock className="mt-0.5 shrink-0 text-accent-2" size={18} />
            <div>
              <div className="text-sm font-semibold">Private by design</div>
              <p className="mt-1 text-[13px] leading-relaxed text-muted">No browser data, passwords, launcher tokens or personal documents are read. Nothing on the player&apos;s machine is modified.</p>
            </div>
          </div>
          <div className="card-flat flex gap-4 p-6">
            <IconFile className="mt-0.5 shrink-0 text-accent-2" size={18} />
            <div>
              <div className="text-sm font-semibold">Honest about limits</div>
              <p className="mt-1 text-[13px] leading-relaxed text-muted">A filename is never treated as proof. Every report lists what was examined, what was skipped and why. <Link href="/docs#limitations" className="text-accent-2 hover:underline">Read the limitations.</Link></p>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}
