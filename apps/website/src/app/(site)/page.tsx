import Link from "next/link";
import { db } from "@/lib/db";
import { IconDownload } from "@/components/icons";
import { getCurrentUser } from "@/lib/auth/session";
import { getRulesetVersion } from "@/lib/config";

export const dynamic = "force-dynamic";

async function facts() {
  // Real numbers from this deployment's catalog — never marketing placeholders.
  const [signatures, families, latest] = await Promise.all([
    db.detectionRule.count({ where: { enabled: true, kind: { notIn: ["KNOWN_MOD", "FEATURE_NAME", "MODULE_PACKAGE", "LIBRARY_PACKAGE"] } } }),
    db.detectionRule.findMany({ where: { enabled: true, family: { not: null }, OR: [{ classification: null }, { classification: { not: "indicator" } }], kind: { notIn: ["KNOWN_MOD", "FEATURE_NAME", "MODULE_PACKAGE", "LIBRARY_PACKAGE"] } }, distinct: ["family"], select: { family: true } }),
    db.applicationVersion.findFirst({ where: { active: true, channel: "stable" }, orderBy: { releasedAt: "desc" } }),
  ]);
  return { signatures, families: families.length, version: latest?.version ?? "—" };
}

const SCOPE_IN = [
  ["Running game process", "Launch arguments, Java agents, loaded native modules, bounded memory read"],
  ["Mods folder", "Every archive: metadata, class constant pools, nested jars, embedded executables"],
  ["Game files", "Client jar and libraries on the class path, verified against the launcher's hashes"],
  ["Configs, packs, logs", "Instance configuration, resource and shader packs, game logs and crash reports"],
];
const SCOPE_OUT = ["Other Minecraft instances", "Documents, downloads, desktop", "Browsers, Discord, passwords, tokens", "Windows records (Prefetch, registry, event logs)"];

const OUTCOMES = [
  ["Confirmed", "A verified signature of a known cheat or prohibited mod matched.", "bg-crit"],
  ["High confidence", "Strong evidence (artifacts, structure, concealment) without a verified signature.", "bg-high"],
  ["Low confidence", "Weak or policy-dependent indicators that need corroboration.", "bg-med"],
  ["Unable to inspect", "A relevant file could not be read completely — listed, never ignored.", "bg-low"],
  ["No evidence", "Nothing matched. Stated as such — never as proof that a player is clean.", "bg-ok"],
];

const ENGINE = [
  ["Signature database", "Mod ids, class packages, string signatures in class constant pools, instance artifacts and hashes, organised in categorised files."],
  ["Structure analysis", "Cheat-module class layouts, obfuscation, encrypted class files and executables hidden inside archives."],
  ["Evasion awareness", "Renamed clients, impersonated mod ids, disguised file types, polyglot archives, redirected folders and anti-unzip archives."],
  ["Corroboration", "Indicators are weighted per suspected client; generic indicators only count in combination and never confirm on their own."],
];

export default async function Home() {
  const [f, user, ruleset] = await Promise.all([facts(), getCurrentUser(), getRulesetVersion()]);
  return (
    <div>
      <section className="mx-auto grid max-w-6xl gap-10 px-5 pb-14 pt-16 lg:grid-cols-[1.1fr_1fr] lg:pt-24">
        <div>
          <div className="eyebrow">Minecraft forensic screensharing</div>
          <h1 className="mt-3 text-[36px] font-bold leading-[1.1] tracking-[-0.02em] sm:text-[44px]">
            Investigate the instance the player is actually running.
          </h1>
          <p className="mt-4 max-w-xl text-[15px] leading-relaxed text-muted">
            The player enters a PIN, picks their running Minecraft instance and consents. screensharing.me examines that instance —
            and only that instance — and streams identified cheats, evidence and its own blind spots to your dashboard.
          </p>
          <div className="mt-7 flex flex-wrap gap-2.5">
            <Link href={user ? "/dashboard/investigations/new" : "/register"} className="btn btn-primary h-10 px-4">Start an investigation</Link>
            <Link href="/download" className="btn btn-secondary h-10 px-4"><IconDownload /> Download the scanner</Link>
          </div>
          <div className="mt-6 text-[12.5px] text-dim">
            Scanner {f.version} · ruleset {ruleset} · {f.signatures} detection signatures across {f.families} identified clients and tools
          </div>
        </div>

        <div className="card overflow-hidden">
          <div className="flex items-center justify-between border-b border-line px-5 py-3">
            <div className="text-[13px] font-semibold">Scope of a scan</div>
            <span className="chip">Read-only</span>
          </div>
          <ul className="divide-y divide-line">
            {SCOPE_IN.map(([t, d]) => (
              <li key={t} className="flex gap-3 px-5 py-3">
                <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-accent" />
                <div><div className="text-[13px] font-medium">{t}</div><div className="mt-0.5 text-[12.5px] text-muted">{d}</div></div>
              </li>
            ))}
          </ul>
          <div className="border-t border-line bg-bg-raised px-5 py-3">
            <div className="eyebrow">Never read</div>
            <div className="mt-2 flex flex-wrap gap-1.5">{SCOPE_OUT.map((s) => <span key={s} className="chip">{s}</span>)}</div>
          </div>
        </div>
      </section>

      <section className="border-y border-line bg-bg-raised">
        <div className="mx-auto max-w-6xl px-5 py-12">
          <div className="eyebrow">Detection engine</div>
          <div className="mt-5 grid gap-x-10 gap-y-6 sm:grid-cols-2 lg:grid-cols-4">
            {ENGINE.map(([t, d]) => (
              <div key={t}><div className="text-[14px] font-semibold">{t}</div><p className="mt-1.5 text-[13px] leading-relaxed text-muted">{d}</p></div>
            ))}
          </div>
        </div>
      </section>

      <section className="mx-auto max-w-6xl px-5 py-14">
        <div className="grid gap-10 lg:grid-cols-[1fr_1.3fr]">
          <div>
            <div className="eyebrow">Findings you can act on</div>
            <h2 className="mt-3 text-[24px] font-semibold tracking-tight">Every finding names the suspect, the file and the signature.</h2>
            <p className="mt-3 text-[14px] leading-relaxed text-muted">
              Each detection lists the suspected client, its location inside the instance, the matching signature, SHA-256 evidence,
              confidence and severity — and whether it is confirmed or needs manual review. Legitimate mods are identified, not flagged.
            </p>
            <Link href="/docs#limitations" className="mt-4 inline-block text-[13px] text-accent-2 hover:underline">Read the limitations</Link>
          </div>
          <div className="card divide-y divide-line">
            {OUTCOMES.map(([t, d, c]) => (
              <div key={t} className="flex gap-3 px-5 py-3.5">
                <span className={`mt-1.5 h-2 w-2 shrink-0 rounded-sm ${c}`} />
                <div><div className="text-[13px] font-semibold">{t}</div><div className="mt-0.5 text-[12.5px] text-muted">{d}</div></div>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="mx-auto max-w-6xl px-5 pb-20">
        <div className="card grid divide-y divide-line sm:grid-cols-4 sm:divide-x sm:divide-y-0">
          {[
            ["01", "Create", "Create an investigation. You receive a one-time PIN valid for 15 minutes."],
            ["02", "Connect", "The player opens screensharing.me.exe with Minecraft running and enters the PIN."],
            ["03", "Select & consent", "The scanner shows the running instance it identified; the player confirms it and consents."],
            ["04", "Review", "Findings arrive live. Export the report as PDF, JSON or CSV."],
          ].map(([n, t, d]) => (
            <div key={n} className="p-5">
              <div className="mono text-[11px] text-dim">{n}</div>
              <div className="mt-1.5 text-[14px] font-semibold">{t}</div>
              <p className="mt-1 text-[12.5px] leading-relaxed text-muted">{d}</p>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
