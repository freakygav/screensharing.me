import Link from "next/link";
import { db } from "@/lib/db";

export const metadata = { title: "Features" };
export const dynamic = "force-dynamic";

const MODULES = [
  ["Instance identification", "Finds running Minecraft processes and determines each one's instance from the process itself: main class, --gameDir, working directory, launcher brand, parent process and class path. Supports the official launcher, Prism, MultiMC, PolyMC, Modrinth App, CurseForge, ATLauncher, GDLauncher, Lunar, Badlion and Feather. If the instance cannot be identified with confidence the scan does not start."],
  ["Launch configuration", "Java agents in the launch arguments and JVM option variables in the game process's own environment (JAVA_TOOL_OPTIONS and friends). Launcher agents are allowlisted by their class content."],
  ["Mod archives", "Every archive in the mods folder and elsewhere in the instance: metadata, class packages, string constants of every class, nested Jar-in-Jar archives, embedded executables, encrypted classes, impersonated mod ids, disguised names and Java-agent manifests. Optional Modrinth hash verification identifies published mods."],
  ["Game files & class path", "The client jar and libraries the running game loads are verified against the SHA-1 hashes in the launcher's version manifest; anything unverifiable is analysed like a mod."],
  ["Configuration, scripts & executables", "Client data folders left in the instance (meteor-client/, wurst/, LiquidBounce/…), string signatures in configs and scripts, and every executable stored in the instance, recognised by content rather than extension."],
  ["Resource & shader packs", "X-ray detection from pack content — transparent terrain textures and hollow or empty block models resolved through blockstates and parent models — plus pack-name signatures."],
  ["Logs & crash reports", "Mod lists of previous sessions, mods removed since, and client class names in stack traces. Chat lines are excluded so what players type never matches."],
  ["Game process & memory", "Native modules loaded into the selected game process (Authenticode-verified) and a bounded read-only memory scan for client class paths and distinctive cheat-module names."],
];

export default async function Features() {
  const families = await db.detectionRule.findMany({
    where: { enabled: true, family: { not: null }, OR: [{ classification: null }, { classification: { not: "indicator" } }], kind: { notIn: ["KNOWN_MOD", "FEATURE_NAME", "MODULE_PACKAGE", "LIBRARY_PACKAGE"] } },
    distinct: ["family"],
    select: { family: true, category: true, features: true },
    orderBy: { family: "asc" },
  });
  return (
    <div className="mx-auto max-w-6xl px-5 py-16">
      <h1 className="text-[32px] font-bold tracking-tight">What the scanner examines</h1>
      <p className="mt-3 max-w-2xl text-muted">Everything below runs against the one Minecraft instance the player selected — never the rest of the computer. Every stage is read-only and reports what it examined, what it skipped and why.</p>
      <div className="card mt-8 divide-y divide-line">
        {MODULES.map(([t, d], i) => (
          <div key={t} className="grid gap-1 px-5 py-4 sm:grid-cols-[48px_240px_1fr]">
            <div className="mono text-[11px] text-dim">{String(i + 1).padStart(2, "0")}</div>
            <div className="text-[14px] font-semibold">{t}</div>
            <p className="text-[13px] leading-relaxed text-muted">{d}</p>
          </div>
        ))}
      </div>
      <h2 className="mt-14 text-[22px] font-semibold tracking-tight">Identified clients and tools in the current catalog</h2>
      <p className="mt-2 text-sm text-muted">Live from the detection catalog. Each family uses identifiers verified against its public source code.</p>
      <div className="card mt-6 overflow-hidden">
        <table className="table">
          <thead><tr><th>Family</th><th>Category</th><th>Known capabilities</th></tr></thead>
          <tbody>
            {families.map((f) => (
              <tr key={f.family ?? ""}><td className="font-semibold text-ink">{f.family}</td><td>{f.category}</td><td className="text-muted">{f.features.join(", ")}</td></tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="mt-6 text-sm text-muted">Closed-source &ldquo;ghost&rdquo; clients do not publish identifiers; they are covered by community-sourced strings and by heuristics (structure, encryption, injection indicators, agents, unsigned modules, memory) with lower evidence tiers. <Link href="/docs#limitations" className="text-accent-2 hover:underline">See limitations</Link>.</p>
    </div>
  );
}
