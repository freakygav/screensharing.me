import Link from "next/link";
import { db } from "@/lib/db";

export const metadata = { title: "Features" };
export const dynamic = "force-dynamic";

const MODULES = [
  ["Minecraft installations", "Discovers the official launcher, Prism, MultiMC, CurseForge, Modrinth App, ATLauncher, GDLauncher, TLauncher, Lunar, Badlion and Feather data folders, and identifies Fabric, Quilt, Forge, NeoForge and OptiFine versions."],
  ["Mod archive analysis", "Opens every mod archive (including nested Jar-in-Jar archives): fabric/quilt/forge/neoforge metadata, compiled package structure, class names, Java-agent manifests, obfuscation ratios and disguised filenames. Optional Modrinth hash verification identifies published mods."],
  ["Game file integrity", "Verifies each installed client jar and its libraries against the SHA-1 hashes Mojang publishes in the version manifest."],
  ["Game logs", "Reads latest.log and archived logs to recover the mod list of previous sessions and flags mods that were loaded but have since been removed."],
  ["JVM & launch configuration", "Inspects launcher profiles and JAVA_TOOL_OPTIONS/_JAVA_OPTIONS for injected Java agents."],
  ["Processes & memory", "Examines running Java game processes: command line, loaded native modules with Authenticode verification, and bounded memory scanning for known client class paths."],
  ["Execution artifacts", "Parses Windows Prefetch (including Win10/11 compressed files) and BAM records for auto-clickers, injectors and Java archives opened by the game."],
  ["Deleted evidence", "Reads the user's Recycle Bin index and the NTFS USN change journal for recently deleted or renamed archives and executables."],
  ["Anti-forensics", "Detects cleared event logs, large system clock changes, disabled forensic services and disabled Prefetch."],
];

export default async function Features() {
  const families = await db.detectionRule.findMany({
    where: { enabled: true, kind: { in: ["MOD_ID", "PACKAGE_PREFIX"] } },
    distinct: ["family"],
    select: { family: true, category: true, features: true },
    orderBy: { family: "asc" },
  });
  return (
    <div className="mx-auto max-w-6xl px-5 py-16">
      <h1 className="text-4xl font-extrabold tracking-tight">What the scanner examines</h1>
      <p className="mt-3 max-w-2xl text-muted">Nine collection modules run on the player&apos;s machine after explicit consent. Every module is read-only and reports its own coverage.</p>
      <div className="mt-10 grid gap-3 sm:grid-cols-3">
        {MODULES.map(([t, d], i) => (
          <div key={t} className="card p-5">
            <div className="font-mono text-[11px] text-accent-2">MODULE {String(i + 1).padStart(2, "0")}</div>
            <div className="mt-2 font-semibold">{t}</div>
            <p className="mt-2 text-[13px] leading-relaxed text-muted">{d}</p>
          </div>
        ))}
      </div>
      <h2 className="mt-16 text-2xl font-bold tracking-tight">Signature families in the current catalog</h2>
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
      <p className="mt-6 text-sm text-muted">Closed-source &ldquo;ghost&rdquo; clients do not publish identifiers; they are covered by heuristics (injection, agents, unsigned modules, deleted archives, memory) with lower evidence tiers. <Link href="/docs#limitations" className="text-accent-2 hover:underline">See limitations</Link>.</p>
    </div>
  );
}
