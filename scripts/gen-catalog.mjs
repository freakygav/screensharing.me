// Generates DETECTION_CATALOG.md from packages/detection-rules/rules.json so the
// documentation can never drift from the rules the scanner actually ships with.
//   node scripts/gen-catalog.mjs
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const { version, rules } = JSON.parse(fs.readFileSync(path.join(root, "packages/detection-rules/rules.json"), "utf8"));

// Verification status per rule/heuristic — kept honest and updated together with the tests.
// F = synthetic fixture test (apps/desktop/tests), L = observed on a real machine during live testing,
// P = artifact parser tested but the full rule path needs administrator rights / a matching artifact, N = not yet exercised.
const status = {
  MOD_ID: "F (Meteor, Wurst, BleachHack, Freecam, Baritone) · L (Meteor, Wurst, Meteor Rejects, Freecam)",
  PACKAGE_PREFIX: "F (Meteor, Wurst, LiquidBounce nested, BleachHack, Baritone) · L",
  MEMORY_STRING: "P (memory reader + matcher tested on a live process; no cheat-loaded JVM was available)",
  MOD_ID_REGEX: "L (matched a real mod named xray_snitch — see false-positive note)",
  RESOURCEPACK_REGEX: "F · L",
  KNOWN_MOD: "F (classification) · L",
  EXECUTABLE_REGEX: "P (Prefetch parser incl. MAM decompression tested; BAM/Prefetch need administrator)",
  FILE_NAME_REGEX: "L (merged into content-based findings for named cheat jars)",
  SHA256: "Code path present; no hash rules shipped (none could be verified)",
};
const builtinStatus = {
  "SSME-H-MODULE_CLASSES": "F · L", "SSME-H-JAVA_AGENT_MANIFEST": "F · L (FP fixed: library agents allowlisted)",
  "SSME-H-OBFUSCATED_ARCHIVE": "F", "SSME-H-DISGUISED_ARCHIVE": "F · L (FP fixed: prefix rule + Modrinth exclusion)",
  "SSME-H-NON_JAR_ARCHIVE": "F", "SSME-H-DUPLICATE_MOD_ID": "F · L", "SSME-H-UNRECOGNIZED_MOD": "F · L",
  "SSME-H-CLIENT_JAR_MODIFIED": "F", "SSME-H-LIBRARY_MODIFIED": "Shares the verified hashing path; no dedicated fixture",
  "SSME-H-LOGGED_MOD_MISSING": "F · L", "SSME-H-LOGGED_CHEAT_MOD": "F", "SSME-H-JAVAAGENT_ARGUMENT": "L (Modrinth App agent correctly allowlisted by content)",
  "SSME-H-JAVA_OPTIONS_ENV": "N", "SSME-H-UNSIGNED_MODULE": "L (FP fixed: known library natives allowlisted)",
  "SSME-H-PREFETCH_JAR_MISSING": "P", "SSME-H-MEMORY_FEATURE_CLUSTER": "P", "SSME-H-EVENT_LOG_CLEARED": "N (query runs; no clear event present)",
  "SSME-H-TIME_CHANGED": "N (query runs; no qualifying event present)", "SSME-H-SERVICE_DISABLED": "N (check runs; services enabled)",
  "SSME-H-PREFETCH_DISABLED": "N (check runs; Prefetch enabled)", "SSME-H-RECYCLED_ARCHIVE": "P ($I parser tested)",
  "SSME-H-USN_ARCHIVE_DELETED": "P (requires administrator; not exercised in automated tests)", "SSME-H-MOD_CHANGED_AFTER_SESSION": "F",
};

const esc = (s) => String(s ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");
const tierLabel = { CONFIRMED_ARTIFACT: "Confirmed artifact", STRONG_INDICATOR: "Strong indicator", SUSPICIOUS_CONFIGURATION: "Suspicious configuration", WEAK_INDICATOR: "Weak indicator", INCONCLUSIVE: "Inconclusive" };

let md = `# Detection catalog

> Generated from \`packages/detection-rules/rules.json\` (ruleset **${version}**, ${rules.length} rules) by \`scripts/gen-catalog.mjs\`.
> Administrators can enable/disable and edit rules at runtime (Admin → Detection catalog); the live catalog is
> delivered to each scan. This file documents the shipped baseline.

## How to read a finding

Every finding carries **two independent scales**:

* **Evidence tier** — how strong the evidence is:
  1. **Confirmed artifact match** — an artifact matched an identifier verified against a client's *public source code* (its declared mod id and/or compiled package). It confirms *what the file is*, not who used it, when, or where.
  2. **Strong forensic indicator** — evidence that is hard to explain innocently (game jar modified vs. Mojang's hash, cheat classes in game memory, cheat mod in a game log, cheat module class layout).
  3. **Suspicious configuration** — settings/files commonly associated with cheating or concealment that also have legitimate uses.
  4. **Weak indicator** — a lead; never actionable alone.
  5. **Inconclusive** — listed for completeness (e.g. an unrecognised mod).
* **Severity** — how serious the matched behaviour would be under typical server rules (CRITICAL … INFO).

No rule uses a file name alone above *Suspicious configuration*, and no verdict ever states that a person cheated.

**Verification legend:** F = covered by a synthetic-fixture automated test · L = observed on a real Windows machine (2,268 real mods across 36 installations) during development · P = parser/reader tested, end-to-end path needs administrator rights or a matching artifact · N = implemented, not yet exercised by a matching artifact.

## Observability per cheat category

What local, read-only forensics can and cannot see. "Feature" detections (KillAura, Reach…) are only ever established *through the client that provides them*; there is no file-level signature for a behaviour.

| Category | Cheat | Realistic local indicators | Not observable locally |
|---|---|---|---|
| Combat | KillAura, AimAssist, TriggerBot, Criticals, Velocity, Reach, Hitboxes | Client jar identified by mod id/package (Meteor, Wurst, LiquidBounce, BleachHack…); cheat module class layout in unknown jars; client classes in game memory; client listed in game logs; Java agent / injected unsigned DLL in javaw.exe | Whether a module was *enabled*, its settings, or that it was used on a given server (server-side anticheat territory) |
| Combat | AutoClicker | Auto-clicker executables in Prefetch/BAM (admin); JNativeHook DLL in temp; AutoHotkey runs | Hardware/mouse-driver macros (Razer/Logitech) unless their software is examined manually; click timing |
| Movement | Fly, Speed, NoFall, Jesus, LongJump, Timer, Sprint | Only via the client that implements them (same as combat) | Use of the feature |
| Utility | X-ray | X-ray mods (name/metadata), X-ray resource packs, X-ray modules inside identified clients | Whether the pack/mod was active; ore-obfuscation bypass |
| Utility | ChestESP, PlayerESP, Freecam | Freecam mod (confirmed by mod id); ESP via identified clients; Tweakeroo (freecam feature) | Use of the feature |
| Utility | Inventory automation, Baritone, automated mining | Baritone (mod id + package, also when bundled), Item Scroller, Inventory Profiles Next (classified) | Which server it was used on |
| Client modification | Injected modifications, Java agents | -javaagent in launcher profiles and running command lines; JAVA_TOOL_OPTIONS; agent manifests in jars; unsigned natives loaded from user-writable folders | Fully fileless injection that leaves no module, agent or log trace |
| Client modification | Modified game libraries | SHA-1 mismatch of client jar / libraries vs. version manifest | Clients that ship their own (non-Mojang) version manifests |
| Concealment | Deleting/renaming clients | Game logs vs. disk; Recycle Bin \`$I\` records and recoverable \`$R\` copies (analysed like any jar); USN journal deletes/renames (admin); Prefetch jar references (admin) | Secure deletion after journal rollover; activity on another PC/VM |
| Concealment | Anti-forensics | Cleared event logs, large clock changes, disabled SysMain/EventLog/BAM/PcaSvc/DPS, Prefetch disabled | Intent behind the change |

## Rules
`;

const groups = [
  ["Cheat-client signatures", (r) => r.id.startsWith("SSME-CL-")],
  ["Utility / automation modifications", (r) => r.id.startsWith("SSME-UT-")],
  ["Execution-artifact rules (Prefetch, BAM, processes)", (r) => r.kind === "EXECUTABLE_REGEX"],
  ["File-name rules", (r) => r.kind === "FILE_NAME_REGEX"],
];
for (const [title, pred] of groups) {
  md += `\n### ${title}\n\n| ID | Name | Kind | Pattern | Tier | Severity | Conf. | Verification |\n|---|---|---|---|---|---|---|---|\n`;
  for (const r of rules.filter(pred))
    md += `| \`${r.id}\` | ${esc(r.name)} | ${r.kind} | \`${esc(r.pattern)}\` | ${tierLabel[r.tier]} | ${r.severity} | ${r.confidence} | ${status[r.kind] ?? ""} |\n`;
  md += "\n<details><summary>False positives &amp; limitations</summary>\n\n";
  for (const r of rules.filter(pred)) md += `* **${r.id}** — *False positives:* ${esc(r.falsePositives)} *Limitations:* ${esc(r.limitations)}${r.references?.length ? ` *Source:* ${r.references.map((u) => `<${u}>`).join(", ")}` : ""}\n`;
  md += "\n</details>\n";
}

md += `\n### Built-in heuristics (scanner engine)\n\nImplemented in \`apps/desktop/src/Screensharing.Scanner/Modules\`. Administrators can disable them or change their severity/tier in the catalog.\n\n| ID | Name | Tier | Severity | Conf. | What it examines | False-positive risk | Verification |\n|---|---|---|---|---|---|---|---|\n`;
for (const r of rules.filter((x) => x.kind === "BUILTIN"))
  md += `| \`${r.id}\` | ${esc(r.name)} | ${tierLabel[r.tier]} | ${r.severity} | ${r.confidence} | ${esc(r.description)} | ${esc(r.falsePositives)} | ${builtinStatus[r.id] ?? ""} |\n`;

md += `\n### Known-mod classifications\n\nThese are **not findings**. They classify mods in the inventory (performance, cosmetic, accessibility, gameplay, utility, library). Unknown mods that are not in this list are verified against the public Modrinth registry by SHA-512 (optional, on by default) before being listed as *Inconclusive — unrecognised*.\n\n| Mod id | Name | Classification |\n|---|---|---|\n`;
for (const r of rules.filter((x) => x.kind === "KNOWN_MOD")) md += `| \`${r.pattern}\` | ${esc(r.name)} | ${r.classification} |\n`;

md += `\n## Researched but intentionally not shipped\n\n* **Closed-source / paid "ghost" clients** (e.g. Vape, Doomsday, Novoware, Drip, Slinky, Whiteout): their internal identifiers are private and change per build. The public tools that target them (e.g. MeowDoomsdayFucker) keep their memory signatures private. Shipping guessed signatures would produce false claims, so these clients are covered only by the structural, injection, agent, deletion and memory heuristics above, and by a file-name rule capped at *Suspicious configuration*.\n* **Aristois, Impact, RusherHack, Future, ThunderHack identifiers**: not verified against source during this build; not added as confirmed rules. Administrators can add them after verification.\n* **SHA-256 fingerprints of specific cheat releases**: the rule kind is supported, but no hashes are shipped because none were obtained from a trustworthy source.\n`;

fs.writeFileSync(path.join(root, "DETECTION_CATALOG.md"), md);
console.log(`DETECTION_CATALOG.md written (${rules.length} rules)`);
