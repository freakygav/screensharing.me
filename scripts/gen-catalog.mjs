// Generates DETECTION_CATALOG.md from packages/detection-rules/rules.json so the
// documentation can never drift from the rules the scanner actually ships with.
//   node scripts/gen-catalog.mjs
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const { version, rules } = JSON.parse(fs.readFileSync(path.join(root, "packages/detection-rules/rules.json"), "utf8"));

// Verification status — kept honest and updated together with the tests.
// F = synthetic fixture test (apps/desktop/tests), L = observed while scanning a real running instance,
// P = reader/matcher tested, no matching real artifact available, N = implemented, not yet exercised.
const kindStatus = {
  MOD_ID: "F (Meteor, Wurst, LiquidBounce, Freecam)",
  PACKAGE_PREFIX: "F (Meteor, Wurst, LiquidBounce nested)",
  MEMORY_STRING: "P (memory reader tested on a live process; no cheat-loaded JVM available)",
  STRING: "F (mixin configs, log stack traces, injection APIs, community strings)",
  INSTANCE_PATH_REGEX: "F (meteor-client/, wurst/)",
  MOD_ID_REGEX: "N",
  RESOURCEPACK_REGEX: "F · L (real X-ray pack)",
  SHADERPACK_REGEX: "F",
  EXECUTABLE_REGEX: "N",
  FILE_NAME_REGEX: "F (supporting evidence only)",
  SHA256: "Code path present; no hash rules shipped (none could be verified)",
};
const builtinStatus = {
  "SSME-H-MODULE_CLASSES": "F", "SSME-H-JAVA_AGENT_MANIFEST": "F", "SSME-H-OBFUSCATED_ARCHIVE": "F", "SSME-H-DISGUISED_ARCHIVE": "F",
  "SSME-H-NON_JAR_ARCHIVE": "F", "SSME-H-DUPLICATE_MOD_ID": "F", "SSME-H-UNRECOGNIZED_MOD": "F · L", "SSME-H-CLIENT_JAR_MODIFIED": "F",
  "SSME-H-LIBRARY_MODIFIED": "Shares the verified hashing path (76 real class-path jars verified on the live instance)",
  "SSME-H-LOGGED_MOD_MISSING": "F · L", "SSME-H-LOGGED_CHEAT_MOD": "F (log and crash report)", "SSME-H-JAVAAGENT_ARGUMENT": "L (Modrinth App launcher agent correctly allowlisted by content)",
  "SSME-H-JAVA_OPTIONS_ENV": "P (environment block read from a live process in tests)", "SSME-H-UNSIGNED_MODULE": "L (144 real modules examined, none flagged)",
  "SSME-H-MEMORY_FEATURE_CLUSTER": "L (false positive found and fixed: vanilla words removed)", "SSME-H-MOD_CHANGED_AFTER_SESSION": "F",
  "SSME-H-ENCRYPTED_CLASSES": "F", "SSME-H-EMBEDDED_EXECUTABLE": "F", "SSME-H-POLYGLOT_ARCHIVE": "F", "SSME-H-EXECUTABLE_IN_INSTANCE": "F",
  "SSME-H-MOD_IMPERSONATION": "F", "SSME-H-METADATA_INCONSISTENT": "F", "SSME-H-XRAY_TEXTURES": "F · L (real X-ray pack, renamed-pack fixture)",
  "SSME-H-CLASSPATH_UNEXPECTED": "L (Modrinth's temp-folder theseus.jar correctly recognised as the launcher's own)", "SSME-H-LINKED_FOLDER": "F (junctions)",
  "SSME-H-UNINSPECTABLE": "F · L",
};

const SOURCES = {
  "cheat-clients": "Cheat clients — identifiers verified against each client's public source",
  "client-strings": "Cheat client string signatures",
  "instance-artifacts": "Instance artifacts (folders/files clients create in the game directory)",
  "injection-clients": "Injection (ghost) clients — community-sourced strings (weak)",
  "injection-indicators": "Generic injection, automation and obfuscation indicators (combination only)",
  "utility-mods": "Utility and automation modifications",
  "packs": "Resource and shader packs",
  "executables": "Executables and file names",
  "heuristics": "Built-in heuristics",
  "module-names": "Cheat-module names (used by the structural heuristic)",
  "known-mods": "Known legitimate modifications (classification only)",
};

const esc = (s) => String(s ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");
const tierLabel = { CONFIRMED_ARTIFACT: "Confirmed", STRONG_INDICATOR: "Strong", SUSPICIOUS_CONFIGURATION: "Suspicious config", WEAK_INDICATOR: "Weak", INCONCLUSIVE: "—" };
const detectionKinds = (r) => !["KNOWN_MOD", "FEATURE_NAME", "MODULE_PACKAGE", "LIBRARY_PACKAGE"].includes(r.kind);

let md = `# Detection catalog

> Generated from \`packages/detection-rules/rules.json\` (ruleset **${version}**) by \`scripts/gen-catalog.mjs\`.
> **${rules.filter(detectionKinds).length} detection signatures and heuristics**, plus ${rules.filter((r) => !detectionKinds(r)).length} classification entries
> (known mods, cheat-module names, library packages). The source is the categorised databases in
> \`packages/detection-rules/signatures/*.json\`; administrators can enable/disable and edit rules at runtime (Admin → Detection catalog),
> and the live catalog is delivered to each scan. This file documents the shipped baseline.

## Scope

Every rule is evaluated against **one Minecraft instance only** — the one the player selects from the running game processes —
plus the jars that game process loads and the process itself. Nothing else on the computer is read. A clean result therefore means
"no evidence in this instance", never "the player is clean".

## How to read a finding

* **Outcome** — what the investigator should do with it:
  * **Confirmed** — a verified signature of a known cheat or prohibited mod matched (tier *Confirmed*).
  * **High confidence** — strong evidence without a verified signature (tier *Strong*). Manual review.
  * **Low confidence** — weak, policy-dependent or community-sourced evidence (tiers *Suspicious config*, *Weak*). Manual review and corroboration.
  * **Unable to inspect** — a relevant file could not be read completely; listed so nothing is silently skipped.
  * **Informational** — e.g. an unrecognised mod; never an accusation.
* **Severity** — how serious the behaviour would be under typical server rules (CRITICAL … INFO), independent of the evidence strength.
* **Suspected client, location, signature** — every finding names the client or component when it can be identified, where it is inside the instance, and what matched.

### Scoring

Indicators matched for the same file are grouped per suspected family. Each distinct rule contributes its \`weight\` (or a default derived from its tier);
the sum is capped at 100. The finding's tier is the stronger of the best single rule and the score tier (100 with at least two *different kinds* of
content evidence = confirmed, 60 = strong, 30 = weak). Generic \`indicator\` families must reach 30 to be reported and are never confirmed.
File names never raise a tier on their own. Classes of well-known libraries (\`LIBRARY_PACKAGE\`) are exempt from generic indicators.

**Verification legend:** F = synthetic-fixture automated test · L = observed while scanning a real running instance (Modrinth App, Fabric 1.21.11, 83 mods, 53 resource packs) · P = reader/matcher tested, no real matching artifact available · N = implemented, not yet exercised.

## Observability per cheat category

| Category | Cheat | Indicators inside the instance | Not observable |
|---|---|---|---|
| Combat | KillAura, AimAssist, TriggerBot, Criticals, Velocity, Reach | Client jar identified by mod id/package/strings; client data folder; cheat-module class layout in unknown jars; client classes in game memory, logs, crash reports; Java agent or unsigned DLL in the game process | Whether a module was enabled or used on a given server |
| Combat | Auto-clickers | JNativeHook/Robot indicators in archives; auto-clicker executables stored in the instance | Hardware/driver macros and clickers run from outside the instance |
| Movement | Fly, Speed, NoFall, Jesus, LongJump, Timer | Only via the client that implements them | Use of the feature |
| Utility | X-ray | Pack content (transparent textures, hollow/empty block models), pack and shader names, X-ray mods | Shader-only X-ray logic; whether a pack was active at a given time |
| Utility | ESP, Freecam, Baritone | Freecam/Baritone by mod id, package, \`baritone/settings.txt\`; ESP via identified clients | Use of the feature |
| Injection | Agents, injected DLLs, class-path injection | -javaagent arguments, JAVA_TOOL_OPTIONS in the game's environment, unverified class-path jars, unsigned modules, native injector API combinations | Fully fileless injection that leaves no module, agent or string |
| Evasion | Renaming, disguising, encrypting | Content-based identification, impersonated mod ids, disguised file types, polyglot and anti-unzip archives, encrypted classes, redirected folders | Clients whose code and strings are fully encrypted and unknown |
| Game integrity | Modified game jar or libraries | SHA-1 of every class-path jar vs. the launcher's version manifest | Launchers that ship no version manifest |
`;

const order = Object.keys(SOURCES);
for (const src of order) {
  const list = rules.filter((r) => r.source === src);
  if (!list.length) continue;
  md += `\n## ${SOURCES[src]}\n\n`;
  if (src === "known-mods") {
    md += `Not findings. They classify mods in the inventory; \`packages\` enables the impersonation check (SSME-H-MOD_IMPERSONATION).\n\n| Mod id | Name | Classification | Expected packages |\n|---|---|---|---|\n`;
    for (const r of list) md += `| \`${r.pattern}\` | ${esc(r.name)} | ${r.classification ?? ""} | ${(r.packages ?? []).map((p) => `\`${p}\``).join(", ")} |\n`;
    continue;
  }
  if (src === "module-names") {
    const hi = list.filter((r) => r.classification === "high-signal").map((r) => `${r.pattern}${r.scopes?.includes("memory") ? "\\*" : ""}`);
    const amb = list.filter((r) => r.classification === "ambiguous").map((r) => r.pattern);
    const seg = list.filter((r) => r.kind === "MODULE_PACKAGE").map((r) => r.pattern);
    md += `Used by SSME-H-MODULE_CLASSES (3+ distinct feature classes, or 2+ high-signal ones) and SSME-H-MEMORY_FEATURE_CLUSTER (\\* = also searched in memory).\n\n* **High-signal:** ${hi.join(", ")}\n* **Ambiguous (only inside module packages):** ${amb.join(", ")}\n* **Module package segments:** ${seg.join(", ")}\n`;
    continue;
  }
  if (src === "heuristics") {
    md += `Implemented in \`apps/desktop/src/Screensharing.Scanner/Modules\`. Administrators can disable them or change severity/tier.\n\n| ID | Name | Tier | Severity | Conf. | What it examines | False-positive risk | Verification |\n|---|---|---|---|---|---|---|---|\n`;
    for (const r of list) md += `| \`${r.id}\` | ${esc(r.name)} | ${tierLabel[r.tier]} | ${r.severity} | ${r.confidence} | ${esc(r.description)} | ${esc(r.falsePositives)} | ${builtinStatus[r.id] ?? ""} |\n`;
    continue;
  }
  md += `| ID | Name | Kind | Pattern | Scopes | Tier | Severity | Conf. | Weight | Verification |\n|---|---|---|---|---|---|---|---|---|---|\n`;
  for (const r of list.filter((x) => x.kind !== "LIBRARY_PACKAGE"))
    md += `| \`${r.id}\` | ${esc(r.name)} | ${r.kind} | \`${esc(r.pattern)}\` | ${(r.scopes ?? []).join(", ")} | ${tierLabel[r.tier]}${r.classification === "indicator" ? " (indicator)" : ""} | ${r.severity} | ${r.confidence} | ${r.weight || "—"} | ${kindStatus[r.kind] ?? ""} |\n`;
  const libs = list.filter((x) => x.kind === "LIBRARY_PACKAGE");
  if (libs.length) md += `\nLibrary packages exempt from generic indicators: ${libs.map((r) => `\`${r.pattern}\` (${esc(r.name)})`).join(", ")}.\n`;
  md += "\n<details><summary>False positives, limitations and sources</summary>\n\n";
  for (const r of list.filter((x) => x.kind !== "LIBRARY_PACKAGE")) md += `* **${r.id}** — *False positives:* ${esc(r.falsePositives)} *Limitations:* ${esc(r.limitations)}${r.references?.length ? ` *Source:* ${r.references.map((u) => `<${u}>`).join(", ")}` : ""}\n`;
  md += "\n</details>\n";
}

md += `\n## Researched but intentionally not shipped\n\n* **Closed-source / paid clients** (Vape, Doomsday, Novoware, Drip, Slinky, Whiteout…): current internal identifiers are private and change per build. They are covered by the structural, encryption, injection, agent and memory heuristics, by community-sourced strings for old builds (weak), and by a file-name rule capped at *Suspicious configuration*.\n* **Short community strings** from andreaonorato/Minecraft-Cheat-Scanner (\`nG@W\`, \`+(M0G.V\`, \`dinkio\`, \`Sa_Vc\`, \`5d@56\`, \`TCNH$1\`, \`hi.a2\`, \`yCcADi\`, \`kc((k\`): 4–7 characters match by chance in gigabytes of memory, so they were not adopted.\n* **Aristois, Impact, RusherHack, Future, ThunderHack identifiers and data folders**: not verified against source during this build. Administrators can add them after verification — no code change is needed.\n* **SHA-256 fingerprints of specific cheat releases**: the rule kind is supported; no hashes are shipped because none were obtained from a trustworthy source.\n`;

fs.writeFileSync(path.join(root, "DETECTION_CATALOG.md"), md);
console.log(`DETECTION_CATALOG.md written (${rules.length} entries, ${rules.filter(detectionKinds).length} detection rules)`);
