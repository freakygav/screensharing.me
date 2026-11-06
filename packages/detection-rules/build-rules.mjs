// Builds the screensharing.me detection catalog from the categorised signature
// databases in ./signatures/*.json.
//
//   node packages/detection-rules/build-rules.mjs
//
// rules.json is (1) embedded in the desktop scanner as the offline fallback
// ruleset and (2) seeded into the DetectionRule table, where administrators can
// manage it. Add or change signatures by editing a file in ./signatures (or add a
// new file): the scanner picks them up without code changes as long as the rule
// uses one of the supported kinds below.
//
// RULES OF THE CATALOG
// - CONFIRMED_ARTIFACT rules use only identifiers verified against public source
//   code (see `references`). Community-sourced strings are WEAK_INDICATOR at most.
// - A file name alone is never more than SUSPICIOUS_CONFIGURATION.
// - Every rule documents false positives and limitations.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
export const VERSION = "2026.11.06.2";

/** Rule kinds understood by the scanner (apps/desktop/src/Screensharing.Scanner/Model/Rules.cs). */
export const KINDS = {
  MOD_ID: "Exact mod id declared in fabric.mod.json / quilt.mod.json / mods.toml / mcmod.info",
  MOD_ID_REGEX: "Regex over declared mod ids and names",
  PACKAGE_PREFIX: "Compiled class package prefix inside an archive (slash separated, trailing slash)",
  STRING: "Literal string signature; `scopes` selects where it is matched",
  MEMORY_STRING: "Literal string searched in the memory of the selected game process",
  SHA256: "SHA-256 of a file",
  INSTANCE_PATH_REGEX: "Regex over paths relative to the instance root (forward slashes)",
  EXECUTABLE_REGEX: "Regex over names of executables found inside the instance",
  FILE_NAME_REGEX: "Regex over file names (supporting evidence only)",
  RESOURCEPACK_REGEX: "Regex over resource pack names",
  SHADERPACK_REGEX: "Regex over shader pack names",
  FEATURE_NAME: "Cheat-module class name (classification high-signal | ambiguous)",
  MODULE_PACKAGE: "Package segment that marks a cheat-module layout (e.g. modules, combat)",
  KNOWN_MOD: "Known modification (classification only); `packages` enables impersonation checks",
  LIBRARY_PACKAGE: "Package of a widely used library whose classes are exempt from generic indicator scoring",
  BUILTIN: "Heuristic implemented in the engine; the pattern is its key",
};
export const SCOPES = ["class", "resource", "config", "log", "script", "binary", "memory"];
const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const TIERS = ["CONFIRMED_ARTIFACT", "STRONG_INDICATOR", "SUSPICIOUS_CONFIGURATION", "WEAK_INDICATOR", "INCONCLUSIVE"];

const files = fs.readdirSync(path.join(here, "signatures")).filter((f) => f.endsWith(".json")).sort();
const rules = [];
const errors = [];
const ids = new Set();

for (const file of files) {
  const db = JSON.parse(fs.readFileSync(path.join(here, "signatures", file), "utf8"));
  for (const raw of db.rules ?? []) {
    const r = {
      family: null, features: [], classification: null, references: [], scopes: [], weight: 0, packages: [],
      ...(db.defaults ?? {}), ...raw,
    };
    const where = `${file}: ${r.id ?? "(no id)"}`;
    if (!/^SSME-[A-Z]{1,4}-[A-Z0-9_]{1,40}$/.test(r.id ?? "")) errors.push(`${where}: invalid id`);
    if (ids.has(r.id)) errors.push(`${where}: duplicate id`);
    ids.add(r.id);
    if (!KINDS[r.kind]) errors.push(`${where}: unknown kind ${r.kind}`);
    for (const f of ["name", "description", "category", "pattern", "falsePositives", "limitations"])
      if (typeof r[f] !== "string" || !r[f].trim()) errors.push(`${where}: missing ${f}`);
    if (!SEVERITIES.includes(r.severity)) errors.push(`${where}: bad severity`);
    if (!TIERS.includes(r.tier)) errors.push(`${where}: bad tier`);
    if (!(r.confidence >= 0 && r.confidence <= 100)) errors.push(`${where}: bad confidence`);
    if (!(r.weight >= 0 && r.weight <= 100)) errors.push(`${where}: bad weight`);
    for (const s of r.scopes) if (!SCOPES.includes(s)) errors.push(`${where}: unknown scope ${s}`);
    if (r.kind === "STRING") {
      if (r.scopes.length === 0) errors.push(`${where}: STRING rules need scopes`);
      if (r.pattern.length < 6) errors.push(`${where}: STRING patterns must be at least 6 characters`);
      if (r.scopes.includes("memory") && r.pattern.length < 8) errors.push(`${where}: memory patterns must be at least 8 characters`);
      if (r.tier === "CONFIRMED_ARTIFACT" && !r.references.length) errors.push(`${where}: confirmed STRING rules need a reference`);
    }
    if ((r.kind === "PACKAGE_PREFIX" || r.kind === "LIBRARY_PACKAGE") && !/^[a-z0-9_$]+(\/[A-Za-z0-9_$]+)*\/$/.test(r.pattern)) errors.push(`${where}: bad package prefix`);
    if (r.kind === "MEMORY_STRING" && r.pattern.length < 8) errors.push(`${where}: memory strings must be at least 8 characters`);
    if (r.kind.endsWith("_REGEX")) {
      try { new RegExp(r.pattern.replace(/^\(\?i\)/, ""), "i"); } catch (e) { errors.push(`${where}: regex does not compile: ${e.message}`); }
    }
    if (r.kind === "FILE_NAME_REGEX" && r.tier === "CONFIRMED_ARTIFACT") errors.push(`${where}: file names cannot confirm`);
    for (const p of r.packages) if (!/^[a-z0-9_$]+(\/[A-Za-z0-9_$]+)*\/$/.test(p)) errors.push(`${where}: bad package ${p}`);
    if (r.kind === "FEATURE_NAME" && !["high-signal", "ambiguous"].includes(r.classification)) errors.push(`${where}: FEATURE_NAME needs classification high-signal|ambiguous`);
    rules.push({
      id: r.id, name: r.name, description: r.description, category: r.category, kind: r.kind, pattern: r.pattern,
      family: r.family, features: r.features, severity: r.severity, tier: r.tier, confidence: r.confidence,
      classification: r.classification, falsePositives: r.falsePositives, limitations: r.limitations, references: r.references,
      scopes: r.scopes, weight: r.weight, packages: r.packages, source: file.replace(/\.json$/, ""),
    });
  }
}

if (errors.length) {
  console.error(errors.join("\n"));
  process.exit(1);
}

const out = { version: VERSION, generatedAt: new Date().toISOString(), rules };
fs.writeFileSync(path.join(here, "rules.json"), JSON.stringify(out, null, 2) + "\n");
const byKind = Object.entries(rules.reduce((a, r) => ((a[r.kind] = (a[r.kind] ?? 0) + 1), a), {})).map(([k, n]) => `${k} ${n}`).join(", ");
console.log(`wrote ${rules.length} rules from ${files.length} databases (version ${VERSION}): ${byKind}`);
