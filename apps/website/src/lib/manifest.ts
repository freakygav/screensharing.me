import { createHash } from "node:crypto";

/**
 * Integrity manifest shared with the desktop scanner (see Screensharing.Scanner/Reporting/Manifest.cs).
 * One line per finding (evidence entries "reference#sha256" sorted ordinally, comma joined), sorted by clientFindingId (ordinal), joined with "\n", SHA-256 hex of UTF-8.
 */
export interface ManifestFinding {
  clientFindingId: string;
  ruleId: string;
  severity: string;
  tier: string;
  confidence: number;
  evidence: { reference: string; sha256?: string | null }[];
}

const ordinal = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

export function manifestLine(f: ManifestFinding): string {
  return `${f.clientFindingId}|${f.ruleId}|${f.severity}|${f.tier}|${f.confidence}|${f.evidence.map((e) => `${e.reference}#${e.sha256 ?? ""}`).sort(ordinal).join(",")}`;
}

export function computeManifest(findings: ManifestFinding[]): string {
  const lines = [...findings]
    .sort((a, b) => (a.clientFindingId < b.clientFindingId ? -1 : a.clientFindingId > b.clientFindingId ? 1 : 0))
    .map(manifestLine);
  return createHash("sha256").update(Buffer.from(lines.join("\n"), "utf8")).digest("hex");
}
