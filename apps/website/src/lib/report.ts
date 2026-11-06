import "server-only";
import { PDFDocument, StandardFonts, rgb, type PDFFont, type PDFPage } from "pdf-lib";
import { OUTCOME_LABEL, type InvestigationSnapshot } from "./investigations";

const TIER_LABEL: Record<string, string> = {
  CONFIRMED_ARTIFACT: "Confirmed artifact match",
  STRONG_INDICATOR: "Strong forensic indicator",
  SUSPICIOUS_CONFIGURATION: "Suspicious configuration",
  WEAK_INDICATOR: "Weak indicator",
  INCONCLUSIVE: "Inconclusive",
};

export function reportToJson(s: InvestigationSnapshot): string {
  const { pin: _pin, lastEventId: _l, ...rest } = s;
  return JSON.stringify({ format: "screensharing.me/report", formatVersion: 2, ...rest }, null, 2);
}

function csvCell(v: unknown): string {
  let str = v === null || v === undefined ? "" : String(v);
  // Neutralise spreadsheet formula injection.
  if (/^[=+\-@\t\r]/.test(str)) str = `'${str}`;
  return /[",\n\r]/.test(str) ? `"${str.replace(/"/g, '""')}"` : str;
}

/** One row per evidence item, finding columns repeated so the file is filterable in spreadsheets. */
export function reportToCsv(s: InvestigationSnapshot): string {
  const header = [
    "investigation_reference", "investigation_id", "subject", "finding_id", "rule_id", "name", "suspected_client", "category", "location",
    "signature", "status", "requires_manual_review", "severity", "evidence_tier", "confidence", "detected_at", "evidence_kind", "evidence_source", "evidence_reference", "sha256", "size_bytes",
    "file_created", "file_modified", "observed_at", "method", "why_it_matters", "limitations",
  ];
  const rows: string[] = [header.join(",")];
  for (const d of s.detections) {
    for (const e of d.evidence) {
      rows.push([
        s.reference, s.id, s.subjectName, d.id, d.ruleId, d.name, d.family, d.category, d.location, d.signature, OUTCOME_LABEL[d.outcome],
        d.outcome === "CONFIRMED" || d.outcome === "INFORMATIONAL" ? "no" : "yes", d.severity, d.tier, d.confidence, d.detectedAt,
        e.kind, e.source, e.reference, e.sha256, e.sizeBytes, e.createdTime, e.modifiedTime, e.observedAt, d.method, d.whyItMatters, d.limitations,
      ].map(csvCell).join(","));
    }
  }
  return "﻿" + rows.join("\r\n") + "\r\n";
}

// ------------------------------------------------------------------- PDF
const COLORS = {
  ink: rgb(0.08, 0.09, 0.12),
  muted: rgb(0.38, 0.41, 0.48),
  accent: rgb(0.298, 0.455, 0.91),
  line: rgb(0.85, 0.86, 0.9),
  CRITICAL: rgb(0.86, 0.15, 0.27),
  HIGH: rgb(0.93, 0.42, 0.2),
  MEDIUM: rgb(0.85, 0.65, 0.1),
  LOW: rgb(0.25, 0.55, 0.9),
  INFO: rgb(0.45, 0.48, 0.55),
};

/** Standard PDF fonts only encode WinAnsi; replace anything else. */
function ansi(text: string): string {
  return text
    .replace(/[‘’]/g, "'")
    .replace(/[“”]/g, '"')
    .replace(/[–—]/g, "-")
    .replace(/…/g, "...")
    .replace(/[^\x09\x0A\x0D\x20-\x7E\xA0-\xFF]/g, "?");
}

class Writer {
  page!: PDFPage;
  y = 0;
  readonly margin = 48;
  readonly width = 595.28; // A4
  readonly height = 841.89;
  constructor(private doc: PDFDocument, private regular: PDFFont, private bold: PDFFont, private mono: PDFFont, private footer: string) {
    this.newPage();
  }
  newPage() {
    this.page = this.doc.addPage([this.width, this.height]);
    this.y = this.height - this.margin;
    const n = this.doc.getPageCount();
    this.page.drawText(ansi(`${this.footer}  -  page ${n}`), { x: this.margin, y: 24, size: 7.5, font: this.regular, color: COLORS.muted });
  }
  ensure(h: number) {
    if (this.y - h < this.margin) this.newPage();
  }
  wrap(text: string, font: PDFFont, size: number, maxWidth: number): string[] {
    const out: string[] = [];
    for (const para of ansi(text).split("\n")) {
      let line = "";
      for (const word of para.split(/\s+/)) {
        // Hard-break very long tokens such as paths and hashes.
        let w = word;
        while (font.widthOfTextAtSize(w, size) > maxWidth) {
          let cut = w.length;
          while (cut > 1 && font.widthOfTextAtSize(w.slice(0, cut), size) > maxWidth) cut--;
          if (line) { out.push(line); line = ""; }
          out.push(w.slice(0, cut));
          w = w.slice(cut);
        }
        const candidate = line ? `${line} ${w}` : w;
        if (font.widthOfTextAtSize(candidate, size) > maxWidth) { out.push(line); line = w; } else line = candidate;
      }
      out.push(line);
    }
    return out;
  }
  text(text: string, opts: { size?: number; font?: "regular" | "bold" | "mono"; color?: ReturnType<typeof rgb>; indent?: number; gap?: number } = {}) {
    const size = opts.size ?? 9.5;
    const font = opts.font === "bold" ? this.bold : opts.font === "mono" ? this.mono : this.regular;
    const indent = opts.indent ?? 0;
    const lines = this.wrap(text, font, size, this.width - this.margin * 2 - indent);
    for (const l of lines) {
      this.ensure(size + 3);
      this.page.drawText(l, { x: this.margin + indent, y: this.y - size, size, font, color: opts.color ?? COLORS.ink });
      this.y -= size + 3;
    }
    this.y -= opts.gap ?? 2;
  }
  rule() {
    this.ensure(10);
    this.page.drawLine({ start: { x: this.margin, y: this.y - 4 }, end: { x: this.width - this.margin, y: this.y - 4 }, thickness: 0.6, color: COLORS.line });
    this.y -= 12;
  }
  kv(label: string, value: string) {
    this.text(`${label}: ${value}`, { size: 9 });
  }
}

export async function reportToPdf(s: InvestigationSnapshot): Promise<Uint8Array> {
  const doc = await PDFDocument.create();
  doc.setTitle(`screensharing.me report ${s.reference}`);
  doc.setAuthor("screensharing.me");
  doc.setCreationDate(new Date());
  const [regular, bold, mono] = await Promise.all([
    doc.embedFont(StandardFonts.Helvetica),
    doc.embedFont(StandardFonts.HelveticaBold),
    doc.embedFont(StandardFonts.Courier),
  ]);
  const w = new Writer(doc, regular, bold, mono, `screensharing.me  -  ${s.reference}  -  generated ${s.generatedAt}`);

  w.text("screensharing.me", { size: 11, font: "bold", color: COLORS.accent, gap: 0 });
  w.text("Minecraft Forensic Investigation Report", { size: 20, font: "bold", gap: 8 });
  w.kv("Investigation", `${s.reference} (${s.id})`);
  w.kv("Subject (player)", s.subjectName);
  if (s.serverName) w.kv("Server", s.serverName);
  w.kv("Investigator", s.owner.displayName);
  w.kv("Status", s.status);
  w.kv("Created", s.createdAt);
  if (s.consentedAt) w.kv("Player consent recorded", s.consentedAt);
  if (s.scan) {
    w.kv("Scan started", s.scan.startedAt);
    if (s.scan.completedAt) w.kv("Scan completed", s.scan.completedAt);
    w.kv("Scanner / ruleset", `${s.scan.engineVersion} / ${s.scan.rulesetVersion}`);
    w.kv("Administrator rights during scan", s.scan.elevated ? "yes" : "no");
    if (s.scan.manifestSha256) w.kv("Evidence manifest SHA-256", `${s.scan.manifestSha256} (${s.scan.manifestVerified ? "verified by server" : "MISMATCH - integrity not verified"})`);
  }
  const summary = (s.scan?.summary ?? {}) as { instance?: Record<string, unknown>; installations?: Record<string, unknown>[]; statistics?: Record<string, number>;
    inspection?: { examined: number; analyzed: number; skipped: number; unableToInspect: number; uninspected?: { location: string; reason?: string | null; status: string }[] }; excludedLocations?: string[] };
  const inst = summary.instance ?? summary.installations?.[0];
  if (inst) {
    w.rule();
    w.text("Examined instance", { size: 13, font: "bold" });
    w.kv("Instance", `${String(inst.name ?? "")} (${String(inst.launcher ?? "")})`);
    w.kv("Game directory", String(inst.path ?? ""));
    if (inst.source) w.kv("Identified from", String(inst.source));
    if (inst.versions || inst.loader) w.kv("Version / loader", `${String(inst.versions ?? "-")} / ${String(inst.loader ?? "-")}`);
    if (inst.processId) w.kv("Game process", `PID ${String(inst.processId)}`);
    w.text("Only this instance was examined. Other instances, user documents, browsers and Windows records were not read.", { size: 8.5, color: COLORS.muted });
  }
  if (summary.inspection) {
    const i = summary.inspection;
    w.kv("Files", `${i.examined} examined, ${i.analyzed} analysed, ${i.skipped} skipped, ${i.unableToInspect} could not be inspected${summary.statistics?.signatures ? `; ${summary.statistics.signatures} signatures applied` : ""}`);
  }
  w.rule();

  w.text("Verdict", { size: 13, font: "bold" });
  w.text(s.verdict.title, { size: 11, font: "bold", color: COLORS.accent });
  w.text(s.verdict.explanation, { gap: 6 });
  w.text(
    `Findings: ${s.counts.total}  |  Critical ${s.counts.severity.CRITICAL}  High ${s.counts.severity.HIGH}  Medium ${s.counts.severity.MEDIUM}  Low ${s.counts.severity.LOW}  Info ${s.counts.severity.INFO}`,
    { size: 9.5, font: "bold" },
  );
  w.text(
    `Evidence tiers: confirmed ${s.counts.tier.CONFIRMED_ARTIFACT}, strong ${s.counts.tier.STRONG_INDICATOR}, suspicious ${s.counts.tier.SUSPICIOUS_CONFIGURATION}, weak ${s.counts.tier.WEAK_INDICATOR}, inconclusive ${s.counts.tier.INCONCLUSIVE}`,
    { size: 9, color: COLORS.muted, gap: 6 },
  );
  w.text("A finding describes what an artifact shows. No single filename, unknown mod or isolated artifact establishes that a person cheated; investigators should weigh evidence tiers, timing and the stated limitations.", { size: 8.5, color: COLORS.muted });

  const coverage = (s.scan?.coverage ?? []) as { name: string; status: string; note?: string | null }[];
  if (coverage.length) {
    w.rule();
    w.text("Scan coverage", { size: 13, font: "bold" });
    for (const c of coverage) w.text(`${c.status.padEnd(9)} ${c.name}${c.note ? ` - ${c.note}` : ""}`, { size: 8.5, font: "mono" });
  }

  w.rule();
  w.text("Findings", { size: 13, font: "bold", gap: 4 });
  if (!s.detections.length) w.text("No findings were recorded.", { color: COLORS.muted });
  s.detections.forEach((d, i) => {
    w.ensure(60);
    w.text(`${i + 1}. ${d.name}`, { size: 11, font: "bold", color: COLORS[d.severity as keyof typeof COLORS] as ReturnType<typeof rgb>, gap: 0 });
    w.text(`${OUTCOME_LABEL[d.outcome]}${d.outcome === "CONFIRMED" || d.outcome === "INFORMATIONAL" ? "" : " (manual review)"}  |  ${d.severity}  |  ${TIER_LABEL[d.tier] ?? d.tier}  |  confidence ${d.confidence}%  |  ${d.category}  |  rule ${d.ruleId}`, { size: 8, color: COLORS.muted });
    if (d.family || d.location || d.signature) w.text([d.family ? `Suspected: ${d.family}` : null, d.location ? `Location: ${d.location}` : null, d.signature ? `Signature: ${d.signature}` : null].filter(Boolean).join("  |  "), { size: 8, font: "mono" });
    w.text(d.description, { size: 9 });
    w.text(`Why this matters: ${d.whyItMatters}`, { size: 8.5 });
    w.text(`Detection method: ${d.method}`, { size: 8.5 });
    w.text(`Limitations: ${d.limitations}`, { size: 8.5 });
    w.text(`Alternative explanations: ${d.alternativeExplanations}`, { size: 8.5 });
    w.text("Evidence:", { size: 8.5, font: "bold", gap: 0 });
    for (const e of d.evidence) {
      w.text(`[${e.kind}] ${e.reference}`, { size: 7.5, font: "mono", indent: 10, gap: 0 });
      const meta = [
        e.source,
        e.sha256 ? `sha256 ${e.sha256}` : null,
        e.sizeBytes != null ? `${e.sizeBytes} bytes` : null,
        e.modifiedTime ? `modified ${e.modifiedTime}` : null,
        `observed ${e.observedAt}`,
      ].filter(Boolean).join("  |  ");
      w.text(meta, { size: 7, font: "mono", indent: 20, color: COLORS.muted, gap: 0 });
      if (e.details) for (const [k, v] of Object.entries(e.details).slice(0, 12)) w.text(`${k}: ${v}`, { size: 7, font: "mono", indent: 20, color: COLORS.muted, gap: 0 });
    }
    w.y -= 8;
  });

  if (summary.inspection?.uninspected?.length) {
    w.rule();
    w.text("Files that could not be inspected", { size: 13, font: "bold" });
    for (const u of summary.inspection.uninspected) w.text(`${u.location} - ${u.reason ?? u.status}`, { size: 7.5, font: "mono", gap: 0 });
  }

  const custody = s.scan?.chainOfCustody as { operations?: { at: string; action: string; target: string }[] } | null;
  if (custody?.operations?.length) {
    w.rule();
    w.text("Chain of custody (read-only collection log)", { size: 13, font: "bold" });
    for (const op of custody.operations.slice(0, 400)) w.text(`${op.at}  ${op.action}  ${op.target}`, { size: 7, font: "mono", gap: 0 });
    if (custody.operations.length > 400) w.text(`... ${custody.operations.length - 400} more entries in the JSON export.`, { size: 7, color: COLORS.muted });
  }
  return doc.save();
}
