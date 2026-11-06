import { describe, expect, it } from "vitest";
import { reportToCsv, reportToJson, reportToPdf } from "@/lib/report";
import { computeVerdict } from "@/lib/investigations";
import type { InvestigationSnapshot } from "@/lib/investigations";

const snap = {
  id: "inv1", reference: "INV-TEST-0001", subjectName: "Steve", serverName: "play.test", notes: null, status: "COMPLETED",
  owner: { id: "u1", username: "mod", displayName: "Mod" },
  createdAt: "2026-11-06T10:00:00.000Z", connectedAt: null, consentedAt: "2026-11-06T10:01:00.000Z", completedAt: "2026-11-06T10:03:00.000Z",
  pin: { pin: "483-921", expiresAt: "2026-11-06T10:15:00.000Z" }, pinExpiresAt: null, device: null,
  scan: {
    id: "s1", status: "COMPLETED", progress: 100, currentActivity: null, engineVersion: "1.0.0", rulesetVersion: "r1", elevated: false,
    startedAt: "2026-11-06T10:01:00.000Z", completedAt: "2026-11-06T10:03:00.000Z", lastUpdateAt: "2026-11-06T10:03:00.000Z",
    failureReason: null, manifestSha256: "f".repeat(64), manifestVerified: true, summary: null,
    coverage: [{ key: "mods", name: "Mod archive analysis", status: "COMPLETED", note: null }],
    chainOfCustody: { operations: [{ at: "2026-11-06T10:01:01.000Z", action: "read-archive", target: "C:\\mods\\x.jar" }] }, categories: [],
  },
  counts: { total: 1, severity: { CRITICAL: 1, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 }, tier: { CONFIRMED_ARTIFACT: 1, STRONG_INDICATOR: 0, SUSPICIOUS_CONFIGURATION: 0, WEAK_INDICATOR: 0, INCONCLUSIVE: 0 } },
  verdict: { level: "confirmed", title: "Confirmed artifact match", explanation: "x" },
  detections: [{
    id: "d1", ruleId: "SSME-CL-0001", name: "=HYPERLINK(\"http://evil\")", description: "Contains “quotes”, ω and \u0000 control", category: "Cheat client", categoryKey: "mods",
    severity: "CRITICAL", tier: "CONFIRMED_ARTIFACT", confidence: 96, method: "m", whyItMatters: "w", limitations: "l", falsePositiveNotes: "f", alternativeExplanations: "a",
    detectedAt: "2026-11-06T10:02:00.000Z",
    evidence: [{ id: "e1", kind: "FILE", source: "Mod archive", reference: "C:\\mods\\" + "very-long-path-segment-".repeat(20) + ".jar", sha256: "a".repeat(64), sizeBytes: 100, createdTime: null, modifiedTime: null, accessedTime: null, observedAt: "2026-11-06T10:02:00.000Z", details: { modId: "meteor-client" } }],
  }],
  lastEventId: "1", generatedAt: "2026-11-06T10:04:00.000Z",
} as unknown as InvestigationSnapshot;

describe("report exports", () => {
  it("JSON never contains the PIN", () => {
    const j = JSON.parse(reportToJson(snap));
    expect(j.pin).toBeUndefined();
    expect(j.reference).toBe("INV-TEST-0001");
    expect(j.detections).toHaveLength(1);
  });

  it("CSV neutralises spreadsheet formula injection", () => {
    const csv = reportToCsv(snap);
    expect(csv).toContain("'=HYPERLINK");
    expect(csv).not.toMatch(/,=HYPERLINK/);
    expect(csv.split("\r\n")[0]).toContain("investigation_reference");
  });

  it("PDF renders non-Latin text and very long paths", async () => {
    const pdf = await reportToPdf(snap);
    expect(Buffer.from(pdf.subarray(0, 5)).toString()).toBe("%PDF-");
    expect(pdf.length).toBeGreaterThan(1500);
  });
});

describe("verdicts", () => {
  const zero = { CONFIRMED_ARTIFACT: 0, STRONG_INDICATOR: 0, SUSPICIOUS_CONFIGURATION: 0, WEAK_INDICATOR: 0, INCONCLUSIVE: 0 };
  it("never calls a clean or weak result a confirmation", () => {
    expect(computeVerdict(zero, true).level).toBe("clear");
    expect(computeVerdict({ ...zero, INCONCLUSIVE: 40 }, true).level).toBe("clear");
    expect(computeVerdict({ ...zero, WEAK_INDICATOR: 3 }, true).level).toBe("review");
    expect(computeVerdict({ ...zero, STRONG_INDICATOR: 1 }, true).level).toBe("strong");
    expect(computeVerdict({ ...zero, CONFIRMED_ARTIFACT: 1 }, true).level).toBe("confirmed");
    expect(computeVerdict({ ...zero, CONFIRMED_ARTIFACT: 1 }, false).level).toBe("review");
    for (const v of [computeVerdict(zero, true), computeVerdict({ ...zero, CONFIRMED_ARTIFACT: 1 }, true)])
      expect(`${v.title} ${v.explanation}`.toLowerCase()).not.toContain("cheater");
  });
});
