import { describe, expect, it } from "vitest";
import { formatPin, generatePinDigits, generateReference, hmacHex, normalizePin, seal, unseal } from "@/lib/crypto";
import { compareSemver } from "@/lib/semver";
import { computeManifest } from "@/lib/manifest";
import { claimPinSchema, findingSchema, registerSchema, ruleSchema } from "@/lib/validation";

describe("PIN generation", () => {
  it("produces six digits formatted as 483-921", () => {
    for (let i = 0; i < 500; i++) {
      const d = generatePinDigits();
      expect(d).toMatch(/^\d{6}$/);
      expect(formatPin(d)).toMatch(/^\d{3}-\d{3}$/);
    }
  });

  it("is not trivially repetitive (CSPRNG sanity check)", () => {
    const set = new Set(Array.from({ length: 2000 }, generatePinDigits));
    expect(set.size).toBeGreaterThan(1900);
  });

  it("normalises user input and rejects malformed PINs", () => {
    expect(normalizePin("483-921")).toBe("483921");
    expect(normalizePin(" 483 921 ")).toBe("483921");
    expect(normalizePin("48392")).toBeNull();
    expect(normalizePin("48a921")).toBeNull();
    expect(normalizePin("4839210")).toBeNull();
  });

  it("stores PINs as keyed HMACs, not plaintext", () => {
    const h = hmacHex("pin", "483921");
    expect(h).toMatch(/^[0-9a-f]{64}$/);
    expect(h).not.toContain("483921");
    expect(hmacHex("pin", "483921")).toBe(h);
    expect(hmacHex("pin", "483922")).not.toBe(h);
  });

  it("seals PINs with authenticated encryption", () => {
    const s = seal("483921");
    expect(unseal(s)).toBe("483921");
    const tampered = s.slice(0, -2) + (s.endsWith("A") ? "BB" : "AA");
    expect(unseal(tampered)).toBeNull();
  });

  it("generates unambiguous investigation references", () => {
    expect(generateReference()).toMatch(/^INV-[2-9A-HJ-NP-Z]{4}-[2-9A-HJ-NP-Z]{4}$/);
  });
});

describe("semver", () => {
  it("orders versions", () => {
    expect(compareSemver("1.0.0", "1.0.1")).toBe(-1);
    expect(compareSemver("1.10.0", "1.9.9")).toBe(1);
    expect(compareSemver("1.0.0-beta", "1.0.0")).toBe(-1);
    expect(compareSemver("2.0.0", "2.0.0")).toBe(0);
  });
});

describe("integrity manifest", () => {
  it("matches the C# implementation's reference vector", () => {
    // Same vector as Screensharing.Scanner.Tests.EngineTests.Manifest_matches_the_backend_algorithm
    const v = computeManifest([
      { clientFindingId: "fb", ruleId: "SSME-CL-0001", severity: "CRITICAL", tier: "CONFIRMED_ARTIFACT", confidence: 96, evidence: [{ reference: "C:/x/b.jar", sha256: "aa" }, { reference: "C:/x/a.jar!/meta", sha256: null }] },
      { clientFindingId: "fa", ruleId: "SSME-H-UNRECOGNIZED_MOD", severity: "INFO", tier: "INCONCLUSIVE", confidence: 0, evidence: [{ reference: "Z\u00e9", sha256: null }] },
    ]);
    expect(v).toBe("e292ff3f6be378f9fca647257454b203247ad24e1dc56101b16f92fc7382fff0");
  });

  it("is independent of upload order", () => {
    const a = { clientFindingId: "a1", ruleId: "R", severity: "LOW", tier: "WEAK_INDICATOR", confidence: 1, evidence: [{ reference: "x", sha256: null }] };
    const b = { ...a, clientFindingId: "b2" };
    expect(computeManifest([a, b])).toBe(computeManifest([b, a]));
  });
});

const now = new Date().toISOString();
const finding = {
  clientFindingId: "f0123456789abcdef", ruleId: "SSME-CL-0001", name: "n", description: "d", category: "Cheat client", categoryKey: "mods",
  severity: "CRITICAL", tier: "CONFIRMED_ARTIFACT", confidence: 96, method: "m", whyItMatters: "w", limitations: "l", falsePositiveNotes: "f",
  alternativeExplanations: "a", detectedAt: now,
  evidence: [{ kind: "FILE", source: "Mod archive", reference: "C:\\mods\\x.jar", sha256: "a".repeat(64), observedAt: now }],
};

describe("desktop payload validation", () => {
  it("accepts a well-formed finding", () => {
    expect(findingSchema.safeParse(finding).success).toBe(true);
  });
  it("rejects unknown properties, bad enums and out-of-range values", () => {
    expect(findingSchema.safeParse({ ...finding, extra: 1 }).success).toBe(false);
    expect(findingSchema.safeParse({ ...finding, severity: "SEVERE" }).success).toBe(false);
    expect(findingSchema.safeParse({ ...finding, confidence: 101 }).success).toBe(false);
    expect(findingSchema.safeParse({ ...finding, ruleId: "DROP TABLE" }).success).toBe(false);
    expect(findingSchema.safeParse({ ...finding, evidence: [] }).success).toBe(false);
  });
  it("requires hashed evidence for confirmed-artifact findings", () => {
    const noHash = { ...finding, evidence: [{ kind: "LOG", source: "s", reference: "r", observedAt: now }] };
    expect(findingSchema.safeParse(noHash).success).toBe(false);
    expect(findingSchema.safeParse({ ...noHash, tier: "WEAK_INDICATOR" }).success).toBe(true);
  });
  it("validates claim requests", () => {
    expect(claimPinSchema.safeParse({ pin: "483-921", appVersion: "1.0.0" }).success).toBe(true);
    expect(claimPinSchema.safeParse({ pin: "483-921", appVersion: "latest" }).success).toBe(false);
  });
});

describe("account and rule validation", () => {
  it("enforces username and password policy; email optional", () => {
    expect(registerSchema.safeParse({ username: "mod_alex", password: "correcthorse9" }).success).toBe(true);
    expect(registerSchema.safeParse({ username: "mod_alex", email: "", password: "correcthorse9" }).success).toBe(true);
    expect(registerSchema.safeParse({ username: "a", password: "correcthorse9" }).success).toBe(false);
    expect(registerSchema.safeParse({ username: "bad name!", password: "correcthorse9" }).success).toBe(false);
    expect(registerSchema.safeParse({ username: "mod_alex", password: "short1" }).success).toBe(false);
    expect(registerSchema.safeParse({ username: "mod_alex", password: "noDigitsHere" }).success).toBe(false);
  });
  it("validates rule patterns by kind", () => {
    const base = { id: "SSME-CU-0001", name: "n", description: "d", category: "c", severity: "HIGH", tier: "STRONG_INDICATOR", confidence: 80, falsePositives: "f", limitations: "l" };
    expect(ruleSchema.safeParse({ ...base, kind: "SHA256", pattern: "a".repeat(64) }).success).toBe(true);
    expect(ruleSchema.safeParse({ ...base, kind: "SHA256", pattern: "xyz" }).success).toBe(false);
    expect(ruleSchema.safeParse({ ...base, kind: "PACKAGE_PREFIX", pattern: "com/example/client/" }).success).toBe(true);
    expect(ruleSchema.safeParse({ ...base, kind: "PACKAGE_PREFIX", pattern: "com.example.client" }).success).toBe(false);
    expect(ruleSchema.safeParse({ ...base, kind: "MEMORY_STRING", pattern: "short" }).success).toBe(false);
  });
});
