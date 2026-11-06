import { z } from "zod";

// ---------------------------------------------------------------- accounts
export const usernameSchema = z
  .string()
  .trim()
  .min(3, "Username must be at least 3 characters.")
  .max(24, "Username must be at most 24 characters.")
  .regex(/^[A-Za-z0-9_.-]+$/, "Use letters, numbers, dot, dash or underscore.");

export const passwordSchema = z
  .string()
  .min(10, "Password must be at least 10 characters.")
  .max(200, "Password is too long.")
  .refine((p) => /[A-Za-z]/.test(p) && /[0-9]/.test(p), "Password must contain letters and numbers.");

export const emailSchema = z.string().trim().toLowerCase().max(254).email("Enter a valid email address.");

export const registerSchema = z.object({
  username: usernameSchema,
  email: z.union([emailSchema, z.literal("")]).optional(),
  password: passwordSchema,
});

export const loginSchema = z.object({
  identifier: z.string().trim().min(1, "Enter your username or email.").max(254),
  password: z.string().min(1, "Enter your password.").max(200),
  adminOnly: z.boolean().optional(),
});

export const tokenSchema = z.object({ token: z.string().min(20).max(200) });
export const requestResetSchema = z.object({ email: emailSchema });
export const resetPasswordSchema = z.object({ token: z.string().min(20).max(200), password: passwordSchema });
export const changePasswordSchema = z.object({ currentPassword: z.string().min(1).max(200), newPassword: passwordSchema });
export const changeEmailSchema = z.object({ email: z.union([emailSchema, z.literal("")]), currentPassword: z.string().min(1).max(200) });

// ---------------------------------------------------------- investigations
export const createInvestigationSchema = z.object({
  subjectName: z
    .string()
    .trim()
    .min(1, "Enter the player's name.")
    .max(32)
    .regex(/^[A-Za-z0-9_ .-]+$/, "Player name contains invalid characters."),
  serverName: z.string().trim().max(64).optional().or(z.literal("")),
  notes: z.string().trim().max(1000).optional().or(z.literal("")),
});

// ------------------------------------------------------------ desktop API
const shortText = (max: number) => z.string().max(max);
export const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const;
export const TIERS = ["CONFIRMED_ARTIFACT", "STRONG_INDICATOR", "SUSPICIOUS_CONFIGURATION", "WEAK_INDICATOR", "INCONCLUSIVE"] as const;
export const CATEGORY_STATUSES = ["PENDING", "RUNNING", "COMPLETED", "SKIPPED", "FAILED"] as const;
const isoDate = z.string().datetime({ offset: true });
const categoryKey = z.string().regex(/^[a-z][a-z0-9_]{1,31}$/);
const semver = z.string().regex(/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]{1,32})?$/, "Invalid version.");

export const claimPinSchema = z.object({
  pin: z.string().max(16),
  appVersion: semver,
  osVersion: shortText(120).optional(),
  elevated: z.boolean().optional(),
});

export const desktopLoginSchema = z.object({
  identifier: z.string().trim().min(1).max(254),
  password: z.string().min(1).max(200),
  appVersion: semver,
});

export const scanStartSchema = z.object({
  engineVersion: semver,
  rulesetVersion: shortText(40),
  elevated: z.boolean(),
  categories: z
    .array(z.object({ key: categoryKey, name: shortText(80) }))
    .min(1)
    .max(30),
});

export const scanProgressSchema = z.object({
  progress: z.number().int().min(0).max(100),
  currentActivity: shortText(200).optional(),
  categories: z
    .array(
      z.object({
        key: categoryKey,
        status: z.enum(CATEGORY_STATUSES),
        itemsExamined: z.number().int().min(0).max(100_000_000),
        findingsCount: z.number().int().min(0).max(100_000),
        message: shortText(300).optional().nullable(),
      }),
    )
    .max(30),
});

export const evidenceSchema = z
  .object({
    kind: z.enum([
      "FILE", "JAR_ENTRY", "LOG", "PREFETCH", "BAM", "REGISTRY", "PROCESS", "MODULE",
      "MEMORY", "EVENT_LOG", "RECYCLE_BIN", "USN", "ENVIRONMENT", "CONFIG", "SERVICE",
    ]),
    source: shortText(120),
    reference: shortText(1024),
    sha256: z.string().regex(/^[a-f0-9]{64}$/).optional().nullable(),
    sizeBytes: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER).optional().nullable(),
    createdTime: isoDate.optional().nullable(),
    modifiedTime: isoDate.optional().nullable(),
    accessedTime: isoDate.optional().nullable(),
    observedAt: isoDate,
    details: z.record(z.string().max(64), z.string().max(2000)).optional().nullable()
      .refine((d) => !d || Object.keys(d).length <= 40, "Too many detail entries."),
  })
  .strict();

export const findingSchema = z
  .object({
    clientFindingId: z.string().regex(/^[A-Za-z0-9_-]{8,64}$/),
    ruleId: z.string().regex(/^SSME-[A-Z]{1,4}-[A-Z0-9_]{1,40}$/),
    name: shortText(200),
    description: shortText(2000),
    category: shortText(80),
    categoryKey,
    severity: z.enum(SEVERITIES),
    tier: z.enum(TIERS),
    confidence: z.number().int().min(0).max(100),
    method: shortText(1000),
    whyItMatters: shortText(2000),
    limitations: shortText(2000),
    falsePositiveNotes: shortText(2000),
    alternativeExplanations: shortText(2000),
    detectedAt: isoDate,
    evidence: z.array(evidenceSchema).min(1).max(25),
  })
  .strict()
  .refine((f) => !(f.tier === "CONFIRMED_ARTIFACT" && f.evidence.every((e) => !e.sha256 && e.kind !== "JAR_ENTRY")),
    "Confirmed artifact findings must reference hashed evidence.");

export const findingsBatchSchema = z.object({ findings: z.array(findingSchema).min(1).max(100) });

const inventoryItem = z.record(z.string().max(64), z.union([z.string().max(1024), z.number(), z.boolean(), z.null()]));
export const scanCompleteSchema = z.object({
  manifestSha256: z.string().regex(/^[a-f0-9]{64}$/),
  findingCount: z.number().int().min(0).max(100_000),
  summary: z.object({
    installations: z.array(inventoryItem).max(200),
    mods: z.array(inventoryItem).max(3000),
    javaRuntimes: z.array(inventoryItem).max(100),
    statistics: z.record(z.string().max(64), z.number()).optional(),
  }),
  coverage: z.array(
    z.object({ key: categoryKey, name: shortText(80), status: z.enum(CATEGORY_STATUSES), note: shortText(500).optional().nullable() }),
  ).max(30),
  chainOfCustody: z.object({
    engineVersion: semver,
    rulesetVersion: shortText(40),
    osVersion: shortText(120),
    elevated: z.boolean(),
    startedAt: isoDate,
    completedAt: isoDate,
    readOnly: z.literal(true),
    operations: z.array(z.object({ at: isoDate, action: shortText(120), target: shortText(1024) })).max(2000),
  }),
});

export const scanFailSchema = z.object({ reason: shortText(500) });

// ------------------------------------------------------------------- admin
export const adminUserPatchSchema = z.object({
  role: z.enum(["USER", "ADMIN"]).optional(),
  disabled: z.boolean().optional(),
  revokeSessions: z.boolean().optional(),
});

export const ruleSchema = z.object({
  id: z.string().regex(/^SSME-[A-Z]{1,4}-[A-Z0-9_]{1,40}$/),
  name: shortText(200).min(1),
  description: shortText(2000).min(1),
  category: shortText(80).min(1),
  kind: z.enum(["MOD_ID", "MOD_ID_REGEX", "PACKAGE_PREFIX", "MEMORY_STRING", "SHA256", "EXECUTABLE_REGEX", "FILE_NAME_REGEX", "RESOURCEPACK_REGEX", "KNOWN_MOD", "BUILTIN"]),
  pattern: shortText(500).min(1),
  family: shortText(80).optional().nullable(),
  features: z.array(shortText(120)).max(40).default([]),
  severity: z.enum(SEVERITIES),
  tier: z.enum(TIERS),
  confidence: z.number().int().min(0).max(100),
  classification: shortText(40).optional().nullable(),
  falsePositives: shortText(2000).min(1),
  limitations: shortText(2000).min(1),
  references: z.array(z.string().url().max(500)).max(10).default([]),
  enabled: z.boolean().default(true),
}).superRefine((r, ctx) => {
  if (r.kind === "SHA256" && !/^[a-f0-9]{64}$/.test(r.pattern)) ctx.addIssue({ code: "custom", path: ["pattern"], message: "SHA256 rules need a lowercase hex digest." });
  if (r.kind === "PACKAGE_PREFIX" && !/^[a-z0-9_$]+(\/[A-Za-z0-9_$]+)*\/$/.test(r.pattern)) ctx.addIssue({ code: "custom", path: ["pattern"], message: "Package prefixes look like com/example/client/ (slash separated, trailing slash)." });
  if (r.kind === "MEMORY_STRING" && r.pattern.length < 8) ctx.addIssue({ code: "custom", path: ["pattern"], message: "Memory strings must be at least 8 characters to avoid false positives." });
});

export const versionSchema = z.object({
  version: semver,
  channel: z.enum(["stable", "beta"]).default("stable"),
  notes: shortText(2000).optional().nullable(),
  sha256: z.string().regex(/^[a-f0-9]{64}$/).optional().nullable().or(z.literal("")),
  downloadUrl: z.string().url().max(500).optional().nullable().or(z.literal("")),
  minimumSupported: z.boolean().default(false),
  active: z.boolean().default(true),
});

export const configPatchSchema = z.object({
  key: z.enum(["registrationOpen", "maintenanceMessage", "pinTtlMinutes", "modrinthLookupDefault"]),
  value: z.union([z.boolean(), z.string().max(500), z.number().int().min(1).max(1440)]),
});
