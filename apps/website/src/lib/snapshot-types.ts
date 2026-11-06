// Client-side shape of InvestigationSnapshot (JSON-serialised by the server).
export interface EvidenceView {
  id: string; kind: string; source: string; reference: string; sha256: string | null; sizeBytes: number | null;
  createdTime: string | null; modifiedTime: string | null; accessedTime: string | null; observedAt: string; details: Record<string, string> | null;
}
export interface DetectionView {
  id: string; ruleId: string; name: string; description: string; category: string; categoryKey: string;
  severity: string; tier: string; confidence: number; method: string; whyItMatters: string; limitations: string;
  falsePositiveNotes: string; alternativeExplanations: string; detectedAt: string; evidence: EvidenceView[];
}
export interface CategoryView { key: string; name: string; status: string; itemsExamined: number; findingsCount: number; message: string | null; startedAt: string | null; completedAt: string | null }
export interface SnapshotView {
  id: string; reference: string; subjectName: string; serverName: string | null; notes: string | null; status: string;
  owner: { id: string; username: string; displayName: string };
  createdAt: string; connectedAt: string | null; consentedAt: string | null; completedAt: string | null;
  pin: { pin: string; expiresAt: string } | null; pinExpiresAt: string | null;
  device: { appVersion: string; osVersion: string | null; elevated: boolean; connectedAt: string; lastHeartbeatAt: string; online: boolean } | null;
  scan: {
    id: string; status: string; progress: number; currentActivity: string | null; engineVersion: string; rulesetVersion: string; elevated: boolean;
    startedAt: string; completedAt: string | null; lastUpdateAt: string; failureReason: string | null; manifestSha256: string | null; manifestVerified: boolean | null;
    summary: { installations?: Record<string, unknown>[]; mods?: Record<string, unknown>[]; javaRuntimes?: Record<string, unknown>[]; statistics?: Record<string, number> } | null;
    coverage: { key: string; name: string; status: string; note?: string | null }[] | null;
    chainOfCustody: { operations?: { at: string; action: string; target: string }[]; [k: string]: unknown } | null;
    categories: CategoryView[];
  } | null;
  counts: { total: number; severity: Record<string, number>; tier: Record<string, number> };
  verdict: { level: string; title: string; explanation: string };
  detections: DetectionView[];
  lastEventId: string;
  generatedAt: string;
}
