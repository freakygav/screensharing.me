const SEV: Record<string, string> = {
  CRITICAL: "text-[#f6c3c5] bg-[rgba(229,72,77,.12)] border-[rgba(229,72,77,.4)]",
  HIGH: "text-[#f7cdb8] bg-[rgba(239,122,69,.1)] border-[rgba(239,122,69,.35)]",
  MEDIUM: "text-[#efd9a6] bg-[rgba(217,165,58,.09)] border-[rgba(217,165,58,.3)]",
  LOW: "text-[#cbd3e3] bg-[rgba(125,143,176,.1)] border-[rgba(125,143,176,.3)]",
  INFO: "text-muted bg-panel-2 border-line",
};
export const SEV_DOT: Record<string, string> = { CRITICAL: "bg-crit", HIGH: "bg-high", MEDIUM: "bg-med", LOW: "bg-low", INFO: "bg-info" };

export function SeverityBadge({ severity }: { severity: string }) {
  return <span className={`chip ${SEV[severity] ?? SEV.INFO}`}>{severity}</span>;
}

export const TIER_LABEL: Record<string, string> = {
  CONFIRMED_ARTIFACT: "Confirmed artifact",
  STRONG_INDICATOR: "Strong indicator",
  SUSPICIOUS_CONFIGURATION: "Suspicious config",
  WEAK_INDICATOR: "Weak indicator",
  INCONCLUSIVE: "Inconclusive",
};

export const OUTCOME_LABEL: Record<string, string> = {
  CONFIRMED: "Confirmed",
  HIGH_CONFIDENCE: "High confidence",
  LOW_CONFIDENCE: "Low confidence",
  UNABLE_TO_INSPECT: "Not inspected",
  INFORMATIONAL: "Informational",
};
const OUTCOME_CLS: Record<string, string> = {
  CONFIRMED: "text-[#f6c3c5] border-[rgba(229,72,77,.4)] bg-[rgba(229,72,77,.12)]",
  HIGH_CONFIDENCE: "text-[#f7cdb8] border-[rgba(239,122,69,.35)] bg-[rgba(239,122,69,.1)]",
  LOW_CONFIDENCE: "text-[#efd9a6] border-[rgba(217,165,58,.3)] bg-[rgba(217,165,58,.08)]",
  UNABLE_TO_INSPECT: "text-ink-2 border-line-strong",
  INFORMATIONAL: "",
};

/** Confirmed vs. needs-manual-review, the distinction investigators act on. */
export function OutcomeBadge({ outcome }: { outcome: string }) {
  return <span className={`chip ${OUTCOME_CLS[outcome] ?? ""}`}>{OUTCOME_LABEL[outcome] ?? outcome}</span>;
}

export function TierBadge({ tier }: { tier: string }) {
  const strong = tier === "CONFIRMED_ARTIFACT" || tier === "STRONG_INDICATOR";
  return <span className={`chip ${strong ? "chip-accent" : ""}`}>{TIER_LABEL[tier] ?? tier}</span>;
}

const STATUS: Record<string, { label: string; cls: string; dot?: string }> = {
  WAITING: { label: "Waiting for desktop", cls: "text-ink-2", dot: "bg-med pulse-dot" },
  CONNECTED: { label: "Connected", cls: "text-ink-2", dot: "bg-blue pulse-dot" },
  SCANNING: { label: "Scanning", cls: "text-ink", dot: "bg-accent pulse-dot" },
  COMPLETED: { label: "Completed", cls: "text-ink-2", dot: "bg-ok" },
  FAILED: { label: "Failed", cls: "text-ink-2", dot: "bg-crit" },
  CANCELLED: { label: "Cancelled", cls: "text-muted", dot: "bg-dim" },
  EXPIRED: { label: "PIN expired", cls: "text-muted", dot: "bg-dim" },
};

export function StatusBadge({ status }: { status: string }) {
  const s = STATUS[status] ?? { label: status, cls: "text-muted", dot: "bg-dim" };
  return (
    <span className={`chip ${s.cls}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${s.dot}`} />
      {s.label}
    </span>
  );
}
