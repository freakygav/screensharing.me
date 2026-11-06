const SEV: Record<string, string> = {
  CRITICAL: "text-[#ffd4dc] bg-[rgba(255,77,106,.14)] border-[rgba(255,77,106,.4)]",
  HIGH: "text-[#ffd9c4] bg-[rgba(255,138,76,.12)] border-[rgba(255,138,76,.35)]",
  MEDIUM: "text-[#fbe7b0] bg-[rgba(245,196,81,.1)] border-[rgba(245,196,81,.32)]",
  LOW: "text-[#cbe9ff] bg-[rgba(77,184,255,.1)] border-[rgba(77,184,255,.3)]",
  INFO: "text-muted bg-[#121620] border-line",
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

export function TierBadge({ tier }: { tier: string }) {
  const strong = tier === "CONFIRMED_ARTIFACT" || tier === "STRONG_INDICATOR";
  return <span className={`chip ${strong ? "border-[rgba(124,92,255,.4)] text-[#d8ceff] bg-[rgba(124,92,255,.12)]" : ""}`}>{TIER_LABEL[tier] ?? tier}</span>;
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
