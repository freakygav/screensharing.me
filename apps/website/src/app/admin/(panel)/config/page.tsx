import { PageHeader } from "@/components/app-shell";
import { getConfig, getRulesetVersion } from "@/lib/config";
import { env } from "@/lib/env";
import { ConfigForm } from "./config-form";

export default async function AdminConfig() {
  const [cfg, ruleset] = await Promise.all([getConfig(), getRulesetVersion()]);
  return (
    <div>
      <PageHeader title="System configuration" subtitle="Runtime settings stored in the database. Secrets remain in environment variables and are never shown here." />
      <div className="max-w-2xl space-y-6 p-8">
        <ConfigForm initial={cfg} />
        <div className="card p-5 text-[13px]">
          <div className="font-semibold">Environment (read-only)</div>
          <dl className="mt-3 space-y-1.5">
            {[["Public origin", env.appOrigin], ["Desktop token TTL", `${env.desktopTokenTtlMinutes} min (sliding, max 12h)`], ["Web session", `${env.webSessionDays} days (admins ${env.adminSessionHours}h)`], ["Ruleset version", ruleset], ["SMTP", process.env.SMTP_URL ? "configured" : "not configured — mail goes to outbox only"], ["Node environment", process.env.NODE_ENV ?? "development"]].map(([k, v]) => (
              <div key={k} className="flex justify-between gap-4"><dt className="text-dim">{k}</dt><dd className="font-mono text-[12px] text-ink-2">{v}</dd></div>
            ))}
          </dl>
        </div>
      </div>
    </div>
  );
}
