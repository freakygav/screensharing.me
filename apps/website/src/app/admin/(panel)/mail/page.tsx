import { db } from "@/lib/db";
import { PageHeader } from "@/components/app-shell";
import { fmtDate } from "@/lib/format";
import { requireAdminPage } from "@/lib/page-auth";
import { audit } from "@/lib/audit";

export default async function AdminMail() {
  const admin = await requireAdminPage();
  await audit({ actorType: "ADMIN", actorId: admin.id, action: "admin.mail_outbox_viewed" });
  const rows = await db.mailOutbox.findMany({ orderBy: { createdAt: "desc" }, take: 100 });
  return (
    <div>
      <PageHeader title="Mail outbox" subtitle={process.env.SMTP_URL ? "Messages sent through SMTP." : "SMTP is not configured: messages are stored here instead of being delivered. Contains one-time links — treat as sensitive."} />
      <div className="space-y-3 p-8">
        {rows.length === 0 && <div className="card-flat px-5 py-10 text-center text-sm text-muted">No mail yet.</div>}
        {rows.map((m) => (
          <details key={m.id} className="card px-5 py-3.5">
            <summary className="flex cursor-pointer items-center justify-between gap-4 text-sm"><span><span className="text-ink">{m.subject}</span> <span className="text-dim">→ {m.to}</span></span><span className="text-xs text-dim">{fmtDate(m.createdAt)} · {m.sentAt ? "sent" : m.error ? "failed" : "outbox"}</span></summary>
            <pre className="mt-3 whitespace-pre-wrap break-all font-mono text-[12px] text-ink-2">{m.body}</pre>
          </details>
        ))}
      </div>
    </div>
  );
}
