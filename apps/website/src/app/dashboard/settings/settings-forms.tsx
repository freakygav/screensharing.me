"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";
import { api } from "@/lib/client-api";
import { FormError, FormSuccess, Spinner } from "@/components/form-bits";

export function SettingsForms({ email, emailVerified }: { email: string | null; emailVerified: boolean }) {
  const router = useRouter();
  const [pw, setPw] = useState({ currentPassword: "", newPassword: "", confirm: "" });
  const [pwMsg, setPwMsg] = useState<{ ok?: string; err?: string }>({});
  const [em, setEm] = useState({ email: email ?? "", currentPassword: "" });
  const [emMsg, setEmMsg] = useState<{ ok?: string; err?: string }>({});
  const [busy, setBusy] = useState<string | null>(null);

  return (
    <div className="space-y-6">
      <form className="card space-y-4 p-6" onSubmit={async (e) => {
        e.preventDefault();
        if (pw.newPassword !== pw.confirm) return setPwMsg({ err: "New passwords do not match." });
        setBusy("pw"); setPwMsg({});
        try { await api("/api/account/password", { body: { currentPassword: pw.currentPassword, newPassword: pw.newPassword } }); setPwMsg({ ok: "Password changed. Other sessions were signed out." }); setPw({ currentPassword: "", newPassword: "", confirm: "" }); }
        catch (err) { setPwMsg({ err: (err as Error).message }); }
        finally { setBusy(null); }
      }}>
        <h2 className="font-semibold">Change password</h2>
        <FormError message={pwMsg.err ?? null} /><FormSuccess message={pwMsg.ok ?? null} />
        <div><label className="label">Current password</label><input type="password" className="input" autoComplete="current-password" value={pw.currentPassword} onChange={(e) => setPw({ ...pw, currentPassword: e.target.value })} /></div>
        <div className="grid gap-4 sm:grid-cols-2">
          <div><label className="label">New password</label><input type="password" className="input" autoComplete="new-password" value={pw.newPassword} onChange={(e) => setPw({ ...pw, newPassword: e.target.value })} /></div>
          <div><label className="label">Confirm new password</label><input type="password" className="input" autoComplete="new-password" value={pw.confirm} onChange={(e) => setPw({ ...pw, confirm: e.target.value })} /></div>
        </div>
        <button className="btn btn-primary" disabled={busy === "pw"}>{busy === "pw" && <Spinner />} Update password</button>
      </form>

      <form className="card space-y-4 p-6" onSubmit={async (e) => {
        e.preventDefault();
        setBusy("em"); setEmMsg({});
        try {
          const r = await api<{ verificationSent: boolean }>("/api/account/email", { body: em });
          setEmMsg({ ok: r.verificationSent ? "Email saved. Check your inbox to verify it." : "Email settings saved." });
          setEm({ ...em, currentPassword: "" });
          router.refresh();
        } catch (err) { setEmMsg({ err: (err as Error).message }); }
        finally { setBusy(null); }
      }}>
        <div className="flex items-center justify-between">
          <h2 className="font-semibold">Email address</h2>
          {email && <span className={`chip ${emailVerified ? "text-ok" : "text-med"}`}>{emailVerified ? "Verified" : "Unverified"}</span>}
        </div>
        <p className="text-[13px] text-muted">A verified email lets you reset your password yourself. Leave empty to remove it — you would then need an administrator to recover the account.</p>
        <FormError message={emMsg.err ?? null} /><FormSuccess message={emMsg.ok ?? null} />
        <div><label className="label">Email</label><input type="email" className="input" value={em.email} onChange={(e) => setEm({ ...em, email: e.target.value })} /></div>
        <div><label className="label">Current password</label><input type="password" className="input" autoComplete="current-password" value={em.currentPassword} onChange={(e) => setEm({ ...em, currentPassword: e.target.value })} /></div>
        <button className="btn btn-secondary" disabled={busy === "em" || !em.currentPassword}>{busy === "em" && <Spinner />} Save email</button>
      </form>
    </div>
  );
}
