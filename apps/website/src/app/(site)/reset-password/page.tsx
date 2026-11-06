"use client";
import { Suspense, useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { AuthCard } from "@/components/auth-card";
import { api } from "@/lib/client-api";
import { FormError, FormSuccess, Spinner } from "@/components/form-bits";

function ResetForm() {
  const token = useSearchParams().get("token") ?? "";
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  if (done) return <div className="space-y-4"><FormSuccess message="Your password has been changed and all sessions were signed out." /><Link href="/login" className="btn btn-primary w-full">Sign in</Link></div>;
  return (
    <form
      className="space-y-4"
      onSubmit={async (e) => {
        e.preventDefault();
        if (password !== confirm) return setError("Passwords do not match.");
        setBusy(true); setError(null);
        try { await api("/api/auth/reset-password", { body: { token, password } }); setDone(true); }
        catch (err) { setError((err as Error).message); }
        finally { setBusy(false); }
      }}
    >
      <FormError message={token ? error : "This page needs a reset link token."} />
      <div><label className="label" htmlFor="pw">New password</label><input id="pw" type="password" className="input" autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} /></div>
      <div><label className="label" htmlFor="pw2">Confirm password</label><input id="pw2" type="password" className="input" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} /></div>
      <button className="btn btn-primary w-full" disabled={busy || !token}>{busy && <Spinner />} Set new password</button>
    </form>
  );
}

export default function ResetPassword() {
  return <AuthCard title="Choose a new password"><Suspense><ResetForm /></Suspense></AuthCard>;
}
