"use client";
import { useState } from "react";
import Link from "next/link";
import { AuthCard } from "@/components/auth-card";
import { api } from "@/lib/client-api";
import { FormError, FormSuccess, Spinner } from "@/components/form-bits";

export default function ForgotPassword() {
  const [email, setEmail] = useState("");
  const [msg, setMsg] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  return (
    <AuthCard title="Reset your password" subtitle="We'll email a one-time link to your verified address." footer={<Link href="/login" className="text-accent-2 hover:underline">Back to sign in</Link>}>
      <form
        className="space-y-4"
        onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true); setError(null); setMsg(null);
          try { const r = await api<{ message: string }>("/api/auth/request-reset", { body: { email } }); setMsg(r.message); }
          catch (err) { setError((err as Error).message); }
          finally { setBusy(false); }
        }}
      >
        <FormError message={error} />
        <FormSuccess message={msg} />
        <div>
          <label className="label" htmlFor="email">Email address</label>
          <input id="email" type="email" className="input" value={email} onChange={(e) => setEmail(e.target.value)} required />
        </div>
        <button className="btn btn-primary w-full" disabled={busy || !email}>{busy && <Spinner />} Send reset link</button>
        <p className="text-xs leading-relaxed text-dim">Registered without an email? Self-service reset is not possible; contact an administrator, who can verify you and issue a one-time link.</p>
      </form>
    </AuthCard>
  );
}
