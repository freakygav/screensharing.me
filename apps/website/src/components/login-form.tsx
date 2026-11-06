"use client";
import { useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import Link from "next/link";
import { api } from "@/lib/client-api";
import { FormError, Spinner } from "./form-bits";

export function LoginForm({ adminOnly = false }: { adminOnly?: boolean }) {
  const router = useRouter();
  const params = useSearchParams();
  const [identifier, setIdentifier] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const r = await api<{ user: { role: string } }>("/api/auth/login", { body: { identifier, password, adminOnly } });
      const next = params.get("next");
      const safeNext = next && next.startsWith("/") && !next.startsWith("//") ? next : null;
      router.replace(safeNext ?? (adminOnly || r.user.role === "ADMIN" ? "/admin" : "/dashboard"));
      router.refresh();
    } catch (err) {
      setError((err as Error).message);
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="space-y-4" noValidate>
      <FormError message={error} />
      <div>
        <label className="label" htmlFor="identifier">{adminOnly ? "Administrator email or username" : "Username or email"}</label>
        <input id="identifier" className="input" autoComplete="username" value={identifier} onChange={(e) => setIdentifier(e.target.value)} required autoFocus />
      </div>
      <div>
        <div className="flex items-center justify-between">
          <label className="label" htmlFor="password">Password</label>
          {!adminOnly && <Link href="/forgot-password" className="mb-1.5 text-xs text-muted hover:text-ink">Forgot password?</Link>}
        </div>
        <input id="password" type="password" className="input" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required />
      </div>
      <button className="btn btn-primary w-full" disabled={busy || !identifier || !password}>
        {busy && <Spinner />} {adminOnly ? "Sign in to admin console" : "Sign in"}
      </button>
    </form>
  );
}
