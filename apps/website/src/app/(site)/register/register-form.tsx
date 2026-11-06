"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";
import { api } from "@/lib/client-api";
import { FormError, Spinner } from "@/components/form-bits";

export function RegisterForm() {
  const router = useRouter();
  const [f, setF] = useState({ username: "", email: "", password: "", confirm: "" });
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const set = (k: keyof typeof f) => (e: React.ChangeEvent<HTMLInputElement>) => setF({ ...f, [k]: e.target.value });

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (f.password !== f.confirm) return setError("Passwords do not match.");
    setBusy(true);
    setError(null);
    try {
      await api("/api/auth/register", { body: { username: f.username, email: f.email, password: f.password } });
      router.replace(f.email ? "/dashboard?welcome=verify" : "/dashboard?welcome=1");
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
        <label className="label" htmlFor="username">Username</label>
        <input id="username" className="input" autoComplete="username" value={f.username} onChange={set("username")} required maxLength={24} autoFocus />
        <p className="hint">3–24 characters: letters, numbers, dot, dash, underscore.</p>
      </div>
      <div>
        <label className="label" htmlFor="email">Email <span className="font-normal text-dim">(optional)</span></label>
        <input id="email" type="email" className="input" autoComplete="email" value={f.email} onChange={set("email")} />
        <p className="hint">Without a verified email you cannot reset your password yourself — an administrator would have to verify you manually.</p>
      </div>
      <div>
        <label className="label" htmlFor="password">Password</label>
        <input id="password" type="password" className="input" autoComplete="new-password" value={f.password} onChange={set("password")} required />
        <p className="hint">At least 10 characters with letters and numbers.</p>
      </div>
      <div>
        <label className="label" htmlFor="confirm">Confirm password</label>
        <input id="confirm" type="password" className="input" autoComplete="new-password" value={f.confirm} onChange={set("confirm")} required />
      </div>
      <button className="btn btn-primary w-full" disabled={busy}>{busy && <Spinner />} Create account</button>
    </form>
  );
}
