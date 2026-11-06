"use client";
import { Suspense, useEffect, useRef, useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { AuthCard } from "@/components/auth-card";
import { api } from "@/lib/client-api";
import { FormError, FormSuccess, Spinner } from "@/components/form-bits";

function Verify() {
  const token = useSearchParams().get("token") ?? "";
  const [state, setState] = useState<"working" | "ok" | "error">("working");
  const [error, setError] = useState<string | null>(null);
  const ran = useRef(false);
  useEffect(() => {
    if (ran.current) return;
    ran.current = true;
    if (!token) { setState("error"); setError("Missing verification token."); return; }
    api("/api/auth/verify-email", { body: { token } }).then(() => setState("ok")).catch((e) => { setState("error"); setError(e.message); });
  }, [token]);
  if (state === "working") return <div className="flex items-center justify-center gap-2 text-sm text-muted"><Spinner /> Verifying…</div>;
  if (state === "ok") return <div className="space-y-4"><FormSuccess message="Your email address is verified." /><Link href="/dashboard" className="btn btn-primary w-full">Go to dashboard</Link></div>;
  return <FormError message={error} />;
}

export default function VerifyEmail() {
  return <AuthCard title="Email verification"><Suspense><Verify /></Suspense></AuthCard>;
}
