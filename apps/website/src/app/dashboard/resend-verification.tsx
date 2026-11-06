"use client";
import { useState } from "react";
import { api } from "@/lib/client-api";

export function ResendVerification() {
  const [state, setState] = useState<string | null>(null);
  return (
    <button className="btn btn-secondary btn-sm" disabled={state === "sent"} onClick={async () => {
      try { await api("/api/account/resend-verification", { method: "POST", body: {} }); setState("sent"); }
      catch (e) { setState((e as Error).message); }
    }}>
      {state === "sent" ? "Verification email sent" : state ?? "Resend verification"}
    </button>
  );
}
