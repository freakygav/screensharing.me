"use client";
import { useState } from "react";

export function FormError({ message }: { message: string | null }) {
  if (!message) return null;
  return (
    <div role="alert" className="fade-up rounded-[10px] border border-[rgba(255,77,106,.35)] bg-[rgba(255,77,106,.08)] px-3.5 py-2.5 text-[13px] text-[#ffd4dc]">
      {message}
    </div>
  );
}

export function FormSuccess({ message }: { message: string | null }) {
  if (!message) return null;
  return (
    <div role="status" className="fade-up rounded-[10px] border border-[rgba(61,220,151,.3)] bg-[rgba(61,220,151,.07)] px-3.5 py-2.5 text-[13px] text-[#c9f7e1]">
      {message}
    </div>
  );
}

export function Spinner({ className = "" }: { className?: string }) {
  return <span className={`inline-block h-3.5 w-3.5 animate-spin rounded-full border-2 border-white/25 border-t-white ${className}`} aria-hidden />;
}

export function CopyButton({ value, label = "Copy" }: { value: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      className="btn btn-secondary btn-sm"
      onClick={async () => {
        await navigator.clipboard.writeText(value);
        setDone(true);
        setTimeout(() => setDone(false), 1400);
      }}
    >
      {done ? "Copied" : label}
    </button>
  );
}
