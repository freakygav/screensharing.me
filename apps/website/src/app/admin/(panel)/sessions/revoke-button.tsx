"use client";
import { useRouter } from "next/navigation";
import { api } from "@/lib/client-api";

export function RevokeButton({ path }: { path: string }) {
  const router = useRouter();
  return <button className="btn btn-ghost btn-sm text-crit" onClick={async () => { await api(path, { method: "DELETE" }).catch((e) => alert(e.message)); router.refresh(); }}>Revoke</button>;
}
