"use client";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { IconLogout } from "./icons";
import { api } from "@/lib/client-api";

export function NavLink({ href, label, icon, exact }: { href: string; label: string; icon: React.ReactNode; exact?: boolean }) {
  const path = usePathname();
  const active = exact ? path === href : path === href || path.startsWith(href + "/");
  return (
    <Link
      href={href}
      className={`flex items-center gap-2.5 rounded-[9px] px-3 py-2 text-[13.5px] transition-colors ${active ? "bg-panel-2 font-semibold text-ink ring-1 ring-line" : "text-muted hover:bg-[#11141c] hover:text-ink"}`}
    >
      <span className={active ? "text-accent-2" : ""}>{icon}</span>
      {label}
    </Link>
  );
}

export function SignOutButton() {
  const router = useRouter();
  return (
    <button
      title="Sign out"
      aria-label="Sign out"
      className="rounded-lg p-1.5 text-dim hover:bg-panel-2 hover:text-ink"
      onClick={async () => {
        await api("/api/auth/logout", { method: "POST", body: {} }).catch(() => undefined);
        router.replace("/login");
        router.refresh();
      }}
    >
      <IconLogout />
    </button>
  );
}
