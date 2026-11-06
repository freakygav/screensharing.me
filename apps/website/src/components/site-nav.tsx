import Link from "next/link";
import { Logo } from "./icons";
import { getCurrentUser } from "@/lib/auth/session";

export async function SiteNav() {
  const user = await getCurrentUser();
  return (
    <header className="sticky top-0 z-40 border-b border-line bg-[rgba(7,8,12,0.72)] backdrop-blur-md">
      <div className="mx-auto flex h-14 max-w-6xl items-center justify-between px-5">
        <Link href="/" className="flex items-center gap-2.5 text-[15px] font-bold tracking-tight">
          <Logo />
          <span>screensharing<span className="text-accent-2">.me</span></span>
        </Link>
        <nav className="flex items-center gap-1 text-sm">
          <Link href="/features" className="rounded-lg px-3 py-1.5 text-muted transition-colors hover:text-ink">Features</Link>
          <Link href="/docs" className="rounded-lg px-3 py-1.5 text-muted transition-colors hover:text-ink">Docs</Link>
          <Link href="/download" className="rounded-lg px-3 py-1.5 text-muted transition-colors hover:text-ink">Download</Link>
          {user ? (
            <Link href={user.role === "ADMIN" ? "/admin" : "/dashboard"} className="ml-2 rounded-lg bg-panel-2 px-3 py-1.5 text-[13px] font-semibold text-ink ring-1 ring-line hover:ring-line-strong">
              {user.role === "ADMIN" ? "Admin" : "Dashboard"}
            </Link>
          ) : (
            <>
              <Link href="/login" className="rounded-lg px-3 py-1.5 text-muted transition-colors hover:text-ink">Sign in</Link>
              <Link href="/register" className="ml-1 rounded-lg bg-panel-2 px-3 py-1.5 text-[13px] font-semibold text-ink ring-1 ring-line hover:ring-line-strong">Create account</Link>
            </>
          )}
        </nav>
      </div>
    </header>
  );
}

export function SiteFooter() {
  return (
    <footer className="border-t border-line">
      <div className="mx-auto flex max-w-6xl flex-col items-start justify-between gap-4 px-5 py-8 text-xs text-dim sm:flex-row sm:items-center">
        <div className="flex items-center gap-2">
          <Logo size={16} />
          <span>© {new Date().getFullYear()} screensharing.me</span>
        </div>
        <div className="flex gap-5">
          <Link href="/docs" className="hover:text-muted">Documentation</Link>
          <Link href="/docs#privacy" className="hover:text-muted">Privacy &amp; data</Link>
          <Link href="/docs#limitations" className="hover:text-muted">Detection limitations</Link>
          <Link href="/admin/login" className="hover:text-muted">Administrator</Link>
        </div>
      </div>
    </footer>
  );
}
