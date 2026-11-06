import Link from "next/link";
import { Logo } from "./icons";
import { NavLink, SignOutButton } from "./nav-client";

export interface NavItem { href: string; label: string; icon: React.ReactNode; exact?: boolean }

export function AppShell({ items, user, badge, children }: { items: NavItem[]; user: { displayName: string; role: string; email: string | null }; badge?: string; children: React.ReactNode }) {
  return (
    <div className="flex min-h-screen">
      <aside className="sticky top-0 flex h-screen w-60 shrink-0 flex-col border-r border-line bg-bg">
        <Link href="/" className="flex h-14 items-center gap-2.5 border-b border-line px-5 text-[15px] font-bold tracking-tight">
          <Logo />
          <span>screensharing<span className="text-accent-2">.me</span></span>
        </Link>
        {badge && <div className="px-5 pt-4"><span className="chip border-accent/40 accent-soft text-ink">{badge}</span></div>}
        <nav className="flex-1 space-y-0.5 overflow-y-auto p-3">
          {items.map((i) => <NavLink key={i.href} {...i} />)}
        </nav>
        <div className="border-t border-line p-3">
          <div className="flex items-center gap-3 rounded-md px-2 py-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-full bg-panel-2 border border-line-strong text-xs font-bold text-white">{user.displayName.slice(0, 2).toUpperCase()}</div>
            <div className="min-w-0 flex-1">
              <div className="truncate text-[13px] font-semibold">{user.displayName}</div>
              <div className="truncate text-[11.5px] text-dim">{user.role === "ADMIN" ? "Administrator" : user.email ?? "No email"}</div>
            </div>
            <SignOutButton />
          </div>
        </div>
      </aside>
      <main className="min-w-0 flex-1">{children}</main>
    </div>
  );
}

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: React.ReactNode; actions?: React.ReactNode }) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-4 border-b border-line px-8 pb-6 pt-8">
      <div>
        <h1 className="text-[22px] font-bold tracking-tight">{title}</h1>
        {subtitle && <p className="mt-1 text-sm text-muted">{subtitle}</p>}
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  );
}

export function StatCard({ label, value, hint, accent }: { label: string; value: React.ReactNode; hint?: React.ReactNode; accent?: string }) {
  return (
    <div className="card p-5">
      <div className="text-xs font-medium text-muted">{label}</div>
      <div className={`mt-2 text-[26px] font-bold tracking-tight ${accent ?? ""}`}>{value}</div>
      {hint && <div className="mt-1 text-xs text-dim">{hint}</div>}
    </div>
  );
}
