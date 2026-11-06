import { redirect } from "next/navigation";
import { AppShell } from "@/components/app-shell";
import { getCurrentUser } from "@/lib/auth/session";
import { IconGrid, IconList, IconPlus, IconSettings, IconClock, IconShield } from "@/components/icons";

export const dynamic = "force-dynamic";

export default async function DashboardLayout({ children }: { children: React.ReactNode }) {
  const user = await getCurrentUser();
  if (!user) redirect("/login?next=/dashboard");
  const items = [
    { href: "/dashboard", label: "Overview", icon: <IconGrid />, exact: true },
    { href: "/dashboard/investigations/new", label: "New investigation", icon: <IconPlus />, exact: true },
    { href: "/dashboard/investigations?scope=active", label: "Active", icon: <IconClock />, exact: true },
    { href: "/dashboard/investigations", label: "History & reports", icon: <IconList /> },
    { href: "/dashboard/settings", label: "Account settings", icon: <IconSettings /> },
    ...(user.role === "ADMIN" ? [{ href: "/admin", label: "Admin console", icon: <IconShield /> }] : []),
  ];
  return <AppShell items={items} user={user}>{children}</AppShell>;
}
