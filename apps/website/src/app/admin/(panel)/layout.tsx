import { AppShell } from "@/components/app-shell";
import { requireAdminPage } from "@/lib/page-auth";
import { IconGrid, IconUsers, IconList, IconRules, IconBox, IconLog, IconMonitor, IconSettings, IconMail } from "@/components/icons";

export const dynamic = "force-dynamic";

export default async function AdminLayout({ children }: { children: React.ReactNode }) {
  const user = await requireAdminPage();
  const items = [
    { href: "/admin", label: "Overview", icon: <IconGrid />, exact: true },
    { href: "/admin/investigations", label: "Investigations", icon: <IconList /> },
    { href: "/admin/users", label: "Users", icon: <IconUsers /> },
    { href: "/admin/sessions", label: "Sessions & devices", icon: <IconMonitor /> },
    { href: "/admin/rules", label: "Detection catalog", icon: <IconRules /> },
    { href: "/admin/versions", label: "App versions", icon: <IconBox /> },
    { href: "/admin/audit", label: "Audit log", icon: <IconLog /> },
    { href: "/admin/config", label: "Configuration", icon: <IconSettings /> },
    { href: "/admin/mail", label: "Mail outbox", icon: <IconMail /> },
    { href: "/dashboard", label: "My dashboard", icon: <IconGrid />, exact: true },
  ];
  return <AppShell items={items} user={user} badge="ADMINISTRATOR">{children}</AppShell>;
}
