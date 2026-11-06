import "server-only";
import { redirect } from "next/navigation";
import { getCurrentUser } from "./auth/session";

export async function requireUserPage() {
  const u = await getCurrentUser();
  if (!u) redirect("/login");
  return u;
}

export async function requireAdminPage() {
  const u = await getCurrentUser();
  if (!u) redirect("/admin/login");
  if (u.role !== "ADMIN") redirect("/dashboard");
  return u;
}
