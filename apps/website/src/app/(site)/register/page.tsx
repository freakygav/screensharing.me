import Link from "next/link";
import { redirect } from "next/navigation";
import { AuthCard } from "@/components/auth-card";
import { RegisterForm } from "./register-form";
import { getCurrentUser } from "@/lib/auth/session";
import { getConfig } from "@/lib/config";

export const metadata = { title: "Create account" };

export default async function RegisterPage() {
  if (await getCurrentUser()) redirect("/dashboard");
  const cfg = await getConfig();
  return (
    <AuthCard title="Create your account" subtitle="Run forensic screenshares for your server." footer={<>Already have an account? <Link href="/login" className="text-accent-2 hover:underline">Sign in</Link></>}>
      {cfg.registrationOpen ? <RegisterForm /> : <p className="text-sm text-muted">Registration is currently closed by the administrators.</p>}
    </AuthCard>
  );
}
