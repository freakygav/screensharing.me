import { Suspense } from "react";
import Link from "next/link";
import { redirect } from "next/navigation";
import { AuthCard } from "@/components/auth-card";
import { LoginForm } from "@/components/login-form";
import { getCurrentUser } from "@/lib/auth/session";

export const metadata = { title: "Sign in" };

export default async function LoginPage() {
  if (await getCurrentUser()) redirect("/dashboard");
  return (
    <AuthCard title="Welcome back" subtitle="Sign in with your username or email address." footer={<>New to screensharing.me? <Link href="/register" className="text-accent-2 hover:underline">Create an account</Link></>}>
      <Suspense><LoginForm /></Suspense>
    </AuthCard>
  );
}
