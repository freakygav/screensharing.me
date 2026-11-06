import { Suspense } from "react";
import Link from "next/link";
import { AuthCard } from "@/components/auth-card";
import { LoginForm } from "@/components/login-form";
import { IconLock } from "@/components/icons";

export const metadata = { title: "Administrator sign in" };

export default function AdminLogin() {
  return (
    <div className="min-h-screen">
      <AuthCard
        title="Administrator console"
        subtitle={<span className="inline-flex items-center gap-1.5"><IconLock size={13} /> Restricted. All sign-in attempts are audited.</span>}
        footer={<Link href="/" className="hover:text-ink">Return to screensharing.me</Link>}
      >
        <Suspense><LoginForm adminOnly /></Suspense>
      </AuthCard>
    </div>
  );
}
