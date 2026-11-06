import Link from "next/link";
import { Logo } from "./icons";

export function AuthCard({ title, subtitle, children, footer }: { title: string; subtitle?: React.ReactNode; children: React.ReactNode; footer?: React.ReactNode }) {
  return (
    <div className="relative">
      <div className="glow-top pointer-events-none absolute inset-x-0 top-0 h-72" />
      <div className="relative mx-auto flex max-w-[420px] flex-col px-5 py-16">
        <Link href="/" className="mx-auto mb-6"><Logo size={36} /></Link>
        <h1 className="text-center text-2xl font-bold tracking-tight">{title}</h1>
        {subtitle && <p className="mt-2 text-center text-sm text-muted">{subtitle}</p>}
        <div className="card mt-7 p-6">{children}</div>
        {footer && <div className="mt-5 text-center text-sm text-muted">{footer}</div>}
      </div>
    </div>
  );
}
