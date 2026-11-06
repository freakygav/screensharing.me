import Link from "next/link";

export default function NotFound() {
  return (
    <div className="flex min-h-screen flex-col items-center justify-center px-5 text-center">
      <div className="font-mono text-sm text-accent-2">404</div>
      <h1 className="mt-2 text-2xl font-bold">Not found</h1>
      <p className="mt-2 text-sm text-muted">The page doesn&apos;t exist or you don&apos;t have access to it.</p>
      <Link href="/" className="btn btn-secondary mt-6">Go home</Link>
    </div>
  );
}
