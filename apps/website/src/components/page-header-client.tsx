export function PageHeaderClient({ title, subtitle }: { title: string; subtitle?: string }) {
  return (
    <div className="border-b border-line px-8 pb-6 pt-8">
      <h1 className="text-[22px] font-bold tracking-tight">{title}</h1>
      {subtitle && <p className="mt-1 text-sm text-muted">{subtitle}</p>}
    </div>
  );
}
