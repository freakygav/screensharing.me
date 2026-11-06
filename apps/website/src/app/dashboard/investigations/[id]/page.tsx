import { notFound } from "next/navigation";
import { requireUserPage } from "@/lib/page-auth";
import { buildSnapshot, expireStalePins } from "@/lib/investigations";
import { db } from "@/lib/db";
import { InvestigationLive } from "@/components/investigation-live";

export default async function InvestigationPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const user = await requireUserPage();
  const inv = await db.investigation.findUnique({ where: { id }, select: { ownerId: true } });
  if (!inv || (inv.ownerId !== user.id && user.role !== "ADMIN")) notFound();
  await expireStalePins({ id });
  const snap = await buildSnapshot(id);
  return <InvestigationLive initial={JSON.parse(JSON.stringify(snap))} backHref="/dashboard/investigations" />;
}
