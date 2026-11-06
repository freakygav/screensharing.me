import { notFound } from "next/navigation";
import { db } from "@/lib/db";
import { buildSnapshot } from "@/lib/investigations";
import { requireAdminPage } from "@/lib/page-auth";
import { audit } from "@/lib/audit";
import { InvestigationLive } from "@/components/investigation-live";

export default async function AdminInvestigation({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const admin = await requireAdminPage();
  const inv = await db.investigation.findUnique({ where: { id }, select: { ownerId: true } });
  if (!inv) notFound();
  if (inv.ownerId !== admin.id) await audit({ actorType: "ADMIN", actorId: admin.id, action: "admin.investigation_viewed", targetType: "Investigation", targetId: id });
  const snap = await buildSnapshot(id);
  return <InvestigationLive initial={JSON.parse(JSON.stringify(snap))} backHref="/admin/investigations" />;
}
