import { handler, json } from "@/lib/http";
import { requireUser } from "@/lib/auth/session";
import { buildSnapshot, expireStalePins, getAuthorizedInvestigation } from "@/lib/investigations";
import { audit } from "@/lib/audit";

export const runtime = "nodejs";

export const GET = handler(async (_req: Request, ctx: { params: Promise<{ id: string }> }) => {
  const { id } = await ctx.params;
  const user = await requireUser();
  const inv = await getAuthorizedInvestigation(id, user);
  await expireStalePins({ id });
  if (user.role === "ADMIN" && inv.ownerId !== user.id) {
    await audit({ actorType: "ADMIN", actorId: user.id, action: "admin.investigation_viewed", targetType: "Investigation", targetId: id });
  }
  return json(await buildSnapshot(id));
});
