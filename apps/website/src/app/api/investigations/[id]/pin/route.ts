import { assertSameOrigin, handler, json } from "@/lib/http";
import { requireUser } from "@/lib/auth/session";
import { getAuthorizedInvestigation, regeneratePin } from "@/lib/investigations";
import { enforce } from "@/lib/ratelimit";
import { audit } from "@/lib/audit";

export const runtime = "nodejs";

/** Issues a fresh PIN (e.g. after expiry). The previous PIN stops working immediately. */
export const POST = handler(async (req: Request, ctx: { params: Promise<{ id: string }> }) => {
  assertSameOrigin(req);
  const { id } = await ctx.params;
  const user = await requireUser();
  await enforce(`regen-pin:${user.id}`, 20, 3600);
  const inv = await getAuthorizedInvestigation(id, user);
  const r = await regeneratePin(inv);
  await audit({ actorType: user.role === "ADMIN" ? "ADMIN" : "USER", actorId: user.id, action: "investigation.pin_regenerated", targetType: "Investigation", targetId: id });
  return json(r);
});
