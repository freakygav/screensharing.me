import "server-only";
import type { User } from "@prisma/client";
import { requireAdmin } from "./auth/session";
import { assertSameOrigin, clientIp } from "./http";
import { audit } from "./audit";
import type { Prisma } from "@prisma/client";

/** Guards an admin mutation: same-origin, admin session, and returns an audit helper bound to the actor. */
export async function adminMutation(req: Request) {
  assertSameOrigin(req);
  const admin: User = await requireAdmin();
  const ip = clientIp(req);
  return {
    admin,
    log: (action: string, targetType: string, targetId: string, details?: Prisma.InputJsonValue) =>
      audit({ actorType: "ADMIN", actorId: admin.id, action, targetType, targetId, details, ip }),
  };
}
