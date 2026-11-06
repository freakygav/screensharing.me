import "server-only";
import type { ActorType, Prisma } from "@prisma/client";
import { db } from "./db";

export interface AuditEntry {
  actorType: ActorType;
  actorId?: string | null;
  action: string;
  targetType?: string;
  targetId?: string;
  details?: Prisma.InputJsonValue;
  ip?: string;
}

export async function audit(entry: AuditEntry, tx: Prisma.TransactionClient = db): Promise<void> {
  await tx.auditLog.create({
    data: {
      actorType: entry.actorType,
      actorId: entry.actorId ?? null,
      action: entry.action,
      targetType: entry.targetType,
      targetId: entry.targetId,
      details: entry.details,
      ip: entry.ip,
    },
  });
}
