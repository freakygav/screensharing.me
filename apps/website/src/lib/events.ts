import "server-only";
import { EventEmitter } from "node:events";
import type { Prisma } from "@prisma/client";
import { db } from "./db";

/**
 * Live investigation updates.
 * Every update is appended to InvestigationEvent (durable, ordered, resumable with
 * Last-Event-ID). The in-process emitter only wakes SSE streams early; streams also
 * poll the table so updates written by other server instances are delivered.
 */
const g = globalThis as unknown as { __ssmeBus?: EventEmitter };
export const bus: EventEmitter = g.__ssmeBus ?? new EventEmitter();
bus.setMaxListeners(10_000);
g.__ssmeBus = bus;

export type InvestigationEventType =
  | "investigation.created"
  | "device.connected"
  | "device.heartbeat"
  | "consent.given"
  | "scan.started"
  | "scan.progress"
  | "scan.findings"
  | "scan.completed"
  | "scan.failed"
  | "investigation.cancelled"
  | "pin.regenerated"
  | "pin.expired";

export async function publish(
  investigationId: string,
  type: InvestigationEventType,
  payload: Prisma.InputJsonValue = {},
  tx: Prisma.TransactionClient = db,
): Promise<void> {
  await tx.investigationEvent.create({ data: { investigationId, type, payload } });
  // Emit after the write; when inside a transaction the poll loop is the backstop.
  setImmediate(() => bus.emit(`inv:${investigationId}`));
}
