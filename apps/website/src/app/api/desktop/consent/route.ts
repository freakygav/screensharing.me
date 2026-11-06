import { db } from "@/lib/db";
import { clientIp, conflict, handler, json, readJson } from "@/lib/http";
import { requireDevice } from "@/lib/investigations";
import { publish } from "@/lib/events";
import { audit } from "@/lib/audit";
import { z } from "zod";

export const runtime = "nodejs";

const schema = z.object({ accepted: z.literal(true), consentVersion: z.string().max(20) });

/** The player explicitly authorises the scan on the desktop. Nothing is collected before this. */
export const POST = handler(async (req: Request) => {
  const device = await requireDevice(req);
  const body = await readJson(req, schema, 4096);
  if (device.investigation.status !== "CONNECTED") throw conflict("Consent has already been recorded or the investigation is not awaiting consent.");
  const now = new Date();
  await db.$transaction(async (tx) => {
    await tx.investigation.update({ where: { id: device.investigationId }, data: { consentedAt: now } });
    await publish(device.investigationId, "consent.given", { consentVersion: body.consentVersion }, tx);
  });
  await audit({ actorType: "DEVICE", action: "desktop.consent_given", targetType: "Investigation", targetId: device.investigationId, ip: clientIp(req), details: { consentVersion: body.consentVersion, deviceId: device.id } });
  return json({ ok: true, consentedAt: now });
});
