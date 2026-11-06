import { clientIp, handler, HttpError, json, readJson } from "@/lib/http";
import { claimPinSchema } from "@/lib/validation";
import { normalizePin } from "@/lib/crypto";
import { assertAppVersionAllowed, claimPin } from "@/lib/investigations";
import { enforce, hit, peek } from "@/lib/ratelimit";
import { audit } from "@/lib/audit";
import { getRulesetVersion } from "@/lib/config";

export const runtime = "nodejs";

const INVALID = "That PIN is invalid, expired or already used. Ask the investigator for a new PIN.";

/**
 * Exchanges a one-time investigation PIN for a short-lived, investigation-scoped device token.
 * Brute-force protection: per-IP limit (10 / 10 min), plus a global failure circuit breaker
 * (300 failed claims / minute across all clients) that pauses claims system-wide.
 */
export const POST = handler(async (req: Request) => {
  const ip = clientIp(req);
  await enforce(`pin-ip:${ip}`, 10, 600);
  if ((await peek("pin-global-fail", 60)) >= 300) throw new HttpError(503, "pin_claims_paused", "PIN entry is temporarily paused. Try again in a minute.");

  const body = await readJson(req, claimPinSchema, 8 * 1024);
  await assertAppVersionAllowed(body.appVersion);
  const digits = normalizePin(body.pin);
  const claimed = digits ? await claimPin(digits, { appVersion: body.appVersion, osVersion: body.osVersion, elevated: body.elevated, ip }) : null;
  if (!claimed) {
    await hit("pin-global-fail", Number.MAX_SAFE_INTEGER, 60);
    await audit({ actorType: "ANONYMOUS", action: "desktop.pin_claim_failed", ip, details: { appVersion: body.appVersion } });
    throw new HttpError(404, "invalid_pin", INVALID);
  }
  await audit({ actorType: "DEVICE", action: "desktop.pin_claimed", targetType: "Investigation", targetId: claimed.investigation.id, ip, details: { appVersion: body.appVersion, deviceId: claimed.device.id } });
  return json({
    deviceToken: claimed.token,
    tokenExpiresAt: claimed.tokenExpiresAt,
    investigation: claimed.investigation,
    rulesetVersion: await getRulesetVersion(),
    consent: {
      version: "2026-11",
      text:
        "The investigator has asked you to run a forensic scan for Minecraft modifications. With your consent, screensharing.me will read: Minecraft and launcher folders (mods, versions, logs, configs), Java installations, running Java processes and their loaded modules and memory, Windows execution records (Prefetch, BAM), the Recycle Bin and NTFS change journal entries for Java archives and executables, selected event logs and service settings. It does not read browser data, passwords, launcher account tokens, documents or photos, and it does not modify any file. Findings and file hashes are sent to the investigator.",
    },
  });
});
