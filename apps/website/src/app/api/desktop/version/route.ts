import { handler, json } from "@/lib/http";
import { db } from "@/lib/db";
import { compareSemver } from "@/lib/semver";

export const runtime = "nodejs";

/** Public: lets the desktop app check for updates before connecting. */
export const GET = handler(async (req: Request) => {
  const current = new URL(req.url).searchParams.get("current") ?? "0.0.0";
  const versions = (await db.applicationVersion.findMany({ where: { active: true, channel: "stable" } })).sort((a, b) => compareSemver(b.version, a.version));
  const latest = versions[0] ?? null;
  const minimum = versions.filter((v) => v.minimumSupported).sort((a, b) => compareSemver(b.version, a.version))[0] ?? null;
  return json({
    latest: latest && { version: latest.version, downloadUrl: latest.downloadUrl, sha256: latest.sha256, notes: latest.notes },
    minimumSupported: minimum?.version ?? null,
    updateAvailable: latest ? compareSemver(latest.version, current) > 0 : false,
    supported: minimum ? compareSemver(current, minimum.version) >= 0 : true,
  });
});
