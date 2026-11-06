import { db } from "@/lib/db";
import { PageHeader } from "@/components/app-shell";
import { compareSemver } from "@/lib/semver";
import { VersionsManager } from "./versions-manager";

export default async function AdminVersions() {
  const [versions, usage] = await Promise.all([
    db.applicationVersion.findMany(),
    db.connectedDevice.groupBy({ by: ["appVersion"], _count: { _all: true } }),
  ]);
  versions.sort((a, b) => compareSemver(b.version, a.version));
  return (
    <div>
      <PageHeader title="Application versions" subtitle="Inactive versions are refused at PIN entry. Versions older than the newest 'minimum supported' release are refused too." />
      <div className="p-8"><VersionsManager versions={JSON.parse(JSON.stringify(versions))} usage={Object.fromEntries(usage.map((u) => [u.appVersion, u._count._all]))} /></div>
    </div>
  );
}
