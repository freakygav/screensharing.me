import { requireUserPage } from "@/lib/page-auth";
import { PageHeader } from "@/components/app-shell";
import { SettingsForms } from "./settings-forms";
import { fmtDate } from "@/lib/format";

export default async function Settings() {
  const user = await requireUserPage();
  return (
    <div>
      <PageHeader title="Account settings" subtitle={`Signed in as ${user.username}. Member since ${fmtDate(user.createdAt)}.`} />
      <div className="max-w-2xl p-8">
        <SettingsForms email={user.email} emailVerified={Boolean(user.emailVerified)} />
      </div>
    </div>
  );
}
