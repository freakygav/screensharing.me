import Link from "next/link";

export const metadata = { title: "Documentation" };

function Section({ id, title, children }: { id: string; title: string; children: React.ReactNode }) {
  return (
    <section id={id} className="scroll-mt-20 border-b border-line py-10 last:border-0">
      <h2 className="text-xl font-bold tracking-tight">{title}</h2>
      <div className="mt-4 space-y-3 text-[14.5px] leading-relaxed text-ink-2">{children}</div>
    </section>
  );
}

export default function Docs() {
  const toc = [["workflow", "Investigation workflow"], ["tiers", "Evidence tiers"], ["modules", "Collection modules"], ["limitations", "Detection limitations"], ["privacy", "Privacy & data"], ["security", "Security model"], ["recovery", "Account recovery"]];
  return (
    <div className="mx-auto grid max-w-6xl gap-10 px-5 py-14 lg:grid-cols-[220px_1fr]">
      <aside className="hidden lg:block">
        <div className="sticky top-20 space-y-1 text-sm">
          {toc.map(([id, t]) => (<a key={id} href={`#${id}`} className="block rounded-lg px-3 py-1.5 text-muted hover:bg-panel-2 hover:text-ink">{t}</a>))}
        </div>
      </aside>
      <article>
        <h1 className="text-4xl font-extrabold tracking-tight">Documentation</h1>
        <p className="mt-3 text-muted">How screensharing.me investigations work, what the scanner can and cannot establish, and how data is handled.</p>
        <Section id="workflow" title="Investigation workflow">
          <ol className="list-decimal space-y-2 pl-5">
            <li>An investigator creates an investigation from the <Link className="text-accent-2" href="/dashboard">dashboard</Link> and receives a six-digit PIN (e.g. <span className="kbd-pin font-mono">483-921</span>). PINs are single-use and expire after 15 minutes.</li>
            <li>The player starts Minecraft, opens <span className="font-mono">screensharing.me.exe</span>, enters the PIN and sees who requested the investigation.</li>
            <li>The scanner shows the running Minecraft instance it identified (launcher, name, folder, process). The player confirms the instance — choosing one if several are running — and authorises the scan. Nothing is collected before consent.</li>
            <li>Progress, completed categories and findings stream to the investigator live. When the scan completes, the report is available for export as PDF, JSON or CSV.</li>
          </ol>
          <p>If the connection drops, the client keeps findings in a local queue and re-sends them when it reconnects; uploads are idempotent. If the desktop stays offline, the investigator can issue a new PIN, which revokes the old connection.</p>
        </Section>
        <Section id="tiers" title="Evidence tiers">
          <ul className="space-y-2">
            <li><b className="text-ink">Confirmed detection</b> — a file matched an identifier verified against a client&apos;s public source (e.g. its mod id and compiled package). Confirms the artifact, not when or where it was used.</li>
            <li><b className="text-ink">High-confidence finding</b> — evidence that is hard to explain innocently (client data folder in the instance, encrypted classes, modified game jar, client classes in the game&apos;s memory or a game log). Needs manual review.</li>
            <li><b className="text-ink">Low-confidence finding</b> — weak, community-sourced or policy-dependent indicators (pack names, utility mods, single heuristics). Needs corroboration.</li>
            <li><b className="text-ink">Unable to inspect</b> — a relevant file could not be read completely (locked, damaged, encrypted or too large). It is listed so nothing is silently skipped.</li>
            <li><b className="text-ink">Informational</b> — listed for completeness (e.g. an unrecognised mod), never an accusation.</li>
          </ul>
          <p>Verdicts never call anyone a cheater. They describe what the strongest evidence supports.</p>
        </Section>
        <Section id="modules" title="Collection modules">
          <p>Only the selected Minecraft instance: the running game process (launch arguments, agents, loaded modules, bounded memory), its mod archives, the game files on its class path, its configuration, scripts and executables, resource and shader packs, and its logs and crash reports. See <Link className="text-accent-2" href="/features">Features</Link>. Each report lists every stage, the files that could not be inspected and the folders that were excluded.</p>
        </Section>
        <Section id="limitations" title="Detection limitations">
          <ul className="list-disc space-y-2 pl-5">
            <li>Closed-source injected clients publish no identifiers. They are covered by unverified community strings and by indirect evidence (structure, encryption, injection indicators, agents, unsigned modules, memory heuristics).</li>
            <li>Memory evidence only exists while the game is running. A closed game leaves no memory evidence.</li>
            <li>The scan is limited to the selected instance by design. Cheats run from another folder, another instance or outside Minecraft (for example a standalone auto-clicker) leave no evidence there unless they are loaded into the game process.</li>
            <li>File names are user-controlled and never exceed the &ldquo;suspicious&rdquo; tier on their own.</li>
            <li>Timestamps can be manipulated; file times are reported as observed, not proven.</li>
            <li>A secondary PC, virtual machine or external device is outside the scope of a local scan.</li>
            <li>Absence of findings does not prove absence of cheating; it means nothing in the examined instance matched the signature database and heuristics.</li>
          </ul>
        </Section>
        <Section id="privacy" title="Privacy & data">
          <p>The scanner reads only the selected instance folder, the jars the running game loads, and the running game process. Every file access passes a scope check; links that lead out of the instance are not followed (except the content folders the game itself loads, which are reported). It never reads other instances, documents, browser data, passwords, launcher account files or Windows records, and it never modifies a file. Account tokens in the game&apos;s command line are redacted.</p>
          <p>It never reads browser data, saved passwords, launcher account files (e.g. <span className="font-mono">launcher_accounts.json</span>), Discord tokens, documents or photos. It never modifies or deletes files. Only findings, hashes, file metadata and an inventory of Minecraft components are uploaded.</p>
        </Section>
        <Section id="security" title="Security model">
          <p>Passwords are hashed with Argon2id. Sessions use random tokens stored as SHA-256 hashes in HttpOnly, SameSite cookies; state-changing requests are origin-checked. PINs are stored as HMACs and are single-use, short-lived and rate-limited per IP with a global brute-force circuit breaker. A PIN only lets a desktop <em>upload</em> to an investigation; viewing results always requires the investigator&apos;s or an administrator&apos;s account. Desktop tokens are investigation-scoped and expire. Every administrative action is written to the audit log.</p>
        </Section>
        <Section id="recovery" title="Account recovery">
          <p>Accounts with a verified email address can reset their password from the sign-in page. Accounts registered without an email cannot receive reset links; an administrator must verify the owner through another channel and issue a one-time reset link. Add an email in account settings to avoid this limitation.</p>
        </Section>
      </article>
    </div>
  );
}
