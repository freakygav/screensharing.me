# Research

## 2026-11-06 (revision 2): instance-scoped scanning and the signature engine

### andreaonorato/Minecraft-Cheat-Scanner — `Strings Scanner.c`
A 23-entry table of `{string, client}` pairs matched line-by-line (`strstr`) against a text dump of `javaw.exe` memory strings that the user
exports manually from Process Hacker. It targets 1.7/1.8-era injection ("ghost") clients (Vape 2.x/Lite, Drek, Gucci, Merge, Zuiy…) plus
JNativeHook as an auto-clicker marker. Observations:
* The approach — distinctive strings in the game process — is sound and is what our memory stage does automatically (read-only `ReadProcessMemory`, UTF-8 and UTF-16, Aho–Corasick).
* The list is unverifiable today and several entries are 4–7 characters (`nG@W`, `kc((k`, `hi.a2`…), which match by chance in gigabytes of memory. We adopted only the 14 entries of 8+ characters, as **weak, community-sourced** rules (`signatures/injection-clients.json`), also applied to class constant pools and binaries in the instance. The rejected entries are listed in DETECTION_CATALOG.md.
* `com/sun/jna/z/Main` is a useful structural idea: a cheat hiding inside a legitimate library's namespace. Our impersonation check generalises it for mods (declared id of a known mod without that mod's packages).
* It stops at the first match and prints a verdict; we report every match with its evidence and never turn a single weak string into a verdict.

### Running launchers (observed on this machine)
The Modrinth App starts `javaw.exe … -Dminecraft.launcher.brand=theseus -cp …\Temp\.tmpXXXX\theseus.jar;…\meta\libraries\…;…\meta\versions\<id>\<id>.jar com.modrinth.theseus.MinecraftLaunch net.fabricmc.loader.impl.launch.knot.KnotClient … --gameDir "…\ModrinthApp\profiles\<name>"`. Prism/MultiMC start `org.prismlauncher.EntryPoint` in the instance's `.minecraft` folder and pass launch parameters on standard input, so the game directory must be read from the process's working directory. These shaped `InstanceResolver`.

### Real artifacts that changed the design
* **X-ray packs no longer make textures transparent.** `Xray_Ultimate 26.X` redirects stone, dirt, deepslate, netherrack… through blockstates to models made of 0.5-pixel edge slabs with full light emission. The X-ray check therefore resolves blockstate → model → parent chain inside the pack and measures geometry, in addition to decoding PNG alpha.
* **"Anti-unzip" archives.** Server resource packs in the Modrinth download cache zero the entry counts and set "disk 65535" in the ZIP end record; Java ignores those fields, .NET refuses them. The same trick could shield a cheat jar, so archives are normalised in memory and inspected anyway.
* **Vanilla words in memory.** `Scaffold`(ing), `Spider` and `Surround` are ordinary game strings; only distinctive compound feature names are searched in memory now.

### Client artifacts verified in source (instance folders)
`meteor-client/` (MeteorClient.FOLDER), `wurst/*.json` (WurstClient), `LiquidBounce/` (ConfigSystem), `bleach/` (BleachFileMang), `baritone/settings.txt` (SettingsUtil); mixin configurations `meteor-client.mixins.json`, `wurst.mixins.json`, `liquidbounce.mixins.json` (fabric.mod.json).

### Visual references
anticheat.ac: near-black neutral surfaces (`#090A0B`, panels ≈ `#161616`), hairline borders (~10 % white), one blue accent (`#3A63EC`), result classes *Detect / Warning / Suspicious*. Our redesign uses the same restraint with its own palette (graphite `#0B0C0E`/`#131416`, accent `#4C74E8`, 6–8 px radii, no gradients or glows). detect.ac/tools sits behind a bot-verification page that blocks automated clients; it was not bypassed and not used.

### Scope decision
The system-wide collectors of revision 1 (Prefetch, BAM, Recycle Bin, USN journal, event logs, services, all Java installations) were removed from the scanner: they read Windows records outside the instance. Their rules are disabled in the catalog (kept for old reports).

---

## Revision 1 (initial build)

Research performed on 2026-11-06 before and during implementation. Sources were read and analysed; **no third-party script or binary was executed**.

## 1. Reference platforms

| Source | What it is | What we took from it |
|---|---|---|
| **screensharing.me** (existing site) | Single-page marketing site: hero ("Screenshares that take minutes, not hours."), scan-code lookup, client download, four stat tiles, three feature cards (deep file analysis, tamper detection, instant verdicts). | Design language measured in the browser: background `#07080C`, text `#E8EBF3`, muted `#8B93A8`, borders `#1F2433`, cards `linear-gradient(#10131B,#0C0E14)` with 12 px radius, primary button gradient `#8A6DFF→#6A4CF0` with purple glow, headline gradient `#FFF→#A48BFF→#4DB8FF`, Inter / JetBrains Mono. Recreated with original code in `apps/website/src/app/globals.css` and mirrored in the WPF theme. The original site's statistics are static numbers; ours are computed from the database. |
| **anticheat.ac** (Ocean) | Commercial PIN-based screenshare scanner for game servers: staff create a PIN, player runs the scanner, results appear in a dashboard. Groups results as *detect* / *warning* / *suspicious* and lists bypass routes (network shares, external devices, archives). | The PIN workflow and the idea of graded result classes. We made the grading explicit and evidence-based (five tiers, separate severity) and require each finding to state limitations and alternative explanations. |
| **detect.ac/tools** | Suite of free forensic utilities (Collector++, WinPrefetchView++, USBDeview++, Autoruns++, SRUM/Saved-files explorers, StringExplorer++). Collector++ reads Prefetch, BAM, Amcache, SRUM, USN journal, registry, event logs, Sysmon and Autoruns and highlights deleted/renamed Prefetch files, clock changes, cleared logs and tampered services. | Confirmed which Windows artifacts are standard in the screensharing community. We implemented Prefetch (incl. compressed), BAM, USN journal, Recycle Bin, event-log clears, clock changes, service tampering and Prefetch disablement. Amcache/SRUM/Sysmon are documented as future work. |
| **MeowDoomsdayFucker** (GitHub) | Closed binary that (a) scans committed memory of `java.exe/javaw.exe` for private byte signatures of the "Doomsday" client and (b) parses Prefetch for `.jar` references and inspects them with a bytecode inspector. Signatures are deliberately unpublished. | Two techniques adopted with our own implementation: bounded read-only memory scanning of Java game processes (Aho–Corasick multi-pattern search) and Prefetch referenced-file analysis for Java. Because the signatures are private, we do **not** claim Doomsday detection. |
| **CheesySSTool.ps1** | A PowerShell launcher/downloader for ~60 third-party screenshare tools. It contains no detection logic itself. Several entries download and run remote code via `Invoke-Expression` / `iwr | iex` and execute downloaded executables without any hash or signature check. | Catalogue of community tools and artifacts (Prefetch, BAM, UserAssist, USN/MFT, Amcache, ShellBags, SRUM, jump lists, PCA, event logs, scheduled tasks, USB history) and of Java/mod analysers (JARParser, Jarabel, Luyten, mod analyzers). Also a clear anti-pattern: our client downloads **only** a JSON rule catalog over authenticated HTTPS, never code. |
| **RedLotus guide / Mod Analyzer**, **Spok's BAM & Prefetch parsers**, **CharlieRP ScreenShareTool** | Community documentation and tools. Key methodology: correlate execution evidence (Prefetch/BAM/memory) with game start time; watch the USN journal for mods deleted after game launch; analyse jar bytecode. | Timeline correlation is surfaced through timestamps on every piece of evidence; deleted-mod detection is implemented via logs-vs-disk, Recycle Bin and USN journal. |

## 2. Verified identifiers (public source code)

Fetched directly from each project's repository (`fabric.mod.json` / source tree):

| Client | Mod id | Package | Source |
|---|---|---|---|
| Meteor Client | `meteor-client` | `meteordevelopment.meteorclient` | MeteorDevelopment/meteor-client |
| Wurst | `wurst` | `net.wurstclient` | Wurst-Imperium/Wurst7 |
| LiquidBounce | `liquidbounce` | `net.ccbluex.liquidbounce` | CCBlueX/LiquidBounce |
| Meteor Rejects | `meteor-rejects` | `anticope.rejects` | AntiCope/meteor-rejects |
| BleachHack | `bleachhack` | `org.bleachhack` | BleachDev/BleachHack |
| Baritone | `baritone` | `baritone.api` | cabaletta/baritone |
| Freecam | `freecam` | — | modrinth.com/mod/freecam |

Identifiers that could not be verified (Aristois, Impact, RusherHack, Future, ThunderHack, and all paid ghost clients) were **not** shipped as confirmed rules.

## 3. Techniques implemented

For each technique: what it investigates · artifact · evidence produced · what it can identify · limitations · false-positive risk.

1. **Installation discovery** — where Minecraft lives · `%APPDATA%\.minecraft`, Prism/PolyMC/MultiMC, CurseForge, Modrinth App, ATLauncher, GDLauncher, TLauncher, Lunar, Feather, Badlion folders, `mmc-pack.json` · inventory of installations and loader versions · context only · portable/custom folders are missed unless the investigator adds them · none (no findings).
2. **Mod archive analysis** — every file in every mods folder (and one subfolder level) · ZIP signature, `fabric.mod.json`, `quilt.mod.json`, `META-INF/mods.toml`, `neoforge.mods.toml`, `mcmod.info`, `MANIFEST.MF`, class entry paths, nested Jar-in-Jar archives (2 levels) · file evidence with SHA-256, size, NTFS timestamps; jar-entry evidence for each identifier · open-source clients by mod id **and** package (corroborated), utility mods, agents, obfuscation, disguised names, hidden archives, duplicates · renamed/re-obfuscated forks evade identifiers · low for identifier rules; medium for obfuscation (legit closed mods).
3. **Cheat-module structure heuristic** — class names · simple class names vs. curated high-signal names (KillAura, Scaffold…) and ambiguous names (Speed, Reach…) counted only in module-like packages · list of feature classes · unknown/private clients that keep readable class names · obfuscated clients evade it · a legit mod with 1–2 such names (threshold is 3 distinct, 2 high-signal gives only a weak indicator).
4. **Modrinth hash verification** (optional) — whether an unknown mod is a published mod · SHA-512 to `api.modrinth.com/v2/version_files` · project title in the inventory · reduces false positives (2,600 → 573 unrecognised on the test machine) · only hashes are sent; CurseForge-only mods stay unrecognised · none.
5. **Game file integrity** — client jar and libraries · `versions/<id>/<id>.json` `downloads.client.sha1` and `libraries[].downloads.artifact.sha1` · expected vs. actual SHA-1 · modified game jars/libraries · only manifests with hashes · corrupted downloads.
6. **Game-log analysis** — what was loaded in previous sessions · `logs/latest.log`, `*.log.gz` (14 days) · Fabric "Loading N mods" list; Forge "Found mod file" lines · cheat clients that were loaded then deleted; mods removed before the screenshare · logs can be deleted/edited · mods removed for legitimate reasons.
7. **JVM option injection** — agents forced into Java · `JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS`, `JDK_JAVA_OPTIONS` (process/user/machine), launcher profile `javaArgs`, Prism `JvmArgs`, running command lines · argument + agent file hash · agent-based injectable clients · launcher agents are allowlisted by **content** (e.g. Modrinth's `theseus.jar` is accepted only if every class is in `com/modrinth/theseus/`) · developer profilers.
8. **Process & module analysis** — running Java game processes · WMI command line (session tokens redacted), loaded modules, Authenticode (WinVerifyTrust) · unsigned modules from user-writable paths · DLL-injected clients · only while the game runs · overlays and library natives (known natives allowlisted after live testing).
9. **Bounded memory scanning** — committed private/mapped memory of game processes · `VirtualQueryEx`/`ReadProcessMemory`, 4 MiB chunks, 3 GiB / 60 s cap · address and region of matched class paths · cheat classes loaded into the JVM · only while running; caps may truncate · cluster-of-feature-names heuristic is weak (chat text).
10. **Prefetch** (administrator) — program execution · `C:\Windows\Prefetch\*.pf`, SCCA v17/23/26/30/31, Win8.1+ MAM/XPRESS-Huffman decompressed with `RtlDecompressBufferEx` · executable, run count, 8 last-run times, referenced files with volume serial mapping · auto-clickers/injectors by name; jars opened by Java that no longer exist · names are controllable; only first ~10 s of file access recorded.
11. **BAM** (administrator) — last execution per path · `HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\<SID>` (current user only) · path + FILETIME · tool execution by name · entries age out (~1 week).
12. **Recycle Bin** — deleted files · `$Recycle.Bin\<SID>\$I*` (v1/v2) and `$R*` content · original path, deletion time, recoverable copy; recoverable jars are analysed exactly like installed mods · deleted cheat jars · Shift+Delete bypasses it · routine mod clean-ups.
13. **USN change journal** (administrator) — deletes/renames · `FSCTL_READ_USN_JOURNAL` on each NTFS volume (48 h, `.jar/.exe/.dll`), parent resolved with `OpenFileById` · file name, reason, timestamp · jars removed from mods folders; tools named like cheats · journal wraps; parent may not resolve · updaters.
14. **Anti-forensics** — tampering · System 104 / Security 1102 (log cleared), Kernel-General 1 (clock change ≥ 5 min), service `Start` values and state, `EnablePrefetcher` · event/registry evidence · concealment attempts · tuning guides disable SysMain/Prefetch; NTP and timezone fixes.

## 4. Deliberately not implemented

* Credential, browser, Discord token or launcher-account access (`launcher_accounts*.json` is never opened).
* Disabling or bypassing security software, raw-disk MFT parsing, kernel drivers.
* Downloading or executing any code at scan time.
* Amcache, SRUM, ShellBags, Jump Lists, Sysmon, USB history — standard in the community and valuable, documented as next steps.
