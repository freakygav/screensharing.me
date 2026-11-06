# Detection catalog

> Generated from `packages/detection-rules/rules.json` (ruleset **2026.11.06.1**, 110 rules) by `scripts/gen-catalog.mjs`.
> Administrators can enable/disable and edit rules at runtime (Admin → Detection catalog); the live catalog is
> delivered to each scan. This file documents the shipped baseline.

## How to read a finding

Every finding carries **two independent scales**:

* **Evidence tier** — how strong the evidence is:
  1. **Confirmed artifact match** — an artifact matched an identifier verified against a client's *public source code* (its declared mod id and/or compiled package). It confirms *what the file is*, not who used it, when, or where.
  2. **Strong forensic indicator** — evidence that is hard to explain innocently (game jar modified vs. Mojang's hash, cheat classes in game memory, cheat mod in a game log, cheat module class layout).
  3. **Suspicious configuration** — settings/files commonly associated with cheating or concealment that also have legitimate uses.
  4. **Weak indicator** — a lead; never actionable alone.
  5. **Inconclusive** — listed for completeness (e.g. an unrecognised mod).
* **Severity** — how serious the matched behaviour would be under typical server rules (CRITICAL … INFO).

No rule uses a file name alone above *Suspicious configuration*, and no verdict ever states that a person cheated.

**Verification legend:** F = covered by a synthetic-fixture automated test · L = observed on a real Windows machine (2,268 real mods across 36 installations) during development · P = parser/reader tested, end-to-end path needs administrator rights or a matching artifact · N = implemented, not yet exercised by a matching artifact.

## Observability per cheat category

What local, read-only forensics can and cannot see. "Feature" detections (KillAura, Reach…) are only ever established *through the client that provides them*; there is no file-level signature for a behaviour.

| Category | Cheat | Realistic local indicators | Not observable locally |
|---|---|---|---|
| Combat | KillAura, AimAssist, TriggerBot, Criticals, Velocity, Reach, Hitboxes | Client jar identified by mod id/package (Meteor, Wurst, LiquidBounce, BleachHack…); cheat module class layout in unknown jars; client classes in game memory; client listed in game logs; Java agent / injected unsigned DLL in javaw.exe | Whether a module was *enabled*, its settings, or that it was used on a given server (server-side anticheat territory) |
| Combat | AutoClicker | Auto-clicker executables in Prefetch/BAM (admin); JNativeHook DLL in temp; AutoHotkey runs | Hardware/mouse-driver macros (Razer/Logitech) unless their software is examined manually; click timing |
| Movement | Fly, Speed, NoFall, Jesus, LongJump, Timer, Sprint | Only via the client that implements them (same as combat) | Use of the feature |
| Utility | X-ray | X-ray mods (name/metadata), X-ray resource packs, X-ray modules inside identified clients | Whether the pack/mod was active; ore-obfuscation bypass |
| Utility | ChestESP, PlayerESP, Freecam | Freecam mod (confirmed by mod id); ESP via identified clients; Tweakeroo (freecam feature) | Use of the feature |
| Utility | Inventory automation, Baritone, automated mining | Baritone (mod id + package, also when bundled), Item Scroller, Inventory Profiles Next (classified) | Which server it was used on |
| Client modification | Injected modifications, Java agents | -javaagent in launcher profiles and running command lines; JAVA_TOOL_OPTIONS; agent manifests in jars; unsigned natives loaded from user-writable folders | Fully fileless injection that leaves no module, agent or log trace |
| Client modification | Modified game libraries | SHA-1 mismatch of client jar / libraries vs. version manifest | Clients that ship their own (non-Mojang) version manifests |
| Concealment | Deleting/renaming clients | Game logs vs. disk; Recycle Bin `$I` records and recoverable `$R` copies (analysed like any jar); USN journal deletes/renames (admin); Prefetch jar references (admin) | Secure deletion after journal rollover; activity on another PC/VM |
| Concealment | Anti-forensics | Cleared event logs, large clock changes, disabled SysMain/EventLog/BAM/PcaSvc/DPS, Prefetch disabled | Intent behind the change |

## Rules

### Cheat-client signatures

| ID | Name | Kind | Pattern | Tier | Severity | Conf. | Verification |
|---|---|---|---|---|---|---|---|
| `SSME-CL-0001` | Meteor Client — mod metadata | MOD_ID | `meteor-client` | Confirmed artifact | CRITICAL | 96 | F (Meteor, Wurst, BleachHack, Freecam, Baritone) · L (Meteor, Wurst, Meteor Rejects, Freecam) |
| `SSME-CL-0002` | Meteor Client — class package structure | PACKAGE_PREFIX | `meteordevelopment/meteorclient/` | Confirmed artifact | CRITICAL | 95 | F (Meteor, Wurst, LiquidBounce nested, BleachHack, Baritone) · L |
| `SSME-CL-0003` | Meteor Client — classes loaded in a running JVM | MEMORY_STRING | `meteordevelopment/meteorclient` | Strong indicator | CRITICAL | 90 | P (memory reader + matcher tested on a live process; no cheat-loaded JVM was available) |
| `SSME-CL-0004` | Wurst Client — mod metadata | MOD_ID | `wurst` | Confirmed artifact | CRITICAL | 96 | F (Meteor, Wurst, BleachHack, Freecam, Baritone) · L (Meteor, Wurst, Meteor Rejects, Freecam) |
| `SSME-CL-0005` | Wurst Client — class package structure | PACKAGE_PREFIX | `net/wurstclient/` | Confirmed artifact | CRITICAL | 95 | F (Meteor, Wurst, LiquidBounce nested, BleachHack, Baritone) · L |
| `SSME-CL-0006` | Wurst Client — classes loaded in a running JVM | MEMORY_STRING | `net/wurstclient` | Strong indicator | CRITICAL | 90 | P (memory reader + matcher tested on a live process; no cheat-loaded JVM was available) |
| `SSME-CL-0007` | LiquidBounce — mod metadata | MOD_ID | `liquidbounce` | Confirmed artifact | CRITICAL | 96 | F (Meteor, Wurst, BleachHack, Freecam, Baritone) · L (Meteor, Wurst, Meteor Rejects, Freecam) |
| `SSME-CL-0008` | LiquidBounce — class package structure | PACKAGE_PREFIX | `net/ccbluex/liquidbounce/` | Confirmed artifact | CRITICAL | 95 | F (Meteor, Wurst, LiquidBounce nested, BleachHack, Baritone) · L |
| `SSME-CL-0009` | LiquidBounce — classes loaded in a running JVM | MEMORY_STRING | `net/ccbluex/liquidbounce` | Strong indicator | CRITICAL | 90 | P (memory reader + matcher tested on a live process; no cheat-loaded JVM was available) |
| `SSME-CL-0010` | Meteor Rejects (Meteor addon) — mod metadata | MOD_ID | `meteor-rejects` | Confirmed artifact | CRITICAL | 96 | F (Meteor, Wurst, BleachHack, Freecam, Baritone) · L (Meteor, Wurst, Meteor Rejects, Freecam) |
| `SSME-CL-0011` | Meteor Rejects (Meteor addon) — class package structure | PACKAGE_PREFIX | `anticope/rejects/` | Confirmed artifact | CRITICAL | 95 | F (Meteor, Wurst, LiquidBounce nested, BleachHack, Baritone) · L |
| `SSME-CL-0012` | Meteor Rejects (Meteor addon) — classes loaded in a running JVM | MEMORY_STRING | `anticope/rejects` | Strong indicator | CRITICAL | 90 | P (memory reader + matcher tested on a live process; no cheat-loaded JVM was available) |
| `SSME-CL-0013` | BleachHack — mod metadata | MOD_ID | `bleachhack` | Confirmed artifact | CRITICAL | 96 | F (Meteor, Wurst, BleachHack, Freecam, Baritone) · L (Meteor, Wurst, Meteor Rejects, Freecam) |
| `SSME-CL-0014` | BleachHack — class package structure | PACKAGE_PREFIX | `org/bleachhack/` | Confirmed artifact | CRITICAL | 95 | F (Meteor, Wurst, LiquidBounce nested, BleachHack, Baritone) · L |
| `SSME-CL-0015` | BleachHack — classes loaded in a running JVM | MEMORY_STRING | `org/bleachhack` | Strong indicator | CRITICAL | 90 | P (memory reader + matcher tested on a live process; no cheat-loaded JVM was available) |

<details><summary>False positives &amp; limitations</summary>

* **SSME-CL-0001** — *False positives:* Very low. The mod id is declared by the client's own metadata. A third party could reuse the id, which is why the package-structure rule is evaluated independently and both are reported. *Limitations:* Detects the archive on disk only. It does not prove the client was launched or used on a specific server; correlate with logs, Prefetch and memory findings. *Source:* <https://github.com/MeteorDevelopment/meteor-client/blob/master/src/main/resources/fabric.mod.json>
* **SSME-CL-0002** — *False positives:* Very low. Addons legitimately depend on these packages but do not ship them; a jar that contains the classes contains the client code. *Limitations:* Renamed/re-obfuscated forks change package names and will not match. Detects presence on disk, not use. *Source:* <https://github.com/MeteorDevelopment/meteor-client/blob/master/src/main/resources/fabric.mod.json>
* **SSME-CL-0003** — *False positives:* Low. The string could be present if the user opened the client's jar in a Java-based tool running in the same JVM, which is uncommon for a game process. *Limitations:* Only examines Java processes running at scan time. If the game was closed before the scan, no memory evidence exists. *Source:* <https://github.com/MeteorDevelopment/meteor-client/blob/master/src/main/resources/fabric.mod.json>
* **SSME-CL-0004** — *False positives:* Very low. The mod id is declared by the client's own metadata. A third party could reuse the id, which is why the package-structure rule is evaluated independently and both are reported. *Limitations:* Detects the archive on disk only. It does not prove the client was launched or used on a specific server; correlate with logs, Prefetch and memory findings. *Source:* <https://github.com/Wurst-Imperium/Wurst7/blob/master/src/main/resources/fabric.mod.json>
* **SSME-CL-0005** — *False positives:* Very low. Addons legitimately depend on these packages but do not ship them; a jar that contains the classes contains the client code. *Limitations:* Renamed/re-obfuscated forks change package names and will not match. Detects presence on disk, not use. *Source:* <https://github.com/Wurst-Imperium/Wurst7/blob/master/src/main/resources/fabric.mod.json>
* **SSME-CL-0006** — *False positives:* Low. The string could be present if the user opened the client's jar in a Java-based tool running in the same JVM, which is uncommon for a game process. *Limitations:* Only examines Java processes running at scan time. If the game was closed before the scan, no memory evidence exists. *Source:* <https://github.com/Wurst-Imperium/Wurst7/blob/master/src/main/resources/fabric.mod.json>
* **SSME-CL-0007** — *False positives:* Very low. The mod id is declared by the client's own metadata. A third party could reuse the id, which is why the package-structure rule is evaluated independently and both are reported. *Limitations:* Detects the archive on disk only. It does not prove the client was launched or used on a specific server; correlate with logs, Prefetch and memory findings. *Source:* <https://github.com/CCBlueX/LiquidBounce/blob/nextgen/src/main/resources/fabric.mod.json>
* **SSME-CL-0008** — *False positives:* Very low. Addons legitimately depend on these packages but do not ship them; a jar that contains the classes contains the client code. *Limitations:* Renamed/re-obfuscated forks change package names and will not match. Detects presence on disk, not use. *Source:* <https://github.com/CCBlueX/LiquidBounce/blob/nextgen/src/main/resources/fabric.mod.json>
* **SSME-CL-0009** — *False positives:* Low. The string could be present if the user opened the client's jar in a Java-based tool running in the same JVM, which is uncommon for a game process. *Limitations:* Only examines Java processes running at scan time. If the game was closed before the scan, no memory evidence exists. *Source:* <https://github.com/CCBlueX/LiquidBounce/blob/nextgen/src/main/resources/fabric.mod.json>
* **SSME-CL-0010** — *False positives:* Very low. The mod id is declared by the client's own metadata. A third party could reuse the id, which is why the package-structure rule is evaluated independently and both are reported. *Limitations:* Detects the archive on disk only. It does not prove the client was launched or used on a specific server; correlate with logs, Prefetch and memory findings. *Source:* <https://github.com/AntiCope/meteor-rejects/blob/master/src/main/resources/fabric.mod.json>
* **SSME-CL-0011** — *False positives:* Very low. Addons legitimately depend on these packages but do not ship them; a jar that contains the classes contains the client code. *Limitations:* Renamed/re-obfuscated forks change package names and will not match. Detects presence on disk, not use. *Source:* <https://github.com/AntiCope/meteor-rejects/blob/master/src/main/resources/fabric.mod.json>
* **SSME-CL-0012** — *False positives:* Low. The string could be present if the user opened the client's jar in a Java-based tool running in the same JVM, which is uncommon for a game process. *Limitations:* Only examines Java processes running at scan time. If the game was closed before the scan, no memory evidence exists. *Source:* <https://github.com/AntiCope/meteor-rejects/blob/master/src/main/resources/fabric.mod.json>
* **SSME-CL-0013** — *False positives:* Very low. The mod id is declared by the client's own metadata. A third party could reuse the id, which is why the package-structure rule is evaluated independently and both are reported. *Limitations:* Detects the archive on disk only. It does not prove the client was launched or used on a specific server; correlate with logs, Prefetch and memory findings. *Source:* <https://github.com/BleachDev/BleachHack/blob/1.19.4/src/main/resources/fabric.mod.json>
* **SSME-CL-0014** — *False positives:* Very low. Addons legitimately depend on these packages but do not ship them; a jar that contains the classes contains the client code. *Limitations:* Renamed/re-obfuscated forks change package names and will not match. Detects presence on disk, not use. *Source:* <https://github.com/BleachDev/BleachHack/blob/1.19.4/src/main/resources/fabric.mod.json>
* **SSME-CL-0015** — *False positives:* Low. The string could be present if the user opened the client's jar in a Java-based tool running in the same JVM, which is uncommon for a game process. *Limitations:* Only examines Java processes running at scan time. If the game was closed before the scan, no memory evidence exists. *Source:* <https://github.com/BleachDev/BleachHack/blob/1.19.4/src/main/resources/fabric.mod.json>

</details>

### Utility / automation modifications

| ID | Name | Kind | Pattern | Tier | Severity | Conf. | Verification |
|---|---|---|---|---|---|---|---|
| `SSME-UT-0016` | Baritone pathing/automation bot | MOD_ID | `baritone` | Confirmed artifact | MEDIUM | 95 | F (Meteor, Wurst, BleachHack, Freecam, Baritone) · L (Meteor, Wurst, Meteor Rejects, Freecam) |
| `SSME-UT-0017` | Baritone classes bundled in archive | PACKAGE_PREFIX | `baritone/api/` | Confirmed artifact | MEDIUM | 92 | F (Meteor, Wurst, LiquidBounce nested, BleachHack, Baritone) · L |
| `SSME-UT-0018` | Freecam modification | MOD_ID | `freecam` | Confirmed artifact | MEDIUM | 90 | F (Meteor, Wurst, BleachHack, Freecam, Baritone) · L (Meteor, Wurst, Meteor Rejects, Freecam) |
| `SSME-UT-0019` | X-ray modification (name/metadata) | MOD_ID_REGEX | `(?i)(^\|[^a-z])x[-_ ]?ray` | Suspicious configuration | HIGH | 75 | L (matched a real mod named xray_snitch — see false-positive note) |
| `SSME-UT-0020` | X-ray resource pack | RESOURCEPACK_REGEX | `(?i)x[-_ ]?ray` | Suspicious configuration | MEDIUM | 65 | F · L |
| `SSME-UT-0078` | Tweakeroo (gameplay tweaks incl. freecam/fast placement) | MOD_ID | `tweakeroo` | Suspicious configuration | LOW | 60 | F (Meteor, Wurst, BleachHack, Freecam, Baritone) · L (Meteor, Wurst, Meteor Rejects, Freecam) |
| `SSME-UT-0079` | Item Scroller (inventory automation) | MOD_ID | `itemscroller` | Suspicious configuration | LOW | 55 | F (Meteor, Wurst, BleachHack, Freecam, Baritone) · L (Meteor, Wurst, Meteor Rejects, Freecam) |

<details><summary>False positives &amp; limitations</summary>

* **SSME-UT-0016** — *False positives:* Baritone is legitimate on singleplayer and on servers that allow it. The finding confirms installation, not misuse. *Limitations:* Cannot determine which server it was used on. *Source:* <https://github.com/cabaletta/baritone/blob/1.20.1/fabric/src/main/resources/fabric.mod.json>
* **SSME-UT-0017** — *False positives:* Baritone is allowed on some servers and in singleplayer. *Limitations:* Presence only. *Source:* <https://github.com/cabaletta/baritone>
* **SSME-UT-0018** — *False positives:* Freecam is permitted on many servers and widely used for building and screenshots. *Limitations:* Server policy determines whether this is a violation. Presence on disk does not prove use on the server. *Source:* <https://modrinth.com/mod/freecam>
* **SSME-UT-0019** — *False positives:* Mods with xray in the name may be anti-xray tools for server owners, or utilities for singleplayer/creative. *Limitations:* Name-based. Requires manual review of the mod.
* **SSME-UT-0020** — *False positives:* Pack names are user-controlled; a pack may be mis-named or unused. *Limitations:* Only checks the pack file/folder name, not whether the pack was active.
* **SSME-UT-0078** — *False positives:* Tweakeroo is a popular, legitimate technical-play mod; most features are harmless. *Limitations:* Cannot see which tweaks were enabled unless its config is reviewed manually. *Source:* <https://github.com/maruohon/tweakeroo>
* **SSME-UT-0079** — *False positives:* Widely allowed on survival servers; usually only prohibited in competitive PvP. *Limitations:* Presence only. *Source:* <https://github.com/maruohon/itemscroller>

</details>

### Execution-artifact rules (Prefetch, BAM, processes)

| ID | Name | Kind | Pattern | Tier | Severity | Conf. | Verification |
|---|---|---|---|---|---|---|---|
| `SSME-EX-0080` | Auto-clicker executed | EXECUTABLE_REGEX | `(?i)auto[\s_\-.]*click` | Suspicious configuration | MEDIUM | 70 | P (Prefetch parser incl. MAM decompression tested; BAM/Prefetch need administrator) |
| `SSME-EX-0081` | DLL injector executed | EXECUTABLE_REGEX | `(?i)(injector\|xenos(64)?\.exe\|extreme ?injector)` | Suspicious configuration | HIGH | 70 | P (Prefetch parser incl. MAM decompression tested; BAM/Prefetch need administrator) |
| `SSME-EX-0082` | Memory editor executed (Cheat Engine) | EXECUTABLE_REGEX | `(?i)^cheat ?engine\|^cheatengine` | Weak indicator | MEDIUM | 50 | P (Prefetch parser incl. MAM decompression tested; BAM/Prefetch need administrator) |
| `SSME-EX-0083` | Process manipulation tool executed | EXECUTABLE_REGEX | `(?i)^(processhacker\|systeminformer)` | Weak indicator | LOW | 35 | P (Prefetch parser incl. MAM decompression tested; BAM/Prefetch need administrator) |
| `SSME-EX-0084` | Secure-delete tool executed | EXECUTABLE_REGEX | `(?i)^sdelete(64)?(a)?\.exe` | Weak indicator | MEDIUM | 45 | P (Prefetch parser incl. MAM decompression tested; BAM/Prefetch need administrator) |
| `SSME-EX-0085` | Macro automation runtime executed (AutoHotkey) | EXECUTABLE_REGEX | `(?i)^autohotkey` | Weak indicator | LOW | 30 | P (Prefetch parser incl. MAM decompression tested; BAM/Prefetch need administrator) |

<details><summary>False positives &amp; limitations</summary>

* **SSME-EX-0080** — *False positives:* Auto-clickers have non-gaming uses (accessibility, idle games). Execution time must be correlated with the game session. *Limitations:* Execution artifacts record that a file with this name ran; names are user-controlled and a renamed tool will not match.
* **SSME-EX-0081** — *False positives:* Some modding tools for other games are named "injector". *Limitations:* Execution artifacts record that a file with this name ran; names are user-controlled and a renamed tool will not match.
* **SSME-EX-0082** — *False positives:* Cheat Engine is commonly used for singleplayer games and learning. *Limitations:* Execution artifacts record that a file with this name ran; names are user-controlled and a renamed tool will not match.
* **SSME-EX-0083** — *False positives:* Popular legitimate administration tools. *Limitations:* Execution artifacts record that a file with this name ran; names are user-controlled and a renamed tool will not match.
* **SSME-EX-0084** — *False positives:* Used legitimately for privacy. *Limitations:* Execution artifacts record that a file with this name ran; names are user-controlled and a renamed tool will not match.
* **SSME-EX-0085** — *False positives:* AutoHotkey is a very common productivity tool. *Limitations:* Execution artifacts record that a file with this name ran; names are user-controlled and a renamed tool will not match.

</details>

### File-name rules

| ID | Name | Kind | Pattern | Tier | Severity | Conf. | Verification |
|---|---|---|---|---|---|---|---|
| `SSME-FN-0086` | File named after a known cheat client | FILE_NAME_REGEX | `(?i)(meteor[-_ ]?client\|wurst[-_ ]?client\|liquidbounce\|aristois\|bleachhack\|doomsday\|novoware\|rusherhack\|thunderhack\|vape[-_ ]?(v4\|lite\|client)\|slinky\|whiteout[-_ ]?client\|drip[-_ ]?(lite\|client))` | Suspicious configuration | MEDIUM | 60 | L (merged into content-based findings for named cheat jars) |
| `SSME-FN-0087` | JNativeHook native library extracted | FILE_NAME_REGEX | `(?i)^jnativehook.*\.dll$` | Weak indicator | LOW | 35 | L (merged into content-based findings for named cheat jars) |

<details><summary>False positives &amp; limitations</summary>

* **SSME-FN-0086** — *False positives:* File names are user-controlled; a file may be mis-named, an installer, or unrelated. A name alone never confirms a client. *Limitations:* Renamed clients will not match. The file content is analysed separately when it still exists.
* **SSME-FN-0087** — *False positives:* Legitimate Java applications (hotkey tools, overlays) also use JNativeHook. *Limitations:* Only observed in temporary folders; the extracting program is not identified.

</details>

### Built-in heuristics (scanner engine)

Implemented in `apps/desktop/src/Screensharing.Scanner/Modules`. Administrators can disable them or change their severity/tier in the catalog.

| ID | Name | Tier | Severity | Conf. | What it examines | False-positive risk | Verification |
|---|---|---|---|---|---|---|---|
| `SSME-H-MODULE_CLASSES` | Cheat-module class structure in archive | Strong indicator | HIGH | 85 | The archive contains classes named after several distinct cheat features (e.g. KillAura, AimAssist, Scaffold) organised like a hacked client's module system. | A legitimate mod may contain one similarly named class (e.g. a 'Reach' attribute). Severity rises with the number of distinct high-signal names. | F · L |
| `SSME-H-JAVA_AGENT_MANIFEST` | Java agent entry point inside mod archive | Suspicious configuration | HIGH | 70 | The archive's manifest declares Premain-Class/Agent-Class, so it can be attached to the JVM as an instrumentation agent and rewrite game classes at load time. | A few legitimate developer tools ship agent manifests; normal gameplay mods do not need one. | F · L (FP fixed: library agents allowlisted) |
| `SSME-H-OBFUSCATED_ARCHIVE` | Heavily obfuscated mod archive | Weak indicator | MEDIUM | 45 | Most class names in the archive are one or two characters long or use non-ASCII/confusable names, consistent with commercial obfuscation used by paid clients. | Some legitimate closed-source mods are obfuscated (e.g. OptiFine-style distributions). | F |
| `SSME-H-DISGUISED_ARCHIVE` | Archive disguised as a different mod | Strong indicator | HIGH | 85 | The file name claims a well-known mod (e.g. 'sodium-…jar') but the archive's own metadata declares a different, unrelated mod id. | Repackaged or forked builds sometimes keep upstream file names. | F · L (FP fixed: prefix rule + Modrinth exclusion) |
| `SSME-H-NON_JAR_ARCHIVE` | Java archive with a non-jar extension in mods folder | Suspicious configuration | MEDIUM | 60 | A file in a mods folder is a Java archive but uses a different extension, which may hide it from casual inspection while some loaders/injectors still use it. | Launchers disable mods by appending '.disabled'; those are reported separately as informational. | F |
| `SSME-H-DUPLICATE_MOD_ID` | Duplicate mod id across archives | Weak indicator | LOW | 40 | Two archives in the same mods folder declare the same mod id, which can indicate a swapped or disguised copy. | Users often leave an old version next to an update. | F · L |
| `SSME-H-UNRECOGNIZED_MOD` | Unrecognised modification (manual review) | Inconclusive | INFO | 0 | A mod archive is not in the catalog of known mods and could not be verified against the Modrinth registry. | Most unrecognised mods are legitimate niche or private mods. | F · L |
| `SSME-H-CLIENT_JAR_MODIFIED` | Vanilla client jar does not match Mojang's published hash | Strong indicator | HIGH | 85 | The SHA-1 of versions/<id>/<id>.jar differs from the hash Mojang publishes in the version manifest, meaning the game executable was modified. | A corrupted download produces the same result; the launcher normally re-downloads mismatching files. | F |
| `SSME-H-LIBRARY_MODIFIED` | Game library does not match published hash | Strong indicator | HIGH | 80 | A library jar referenced by an installed version manifest has a different SHA-1 than the manifest declares. | Interrupted downloads or manual library replacement by some launchers. | Shares the verified hashing path; no dedicated fixture |
| `SSME-H-LOGGED_MOD_MISSING` | Mod loaded in a previous session is no longer present | Suspicious configuration | MEDIUM | 65 | The game log shows a mod being loaded that no longer exists in any examined mods folder. Removing mods shortly before a screenshare is a common concealment technique. | Users legitimately remove or update mods; logs can also come from another instance folder. | F · L |
| `SSME-H-LOGGED_CHEAT_MOD` | Game log shows a known cheat client being loaded | Strong indicator | CRITICAL | 90 | The Fabric/Quilt mod list in a game log contains a mod id that belongs to a known cheat client. | Log files can be copied from elsewhere, but this is uncommon. | F |
| `SSME-H-JAVAAGENT_ARGUMENT` | Java agent supplied in launch arguments | Suspicious configuration | HIGH | 75 | A Minecraft launch configuration or running game process uses -javaagent with an agent outside the launcher's own installation directory. | Some launchers and profilers use agents; agents within known launcher directories are reported as informational only. | L (Modrinth App agent correctly allowlisted by content) |
| `SSME-H-JAVA_OPTIONS_ENV` | JVM options injected through environment variable | Strong indicator | HIGH | 85 | JAVA_TOOL_OPTIONS / _JAVA_OPTIONS / JDK_JAVA_OPTIONS contains -javaagent or -agentpath, which forces every Java process (including Minecraft) to load the agent. | Rare developer setups (profilers, APM agents). | N |
| `SSME-H-UNSIGNED_MODULE` | Unsigned native module loaded into the game | Suspicious configuration | MEDIUM | 65 | A running Java game process has a native DLL loaded from a user-writable location without a valid Authenticode signature and not matching known game natives (LWJGL, OpenAL, GLFW). | Overlays, shader tools and some legitimate mods load unsigned natives. | L (FP fixed: known library natives allowlisted) |
| `SSME-H-PREFETCH_JAR_MISSING` | Jar opened by Java no longer exists | Weak indicator | LOW | 40 | Windows Prefetch shows Java opening a .jar that no longer exists on disk and is outside launcher library folders. | Launchers delete superseded jars; installers run from temporary folders. | P |
| `SSME-H-MEMORY_FEATURE_CLUSTER` | Cheat feature names present in game memory | Weak indicator | LOW | 35 | Several distinct cheat-feature names (e.g. KillAura, AimAssist, TriggerBot) were found as strings in the game's memory. | Chat messages, server MOTDs or GUI text discussing cheats put the same words in memory. Treat as a lead only. | P |
| `SSME-H-EVENT_LOG_CLEARED` | Windows event log was cleared | Suspicious configuration | MEDIUM | 70 | An event log clear record (System 104 / Security 1102) exists within the last 7 days. | Administrators and some cleanup utilities clear logs routinely. | N (query runs; no clear event present) |
| `SSME-H-TIME_CHANGED` | System clock changed significantly | Weak indicator | LOW | 40 | The system time was changed by more than 5 minutes within the last 7 days. Changing the clock is used to mislead timestamp-based analysis. | Time zone changes, dual-boot systems and failing CMOS batteries. | N (query runs; no qualifying event present) |
| `SSME-H-SERVICE_DISABLED` | Forensic-relevant Windows service disabled | Suspicious configuration | MEDIUM | 60 | A service that produces forensic artifacts (SysMain/Prefetch, EventLog, BAM, PcaSvc, DPS) is disabled or stopped. | 'Debloat' guides commonly disable SysMain; this does not indicate intent on its own. | N (check runs; services enabled) |
| `SSME-H-PREFETCH_DISABLED` | Prefetch disabled in registry | Suspicious configuration | MEDIUM | 60 | EnablePrefetcher is set to 0, so Windows stops recording program execution in Prefetch. | Some SSD tuning guides recommend this. | N (check runs; Prefetch enabled) |
| `SSME-H-RECYCLED_ARCHIVE` | Recently deleted Minecraft archive in Recycle Bin | Weak indicator | LOW | 40 | A .jar/.exe/.dll deleted within the last 7 days from a Minecraft-related folder is in the Recycle Bin. | Users routinely delete old mods. | P ($I parser tested) |
| `SSME-H-USN_ARCHIVE_DELETED` | Archive deleted or renamed recently (USN journal) | Weak indicator | LOW | 40 | The NTFS change journal records a .jar/.exe/.dll being deleted or renamed in the last 48 hours. | Launchers and updaters delete and rename files constantly; only names matching rules or Minecraft folders are reported. | P (requires administrator; not exercised in automated tests) |
| `SSME-H-MOD_CHANGED_AFTER_SESSION` | Mods folder changed after the last game session | Weak indicator | LOW | 35 | A file in the mods folder was modified or created after the most recent game log was written. | Installing or updating mods between sessions is normal. | F |

### Known-mod classifications

These are **not findings**. They classify mods in the inventory (performance, cosmetic, accessibility, gameplay, utility, library). Unknown mods that are not in this list are verified against the public Modrinth registry by SHA-512 (optional, on by default) before being listed as *Inconclusive — unrecognised*.

| Mod id | Name | Classification |
|---|---|---|
| `sodium` | Sodium | performance |
| `lithium` | Lithium | performance |
| `iris` | Iris Shaders | cosmetic |
| `indium` | Indium | library |
| `fabric-api` | Fabric API | library |
| `fabricloader` | Fabric Loader | library |
| `modmenu` | Mod Menu | utility |
| `ferritecore` | FerriteCore | performance |
| `krypton` | Krypton | performance |
| `immediatelyfast` | ImmediatelyFast | performance |
| `entityculling` | Entity Culling | performance |
| `c2me` | Concurrent Chunk Management Engine | performance |
| `starlight` | Starlight | performance |
| `continuity` | Continuity | cosmetic |
| `cloth-config` | Cloth Config | library |
| `cloth_config` | Cloth Config | library |
| `yet_another_config_lib_v3` | YetAnotherConfigLib | library |
| `architectury` | Architectury API | library |
| `lambdynlights` | LambDynamicLights | cosmetic |
| `zoomify` | Zoomify | accessibility |
| `ok_zoomer` | Ok Zoomer | accessibility |
| `appleskin` | AppleSkin | gameplay |
| `xaerominimap` | Xaero's Minimap | gameplay |
| `xaeroworldmap` | Xaero's World Map | gameplay |
| `journeymap` | JourneyMap | gameplay |
| `optifine` | OptiFine | performance |
| `essential` | Essential | cosmetic |
| `replaymod` | Replay Mod | utility |
| `voicechat` | Simple Voice Chat | utility |
| `jei` | Just Enough Items | utility |
| `roughlyenoughitems` | Roughly Enough Items | utility |
| `emi` | EMI | utility |
| `sodium-extra` | Sodium Extra | performance |
| `reeses-sodium-options` | Reese's Sodium Options | utility |
| `moreculling` | More Culling | performance |
| `dynamic_fps` | Dynamic FPS | performance |
| `notenoughcrashes` | Not Enough Crashes | utility |
| `fabric-language-kotlin` | Fabric Language Kotlin | library |
| `mixinextras` | MixinExtras | library |
| `forge` | Minecraft Forge | library |
| `neoforge` | NeoForge | library |
| `minecraft` | Minecraft | library |
| `java` | Java | library |
| `badoptimizations` | BadOptimizations | performance |
| `modernfix` | ModernFix | performance |
| `puzzle` | Puzzle | utility |
| `entity_model_features` | Entity Model Features | cosmetic |
| `entity_texture_features` | Entity Texture Features | cosmetic |
| `betterf3` | BetterF3 | utility |
| `controlling` | Controlling | accessibility |
| `mousetweaks` | Mouse Tweaks | accessibility |
| `tweakeroo` | Tweakeroo | gameplay |
| `itemscroller` | Item Scroller | gameplay |
| `litematica` | Litematica | utility |
| `minihud` | MiniHUD | gameplay |
| `malilib` | MaLiLib | library |
| `inventoryprofilesnext` | Inventory Profiles Next | gameplay |

## Researched but intentionally not shipped

* **Closed-source / paid "ghost" clients** (e.g. Vape, Doomsday, Novoware, Drip, Slinky, Whiteout): their internal identifiers are private and change per build. The public tools that target them (e.g. MeowDoomsdayFucker) keep their memory signatures private. Shipping guessed signatures would produce false claims, so these clients are covered only by the structural, injection, agent, deletion and memory heuristics above, and by a file-name rule capped at *Suspicious configuration*.
* **Aristois, Impact, RusherHack, Future, ThunderHack identifiers**: not verified against source during this build; not added as confirmed rules. Administrators can add them after verification.
* **SHA-256 fingerprints of specific cheat releases**: the rule kind is supported, but no hashes are shipped because none were obtained from a trustworthy source.
