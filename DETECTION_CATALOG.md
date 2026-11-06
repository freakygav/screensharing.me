# Detection catalog

> Generated from `packages/detection-rules/rules.json` (ruleset **2026.11.06.2**) by `scripts/gen-catalog.mjs`.
> **98 detection signatures and heuristics**, plus 145 classification entries
> (known mods, cheat-module names, library packages). The source is the categorised databases in
> `packages/detection-rules/signatures/*.json`; administrators can enable/disable and edit rules at runtime (Admin → Detection catalog),
> and the live catalog is delivered to each scan. This file documents the shipped baseline.

## Scope

Every rule is evaluated against **one Minecraft instance only** — the one the player selects from the running game processes —
plus the jars that game process loads and the process itself. Nothing else on the computer is read. A clean result therefore means
"no evidence in this instance", never "the player is clean".

## How to read a finding

* **Outcome** — what the investigator should do with it:
  * **Confirmed** — a verified signature of a known cheat or prohibited mod matched (tier *Confirmed*).
  * **High confidence** — strong evidence without a verified signature (tier *Strong*). Manual review.
  * **Low confidence** — weak, policy-dependent or community-sourced evidence (tiers *Suspicious config*, *Weak*). Manual review and corroboration.
  * **Unable to inspect** — a relevant file could not be read completely; listed so nothing is silently skipped.
  * **Informational** — e.g. an unrecognised mod; never an accusation.
* **Severity** — how serious the behaviour would be under typical server rules (CRITICAL … INFO), independent of the evidence strength.
* **Suspected client, location, signature** — every finding names the client or component when it can be identified, where it is inside the instance, and what matched.

### Scoring

Indicators matched for the same file are grouped per suspected family. Each distinct rule contributes its `weight` (or a default derived from its tier);
the sum is capped at 100. The finding's tier is the stronger of the best single rule and the score tier (100 with at least two *different kinds* of
content evidence = confirmed, 60 = strong, 30 = weak). Generic `indicator` families must reach 30 to be reported and are never confirmed.
File names never raise a tier on their own. Classes of well-known libraries (`LIBRARY_PACKAGE`) are exempt from generic indicators.

**Verification legend:** F = synthetic-fixture automated test · L = observed while scanning a real running instance (Modrinth App, Fabric 1.21.11, 83 mods, 53 resource packs) · P = reader/matcher tested, no real matching artifact available · N = implemented, not yet exercised.

## Observability per cheat category

| Category | Cheat | Indicators inside the instance | Not observable |
|---|---|---|---|
| Combat | KillAura, AimAssist, TriggerBot, Criticals, Velocity, Reach | Client jar identified by mod id/package/strings; client data folder; cheat-module class layout in unknown jars; client classes in game memory, logs, crash reports; Java agent or unsigned DLL in the game process | Whether a module was enabled or used on a given server |
| Combat | Auto-clickers | JNativeHook/Robot indicators in archives; auto-clicker executables stored in the instance | Hardware/driver macros and clickers run from outside the instance |
| Movement | Fly, Speed, NoFall, Jesus, LongJump, Timer | Only via the client that implements them | Use of the feature |
| Utility | X-ray | Pack content (transparent textures, hollow/empty block models), pack and shader names, X-ray mods | Shader-only X-ray logic; whether a pack was active at a given time |
| Utility | ESP, Freecam, Baritone | Freecam/Baritone by mod id, package, `baritone/settings.txt`; ESP via identified clients | Use of the feature |
| Injection | Agents, injected DLLs, class-path injection | -javaagent arguments, JAVA_TOOL_OPTIONS in the game's environment, unverified class-path jars, unsigned modules, native injector API combinations | Fully fileless injection that leaves no module, agent or string |
| Evasion | Renaming, disguising, encrypting | Content-based identification, impersonated mod ids, disguised file types, polyglot and anti-unzip archives, encrypted classes, redirected folders | Clients whose code and strings are fully encrypted and unknown |
| Game integrity | Modified game jar or libraries | SHA-1 of every class-path jar vs. the launcher's version manifest | Launchers that ship no version manifest |

## Cheat clients — identifiers verified against each client's public source

| ID | Name | Kind | Pattern | Scopes | Tier | Severity | Conf. | Weight | Verification |
|---|---|---|---|---|---|---|---|---|---|
| `SSME-CL-0001` | Meteor Client — mod metadata | MOD_ID | `meteor-client` |  | Confirmed | CRITICAL | 96 | — | F (Meteor, Wurst, LiquidBounce, Freecam) |
| `SSME-CL-0002` | Meteor Client — class package structure | PACKAGE_PREFIX | `meteordevelopment/meteorclient/` |  | Confirmed | CRITICAL | 95 | — | F (Meteor, Wurst, LiquidBounce nested) |
| `SSME-CL-0003` | Meteor Client — classes loaded in a running JVM | MEMORY_STRING | `meteordevelopment/meteorclient` |  | Strong | CRITICAL | 90 | — | P (memory reader tested on a live process; no cheat-loaded JVM available) |
| `SSME-CL-0004` | Wurst Client — mod metadata | MOD_ID | `wurst` |  | Confirmed | CRITICAL | 96 | — | F (Meteor, Wurst, LiquidBounce, Freecam) |
| `SSME-CL-0005` | Wurst Client — class package structure | PACKAGE_PREFIX | `net/wurstclient/` |  | Confirmed | CRITICAL | 95 | — | F (Meteor, Wurst, LiquidBounce nested) |
| `SSME-CL-0006` | Wurst Client — classes loaded in a running JVM | MEMORY_STRING | `net/wurstclient` |  | Strong | CRITICAL | 90 | — | P (memory reader tested on a live process; no cheat-loaded JVM available) |
| `SSME-CL-0007` | LiquidBounce — mod metadata | MOD_ID | `liquidbounce` |  | Confirmed | CRITICAL | 96 | — | F (Meteor, Wurst, LiquidBounce, Freecam) |
| `SSME-CL-0008` | LiquidBounce — class package structure | PACKAGE_PREFIX | `net/ccbluex/liquidbounce/` |  | Confirmed | CRITICAL | 95 | — | F (Meteor, Wurst, LiquidBounce nested) |
| `SSME-CL-0009` | LiquidBounce — classes loaded in a running JVM | MEMORY_STRING | `net/ccbluex/liquidbounce` |  | Strong | CRITICAL | 90 | — | P (memory reader tested on a live process; no cheat-loaded JVM available) |
| `SSME-CL-0010` | Meteor Rejects (Meteor addon) — mod metadata | MOD_ID | `meteor-rejects` |  | Confirmed | CRITICAL | 96 | — | F (Meteor, Wurst, LiquidBounce, Freecam) |
| `SSME-CL-0011` | Meteor Rejects (Meteor addon) — class package structure | PACKAGE_PREFIX | `anticope/rejects/` |  | Confirmed | CRITICAL | 95 | — | F (Meteor, Wurst, LiquidBounce nested) |
| `SSME-CL-0012` | Meteor Rejects (Meteor addon) — classes loaded in a running JVM | MEMORY_STRING | `anticope/rejects` |  | Strong | CRITICAL | 90 | — | P (memory reader tested on a live process; no cheat-loaded JVM available) |
| `SSME-CL-0013` | BleachHack — mod metadata | MOD_ID | `bleachhack` |  | Confirmed | CRITICAL | 96 | — | F (Meteor, Wurst, LiquidBounce, Freecam) |
| `SSME-CL-0014` | BleachHack — class package structure | PACKAGE_PREFIX | `org/bleachhack/` |  | Confirmed | CRITICAL | 95 | — | F (Meteor, Wurst, LiquidBounce nested) |
| `SSME-CL-0015` | BleachHack — classes loaded in a running JVM | MEMORY_STRING | `org/bleachhack` |  | Strong | CRITICAL | 90 | — | P (memory reader tested on a live process; no cheat-loaded JVM available) |

<details><summary>False positives, limitations and sources</summary>

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

## Cheat client string signatures

| ID | Name | Kind | Pattern | Scopes | Tier | Severity | Conf. | Weight | Verification |
|---|---|---|---|---|---|---|---|---|---|
| `SSME-ST-0001` | Meteor Client mixin configuration | STRING | `meteor-client.mixins.json` | resource, log | Strong | CRITICAL | 88 | 60 | F (mixin configs, log stack traces, injection APIs, community strings) |
| `SSME-ST-0002` | Wurst Client mixin configuration | STRING | `wurst.mixins.json` | resource, log | Strong | CRITICAL | 88 | 60 | F (mixin configs, log stack traces, injection APIs, community strings) |
| `SSME-ST-0003` | LiquidBounce mixin configuration | STRING | `liquidbounce.mixins.json` | resource, log | Strong | CRITICAL | 88 | 60 | F (mixin configs, log stack traces, injection APIs, community strings) |
| `SSME-ST-0010` | Meteor Client code in a log or stack trace | STRING | `meteordevelopment.meteorclient.` | log, config | Strong | CRITICAL | 88 | 60 | F (mixin configs, log stack traces, injection APIs, community strings) |
| `SSME-ST-0011` | Wurst Client code in a log or stack trace | STRING | `net.wurstclient.` | log, config | Strong | CRITICAL | 88 | 60 | F (mixin configs, log stack traces, injection APIs, community strings) |
| `SSME-ST-0012` | LiquidBounce code in a log or stack trace | STRING | `net.ccbluex.liquidbounce.` | log, config | Strong | CRITICAL | 88 | 60 | F (mixin configs, log stack traces, injection APIs, community strings) |
| `SSME-ST-0013` | BleachHack code in a log or stack trace | STRING | `org.bleachhack.` | log, config | Strong | CRITICAL | 85 | 60 | F (mixin configs, log stack traces, injection APIs, community strings) |
| `SSME-ST-0014` | Meteor Rejects code in a log or stack trace | STRING | `anticope.rejects.` | log, config | Strong | CRITICAL | 85 | 60 | F (mixin configs, log stack traces, injection APIs, community strings) |
| `SSME-ST-0015` | Meteor Client classes referenced by another archive | STRING | `meteordevelopment/meteorclient/` | class | Weak | MEDIUM | 50 | 35 | F (mixin configs, log stack traces, injection APIs, community strings) |

<details><summary>False positives, limitations and sources</summary>

* **SSME-ST-0001** — *False positives:* Very low. A Meteor addon does not ship Meteor's own mixin configuration. *Limitations:* Renamed forks change the configuration name. *Source:* <https://github.com/MeteorDevelopment/meteor-client/blob/master/src/main/resources/fabric.mod.json>
* **SSME-ST-0002** — *False positives:* Very low. *Limitations:* Renamed forks change the configuration name. *Source:* <https://github.com/Wurst-Imperium/Wurst7/blob/master/src/main/resources/fabric.mod.json>
* **SSME-ST-0003** — *False positives:* Very low. *Limitations:* Renamed forks change the configuration name. *Source:* <https://github.com/CCBlueX/LiquidBounce/blob/nextgen/src/main/resources/fabric.mod.json>
* **SSME-ST-0010** — *False positives:* Low. Chat lines are excluded, so players typing the name does not match. *Limitations:* Logs are rotated; only logs still present in the instance are examined. *Source:* <https://github.com/MeteorDevelopment/meteor-client>
* **SSME-ST-0011** — *False positives:* Low. Chat lines are excluded. *Limitations:* Only logs still present in the instance are examined. *Source:* <https://github.com/Wurst-Imperium/Wurst7>
* **SSME-ST-0012** — *False positives:* Low. Chat lines are excluded. *Limitations:* Only logs still present in the instance are examined. *Source:* <https://github.com/CCBlueX/LiquidBounce>
* **SSME-ST-0013** — *False positives:* Low. Chat lines are excluded. *Limitations:* Only logs still present in the instance are examined. *Source:* <https://github.com/BleachDev/BleachHack>
* **SSME-ST-0014** — *False positives:* Low. Chat lines are excluded. *Limitations:* Only logs still present in the instance are examined. *Source:* <https://github.com/AntiCope/meteor-rejects>
* **SSME-ST-0015** — *False positives:* Addons may be cosmetic; review the addon's feature classes. *Limitations:* An addon alone does nothing without Meteor Client; check for the client itself. *Source:* <https://github.com/MeteorDevelopment/meteor-addon-template>

</details>

## Instance artifacts (folders/files clients create in the game directory)

| ID | Name | Kind | Pattern | Scopes | Tier | Severity | Conf. | Weight | Verification |
|---|---|---|---|---|---|---|---|---|---|
| `SSME-IP-0001` | Meteor Client data folder in instance | INSTANCE_PATH_REGEX | `^meteor-client/` |  | Strong | CRITICAL | 85 | 60 | F (meteor-client/, wurst/) |
| `SSME-IP-0002` | Wurst Client configuration in instance | INSTANCE_PATH_REGEX | `^wurst/(enabled-hacks\|keybinds\|settings\|friends\|windows\|preferences\|analytics)\.json$` |  | Strong | CRITICAL | 85 | 60 | F (meteor-client/, wurst/) |
| `SSME-IP-0003` | LiquidBounce data folder in instance | INSTANCE_PATH_REGEX | `(?i)^liquidbounce/` |  | Strong | CRITICAL | 85 | 60 | F (meteor-client/, wurst/) |
| `SSME-IP-0004` | BleachHack data folder in instance | INSTANCE_PATH_REGEX | `^bleach/` |  | Strong | CRITICAL | 75 | 45 | F (meteor-client/, wurst/) |
| `SSME-IP-0005` | Baritone settings in instance | INSTANCE_PATH_REGEX | `^baritone/settings\.txt$` |  | Strong | MEDIUM | 85 | 60 | F (meteor-client/, wurst/) |

<details><summary>False positives, limitations and sources</summary>

* **SSME-IP-0001** — *False positives:* Low. The folder is created by the client's own code; another mod would have to use the same folder name. A copied instance folder carries the artifact with it. *Limitations:* Shows that the client ran in this instance at some point (the folder survives uninstalling the client). It does not show when. *Source:* <https://github.com/MeteorDevelopment/meteor-client/blob/master/src/main/java/meteordevelopment/meteorclient/MeteorClient.java>
* **SSME-IP-0002** — *False positives:* Low. The folder is created by the client's own code; another mod would have to use the same folder name. A copied instance folder carries the artifact with it. *Limitations:* Shows that the client ran in this instance at some point (the folder survives uninstalling the client). It does not show when. *Source:* <https://github.com/Wurst-Imperium/Wurst7/blob/master/src/main/java/net/wurstclient/WurstClient.java>
* **SSME-IP-0003** — *False positives:* Low. The folder is created by the client's own code; another mod would have to use the same folder name. A copied instance folder carries the artifact with it. *Limitations:* Shows that the client ran in this instance at some point (the folder survives uninstalling the client). It does not show when. *Source:* <https://github.com/CCBlueX/LiquidBounce/blob/nextgen/src/main/kotlin/net/ccbluex/liquidbounce/config/ConfigSystem.kt>
* **SSME-IP-0004** — *False positives:* Low to moderate: the folder name is short and generic. Review its contents. *Limitations:* Shows that the client ran in this instance at some point (the folder survives uninstalling the client). It does not show when. *Source:* <https://github.com/BleachDev/BleachHack/blob/1.19.4/src/main/java/org/bleachhack/util/io/BleachFileMang.java>
* **SSME-IP-0005** — *False positives:* Baritone is allowed on some servers and in singleplayer. *Limitations:* Shows that the client ran in this instance at some point (the folder survives uninstalling the client). It does not show when. *Source:* <https://github.com/cabaletta/baritone/blob/1.20.1/src/api/java/baritone/api/utils/SettingsUtil.java>

</details>

## Injection (ghost) clients — community-sourced strings (weak)

| ID | Name | Kind | Pattern | Scopes | Tier | Severity | Conf. | Weight | Verification |
|---|---|---|---|---|---|---|---|---|---|
| `SSME-IC-0001` | AVIX client string | STRING | `/AVIX-Config` | memory, class, binary | Weak | HIGH | 45 | 35 | F (mixin configs, log stack traces, injection APIs, community strings) |
| `SSME-IC-0002` | Bape client string | STRING | `trumpclientftw_bape` | memory, class, binary | Weak | HIGH | 45 | 35 | F (mixin configs, log stack traces, injection APIs, community strings) |
| `SSME-IC-0003` | Drek client string | STRING | `dg82fo.pw` | memory, class, binary | Weak | HIGH | 45 | 35 | F (mixin configs, log stack traces, injection APIs, community strings) |
| `SSME-IC-0004` | Gucci client string | STRING | `G0ttaDipMen.java` | memory, class, binary | Weak | HIGH | 45 | 35 | F (mixin configs, log stack traces, injection APIs, community strings) |
| `SSME-IC-0005` | Harambe client string | STRING | `Harambe.png` | memory, class, binary | Weak | HIGH | 45 | 35 | F (mixin configs, log stack traces, injection APIs, community strings) |
| `SSME-IC-0006` | Incognito client string | STRING | `czaarek99` | memory, class, binary | Weak | HIGH | 45 | 35 | F (mixin configs, log stack traces, injection APIs, community strings) |
| `SSME-IC-0007` | Onetap client string | STRING | `onetap.cc` | memory, class, binary | Weak | HIGH | 45 | 35 | F (mixin configs, log stack traces, injection APIs, community strings) |
| `SSME-IC-0008` | Spooky client string | STRING | `bspkrs.IlIIIlIlIllIIlllIllIllIII` | memory, class, binary | Weak | HIGH | 45 | 35 | F (mixin configs, log stack traces, injection APIs, community strings) |
| `SSME-IC-0009` | Vape v2 hidden loader class | STRING | `com/sun/jna/z/Main` | memory, class, binary | Weak | HIGH | 55 | 45 | F (mixin configs, log stack traces, injection APIs, community strings) |
| `SSME-IC-0010` | Time Changer client string | STRING | `/a.class:::0` | memory, class, binary | Weak | HIGH | 45 | 35 | F (mixin configs, log stack traces, injection APIs, community strings) |
| `SSME-IC-0011` | Zuiy client string | STRING | `0SO1Lk2KASxzsd` | memory, class, binary | Weak | HIGH | 45 | 35 | F (mixin configs, log stack traces, injection APIs, community strings) |
| `SSME-IC-0012` | Vape 2.50 network endpoint | STRING | `74.91.125.194` | memory, class, binary | Weak | HIGH | 45 | 35 | F (mixin configs, log stack traces, injection APIs, community strings) |
| `SSME-IC-0013` | Vape Lite network endpoint | STRING | `144.217.241.181` | memory, class, binary | Weak | HIGH | 45 | 35 | F (mixin configs, log stack traces, injection APIs, community strings) |
| `SSME-IC-0014` | Vea client string | STRING | `/tcpnodelaymod/COM1` | memory, class, binary | Weak | HIGH | 45 | 35 | F (mixin configs, log stack traces, injection APIs, community strings) |

<details><summary>False positives, limitations and sources</summary>

* **SSME-IC-0001** — *False positives:* Unverified community signature. Short or generic strings can occur in unrelated data; never act on this finding alone. *Limitations:* Targets old (1.7/1.8-era) injection clients; current releases are not covered. *Source:* <https://github.com/andreaonorato/Minecraft-Cheat-Scanner/blob/master/Strings%20Scanner.c>
* **SSME-IC-0002** — *False positives:* Unverified community signature. Short or generic strings can occur in unrelated data; never act on this finding alone. *Limitations:* Targets old (1.7/1.8-era) injection clients; current releases are not covered. *Source:* <https://github.com/andreaonorato/Minecraft-Cheat-Scanner/blob/master/Strings%20Scanner.c>
* **SSME-IC-0003** — *False positives:* Unverified community signature. Short or generic strings can occur in unrelated data; never act on this finding alone. *Limitations:* Targets old (1.7/1.8-era) injection clients; current releases are not covered. *Source:* <https://github.com/andreaonorato/Minecraft-Cheat-Scanner/blob/master/Strings%20Scanner.c>
* **SSME-IC-0004** — *False positives:* Unverified community signature. Short or generic strings can occur in unrelated data; never act on this finding alone. *Limitations:* Targets old (1.7/1.8-era) injection clients; current releases are not covered. *Source:* <https://github.com/andreaonorato/Minecraft-Cheat-Scanner/blob/master/Strings%20Scanner.c>
* **SSME-IC-0005** — *False positives:* Unverified community signature. Short or generic strings can occur in unrelated data; never act on this finding alone. *Limitations:* Targets old (1.7/1.8-era) injection clients; current releases are not covered. *Source:* <https://github.com/andreaonorato/Minecraft-Cheat-Scanner/blob/master/Strings%20Scanner.c>
* **SSME-IC-0006** — *False positives:* This is also a developer handle that can appear in unrelated credits. Never act on this finding alone. *Limitations:* Targets old (1.7/1.8-era) injection clients; current releases are not covered. *Source:* <https://github.com/andreaonorato/Minecraft-Cheat-Scanner/blob/master/Strings%20Scanner.c>
* **SSME-IC-0007** — *False positives:* Unverified community signature. Short or generic strings can occur in unrelated data; never act on this finding alone. *Limitations:* Targets old (1.7/1.8-era) injection clients; current releases are not covered. *Source:* <https://github.com/andreaonorato/Minecraft-Cheat-Scanner/blob/master/Strings%20Scanner.c>
* **SSME-IC-0008** — *False positives:* Unverified community signature. Short or generic strings can occur in unrelated data; never act on this finding alone. *Limitations:* Targets old (1.7/1.8-era) injection clients; current releases are not covered. *Source:* <https://github.com/andreaonorato/Minecraft-Cheat-Scanner/blob/master/Strings%20Scanner.c>
* **SSME-IC-0009** — *False positives:* Unverified community signature. Short or generic strings can occur in unrelated data; never act on this finding alone. *Limitations:* Targets old (1.7/1.8-era) injection clients; current releases are not covered. *Source:* <https://github.com/andreaonorato/Minecraft-Cheat-Scanner/blob/master/Strings%20Scanner.c>
* **SSME-IC-0010** — *False positives:* Unverified community signature. Short or generic strings can occur in unrelated data; never act on this finding alone. *Limitations:* Targets old (1.7/1.8-era) injection clients; current releases are not covered. *Source:* <https://github.com/andreaonorato/Minecraft-Cheat-Scanner/blob/master/Strings%20Scanner.c>
* **SSME-IC-0011** — *False positives:* Unverified community signature. Short or generic strings can occur in unrelated data; never act on this finding alone. *Limitations:* Targets old (1.7/1.8-era) injection clients; current releases are not covered. *Source:* <https://github.com/andreaonorato/Minecraft-Cheat-Scanner/blob/master/Strings%20Scanner.c>
* **SSME-IC-0012** — *False positives:* IP addresses are re-assigned over time and can appear in unrelated server lists. *Limitations:* Targets old (1.7/1.8-era) injection clients; current releases are not covered. *Source:* <https://github.com/andreaonorato/Minecraft-Cheat-Scanner/blob/master/Strings%20Scanner.c>
* **SSME-IC-0013** — *False positives:* IP addresses are re-assigned over time and can appear in unrelated server lists. *Limitations:* Targets old (1.7/1.8-era) injection clients; current releases are not covered. *Source:* <https://github.com/andreaonorato/Minecraft-Cheat-Scanner/blob/master/Strings%20Scanner.c>
* **SSME-IC-0014** — *False positives:* Unverified community signature. Short or generic strings can occur in unrelated data; never act on this finding alone. *Limitations:* Targets old (1.7/1.8-era) injection clients; current releases are not covered. *Source:* <https://github.com/andreaonorato/Minecraft-Cheat-Scanner/blob/master/Strings%20Scanner.c>

</details>

## Generic injection, automation and obfuscation indicators (combination only)

| ID | Name | Kind | Pattern | Scopes | Tier | Severity | Conf. | Weight | Verification |
|---|---|---|---|---|---|---|---|---|---|
| `SSME-IJ-0001` | Remote thread creation API | STRING | `CreateRemoteThread` | binary | Weak (indicator) | HIGH | 55 | 25 | F (mixin configs, log stack traces, injection APIs, community strings) |
| `SSME-IJ-0002` | Remote memory allocation API | STRING | `VirtualAllocEx` | binary | Weak (indicator) | HIGH | 55 | 25 | F (mixin configs, log stack traces, injection APIs, community strings) |
| `SSME-IJ-0003` | Remote memory write API | STRING | `WriteProcessMemory` | binary | Weak (indicator) | HIGH | 55 | 25 | F (mixin configs, log stack traces, injection APIs, community strings) |
| `SSME-IJ-0004` | Undocumented thread creation API | STRING | `NtCreateThreadEx` | binary | Weak (indicator) | HIGH | 55 | 30 | F (mixin configs, log stack traces, injection APIs, community strings) |
| `SSME-IJ-0005` | Attach to running Java VM from native code | STRING | `JNI_GetCreatedJavaVMs` | binary | Weak (indicator) | HIGH | 60 | 40 | F (mixin configs, log stack traces, injection APIs, community strings) |
| `SSME-IJ-0006` | JVM tool interface agent entry point | STRING | `Agent_OnAttach` | binary | Weak (indicator) | HIGH | 55 | 30 | F (mixin configs, log stack traces, injection APIs, community strings) |
| `SSME-IJ-0010` | Runtime class redefinition | STRING | `redefineClasses` | class | Weak (indicator) | MEDIUM | 40 | 20 | F (mixin configs, log stack traces, injection APIs, community strings) |
| `SSME-IJ-0011` | Instrumentation API usage | STRING | `java/lang/instrument/Instrumentation` | class | Weak (indicator) | MEDIUM | 40 | 15 | F (mixin configs, log stack traces, injection APIs, community strings) |
| `SSME-IJ-0012` | Dynamic agent attach API | STRING | `com/sun/tools/attach/VirtualMachine` | class | Weak (indicator) | MEDIUM | 45 | 25 | F (mixin configs, log stack traces, injection APIs, community strings) |
| `SSME-IJ-0020` | Global input hook library (JNativeHook) | STRING | `com/github/kwhat/jnativehook` | class | Weak (indicator) | MEDIUM | 40 | 30 | F (mixin configs, log stack traces, injection APIs, community strings) |
| `SSME-IJ-0021` | Synthetic mouse input from Java | STRING | `java/awt/Robot` | class | Weak (indicator) | MEDIUM | 35 | 15 | F (mixin configs, log stack traces, injection APIs, community strings) |
| `SSME-OB-0001` | Allatori obfuscator watermark | STRING | `ALLATORIxDEMO` | class, resource | Weak (indicator) | LOW | 35 | 30 | F (mixin configs, log stack traces, injection APIs, community strings) |
| `SSME-IJ-0030` | Java agent in a script or configuration | STRING | `-javaagent:` | script, config | Weak (indicator) | MEDIUM | 45 | 30 | F (mixin configs, log stack traces, injection APIs, community strings) |

Library packages exempt from generic indicators: `org/spongepowered/` (Mixin (SpongePowered)), `net/bytebuddy/` (Byte Buddy), `kotlinx/coroutines/debug/` (Kotlin coroutines debug agent), `net/fabricmc/loader/` (Fabric Loader), `org/objectweb/asm/` (ObjectWeb ASM), `me/lucko/spark/` (Spark profiler).

<details><summary>False positives, limitations and sources</summary>

* **SSME-IJ-0001** — *False positives:* Each string has legitimate uses; only combinations are reported, and never as proof. *Limitations:* Packed or encrypted binaries hide their imports; absence of these strings proves nothing.
* **SSME-IJ-0002** — *False positives:* Each string has legitimate uses; only combinations are reported, and never as proof. *Limitations:* Packed or encrypted binaries hide their imports; absence of these strings proves nothing.
* **SSME-IJ-0003** — *False positives:* Each string has legitimate uses; only combinations are reported, and never as proof. *Limitations:* Packed or encrypted binaries hide their imports; absence of these strings proves nothing.
* **SSME-IJ-0004** — *False positives:* Each string has legitimate uses; only combinations are reported, and never as proof. *Limitations:* Packed or encrypted binaries hide their imports; absence of these strings proves nothing.
* **SSME-IJ-0005** — *False positives:* Each string has legitimate uses; only combinations are reported, and never as proof. *Limitations:* Packed or encrypted binaries hide their imports; absence of these strings proves nothing.
* **SSME-IJ-0006** — *False positives:* Each string has legitimate uses; only combinations are reported, and never as proof. *Limitations:* Packed or encrypted binaries hide their imports; absence of these strings proves nothing.
* **SSME-IJ-0010** — *False positives:* Each string has legitimate uses; only combinations are reported, and never as proof. *Limitations:* Packed or encrypted binaries hide their imports; absence of these strings proves nothing.
* **SSME-IJ-0011** — *False positives:* Each string has legitimate uses; only combinations are reported, and never as proof. *Limitations:* Packed or encrypted binaries hide their imports; absence of these strings proves nothing.
* **SSME-IJ-0012** — *False positives:* Each string has legitimate uses; only combinations are reported, and never as proof. *Limitations:* Packed or encrypted binaries hide their imports; absence of these strings proves nothing.
* **SSME-IJ-0020** — *False positives:* Hotkey and overlay mods also use global hooks. *Limitations:* Packed or encrypted binaries hide their imports; absence of these strings proves nothing.
* **SSME-IJ-0021** — *False positives:* Each string has legitimate uses; only combinations are reported, and never as proof. *Limitations:* Packed or encrypted binaries hide their imports; absence of these strings proves nothing.
* **SSME-OB-0001** — *False positives:* Some legitimate closed-source mods are obfuscated. *Limitations:* Packed or encrypted binaries hide their imports; absence of these strings proves nothing.
* **SSME-IJ-0030** — *False positives:* Launcher configuration files that legitimately configure a profiler or the launcher's own agent. *Limitations:* Packed or encrypted binaries hide their imports; absence of these strings proves nothing.

</details>

## Utility and automation modifications

| ID | Name | Kind | Pattern | Scopes | Tier | Severity | Conf. | Weight | Verification |
|---|---|---|---|---|---|---|---|---|---|
| `SSME-UT-0016` | Baritone pathing/automation bot | MOD_ID | `baritone` |  | Confirmed | MEDIUM | 95 | — | F (Meteor, Wurst, LiquidBounce, Freecam) |
| `SSME-UT-0017` | Baritone classes bundled in archive | PACKAGE_PREFIX | `baritone/api/` |  | Confirmed | MEDIUM | 92 | — | F (Meteor, Wurst, LiquidBounce nested) |
| `SSME-UT-0018` | Freecam modification | MOD_ID | `freecam` |  | Confirmed | MEDIUM | 90 | — | F (Meteor, Wurst, LiquidBounce, Freecam) |
| `SSME-UT-0019` | X-ray modification (name/metadata) | MOD_ID_REGEX | `(?i)(^\|[^a-z])x[-_ ]?ray` |  | Suspicious config | HIGH | 75 | — | N |
| `SSME-UT-0020` | X-ray resource pack | RESOURCEPACK_REGEX | `(?i)x[-_ ]?ray` |  | Suspicious config | MEDIUM | 65 | — | F · L (real X-ray pack) |
| `SSME-UT-0078` | Tweakeroo (gameplay tweaks incl. freecam/fast placement) | MOD_ID | `tweakeroo` |  | Suspicious config | LOW | 60 | — | F (Meteor, Wurst, LiquidBounce, Freecam) |
| `SSME-UT-0079` | Item Scroller (inventory automation) | MOD_ID | `itemscroller` |  | Suspicious config | LOW | 55 | — | F (Meteor, Wurst, LiquidBounce, Freecam) |

<details><summary>False positives, limitations and sources</summary>

* **SSME-UT-0016** — *False positives:* Baritone is legitimate on singleplayer and on servers that allow it. The finding confirms installation, not misuse. *Limitations:* Cannot determine which server it was used on. *Source:* <https://github.com/cabaletta/baritone/blob/1.20.1/fabric/src/main/resources/fabric.mod.json>
* **SSME-UT-0017** — *False positives:* Baritone is allowed on some servers and in singleplayer. *Limitations:* Presence only. *Source:* <https://github.com/cabaletta/baritone>
* **SSME-UT-0018** — *False positives:* Freecam is permitted on many servers and widely used for building and screenshots. *Limitations:* Server policy determines whether this is a violation. Presence on disk does not prove use on the server. *Source:* <https://modrinth.com/mod/freecam>
* **SSME-UT-0019** — *False positives:* Mods with xray in the name may be anti-xray tools for server owners, or utilities for singleplayer/creative. *Limitations:* Name-based. Requires manual review of the mod.
* **SSME-UT-0020** — *False positives:* Pack names are user-controlled; a pack may be mis-named or unused. *Limitations:* Only checks the pack file/folder name, not whether the pack was active.
* **SSME-UT-0078** — *False positives:* Tweakeroo is a popular, legitimate technical-play mod; most features are harmless. *Limitations:* Cannot see which tweaks were enabled unless its config is reviewed manually. *Source:* <https://github.com/maruohon/tweakeroo>
* **SSME-UT-0079** — *False positives:* Widely allowed on survival servers; usually only prohibited in competitive PvP. *Limitations:* Presence only. *Source:* <https://github.com/maruohon/itemscroller>

</details>

## Resource and shader packs

| ID | Name | Kind | Pattern | Scopes | Tier | Severity | Conf. | Weight | Verification |
|---|---|---|---|---|---|---|---|---|---|
| `SSME-SP-0001` | X-ray shader pack | SHADERPACK_REGEX | `(?i)x[-_ ]?ray` |  | Suspicious config | MEDIUM | 60 | — | F |

<details><summary>False positives, limitations and sources</summary>

* **SSME-SP-0001** — *False positives:* Pack names are user-controlled; a pack may be mis-named or unused. *Limitations:* Only the name is checked; shader programs are not interpreted.

</details>

## Executables and file names

| ID | Name | Kind | Pattern | Scopes | Tier | Severity | Conf. | Weight | Verification |
|---|---|---|---|---|---|---|---|---|---|
| `SSME-EX-0080` | Auto-clicker executed | EXECUTABLE_REGEX | `(?i)auto[\s_\-.]*click` |  | Suspicious config | MEDIUM | 70 | — | N |
| `SSME-EX-0081` | DLL injector executed | EXECUTABLE_REGEX | `(?i)(injector\|xenos(64)?\.exe\|extreme ?injector)` |  | Suspicious config | HIGH | 70 | — | N |
| `SSME-EX-0082` | Memory editor executed (Cheat Engine) | EXECUTABLE_REGEX | `(?i)^cheat ?engine\|^cheatengine` |  | Weak | MEDIUM | 50 | — | N |
| `SSME-EX-0083` | Process manipulation tool executed | EXECUTABLE_REGEX | `(?i)^(processhacker\|systeminformer)` |  | Weak | LOW | 35 | — | N |
| `SSME-EX-0084` | Secure-delete tool executed | EXECUTABLE_REGEX | `(?i)^sdelete(64)?(a)?\.exe` |  | Weak | MEDIUM | 45 | — | N |
| `SSME-EX-0085` | Macro automation runtime executed (AutoHotkey) | EXECUTABLE_REGEX | `(?i)^autohotkey` |  | Weak | LOW | 30 | — | N |
| `SSME-FN-0086` | File named after a known cheat client | FILE_NAME_REGEX | `(?i)(meteor[-_ ]?client\|wurst[-_ ]?client\|liquidbounce\|aristois\|bleachhack\|doomsday\|novoware\|rusherhack\|thunderhack\|vape[-_ ]?(v4\|lite\|client)\|slinky\|whiteout[-_ ]?client\|drip[-_ ]?(lite\|client))` |  | Suspicious config | MEDIUM | 60 | — | F (supporting evidence only) |
| `SSME-FN-0087` | JNativeHook native library extracted | FILE_NAME_REGEX | `(?i)^jnativehook.*\.dll$` |  | Weak | LOW | 35 | — | F (supporting evidence only) |

<details><summary>False positives, limitations and sources</summary>

* **SSME-EX-0080** — *False positives:* Auto-clickers have non-gaming uses (accessibility, idle games). Execution time must be correlated with the game session. *Limitations:* Matched against executables stored inside the selected instance. Names are user-controlled; a renamed tool will not match, but every executable in the instance is also string-scanned.
* **SSME-EX-0081** — *False positives:* Some modding tools for other games are named "injector". *Limitations:* Matched against executables stored inside the selected instance. Names are user-controlled; a renamed tool will not match, but every executable in the instance is also string-scanned.
* **SSME-EX-0082** — *False positives:* Cheat Engine is commonly used for singleplayer games and learning. *Limitations:* Matched against executables stored inside the selected instance. Names are user-controlled; a renamed tool will not match, but every executable in the instance is also string-scanned.
* **SSME-EX-0083** — *False positives:* Popular legitimate administration tools. *Limitations:* Matched against executables stored inside the selected instance. Names are user-controlled; a renamed tool will not match, but every executable in the instance is also string-scanned.
* **SSME-EX-0084** — *False positives:* Used legitimately for privacy. *Limitations:* Matched against executables stored inside the selected instance. Names are user-controlled; a renamed tool will not match, but every executable in the instance is also string-scanned.
* **SSME-EX-0085** — *False positives:* AutoHotkey is a very common productivity tool. *Limitations:* Matched against executables stored inside the selected instance. Names are user-controlled; a renamed tool will not match, but every executable in the instance is also string-scanned.
* **SSME-FN-0086** — *False positives:* File names are user-controlled; a file may be mis-named, an installer, or unrelated. A name alone never confirms a client. *Limitations:* Renamed clients will not match. The file content is analysed separately when it still exists.
* **SSME-FN-0087** — *False positives:* Legitimate Java applications (hotkey tools, overlays) also use JNativeHook. *Limitations:* Only observed in temporary folders; the extracting program is not identified.

</details>

## Built-in heuristics

Implemented in `apps/desktop/src/Screensharing.Scanner/Modules`. Administrators can disable them or change severity/tier.

| ID | Name | Tier | Severity | Conf. | What it examines | False-positive risk | Verification |
|---|---|---|---|---|---|---|---|
| `SSME-H-CLASSPATH_UNEXPECTED` | Unverified archive on the game's class path | Suspicious config | MEDIUM | 60 | The running game loads a jar from outside the instance, the launcher's library and version folders, and the jar is not recognised as the launcher's own. Adding a jar to the class path is a way to inject code without using the mods folder. | Custom launch scripts and some third-party launchers place jars elsewhere. | L (Modrinth's temp-folder theseus.jar correctly recognised as the launcher's own) |
| `SSME-H-CLIENT_JAR_MODIFIED` | Vanilla client jar does not match Mojang's published hash | Strong | HIGH | 85 | The SHA-1 of the client jar on the running game's class path differs from the hash Mojang publishes in the version manifest next to it, meaning the game code itself was modified. | A corrupted download produces the same result; the launcher normally re-downloads mismatching files. | F |
| `SSME-H-DISGUISED_ARCHIVE` | Archive disguised as a different mod | Strong | HIGH | 85 | The file name claims a well-known mod (e.g. 'sodium-…jar') but the archive's own metadata declares a different, unrelated mod id. | Repackaged or forked builds sometimes keep upstream file names. | F |
| `SSME-H-DUPLICATE_MOD_ID` | Duplicate mod id across archives | Weak | LOW | 40 | Two archives in the same mods folder declare the same mod id, which can indicate a swapped or disguised copy. | Users often leave an old version next to an update. | F |
| `SSME-H-EMBEDDED_EXECUTABLE` | Native executable embedded in archive | Suspicious config | MEDIUM | 60 | The archive contains a Windows executable (PE) image. Executables hidden under non-library names or extensions are reported as strong indicators. | Many legitimate mods ship native libraries (.dll) for audio codecs, voice chat, Discord presence or compression; those are inspected but not reported unless their strings match. | F |
| `SSME-H-ENCRYPTED_CLASSES` | Encrypted or non-standard class files in archive | Strong | HIGH | 80 | Entries named *.class do not start with the Java class-file magic (CAFEBABE). The JVM cannot load them directly, so the archive must decrypt them with its own class loader — a technique used to hide cheat code from string and class scanning. | A handful of mods ship non-class data under a .class name by mistake; a single entry is reported as a weak indicator only. | F |
| `SSME-H-EXECUTABLE_IN_INSTANCE` | Unexpected executable inside the instance | Suspicious config | MEDIUM | 60 | A Windows executable or DLL is stored inside the Minecraft instance outside its native-library folders and is not Authenticode-signed. Executables disguised with another extension are strong indicators. | Some mods extract unsigned helper DLLs into the instance (e.g. Discord rich presence). | F |
| `SSME-H-JAVA_AGENT_MANIFEST` | Java agent entry point inside mod archive | Suspicious config | HIGH | 70 | The archive's manifest declares Premain-Class/Agent-Class, so it can be attached to the JVM as an instrumentation agent and rewrite game classes at load time. | A few legitimate developer tools ship agent manifests; normal gameplay mods do not need one. | F |
| `SSME-H-JAVA_OPTIONS_ENV` | JVM options injected through the game's environment | Strong | HIGH | 85 | The environment of the selected game process contains JAVA_TOOL_OPTIONS / _JAVA_OPTIONS / JDK_JAVA_OPTIONS with -javaagent or -agentpath, so the JVM loaded an agent that does not appear in the visible launch arguments. | Rare developer setups (profilers, APM agents). | P (environment block read from a live process in tests) |
| `SSME-H-JAVAAGENT_ARGUMENT` | Java agent supplied in launch arguments | Suspicious config | HIGH | 75 | The selected game process (or its launcher configuration inside the instance) uses -javaagent/-agentpath with an agent that is not the launcher's own. | Profilers and some launchers use agents; launcher agents are allowlisted by their class content, not by path. | L (Modrinth App launcher agent correctly allowlisted by content) |
| `SSME-H-LIBRARY_MODIFIED` | Game library does not match published hash | Strong | HIGH | 80 | A library jar on the running game's class path has a different SHA-1 than its version manifest declares. | Interrupted downloads or manual library replacement by some launchers. | Shares the verified hashing path (76 real class-path jars verified on the live instance) |
| `SSME-H-LINKED_FOLDER` | Instance folder redirected outside the instance | Suspicious config | LOW | 55 | A folder the game loads content from (mods, config, resourcepacks or shaderpacks) is a symbolic link or junction to a location outside the instance. The game loads the redirected content; hiding mods behind a link keeps them out of a casual look at the instance folder. The redirected folder is followed and inspected as part of the instance. | Some players share one mods or resourcepacks folder between instances with links. | F (junctions) |
| `SSME-H-LOGGED_CHEAT_MOD` | Instance log or crash report shows a known cheat client being loaded | Strong | CRITICAL | 90 | The mod list in a game log or crash report of the selected instance contains a mod id that belongs to a known cheat client. | Log files can be copied from elsewhere, but this is uncommon. | F (log and crash report) |
| `SSME-H-LOGGED_MOD_MISSING` | Mod loaded in a previous session is no longer present | Suspicious config | MEDIUM | 65 | A log of the selected instance shows a mod being loaded that no longer exists in the instance's mods folder. Removing mods shortly before a screenshare is a common concealment technique. | Users legitimately remove or update mods between sessions. | F · L |
| `SSME-H-MEMORY_FEATURE_CLUSTER` | Cheat feature names present in game memory | Weak | LOW | 35 | Several distinct cheat-feature names (e.g. KillAura, AimAssist, TriggerBot) were found as strings in the memory of the selected game process. | Chat messages, server MOTDs or GUI text discussing cheats put the same words in memory. Treat as a lead only. | L (false positive found and fixed: vanilla words removed) |
| `SSME-H-METADATA_INCONSISTENT` | Inconsistent mod metadata | Weak | LOW | 40 | The mod metadata references entrypoint classes or mixin configurations that do not exist in the archive, or the archive declares no metadata while containing game-modifying classes. | Broken builds and mods that rely on language adapters can produce the same pattern. | F |
| `SSME-H-MOD_CHANGED_AFTER_SESSION` | Mods folder changed after the last game session | Weak | LOW | 35 | A file in the instance's mods folder was modified or created after the instance's most recent game log was written. | Installing or updating mods between sessions is normal. | F |
| `SSME-H-MOD_IMPERSONATION` | Archive impersonates a well-known mod | Strong | HIGH | 85 | The archive declares the mod id of a well-known mod, but contains none of the class packages every genuine build of that mod ships. Cheat clients adopt popular mod ids to blend into the mod list. | Unofficial forks that were re-packaged under a new package name. | F |
| `SSME-H-MODULE_CLASSES` | Cheat-module class structure in archive | Strong | HIGH | 85 | The archive contains classes named after several distinct cheat features (e.g. KillAura, AimAssist, Scaffold) organised like a hacked client's module system. | A legitimate mod may contain one similarly named class (e.g. a 'Reach' attribute). Severity rises with the number of distinct high-signal names. | F |
| `SSME-H-NON_JAR_ARCHIVE` | Java archive with a non-jar extension in mods folder | Suspicious config | MEDIUM | 60 | A file in a mods folder is a Java archive but uses a different extension, which may hide it from casual inspection while some loaders/injectors still use it. | Launchers disable mods by appending '.disabled'; those are reported separately as informational. | F |
| `SSME-H-OBFUSCATED_ARCHIVE` | Heavily obfuscated mod archive | Weak | MEDIUM | 45 | Most class names in the archive are one or two characters long or use non-ASCII/confusable names, consistent with commercial obfuscation used by paid clients. | Some legitimate closed-source mods are obfuscated (e.g. OptiFine-style distributions). | F |
| `SSME-H-POLYGLOT_ARCHIVE` | Executable disguised as a Java archive | Strong | HIGH | 85 | The file is a Windows executable that also contains a ZIP/JAR directory (or has data prepended to the archive). Such polyglot files can be loaded as a mod and run as a program. | Self-extracting installers have the same structure but do not belong in a mods folder. | F |
| `SSME-H-UNINSPECTABLE` | File could not be inspected | — | INFO | 0 | A relevant file of the instance could not be fully inspected (locked, unreadable, corrupt, encrypted entries or above the size limit). The scan cannot make a statement about its content. | Not an accusation. Files in use by the game are normally still readable. | F · L |
| `SSME-H-UNRECOGNIZED_MOD` | Unrecognised modification (manual review) | — | INFO | 0 | A mod archive in the instance is not in the catalog of known mods and could not be verified against the Modrinth registry. Listed for manual review. | Most unrecognised mods are legitimate niche or private mods. | F · L |
| `SSME-H-UNSIGNED_MODULE` | Unsigned native module loaded into the game | Suspicious config | MEDIUM | 65 | The selected game process has a native DLL loaded from a user-writable location without a valid Authenticode signature and not matching known game natives (LWJGL, OpenAL, GLFW, JNA, voice-chat codecs). | Overlays, shader tools and some legitimate mods load unsigned natives. | L (144 real modules examined, none flagged) |
| `SSME-H-XRAY_TEXTURES` | X-ray textures in resource pack | Strong | HIGH | 85 | The resource pack replaces common terrain blocks (stone, deepslate, dirt, netherrack…) with fully transparent textures or empty block models, which makes ores visible through terrain. Detected from the pack's content, so renaming the pack does not hide it. | Some creative/map-making packs make blocks transparent deliberately. | F · L (real X-ray pack, renamed-pack fixture) |

## Cheat-module names (used by the structural heuristic)

Used by SSME-H-MODULE_CLASSES (3+ distinct feature classes, or 2+ high-signal ones) and SSME-H-MEMORY_FEATURE_CLUSTER (\* = also searched in memory).

* **High-signal:** KillAura\*, AimAssist\*, AimBot, TriggerBot\*, AutoClicker\*, CrystalAura\*, AutoCrystal\*, AnchorAura\*, BedAura\*, Scaffold, ScaffoldWalk\*, AntiKnockback\*, AntiKB, Criticals, AutoTotem\*, ChestESP\*, PlayerESP\*, StorageESP\*, BowAimbot\*, NoFall\*, LongJump\*, HighJump\*, Jesus, Nuker, FastPlace, AutoArmor, AutoPot, AutoSoup, NoSlow, NoSlowdown, ElytraFly\*, BoatFly\*, AntiBot, Spider, Surround, HoleFiller\*, AutoAnchor\*, TpAura\*, InfiniteAura\*, MultiAura\*, SilentAura\*, WTap, AutoWTap\*, HitSelect, BlockHit
* **Ambiguous (only inside module packages):** Velocity, Reach, Fly, Flight, Speed, Timer, XRay, ESP, Freecam, Tracers, Step, Blink, Sprint, HitBoxes, Hitbox, Fullbright, Nametags, AutoTool, Phase, Glide, NoClip, AirJump
* **Module package segments:** module, modules, feature, features, hack, hacks, cheat, cheats, combat, movement, render, visual, visuals, exploit, exploits

## Known legitimate modifications (classification only)

Not findings. They classify mods in the inventory; `packages` enables the impersonation check (SSME-H-MOD_IMPERSONATION).

| Mod id | Name | Classification | Expected packages |
|---|---|---|---|
| `sodium` | Sodium | performance | `net/caffeinemc/mods/sodium/`, `me/jellysquid/mods/sodium/` |
| `lithium` | Lithium | performance | `net/caffeinemc/mods/lithium/`, `me/jellysquid/mods/lithium/` |
| `iris` | Iris Shaders | cosmetic | `net/irisshaders/iris/`, `net/coderbot/iris/` |
| `indium` | Indium | library |  |
| `fabric-api` | Fabric API | library | `net/fabricmc/fabric/` |
| `fabricloader` | Fabric Loader | library |  |
| `modmenu` | Mod Menu | utility | `com/terraformersmc/modmenu/` |
| `ferritecore` | FerriteCore | performance | `malte0811/ferritecore/` |
| `krypton` | Krypton | performance | `me/steinborn/krypton/` |
| `immediatelyfast` | ImmediatelyFast | performance | `net/raphimc/immediatelyfast/` |
| `entityculling` | Entity Culling | performance | `dev/tr7zw/entityculling/` |
| `c2me` | Concurrent Chunk Management Engine | performance |  |
| `starlight` | Starlight | performance |  |
| `continuity` | Continuity | cosmetic | `me/pepperbell/continuity/` |
| `cloth-config` | Cloth Config | library | `me/shedaniel/clothconfig2/`, `me/shedaniel/autoconfig/` |
| `cloth_config` | Cloth Config | library |  |
| `yet_another_config_lib_v3` | YetAnotherConfigLib | library | `dev/isxander/yacl3/` |
| `architectury` | Architectury API | library |  |
| `lambdynlights` | LambDynamicLights | cosmetic |  |
| `zoomify` | Zoomify | accessibility | `dev/isxander/zoomify/` |
| `ok_zoomer` | Ok Zoomer | accessibility |  |
| `appleskin` | AppleSkin | gameplay | `squeek/appleskin/` |
| `xaerominimap` | Xaero's Minimap | gameplay | `xaero/` |
| `xaeroworldmap` | Xaero's World Map | gameplay | `xaero/` |
| `journeymap` | JourneyMap | gameplay |  |
| `optifine` | OptiFine | performance |  |
| `essential` | Essential | cosmetic |  |
| `replaymod` | Replay Mod | utility |  |
| `voicechat` | Simple Voice Chat | utility | `de/maxhenkel/voicechat/` |
| `jei` | Just Enough Items | utility | `mezz/jei/` |
| `roughlyenoughitems` | Roughly Enough Items | utility |  |
| `emi` | EMI | utility | `dev/emi/emi/` |
| `sodium-extra` | Sodium Extra | performance |  |
| `reeses-sodium-options` | Reese's Sodium Options | utility |  |
| `moreculling` | More Culling | performance |  |
| `dynamic_fps` | Dynamic FPS | performance |  |
| `notenoughcrashes` | Not Enough Crashes | utility |  |
| `fabric-language-kotlin` | Fabric Language Kotlin | library |  |
| `mixinextras` | MixinExtras | library |  |
| `forge` | Minecraft Forge | library |  |
| `neoforge` | NeoForge | library |  |
| `minecraft` | Minecraft | library |  |
| `java` | Java | library |  |
| `badoptimizations` | BadOptimizations | performance |  |
| `modernfix` | ModernFix | performance | `org/embeddedt/modernfix/` |
| `puzzle` | Puzzle | utility |  |
| `entity_model_features` | Entity Model Features | cosmetic |  |
| `entity_texture_features` | Entity Texture Features | cosmetic |  |
| `betterf3` | BetterF3 | utility |  |
| `controlling` | Controlling | accessibility |  |
| `mousetweaks` | Mouse Tweaks | accessibility |  |
| `tweakeroo` | Tweakeroo | gameplay | `fi/dy/masa/tweakeroo/` |
| `itemscroller` | Item Scroller | gameplay | `fi/dy/masa/itemscroller/` |
| `litematica` | Litematica | utility | `fi/dy/masa/litematica/` |
| `minihud` | MiniHUD | gameplay | `fi/dy/masa/minihud/` |
| `malilib` | MaLiLib | library | `fi/dy/masa/malilib/` |
| `inventoryprofilesnext` | Inventory Profiles Next | gameplay |  |

## Researched but intentionally not shipped

* **Closed-source / paid clients** (Vape, Doomsday, Novoware, Drip, Slinky, Whiteout…): current internal identifiers are private and change per build. They are covered by the structural, encryption, injection, agent and memory heuristics, by community-sourced strings for old builds (weak), and by a file-name rule capped at *Suspicious configuration*.
* **Short community strings** from andreaonorato/Minecraft-Cheat-Scanner (`nG@W`, `+(M0G.V`, `dinkio`, `Sa_Vc`, `5d@56`, `TCNH$1`, `hi.a2`, `yCcADi`, `kc((k`): 4–7 characters match by chance in gigabytes of memory, so they were not adopted.
* **Aristois, Impact, RusherHack, Future, ThunderHack identifiers and data folders**: not verified against source during this build. Administrators can add them after verification — no code change is needed.
* **SHA-256 fingerprints of specific cheat releases**: the rule kind is supported; no hashes are shipped because none were obtained from a trustworthy source.
