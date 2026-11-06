// Authoring source for the screensharing.me detection catalog.
// Run `node packages/detection-rules/build-rules.mjs` to regenerate rules.json,
// which is (1) embedded in the desktop scanner as the offline fallback ruleset and
// (2) seeded into the DetectionRule table, where administrators can manage it.
//
// RULES OF THE CATALOG
// - Only identifiers verified against public source code are used for
//   CONFIRMED_ARTIFACT rules (see `references`).
// - A file name alone is never more than SUSPICIOUS_CONFIGURATION.
// - Every rule documents false positives and limitations.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const VERSION = "2026.11.06.1";

const rules = [];
const add = (r) => rules.push({ family: null, features: [], classification: null, references: [], ...r });

// ---------------------------------------------------------------------------
// 1. Open-source cheat clients — identifiers verified from their repositories.
// ---------------------------------------------------------------------------
const clients = [
  {
    key: "METEOR", name: "Meteor Client", modId: "meteor-client", pkg: "meteordevelopment/meteorclient/",
    features: ["KillAura", "CrystalAura", "AutoTotem", "Velocity", "Reach", "Fly", "Speed", "NoFall", "Jesus", "Timer", "XRay", "ESP", "Freecam", "Tracers", "Scaffold", "AutoClicker (TriggerBot)"],
    ref: "https://github.com/MeteorDevelopment/meteor-client/blob/master/src/main/resources/fabric.mod.json",
  },
  {
    key: "WURST", name: "Wurst Client", modId: "wurst", pkg: "net/wurstclient/",
    features: ["KillAura", "TriggerBot", "Reach", "AntiKnockback", "Criticals", "Flight", "Speed", "NoFall", "Jesus", "XRay", "ChestESP", "PlayerESP", "Freecam", "AutoMine"],
    ref: "https://github.com/Wurst-Imperium/Wurst7/blob/master/src/main/resources/fabric.mod.json",
  },
  {
    key: "LIQUIDBOUNCE", name: "LiquidBounce", modId: "liquidbounce", pkg: "net/ccbluex/liquidbounce/",
    features: ["KillAura", "AimBot", "Velocity", "Criticals", "Fly", "Speed", "NoFall", "LongJump", "Timer", "Scaffold", "ESP", "XRay"],
    ref: "https://github.com/CCBlueX/LiquidBounce/blob/nextgen/src/main/resources/fabric.mod.json",
  },
  {
    key: "METEOR_REJECTS", name: "Meteor Rejects (Meteor addon)", modId: "meteor-rejects", pkg: "anticope/rejects/",
    features: ["Additional combat, movement and render modules for Meteor Client"],
    ref: "https://github.com/AntiCope/meteor-rejects/blob/master/src/main/resources/fabric.mod.json",
  },
  {
    key: "BLEACHHACK", name: "BleachHack", modId: "bleachhack", pkg: "org/bleachhack/",
    features: ["KillAura", "Flight", "Speed", "NoFall", "Jesus", "ESP", "XRay", "Freecam"],
    ref: "https://github.com/BleachDev/BleachHack/blob/1.19.4/src/main/resources/fabric.mod.json",
  },
];

let n = 1;
const id = (p) => `SSME-${p}-${String(n++).padStart(4, "0")}`;
for (const c of clients) {
  add({
    id: id("CL"), name: `${c.name} — mod metadata`, kind: "MOD_ID", pattern: c.modId, family: c.name, features: c.features,
    category: "Cheat client", severity: "CRITICAL", tier: "CONFIRMED_ARTIFACT", confidence: 96,
    description: `A mod archive declares the mod id "${c.modId}", the identifier used by ${c.name}.`,
    falsePositives: "Very low. The mod id is declared by the client's own metadata. A third party could reuse the id, which is why the package-structure rule is evaluated independently and both are reported.",
    limitations: "Detects the archive on disk only. It does not prove the client was launched or used on a specific server; correlate with logs, Prefetch and memory findings.",
    references: [c.ref],
  });
  add({
    id: id("CL"), name: `${c.name} — class package structure`, kind: "PACKAGE_PREFIX", pattern: c.pkg, family: c.name, features: c.features,
    category: "Cheat client", severity: "CRITICAL", tier: "CONFIRMED_ARTIFACT", confidence: 95,
    description: `A Java archive contains compiled classes under the package "${c.pkg.replaceAll("/", ".").replace(/\.$/, "")}", which belongs to ${c.name}.`,
    falsePositives: "Very low. Addons legitimately depend on these packages but do not ship them; a jar that contains the classes contains the client code.",
    limitations: "Renamed/re-obfuscated forks change package names and will not match. Detects presence on disk, not use.",
    references: [c.ref],
  });
  add({
    id: id("CL"), name: `${c.name} — classes loaded in a running JVM`, kind: "MEMORY_STRING", pattern: c.pkg.replace(/\/$/, ""), family: c.name, features: c.features,
    category: "Cheat client", severity: "CRITICAL", tier: "STRONG_INDICATOR", confidence: 90,
    description: `The internal class path of ${c.name} was found in the memory of a running Java (Minecraft) process, indicating its classes were loaded.`,
    falsePositives: "Low. The string could be present if the user opened the client's jar in a Java-based tool running in the same JVM, which is uncommon for a game process.",
    limitations: "Only examines Java processes running at scan time. If the game was closed before the scan, no memory evidence exists.",
    references: [c.ref],
  });
}

// ---------------------------------------------------------------------------
// 2. Utility / automation modifications frequently prohibited by servers.
// ---------------------------------------------------------------------------
add({
  id: id("UT"), name: "Baritone pathing/automation bot", kind: "MOD_ID", pattern: "baritone", family: "Baritone",
  features: ["Automated pathing", "Automated mining", "Build automation"],
  category: "Automation", severity: "MEDIUM", tier: "CONFIRMED_ARTIFACT", confidence: 95,
  description: "Baritone, a bot that automates walking, mining and building, is installed.",
  falsePositives: "Baritone is legitimate on singleplayer and on servers that allow it. The finding confirms installation, not misuse.",
  limitations: "Cannot determine which server it was used on.",
  references: ["https://github.com/cabaletta/baritone/blob/1.20.1/fabric/src/main/resources/fabric.mod.json"],
});
add({
  id: id("UT"), name: "Baritone classes bundled in archive", kind: "PACKAGE_PREFIX", pattern: "baritone/api/", family: "Baritone",
  features: ["Automated pathing", "Automated mining"],
  category: "Automation", severity: "MEDIUM", tier: "CONFIRMED_ARTIFACT", confidence: 92,
  description: "A Java archive contains the Baritone API classes (Baritone may be bundled inside another client, e.g. Meteor's Baritone build).",
  falsePositives: "Baritone is allowed on some servers and in singleplayer.",
  limitations: "Presence only.",
  references: ["https://github.com/cabaletta/baritone"],
});
add({
  id: id("UT"), name: "Freecam modification", kind: "MOD_ID", pattern: "freecam", family: "Freecam",
  features: ["Freecam (detached camera — can reveal hidden bases and players)"],
  category: "Utility modification", severity: "MEDIUM", tier: "CONFIRMED_ARTIFACT", confidence: 90,
  description: "A freecam mod is installed. Freecam lets the camera leave the player's body and look through terrain from new angles.",
  falsePositives: "Freecam is permitted on many servers and widely used for building and screenshots.",
  limitations: "Server policy determines whether this is a violation. Presence on disk does not prove use on the server.",
  references: ["https://modrinth.com/mod/freecam"],
});
add({
  id: id("UT"), name: "X-ray modification (name/metadata)", kind: "MOD_ID_REGEX", pattern: "(?i)(^|[^a-z])x[-_ ]?ray", family: "X-ray",
  features: ["X-ray (seeing ores through blocks)"],
  category: "Utility modification", severity: "HIGH", tier: "SUSPICIOUS_CONFIGURATION", confidence: 75,
  description: "A mod whose id or name contains \"xray\" is installed. X-ray mods render ores and hidden blocks through terrain.",
  falsePositives: "Mods with xray in the name may be anti-xray tools for server owners, or utilities for singleplayer/creative.",
  limitations: "Name-based. Requires manual review of the mod.",
});
add({
  id: id("UT"), name: "X-ray resource pack", kind: "RESOURCEPACK_REGEX", pattern: "(?i)x[-_ ]?ray", family: "X-ray",
  features: ["X-ray via transparent block textures"],
  category: "Utility modification", severity: "MEDIUM", tier: "SUSPICIOUS_CONFIGURATION", confidence: 65,
  description: "A resource pack whose name contains \"xray\" is present. X-ray texture packs make stone transparent so ores are visible.",
  falsePositives: "Pack names are user-controlled; a pack may be mis-named or unused.",
  limitations: "Only checks the pack file/folder name, not whether the pack was active.",
});

// Known legitimate / classified mods. Mods listed here are NOT findings;
// they are classified in the mod inventory so investigators see context.
const known = [
  ["sodium", "Sodium", "performance"], ["lithium", "Lithium", "performance"], ["iris", "Iris Shaders", "cosmetic"],
  ["indium", "Indium", "library"], ["fabric-api", "Fabric API", "library"], ["fabricloader", "Fabric Loader", "library"],
  ["modmenu", "Mod Menu", "utility"], ["ferritecore", "FerriteCore", "performance"], ["krypton", "Krypton", "performance"],
  ["immediatelyfast", "ImmediatelyFast", "performance"], ["entityculling", "Entity Culling", "performance"],
  ["c2me", "Concurrent Chunk Management Engine", "performance"], ["starlight", "Starlight", "performance"],
  ["continuity", "Continuity", "cosmetic"], ["cloth-config", "Cloth Config", "library"], ["cloth_config", "Cloth Config", "library"],
  ["yet_another_config_lib_v3", "YetAnotherConfigLib", "library"], ["architectury", "Architectury API", "library"],
  ["lambdynlights", "LambDynamicLights", "cosmetic"], ["zoomify", "Zoomify", "accessibility"], ["ok_zoomer", "Ok Zoomer", "accessibility"],
  ["appleskin", "AppleSkin", "gameplay"], ["xaerominimap", "Xaero's Minimap", "gameplay"], ["xaeroworldmap", "Xaero's World Map", "gameplay"],
  ["journeymap", "JourneyMap", "gameplay"], ["optifine", "OptiFine", "performance"], ["essential", "Essential", "cosmetic"],
  ["replaymod", "Replay Mod", "utility"], ["voicechat", "Simple Voice Chat", "utility"], ["jei", "Just Enough Items", "utility"],
  ["roughlyenoughitems", "Roughly Enough Items", "utility"], ["emi", "EMI", "utility"], ["sodium-extra", "Sodium Extra", "performance"],
  ["reeses-sodium-options", "Reese's Sodium Options", "utility"], ["moreculling", "More Culling", "performance"],
  ["dynamic_fps", "Dynamic FPS", "performance"], ["notenoughcrashes", "Not Enough Crashes", "utility"],
  ["fabric-language-kotlin", "Fabric Language Kotlin", "library"], ["mixinextras", "MixinExtras", "library"],
  ["forge", "Minecraft Forge", "library"], ["neoforge", "NeoForge", "library"], ["minecraft", "Minecraft", "library"], ["java", "Java", "library"],
  ["badoptimizations", "BadOptimizations", "performance"], ["modernfix", "ModernFix", "performance"], ["puzzle", "Puzzle", "utility"],
  ["entity_model_features", "Entity Model Features", "cosmetic"], ["entity_texture_features", "Entity Texture Features", "cosmetic"],
  ["betterf3", "BetterF3", "utility"], ["controlling", "Controlling", "accessibility"], ["mousetweaks", "Mouse Tweaks", "accessibility"],
  ["tweakeroo", "Tweakeroo", "gameplay"], ["itemscroller", "Item Scroller", "gameplay"], ["litematica", "Litematica", "utility"],
  ["minihud", "MiniHUD", "gameplay"], ["malilib", "MaLiLib", "library"], ["inventoryprofilesnext", "Inventory Profiles Next", "gameplay"],
];
for (const [modId, name, cls] of known) {
  add({
    id: id("KM"), name, kind: "KNOWN_MOD", pattern: modId, classification: cls, family: name,
    category: "Known modification", severity: "INFO", tier: "INCONCLUSIVE", confidence: 0,
    description: `Classification entry for ${name} (${cls}). Known mods are listed in the inventory and are not reported as findings.`,
    falsePositives: "Not applicable — classification only.",
    limitations: "Classification is by declared mod id; a malicious jar can impersonate a mod id. Package-structure and heuristic rules still run on every archive.",
  });
}

// Mods that are commonly allowed but carry gameplay advantages: reported as LOW.
add({
  id: id("UT"), name: "Tweakeroo (gameplay tweaks incl. freecam/fast placement)", kind: "MOD_ID", pattern: "tweakeroo", family: "Tweakeroo",
  features: ["Freecam", "Flexible block placement", "Fast right click"], category: "Gameplay modification",
  severity: "LOW", tier: "SUSPICIOUS_CONFIGURATION", confidence: 60,
  description: "Tweakeroo is installed. It contains optional features (freecam, fast block placement) that many PvP servers prohibit.",
  falsePositives: "Tweakeroo is a popular, legitimate technical-play mod; most features are harmless.",
  limitations: "Cannot see which tweaks were enabled unless its config is reviewed manually.",
  references: ["https://github.com/maruohon/tweakeroo"],
});
add({
  id: id("UT"), name: "Item Scroller (inventory automation)", kind: "MOD_ID", pattern: "itemscroller", family: "Item Scroller",
  features: ["Inventory automation"], category: "Gameplay modification",
  severity: "LOW", tier: "SUSPICIOUS_CONFIGURATION", confidence: 55,
  description: "Item Scroller automates inventory item movement and crafting.",
  falsePositives: "Widely allowed on survival servers; usually only prohibited in competitive PvP.",
  limitations: "Presence only.",
  references: ["https://github.com/maruohon/itemscroller"],
});

// ---------------------------------------------------------------------------
// 3. Executables / tools observed in execution artifacts (Prefetch, BAM, processes)
// ---------------------------------------------------------------------------
const exe = (name, pattern, category, severity, tier, confidence, description, falsePositives) =>
  add({ id: id("EX"), name, kind: "EXECUTABLE_REGEX", pattern, category, severity, tier, confidence, description, falsePositives,
        limitations: "Execution artifacts record that a file with this name ran; names are user-controlled and a renamed tool will not match." });
exe("Auto-clicker executed", "(?i)auto[\\s_\\-.]*click", "Automation", "MEDIUM", "SUSPICIOUS_CONFIGURATION", 70,
  "An executable whose name identifies it as an auto-clicker was executed. Auto-clickers automate attacks (CPS manipulation).",
  "Auto-clickers have non-gaming uses (accessibility, idle games). Execution time must be correlated with the game session.");
exe("DLL injector executed", "(?i)(injector|xenos(64)?\\.exe|extreme ?injector)", "Injection", "HIGH", "SUSPICIOUS_CONFIGURATION", 70,
  "An executable named like a DLL injector was executed. Injectors are used to load ghost clients into the game process.",
  "Some modding tools for other games are named \"injector\".");
exe("Memory editor executed (Cheat Engine)", "(?i)^cheat ?engine|^cheatengine", "Memory tooling", "MEDIUM", "WEAK_INDICATOR", 50,
  "Cheat Engine, a memory scanner/editor, was executed.",
  "Cheat Engine is commonly used for singleplayer games and learning.");
exe("Process manipulation tool executed", "(?i)^(processhacker|systeminformer)", "Memory tooling", "LOW", "WEAK_INDICATOR", 35,
  "Process Hacker / System Informer was executed. These tools can terminate processes, edit memory strings and unload modules.",
  "Popular legitimate administration tools.");
exe("Secure-delete tool executed", "(?i)^sdelete(64)?(a)?\\.exe", "Anti-forensics", "MEDIUM", "WEAK_INDICATOR", 45,
  "A secure file deletion tool was executed. Secure deletion prevents recovery of files that were removed.",
  "Used legitimately for privacy.");
exe("Macro automation runtime executed (AutoHotkey)", "(?i)^autohotkey", "Automation", "LOW", "WEAK_INDICATOR", 30,
  "AutoHotkey was executed. AutoHotkey scripts can implement clicker or macro behaviour.",
  "AutoHotkey is a very common productivity tool.");

// ---------------------------------------------------------------------------
// 4. File names (never more than suspicious on their own)
// ---------------------------------------------------------------------------
add({
  id: id("FN"), name: "File named after a known cheat client", kind: "FILE_NAME_REGEX",
  pattern: "(?i)(meteor[-_ ]?client|wurst[-_ ]?client|liquidbounce|aristois|bleachhack|doomsday|novoware|rusherhack|thunderhack|vape[-_ ]?(v4|lite|client)|slinky|whiteout[-_ ]?client|drip[-_ ]?(lite|client))",
  category: "Cheat client", severity: "MEDIUM", tier: "SUSPICIOUS_CONFIGURATION", confidence: 60,
  description: "A Java archive, executable or library is named after a known cheat client.",
  falsePositives: "File names are user-controlled; a file may be mis-named, an installer, or unrelated. A name alone never confirms a client.",
  limitations: "Renamed clients will not match. The file content is analysed separately when it still exists.",
});
add({
  id: id("FN"), name: "JNativeHook native library extracted", kind: "FILE_NAME_REGEX", pattern: "(?i)^jnativehook.*\\.dll$",
  category: "Automation", severity: "LOW", tier: "WEAK_INDICATOR", confidence: 35,
  description: "The JNativeHook native library was extracted to a temporary folder. JNativeHook gives Java programs global mouse/keyboard hooks and is used by Java auto-clickers.",
  falsePositives: "Legitimate Java applications (hotkey tools, overlays) also use JNativeHook.",
  limitations: "Only observed in temporary folders; the extracting program is not identified.",
});

// ---------------------------------------------------------------------------
// 5. Built-in heuristics implemented in the scanning engine. Pattern unused.
// ---------------------------------------------------------------------------
const h = (key, name, category, severity, tier, confidence, description, falsePositives, limitations) =>
  add({ id: `SSME-H-${key}`, name, kind: "BUILTIN", pattern: key, category, severity, tier, confidence, description, falsePositives, limitations });

h("MODULE_CLASSES", "Cheat-module class structure in archive", "Client modification", "HIGH", "STRONG_INDICATOR", 85,
  "The archive contains classes named after several distinct cheat features (e.g. KillAura, AimAssist, Scaffold) organised like a hacked client's module system.",
  "A legitimate mod may contain one similarly named class (e.g. a 'Reach' attribute). Severity rises with the number of distinct high-signal names.",
  "Obfuscated clients rename classes and evade this heuristic.");
h("JAVA_AGENT_MANIFEST", "Java agent entry point inside mod archive", "Injection", "HIGH", "SUSPICIOUS_CONFIGURATION", 70,
  "The archive's manifest declares Premain-Class/Agent-Class, so it can be attached to the JVM as an instrumentation agent and rewrite game classes at load time.",
  "A few legitimate developer tools ship agent manifests; normal gameplay mods do not need one.",
  "Detects capability, not use.");
h("OBFUSCATED_ARCHIVE", "Heavily obfuscated mod archive", "Client modification", "MEDIUM", "WEAK_INDICATOR", 45,
  "Most class names in the archive are one or two characters long or use non-ASCII/confusable names, consistent with commercial obfuscation used by paid clients.",
  "Some legitimate closed-source mods are obfuscated (e.g. OptiFine-style distributions).",
  "Obfuscation is not proof of cheating.");
h("DISGUISED_ARCHIVE", "Archive disguised as a different mod", "Client modification", "HIGH", "STRONG_INDICATOR", 85,
  "The file name claims a well-known mod (e.g. 'sodium-…jar') but the archive's own metadata declares a different, unrelated mod id.",
  "Repackaged or forked builds sometimes keep upstream file names.",
  "Only triggers for file names containing a known-mod id.");
h("NON_JAR_ARCHIVE", "Java archive with a non-jar extension in mods folder", "Client modification", "MEDIUM", "SUSPICIOUS_CONFIGURATION", 60,
  "A file in a mods folder is a Java archive but uses a different extension, which may hide it from casual inspection while some loaders/injectors still use it.",
  "Launchers disable mods by appending '.disabled'; those are reported separately as informational.",
  "Disabled archives are not loaded by the game.");
h("DUPLICATE_MOD_ID", "Duplicate mod id across archives", "Client modification", "LOW", "WEAK_INDICATOR", 40,
  "Two archives in the same mods folder declare the same mod id, which can indicate a swapped or disguised copy.",
  "Users often leave an old version next to an update.",
  "Mod loaders refuse to start with duplicates, so the configuration may never have run.");
h("UNRECOGNIZED_MOD", "Unrecognised modification (manual review)", "Unrecognised modification", "INFO", "INCONCLUSIVE", 0,
  "A mod archive is not in the catalog of known mods and could not be verified against the Modrinth registry.",
  "Most unrecognised mods are legitimate niche or private mods.",
  "Listed for completeness; this is not an accusation.");
h("CLIENT_JAR_MODIFIED", "Vanilla client jar does not match Mojang's published hash", "Game integrity", "HIGH", "STRONG_INDICATOR", 85,
  "The SHA-1 of versions/<id>/<id>.jar differs from the hash Mojang publishes in the version manifest, meaning the game executable was modified.",
  "A corrupted download produces the same result; the launcher normally re-downloads mismatching files.",
  "Only versions with a downloads.client.sha1 entry can be checked.");
h("LIBRARY_MODIFIED", "Game library does not match published hash", "Game integrity", "HIGH", "STRONG_INDICATOR", 80,
  "A library jar referenced by an installed version manifest has a different SHA-1 than the manifest declares.",
  "Interrupted downloads or manual library replacement by some launchers.",
  "Libraries without a declared hash cannot be checked.");
h("LOGGED_MOD_MISSING", "Mod loaded in a previous session is no longer present", "Client modification", "MEDIUM", "SUSPICIOUS_CONFIGURATION", 65,
  "The game log shows a mod being loaded that no longer exists in any examined mods folder. Removing mods shortly before a screenshare is a common concealment technique.",
  "Users legitimately remove or update mods; logs can also come from another instance folder.",
  "Logs only list mod ids and versions, not file hashes.");
h("LOGGED_CHEAT_MOD", "Game log shows a known cheat client being loaded", "Cheat client", "CRITICAL", "STRONG_INDICATOR", 90,
  "The Fabric/Quilt mod list in a game log contains a mod id that belongs to a known cheat client.",
  "Log files can be copied from elsewhere, but this is uncommon.",
  "Shows the client was loaded by the game at the log's timestamp, not which server was joined.");
h("JAVAAGENT_ARGUMENT", "Java agent supplied in launch arguments", "Injection", "HIGH", "SUSPICIOUS_CONFIGURATION", 75,
  "A Minecraft launch configuration or running game process uses -javaagent with an agent outside the launcher's own installation directory.",
  "Some launchers and profilers use agents; agents within known launcher directories are reported as informational only.",
  "Arguments for processes that are not running are only visible if stored in a launcher profile.");
h("JAVA_OPTIONS_ENV", "JVM options injected through environment variable", "Injection", "HIGH", "STRONG_INDICATOR", 85,
  "JAVA_TOOL_OPTIONS / _JAVA_OPTIONS / JDK_JAVA_OPTIONS contains -javaagent or -agentpath, which forces every Java process (including Minecraft) to load the agent.",
  "Rare developer setups (profilers, APM agents).",
  "Only the current user and machine environment are read.");
h("UNSIGNED_MODULE", "Unsigned native module loaded into the game", "Injection", "MEDIUM", "SUSPICIOUS_CONFIGURATION", 65,
  "A running Java game process has a native DLL loaded from a user-writable location without a valid Authenticode signature and not matching known game natives (LWJGL, OpenAL, GLFW).",
  "Overlays, shader tools and some legitimate mods load unsigned natives.",
  "Only processes running at scan time are examined.");
h("PREFETCH_JAR_MISSING", "Jar opened by Java no longer exists", "Deleted evidence", "LOW", "WEAK_INDICATOR", 40,
  "Windows Prefetch shows Java opening a .jar that no longer exists on disk and is outside launcher library folders.",
  "Launchers delete superseded jars; installers run from temporary folders.",
  "Requires administrator rights; Prefetch only records files touched in the first seconds of execution.");
h("MEMORY_FEATURE_CLUSTER", "Cheat feature names present in game memory", "Client modification", "LOW", "WEAK_INDICATOR", 35,
  "Several distinct cheat-feature names (e.g. KillAura, AimAssist, TriggerBot) were found as strings in the game's memory.",
  "Chat messages, server MOTDs or GUI text discussing cheats put the same words in memory. Treat as a lead only.",
  "Memory scanning is capped per process; absence proves nothing.");
h("EVENT_LOG_CLEARED", "Windows event log was cleared", "Anti-forensics", "MEDIUM", "SUSPICIOUS_CONFIGURATION", 70,
  "An event log clear record (System 104 / Security 1102) exists within the last 7 days.",
  "Administrators and some cleanup utilities clear logs routinely.",
  "The Security log requires administrator rights.");
h("TIME_CHANGED", "System clock changed significantly", "Anti-forensics", "LOW", "WEAK_INDICATOR", 40,
  "The system time was changed by more than 5 minutes within the last 7 days. Changing the clock is used to mislead timestamp-based analysis.",
  "Time zone changes, dual-boot systems and failing CMOS batteries.",
  "Small NTP corrections are ignored.");
h("SERVICE_DISABLED", "Forensic-relevant Windows service disabled", "Anti-forensics", "MEDIUM", "SUSPICIOUS_CONFIGURATION", 60,
  "A service that produces forensic artifacts (SysMain/Prefetch, EventLog, BAM, PcaSvc, DPS) is disabled or stopped.",
  "'Debloat' guides commonly disable SysMain; this does not indicate intent on its own.",
  "Reports configuration at scan time only.");
h("PREFETCH_DISABLED", "Prefetch disabled in registry", "Anti-forensics", "MEDIUM", "SUSPICIOUS_CONFIGURATION", 60,
  "EnablePrefetcher is set to 0, so Windows stops recording program execution in Prefetch.",
  "Some SSD tuning guides recommend this.",
  "Configuration only.");
h("RECYCLED_ARCHIVE", "Recently deleted Minecraft archive in Recycle Bin", "Deleted evidence", "LOW", "WEAK_INDICATOR", 40,
  "A .jar/.exe/.dll deleted within the last 7 days from a Minecraft-related folder is in the Recycle Bin.",
  "Users routinely delete old mods.",
  "Permanently deleted files (Shift+Delete) do not appear; see the USN journal finding.");
h("USN_ARCHIVE_DELETED", "Archive deleted or renamed recently (USN journal)", "Deleted evidence", "LOW", "WEAK_INDICATOR", 40,
  "The NTFS change journal records a .jar/.exe/.dll being deleted or renamed in the last 48 hours.",
  "Launchers and updaters delete and rename files constantly; only names matching rules or Minecraft folders are reported.",
  "Requires administrator rights; journal size limits how far back records go.");
h("MOD_CHANGED_AFTER_SESSION", "Mods folder changed after the last game session", "Client modification", "LOW", "WEAK_INDICATOR", 35,
  "A file in the mods folder was modified or created after the most recent game log was written.",
  "Installing or updating mods between sessions is normal.",
  "File timestamps can be altered.");

const out = { version: VERSION, generatedAt: new Date().toISOString(), rules };
fs.writeFileSync(path.join(here, "rules.json"), JSON.stringify(out, null, 2));
console.log(`wrote ${rules.length} rules (version ${VERSION})`);
