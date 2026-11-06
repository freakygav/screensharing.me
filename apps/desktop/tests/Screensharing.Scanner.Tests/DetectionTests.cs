using System.IO.Compression;
using System.Text;
using Screensharing.Scanner.Engine;
using Screensharing.Scanner.Model;
using Screensharing.Scanner.Tests.Fixtures;
using static Screensharing.Scanner.Tests.TestUtil;

namespace Screensharing.Scanner.Tests;

/// <summary>Positive and negative detection cases on synthetic instances.</summary>
public class DetectionTests
{
    // ------------------------------------------------------------------ negatives

    [Fact]
    public async Task Clean_fabric_instance_produces_no_findings()
    {
        using var fx = new FixtureBuilder();
        fx.AddVersion("1.21.1");
        fx.AddMod("sodium-fabric-0.6.0+mc1.21.1.jar", Sodium);
        fx.AddMod("lithium-fabric-0.13.0.jar", Lithium);
        fx.AddMod("modmenu-11.0.2.jar", ModMenu);
        fx.AddMod("fabric-api-0.105.0+1.21.1.jar", FabricApi);
        fx.AddText("config/modmenu.json", "{\"sorting\":\"ascending\"}");
        fx.AddText("config/sodium-options.json", "{\"quality\":{\"weather_quality\":\"DEFAULT\"}}");
        fx.AddFile("resourcepacks/Faithful 32x.zip", BuildPack(("assets/minecraft/textures/block/stone.png", FixtureBuilder.BuildPng(false)), ("assets/minecraft/textures/block/dirt.png", FixtureBuilder.BuildPng(false)), ("assets/minecraft/textures/block/deepslate.png", FixtureBuilder.BuildPng(false))));
        fx.AddFabricLog([("sodium", "0.6.0"), ("lithium", "0.13.0"), ("modmenu", "11.0.2"), ("fabric-api", "0.105.0")],
            extraLines: ["[12:05:00] [Render thread/INFO]: [System] [CHAT] <Steve> does anyone use net.wurstclient. or meteor-client.mixins.json lol"]);

        var r = await Scan(fx);

        Assert.Empty(r.Findings);
        Assert.Equal(4, r.Mods.Count);
        Assert.All(r.Mods, m => Assert.NotEqual("unrecognised", m["classification"]));
        Assert.Equal(2, r.Statistics["integrityVerified"]);
        Assert.True(r.Statistics["filesAnalyzed"] >= 8);
    }

    [Fact]
    public async Task Legitimate_mod_with_ambiguous_class_names_is_not_flagged()
    {
        using var fx = new FixtureBuilder();
        fx.AddMod("better-combat.jar", new FixtureBuilder.JarSpec
        {
            FabricId = "bettercombat",
            Classes = ["net/bettercombat/attributes/Reach", "net/bettercombat/client/animation/Speed", "net/bettercombat/logic/Velocity", "net/bettercombat/Timer"],
            ClassStrings = new() { ["net/bettercombat/Timer"] = ["Speed", "Reach", "java/util/Timer"] },
        });
        var r = await Scan(fx);
        Assert.DoesNotContain(r.Findings, f => f.Outcome != FindingOutcome.Informational);
    }

    [Fact]
    public async Task A_single_generic_indicator_is_never_reported()
    {
        using var fx = new FixtureBuilder();
        fx.AddMod("screenshot-helper.jar", new FixtureBuilder.JarSpec
        {
            FabricId = "screenshot_helper",
            Classes = ["dev/shots/Capture"],
            ClassStrings = new() { ["dev/shots/Capture"] = ["java/awt/Robot", "createScreenCapture"] },
        });
        var r = await Scan(fx);
        Assert.Empty(r.Detections());
        Assert.Single(r.Findings, f => f.RuleId == Builtin.UnrecognizedMod);
    }

    [Fact]
    public async Task Unrecognised_mod_is_informational_not_suspicious()
    {
        using var fx = new FixtureBuilder();
        fx.AddMod("tinyprivate.jar", new FixtureBuilder.JarSpec { FabricId = "my_private_tweaks", Classes = ["me/private/Tweaks", "me/private/Config"] });
        var r = await Scan(fx);
        var f = Assert.Single(r.Findings);
        Assert.Equal(Builtin.UnrecognizedMod, f.RuleId);
        Assert.Equal(FindingOutcome.Informational, f.Outcome);
        Assert.Equal(Severity.Info, f.Severity);
    }

    // ------------------------------------------------------------------ known clients

    [Fact]
    public async Task Meteor_client_is_confirmed_with_corroborating_evidence()
    {
        using var fx = new FixtureBuilder();
        var path = fx.AddMod("meteor-client-0.5.8.jar", Meteor);
        var r = await Scan(fx);

        var f = Assert.Single(r.Findings.Where(x => x.Family == "Meteor Client"));
        Assert.Equal(FindingOutcome.Confirmed, f.Outcome);
        Assert.False(f.RequiresManualReview);
        Assert.Equal(Severity.Critical, f.Severity);
        Assert.True(f.Confidence >= 96);
        Assert.Equal(path, f.Evidence[0].Reference);
        Assert.Matches("^[0-9a-f]{64}$", f.Evidence[0].Sha256!);
        Assert.Equal("mods/meteor-client-0.5.8.jar", f.Location);
        Assert.Contains("mod id \"meteor-client\"", f.Signature);
        Assert.Contains("package meteordevelopment.meteorclient", f.Signature);
        Assert.Contains(f.Evidence, e => e.Kind == EvidenceKind.JarEntry && e.Details?.GetValueOrDefault("string") == "meteor-client.mixins.json");
        Assert.DoesNotContain(r.Findings, x => x.RuleId == Builtin.UnrecognizedMod);
    }

    [Fact]
    public async Task Cheat_client_renamed_as_performance_mod_is_identified_and_flagged_as_disguised()
    {
        using var fx = new FixtureBuilder();
        fx.AddMod("sodium-fabric-0.5.11.jar", Wurst);
        var r = await Scan(fx);
        Assert.Contains(r.Findings, f => f.Family == "Wurst Client" && f.Outcome == FindingOutcome.Confirmed);
        var d = Assert.Single(r.Findings.Where(f => f.RuleId == Builtin.DisguisedArchive));
        Assert.Contains("sodium", d.Description);
    }

    [Fact]
    public async Task Renamed_client_with_stripped_metadata_is_identified_by_its_strings()
    {
        using var fx = new FixtureBuilder();
        // No fabric.mod.json, obfuscated class names, but the client's mixin configuration is still inside.
        fx.AddMod("OptiFine_HD_U_I6.jar", new FixtureBuilder.JarSpec
        {
            Classes = ["a/a", "a/b", "a/c"],
            Resources = new() { ["liquidbounce.mixins.json"] = "{\"package\":\"x\"}" },
        });
        var r = await Scan(fx);
        var f = Assert.Single(r.Findings.Where(x => x.Family == "LiquidBounce"));
        Assert.Equal(FindingOutcome.HighConfidence, f.Outcome);
        Assert.True(f.RequiresManualReview);
        Assert.Contains("liquidbounce.mixins.json", f.Signature);
    }

    [Fact]
    public async Task Cheat_nested_inside_innocent_jar_in_jar_is_detected()
    {
        using var fx = new FixtureBuilder();
        fx.AddMod("better-hud.jar", new FixtureBuilder.JarSpec
        {
            FabricId = "better_hud", Classes = ["dev/hud/Hud"],
            Nested = [("META-INF/jars/core.jar", new FixtureBuilder.JarSpec { FabricId = "liquidbounce", Classes = ["net/ccbluex/liquidbounce/LiquidBounce"] })],
        });
        var r = await Scan(fx);
        var f = Assert.Single(r.Findings.Where(x => x.Family == "LiquidBounce"));
        Assert.Equal(EvidenceTier.ConfirmedArtifact, f.Tier);
        Assert.Contains(f.Evidence, e => e.Reference.Contains("META-INF/jars/core.jar"));
    }

    [Fact]
    public async Task Unknown_client_with_cheat_module_layout_is_a_strong_indicator()
    {
        using var fx = new FixtureBuilder();
        fx.AddMod("utilities.jar", new FixtureBuilder.JarSpec
        {
            FabricId = "qol-utilities",
            Classes = ["dev/x/client/module/combat/KillAura", "dev/x/client/module/combat/AimAssist", "dev/x/client/module/movement/Fly", "dev/x/client/module/movement/Speed", "dev/x/client/module/world/Scaffold", "dev/x/client/Main"],
        });
        var r = await Scan(fx);
        var f = Assert.Single(r.Findings.Where(x => x.RuleId == Builtin.ModuleClasses));
        Assert.Equal(EvidenceTier.StrongIndicator, f.Tier);
        Assert.Equal("Unidentified cheat client", f.Family);
        Assert.Contains("KillAura", f.Description);
    }

    // ------------------------------------------------------------------ evasion

    [Fact]
    public async Task Archive_impersonating_a_known_mod_is_flagged()
    {
        using var fx = new FixtureBuilder();
        fx.AddMod("sodium-fabric-0.6.0.jar", new FixtureBuilder.JarSpec { FabricId = "sodium", FabricName = "Sodium", Classes = ["dev/evil/core/Main", "dev/evil/core/Hooks"] });
        fx.AddMod("sodium-genuine.jar", Sodium, Path.Combine(fx.GameDir, "mods", "1.21"));
        var r = await Scan(fx);
        var f = Assert.Single(r.Findings.Where(x => x.RuleId == Builtin.ModImpersonation));
        Assert.Equal("mods/sodium-fabric-0.6.0.jar", f.Location);
        Assert.Equal(FindingOutcome.HighConfidence, f.Outcome);
    }

    [Fact]
    public async Task Encrypted_class_entries_are_detected()
    {
        using var fx = new FixtureBuilder();
        var raw = new Dictionary<string, byte[]>();
        for (var i = 0; i < 8; i++) raw[$"x/Loader{i}.class"] = Encoding.ASCII.GetBytes("ENCRYPTED-PAYLOAD-" + new string('Z', 80));
        fx.AddMod("perf.jar", new FixtureBuilder.JarSpec { FabricId = "perf_boost", Classes = ["x/Boot"], RawEntries = raw });
        var r = await Scan(fx);
        var f = Assert.Single(r.Findings.Where(x => x.RuleId == Builtin.EncryptedClasses));
        Assert.Equal(EvidenceTier.StrongIndicator, f.Tier);
    }

    [Fact]
    public async Task Executable_disguised_inside_a_mod_is_detected_and_its_strings_scored()
    {
        using var fx = new FixtureBuilder();
        fx.AddMod("hud.jar", new FixtureBuilder.JarSpec
        {
            FabricId = "simple_hud", Classes = ["dev/hud/Hud"],
            RawEntries = new() { ["assets/hud/icon.png"] = FixtureBuilder.BuildPe("CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory", "JNI_GetCreatedJavaVMs") },
        });
        var r = await Scan(fx);
        var exe = Assert.Single(r.Findings.Where(x => x.RuleId == Builtin.EmbeddedExecutable));
        Assert.Equal(EvidenceTier.StrongIndicator, exe.Tier);
        var inj = Assert.Single(r.Findings.Where(x => x.Family == "Native injector (generic)"));
        Assert.Equal(EvidenceTier.StrongIndicator, inj.Tier); // combined indicators are never "confirmed"
        Assert.Contains("JNI_GetCreatedJavaVMs", inj.Signature);
    }

    [Fact]
    public async Task Executable_disguised_as_a_jar_or_appended_to_one_is_detected()
    {
        using var fx = new FixtureBuilder();
        fx.AddFile("mods/fastmath.jar", FixtureBuilder.BuildPe("CreateRemoteThread"));
        fx.AddFile("mods/lagfix.jar", [.. FixtureBuilder.BuildPe("loader"), .. FixtureBuilder.BuildJar(new FixtureBuilder.JarSpec { FabricId = "lagfix", Classes = ["l/Fix"] })]);
        var r = await Scan(fx);
        Assert.Contains(r.Findings, f => f.RuleId == Builtin.ExecutableInInstance && f.Location == "mods/fastmath.jar" && f.Tier == EvidenceTier.StrongIndicator);
        Assert.Contains(r.Findings, f => f.RuleId == Builtin.PolyglotArchive && f.Location == "mods/lagfix.jar");
    }

    [Fact]
    public async Task Native_injector_disguised_in_the_instance_is_detected()
    {
        using var fx = new FixtureBuilder();
        fx.AddFile("config/cache/textures.dat", FixtureBuilder.BuildPe("CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory", "NtCreateThreadEx"));
        var r = await Scan(fx);
        var exe = Assert.Single(r.Findings.Where(f => f.RuleId == Builtin.ExecutableInInstance));
        Assert.Equal(EvidenceTier.StrongIndicator, exe.Tier);
        Assert.Contains("disguised", exe.Description);
        Assert.Contains(r.Findings, f => f.Family == "Native injector (generic)" && f.Location == "config/cache/textures.dat");
    }

    [Fact]
    public async Task Community_injection_client_string_is_only_a_weak_indicator()
    {
        using var fx = new FixtureBuilder();
        fx.AddMod("jna-helper.jar", new FixtureBuilder.JarSpec
        {
            Classes = ["com/sun/jna/z/Main"],
            ClassStrings = new() { ["com/sun/jna/z/Main"] = ["com/sun/jna/z/Main"] },
        });
        var r = await Scan(fx);
        var f = Assert.Single(r.Findings.Where(x => x.Family == "Vape (injection client)"));
        Assert.Equal(FindingOutcome.LowConfidence, f.Outcome);
    }

    [Fact]
    public async Task Anti_unzip_protected_archive_is_still_inspected()
    {
        using var fx = new FixtureBuilder();
        var jar = FixtureBuilder.BuildJar(Wurst);
        // Zero the entry counts and set "disk 65535" in the end record, as protected server packs do (Java still loads these).
        var eocd = -1;
        for (var i = jar.Length - 22; i >= 0; i--) if (jar[i] == 'P' && jar[i + 1] == 'K' && jar[i + 2] == 5 && jar[i + 3] == 6) { eocd = i; break; }
        jar[eocd + 4] = 0xFF; jar[eocd + 5] = 0xFF; jar[eocd + 8] = jar[eocd + 9] = jar[eocd + 10] = jar[eocd + 11] = 0;
        fx.AddFile("mods/performance.jar", jar);
        var r = await Scan(fx);
        Assert.Contains(r.Findings, f => f.Family == "Wurst Client" && f.Outcome == FindingOutcome.Confirmed);
        Assert.Contains(r.Custody, o => o.Action == "normalize-zip-directory");
    }

    [Fact]
    public async Task Inconsistent_metadata_is_a_weak_indicator()
    {
        using var fx = new FixtureBuilder();
        fx.AddMod("tweaks.jar", new FixtureBuilder.JarSpec { FabricId = "tweaks", Classes = ["t/Other"], Entrypoints = ["com.example.tweaks.TweaksMod"], Mixins = ["tweaks.mixins.json"] });
        var r = await Scan(fx);
        var f = Assert.Single(r.Findings.Where(x => x.RuleId == Builtin.MetadataInconsistent));
        Assert.Equal(EvidenceTier.WeakIndicator, f.Tier);
        Assert.Contains("com.example.tweaks.TweaksMod", f.Description);
    }

    [Fact]
    public async Task Hidden_archive_with_wrong_extension_and_agent_manifest_are_flagged()
    {
        using var fx = new FixtureBuilder();
        fx.AddMod("readme.txt", new FixtureBuilder.JarSpec { FabricId = "secret", Classes = ["s/S"] });
        fx.AddMod("helper.jar", new FixtureBuilder.JarSpec { FabricId = "helper", Classes = ["h/Agent"], Manifest = new() { ["Premain-Class"] = "h.Agent" } });
        var r = await Scan(fx);
        Assert.Contains(r.Findings, f => f.RuleId == Builtin.NonJarArchive && f.Location == "mods/readme.txt");
        Assert.Contains(r.Findings, f => f.RuleId == Builtin.JavaAgentManifest && f.Signature == "Premain-Class: h.Agent");
    }

    [Fact]
    public async Task Heavily_obfuscated_archive_is_a_weak_indicator()
    {
        using var fx = new FixtureBuilder();
        fx.AddMod("x.jar", new FixtureBuilder.JarSpec { FabricId = "x_mod", Classes = Enumerable.Range(0, 40).Select(i => $"{(char)('a' + i % 26)}{(i >= 26 ? "a" : "")}") });
        var r = await Scan(fx);
        var f = Assert.Single(r.Findings.Where(x => x.RuleId == Builtin.ObfuscatedArchive));
        Assert.Equal(EvidenceTier.WeakIndicator, f.Tier);
    }

    // ------------------------------------------------------------------ instance artifacts, logs, packs

    [Fact]
    public async Task Client_data_folder_left_in_the_instance_is_detected()
    {
        using var fx = new FixtureBuilder();
        Directory.CreateDirectory(Path.Combine(fx.GameDir, "meteor-client"));
        fx.AddText("wurst/enabled-hacks.json", "[\"Killaura\"]");
        var r = await Scan(fx);
        Assert.Contains(r.Findings, f => f.Family == "Meteor Client" && f.Location == "meteor-client/" && f.Outcome == FindingOutcome.HighConfidence);
        Assert.Contains(r.Findings, f => f.Family == "Wurst Client" && f.Location == "wurst/enabled-hacks.json");
    }

    [Fact]
    public async Task Log_reveals_cheat_and_removed_mod_and_stack_traces_but_never_chat()
    {
        using var fx = new FixtureBuilder();
        fx.AddMod("sodium.jar", Sodium);
        fx.AddFabricLog([("sodium", "0.6.0"), ("meteor-client", "0.5.8"), ("mystery-mod", "1.0")],
            extraLines: ["[12:03:00] [Render thread/ERROR]: Error in module", "\tat net.wurstclient.hacks.KillauraHack.onUpdate(KillauraHack.java:120)"]);
        fx.AddFabricLog([("sodium", "0.6.0")], name: "2026-11-01-1.log", extraLines: ["[12:00:09] [Render thread/INFO]: [CHAT] <Alex> net.ccbluex.liquidbounce. is that a client?"]);
        var r = await Scan(fx);
        Assert.Contains(r.Findings, f => f.RuleId == Builtin.LoggedCheatMod && f.Family == "Meteor Client");
        Assert.Contains(r.Findings, f => f.RuleId == Builtin.LoggedModMissing && f.Description.Contains("mystery-mod"));
        Assert.Contains(r.Findings, f => f.Family == "Wurst Client" && f.Location == "logs/latest.log");
        Assert.DoesNotContain(r.Findings, f => f.Family == "LiquidBounce");
    }

    [Fact]
    public async Task Crash_report_mod_list_reveals_a_cheat_client()
    {
        using var fx = new FixtureBuilder();
        fx.AddText("crash-reports/crash-2026-11-05_20.11.03-client.txt",
            "---- Minecraft Crash Report ----\n-- System Details --\nDetails:\n\tFabric Mods: \n\t\tfabricloader: Fabric Loader 0.16.5\n\t\tmeteor-client: Meteor Client 0.5.8\n\t\tsodium: Sodium 0.6.0\n\tLaunched Version: fabric-loader\n");
        var r = await Scan(fx);
        var f = Assert.Single(r.Findings.Where(x => x.RuleId == Builtin.LoggedCheatMod));
        Assert.Equal("Meteor Client", f.Family);
    }

    [Fact]
    public async Task Xray_pack_is_detected_by_content_even_when_renamed()
    {
        using var fx = new FixtureBuilder();
        var t = FixtureBuilder.BuildPng(true);
        fx.AddFile("resourcepacks/Faithful Edit.zip", BuildPack(("assets/minecraft/textures/block/stone.png", t), ("assets/minecraft/textures/block/deepslate.png", t), ("assets/minecraft/textures/block/dirt.png", t), ("assets/minecraft/textures/block/diamond_ore.png", FixtureBuilder.BuildPng(false))));
        // A folder pack hiding terrain with empty block models.
        foreach (var b in new[] { "stone", "netherrack", "andesite" }) fx.AddText($"resourcepacks/my pack/assets/minecraft/models/block/{b}.json", "{\"parent\":\"block/block\",\"elements\":[]}");
        fx.AddText("resourcepacks/my pack/pack.mcmeta", "{\"pack\":{\"pack_format\":34,\"description\":\"\"}}");
        File.WriteAllText(Path.Combine(fx.GameDir, "options.txt"), "resourcePacks:[\"vanilla\",\"file/Faithful Edit.zip\"]\n");
        var r = await Scan(fx);
        var zip = Assert.Single(r.Findings.Where(f => f.RuleId == Builtin.XrayTextures && f.Location == "resourcepacks/Faithful Edit.zip"));
        Assert.Equal(EvidenceTier.StrongIndicator, zip.Tier);
        Assert.Contains("enabled in options.txt", zip.Description);
        Assert.Contains(r.Findings, f => f.RuleId == Builtin.XrayTextures && f.Location == "resourcepacks/my pack/");
    }

    [Fact]
    public async Task Xray_pack_name_and_utility_mods_are_reported_with_policy_severity()
    {
        using var fx = new FixtureBuilder();
        Directory.CreateDirectory(Path.Combine(fx.GameDir, "resourcepacks", "Xray Ultimate 1.21"));
        Directory.CreateDirectory(Path.Combine(fx.GameDir, "shaderpacks", "XRay_Shader"));
        fx.AddMod("freecam-1.2.jar", new FixtureBuilder.JarSpec { FabricId = "freecam", Classes = ["net/xolt/freecam/Freecam"] });
        var r = await Scan(fx);
        Assert.Contains(r.Findings, f => f.Category == "Utility modification" && f.Name.Contains("X-ray") && f.Outcome == FindingOutcome.LowConfidence);
        Assert.Contains(r.Findings, f => f.RuleId == "SSME-SP-0001");
        Assert.Contains(r.Findings, f => f.Family == "Freecam" && f.Severity == Severity.Medium);
    }

    [Fact]
    public async Task Modified_client_jar_on_the_class_path_is_detected()
    {
        using var fx = new FixtureBuilder();
        fx.AddVersion("1.21.1", tampered: true);
        var r = await Scan(fx);
        var f = Assert.Single(r.Findings.Where(x => x.RuleId == Builtin.ClientJarModified));
        Assert.Equal(EvidenceTier.StrongIndicator, f.Tier);
        Assert.Equal(1, r.Statistics["integrityVerified"]); // the library still matches
    }

    [Fact]
    public async Task Mod_added_after_last_session_is_only_a_weak_indicator()
    {
        using var fx = new FixtureBuilder();
        fx.AddFabricLog([("sodium", "0.6.0")], age: TimeSpan.FromHours(5));
        var late = fx.AddMod("sodium.jar", Sodium);
        File.SetCreationTimeUtc(late, DateTime.UtcNow.AddHours(-1));
        File.SetLastWriteTimeUtc(late, DateTime.UtcNow.AddHours(-1));
        var r = await Scan(fx);
        var f = Assert.Single(r.Findings.Where(x => x.RuleId == Builtin.ModChangedAfterSession));
        Assert.Equal(EvidenceTier.WeakIndicator, f.Tier);
    }

    [Fact]
    public async Task Duplicate_mod_ids_in_one_folder_are_a_weak_indicator()
    {
        using var fx = new FixtureBuilder();
        fx.AddMod("sodium-a.jar", Sodium);
        fx.AddMod("sodium-b.jar", Sodium);
        var r = await Scan(fx);
        Assert.Single(r.Findings.Where(x => x.RuleId == Builtin.DuplicateModId));
    }

    // ------------------------------------------------------------------ limits and honesty

    [Fact]
    public async Task Files_that_cannot_be_inspected_are_reported_as_such()
    {
        using var fx = new FixtureBuilder();
        fx.AddFile("mods/broken.jar", [0x50, 0x4B, 0x03, 0x04, 1, 2, 3, 4, 5, 6, 7, 8]);
        fx.AddFile("mods/encrypted.jar", EncryptedZip());
        var r = await Scan(fx);
        Assert.Contains(r.Findings, f => f.Outcome == FindingOutcome.UnableToInspect && f.Location == "mods/broken.jar");
        Assert.Contains(r.Findings, f => f.Outcome == FindingOutcome.UnableToInspect && f.Location == "mods/encrypted.jar" && f.Description.Contains("password-protected"));
        Assert.Equal(2.0, r.Statistics["filesUnableToInspect"]);
        Assert.Equal(2, (int)r.Inspection["unableToInspect"]!);
    }

    [Fact]
    public async Task Disabled_rules_never_report()
    {
        using var fx = new FixtureBuilder();
        fx.AddMod("meteor.jar", Meteor);
        var rules = new RuleSet { Version = "t", Rules = Rules.Rules.Where(r => r.Family != "Meteor Client" && r.Id != Builtin.ModuleClasses && r.Id != Builtin.UnrecognizedMod).ToList() };
        var r = await Scan(fx, rules);
        Assert.Empty(r.Detections());
    }

    [Fact]
    public async Task Findings_have_complete_documentation_fields()
    {
        using var fx = new FixtureBuilder();
        fx.AddMod("meteor.jar", Meteor);
        fx.AddMod("unknown.jar", new FixtureBuilder.JarSpec { FabricId = "unknown_thing", Classes = ["u/U"] });
        Directory.CreateDirectory(Path.Combine(fx.GameDir, "LiquidBounce"));
        var r = await Scan(fx);
        Assert.True(r.Findings.Count >= 3);
        foreach (var f in r.Findings)
        {
            foreach (var s in new[] { f.Name, f.Description, f.Category, f.Method, f.WhyItMatters, f.Limitations, f.FalsePositiveNotes, f.AlternativeExplanations })
                Assert.False(string.IsNullOrWhiteSpace(s));
            Assert.NotEmpty(f.Evidence);
            Assert.False(string.IsNullOrWhiteSpace(f.Location));
            Assert.False(string.IsNullOrWhiteSpace(f.Signature));
            Assert.Matches("^SSME-[A-Z]{1,4}-[A-Z0-9_]{1,40}$", f.RuleId);
        }
    }

    // ------------------------------------------------------------------ helpers

    private static byte[] BuildPack(params (string Name, byte[] Data)[] entries)
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            var meta = zip.CreateEntry("pack.mcmeta");
            using (var w = new StreamWriter(meta.Open())) w.Write("{\"pack\":{\"pack_format\":34,\"description\":\"pack\"}}");
            foreach (var (name, data) in entries)
            {
                using var s = zip.CreateEntry(name).Open();
                s.Write(data);
            }
        }
        return ms.ToArray();
    }

    /// <summary>A ZIP whose single class entry has the "encrypted" general-purpose flag set (traditional PKWARE encryption).</summary>
    private static byte[] EncryptedZip()
    {
        var jar = FixtureBuilder.BuildJar(new FixtureBuilder.JarSpec { Classes = ["e/Secret"] });
        // Set bit 0 of the general purpose flags in every local and central header.
        for (var i = 0; i < jar.Length - 4; i++)
        {
            if (jar[i] == 'P' && jar[i + 1] == 'K' && jar[i + 2] == 3 && jar[i + 3] == 4) jar[i + 6] |= 1;
            if (jar[i] == 'P' && jar[i + 1] == 'K' && jar[i + 2] == 1 && jar[i + 3] == 2) jar[i + 8] |= 1;
        }
        return jar;
    }
}
