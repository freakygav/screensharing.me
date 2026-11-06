using Screensharing.Scanner.Analysis;
using Screensharing.Scanner.Model;
using Screensharing.Scanner.Tests.Fixtures;
using static Screensharing.Scanner.Tests.TestUtil;

namespace Screensharing.Scanner.Tests;

/// <summary>Positive and negative detection cases on synthetic installations.</summary>
public class DetectionTests
{
    [Fact]
    public async Task Clean_fabric_installation_produces_no_findings()
    {
        using var fx = new FixtureBuilder();
        fx.AddVersion("1.21.1");
        fx.AddMod("sodium-fabric-0.6.0+mc1.21.1.jar", Sodium);
        fx.AddMod("lithium-fabric-0.13.0.jar", Lithium);
        fx.AddMod("modmenu-11.0.2.jar", ModMenu);
        fx.AddMod("fabric-api-0.105.0+1.21.1.jar", FabricApi);
        fx.AddFabricLog([("sodium", "0.6.0"), ("lithium", "0.13.0"), ("modmenu", "11.0.2"), ("fabric-api", "0.105.0")]);

        var r = await Scan(fx);

        Assert.Empty(r.Findings);
        Assert.Equal(4, r.Mods.Count);
        Assert.All(r.Mods, m => Assert.NotEqual("unrecognised", m["classification"]));
        Assert.Contains(r.Installations, i => (string)i["launcher"]! == "Official launcher (.minecraft)");
    }

    [Fact]
    public async Task Vanilla_installation_without_mods_produces_no_findings()
    {
        using var fx = new FixtureBuilder();
        fx.AddVersion("1.21.1");
        fx.AddVersion("1.20.4");
        var r = await Scan(fx);
        Assert.Empty(r.Findings);
        Assert.Equal(3, r.Statistics["integrityChecks"]); // two client jars + one shared library, all hash-verified
    }

    [Fact]
    public async Task Meteor_client_is_a_confirmed_artifact_with_corroborating_evidence()
    {
        using var fx = new FixtureBuilder();
        var path = fx.AddMod("meteor-client-0.5.8.jar", Meteor);
        var r = await Scan(fx);

        var f = Assert.Single(r.Findings.Where(x => x.Family == "Meteor Client"));
        Assert.Equal(EvidenceTier.ConfirmedArtifact, f.Tier);
        Assert.Equal(Severity.Critical, f.Severity);
        Assert.True(f.Confidence >= 96);
        Assert.Equal(path, f.Evidence[0].Reference);
        Assert.Matches("^[0-9a-f]{64}$", f.Evidence[0].Sha256!);
        Assert.Contains(f.Evidence, e => e.Kind == EvidenceKind.JarEntry && e.Reference.Contains("meteordevelopment"));
        Assert.Contains("declares mod id \"meteor-client\"", f.Description);
        Assert.DoesNotContain(r.Findings, x => x.RuleId == Builtin.UnrecognizedMod);
    }

    [Fact]
    public async Task Cheat_client_renamed_as_performance_mod_is_flagged_as_disguised()
    {
        using var fx = new FixtureBuilder();
        fx.AddMod("sodium-fabric-0.5.11.jar", new FixtureBuilder.JarSpec { FabricId = "wurst", FabricName = "Wurst Client", Classes = ["net/wurstclient/WurstClient", "net/wurstclient/hacks/KillauraHack"] });
        var r = await Scan(fx);
        Assert.Contains(r.Findings, f => f.Family == "Wurst Client" && f.Tier == EvidenceTier.ConfirmedArtifact);
        var d = Assert.Single(r.Findings.Where(f => f.RuleId == Builtin.DisguisedArchive));
        Assert.Contains("sodium", d.Description);
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
        Assert.Contains("KillAura", f.Description);
        Assert.True(f.Confidence >= 78);
    }

    [Fact]
    public async Task Legitimate_mod_with_one_ambiguous_class_name_is_not_flagged()
    {
        using var fx = new FixtureBuilder();
        // e.g. an attribute library with a Reach/Speed helper outside module packages
        fx.AddMod("attributes.jar", new FixtureBuilder.JarSpec { FabricId = "sodium", Classes = ["com/legit/attributes/Reach", "com/legit/attributes/Speed", "com/legit/render/Fly", "com/legit/Main"] });
        var r = await Scan(fx);
        Assert.DoesNotContain(r.Findings, f => f.RuleId == Builtin.ModuleClasses);
        Assert.Empty(r.AboveInconclusive());
    }

    [Fact]
    public async Task Cheat_nested_inside_innocent_jar_in_jar_is_detected()
    {
        using var fx = new FixtureBuilder();
        fx.AddMod("better-sky.jar", new FixtureBuilder.JarSpec
        {
            FabricId = "bettersky",
            Classes = ["com/sky/Better"],
            Nested = [("META-INF/jars/lib.jar", new FixtureBuilder.JarSpec { FabricId = "liquidbounce", Classes = ["net/ccbluex/liquidbounce/LiquidBounce"] })],
        });
        var r = await Scan(fx);
        var f = Assert.Single(r.Findings.Where(x => x.Family == "LiquidBounce"));
        Assert.Equal(EvidenceTier.ConfirmedArtifact, f.Tier);
        Assert.Contains(f.Evidence, e => e.Reference.Contains("META-INF/jars/lib.jar!/net/ccbluex"));
    }

    [Fact]
    public async Task Java_agent_manifest_is_flagged()
    {
        using var fx = new FixtureBuilder();
        fx.AddMod("perf-boost.jar", new FixtureBuilder.JarSpec { FabricId = "perfboost", Classes = ["x/Agent"], Manifest = new() { ["Premain-Class"] = "x.Agent" } });
        var r = await Scan(fx);
        Assert.Contains(r.Findings, f => f.RuleId == Builtin.JavaAgentManifest && f.Description.Contains("Premain-Class"));
    }

    [Fact]
    public async Task Hidden_archive_with_wrong_extension_is_flagged()
    {
        using var fx = new FixtureBuilder();
        var p = Path.Combine(fx.Mods, "readme.txt");
        File.WriteAllBytes(p, FixtureBuilder.BuildJar(new FixtureBuilder.JarSpec { FabricId = "sodium", Classes = ["a/B"] }));
        File.WriteAllText(Path.Combine(fx.Mods, "notes.txt"), "just text");
        var r = await Scan(fx);
        Assert.Single(r.Findings.Where(f => f.RuleId == Builtin.NonJarArchive));
    }

    [Fact]
    public async Task Heavily_obfuscated_archive_is_a_weak_indicator()
    {
        using var fx = new FixtureBuilder();
        var classes = Enumerable.Range(0, 40).Select(i => $"{(char)('a' + i % 26)}{(i >= 26 ? "x" : "")}").ToList();
        fx.AddMod("client.jar", new FixtureBuilder.JarSpec { FabricId = "mysteryclient", Classes = classes });
        var r = await Scan(fx);
        var f = Assert.Single(r.Findings.Where(x => x.RuleId == Builtin.ObfuscatedArchive));
        Assert.Equal(EvidenceTier.WeakIndicator, f.Tier);
    }

    [Fact]
    public async Task Modified_client_jar_is_detected_by_manifest_hash()
    {
        using var fx = new FixtureBuilder();
        fx.AddVersion("1.8.9", tampered: true);
        var r = await Scan(fx);
        var f = Assert.Single(r.Findings.Where(x => x.RuleId == Builtin.ClientJarModified));
        Assert.Equal(EvidenceTier.StrongIndicator, f.Tier);
        Assert.NotEqual(f.Evidence[0].Details!["expectedSha1"], f.Evidence[0].Details!["actualSha1"]);
    }

    [Fact]
    public async Task Log_reveals_cheat_and_removed_mod_after_deletion()
    {
        using var fx = new FixtureBuilder();
        fx.AddMod("sodium.jar", Sodium);
        fx.AddFabricLog([("sodium", "0.6.0"), ("meteor-client", "0.5.8"), ("shady-helper", "1.0")]);
        var r = await Scan(fx);
        var cheat = Assert.Single(r.Findings.Where(f => f.RuleId == Builtin.LoggedCheatMod));
        Assert.Contains("meteor-client", cheat.Description);
        Assert.Contains("no longer present", cheat.Description);
        var missing = Assert.Single(r.Findings.Where(f => f.RuleId == Builtin.LoggedModMissing));
        Assert.Contains("shady-helper", missing.Description);
    }

    [Fact]
    public async Task Mod_added_after_last_session_is_only_a_weak_indicator()
    {
        using var fx = new FixtureBuilder();
        fx.AddFabricLog([("sodium", "0.6.0")], age: TimeSpan.FromDays(2));
        var p = fx.AddMod("sodium.jar", Sodium);
        FixtureBuilder.Age(p, TimeSpan.FromHours(2));
        var r = await Scan(fx);
        var f = Assert.Single(r.Findings.Where(x => x.RuleId == Builtin.ModChangedAfterSession));
        Assert.Equal(EvidenceTier.WeakIndicator, f.Tier);
        Assert.Equal(Severity.Low, f.Severity);
    }

    [Fact]
    public async Task Xray_resource_pack_and_utility_mods_are_reported_with_policy_severity()
    {
        using var fx = new FixtureBuilder();
        Directory.CreateDirectory(Path.Combine(fx.GameDir, "resourcepacks", "Xray Ultimate 1.21"));
        fx.AddMod("freecam-1.3.jar", new FixtureBuilder.JarSpec { FabricId = "freecam", Classes = ["net/xolt/freecam/Freecam"] });
        fx.AddMod("baritone-standalone.jar", new FixtureBuilder.JarSpec { FabricId = "baritone", Classes = ["baritone/api/BaritoneAPI", "baritone/Baritone"] });
        var r = await Scan(fx);
        Assert.Contains(r.Findings, f => f.Family == "X-ray" && f.Tier == EvidenceTier.SuspiciousConfiguration);
        var freecam = Assert.Single(r.Findings.Where(f => f.Family == "Freecam"));
        Assert.Equal(Severity.Medium, freecam.Severity);
        var baritone = Assert.Single(r.Findings.Where(f => f.Family == "Baritone"));
        Assert.Equal(2, baritone.Evidence.Count(e => e.Kind == EvidenceKind.JarEntry)); // mod id + package merged into one finding
    }

    [Fact]
    public async Task Duplicate_mod_ids_in_one_folder_are_a_weak_indicator()
    {
        using var fx = new FixtureBuilder();
        fx.AddMod("sodium-0.5.jar", Sodium);
        fx.AddMod("sodium-0.6.jar", Sodium);
        var r = await Scan(fx);
        Assert.Single(r.Findings.Where(f => f.RuleId == Builtin.DuplicateModId));
    }

    [Fact]
    public async Task Unrecognised_mod_is_inconclusive_not_suspicious()
    {
        using var fx = new FixtureBuilder();
        fx.AddMod("my-private-mod.jar", new FixtureBuilder.JarSpec { FabricId = "my_private_mod", Classes = ["me/dev/PrivateMod"] });
        var r = await Scan(fx);
        var f = Assert.Single(r.Findings);
        Assert.Equal(Builtin.UnrecognizedMod, f.RuleId);
        Assert.Equal(EvidenceTier.Inconclusive, f.Tier);
        Assert.Equal(Severity.Info, f.Severity);
    }

    [Fact]
    public async Task Disabled_rules_never_report()
    {
        using var fx = new FixtureBuilder();
        fx.AddMod("meteor.jar", Meteor);
        var rules = new RuleSet { Version = "test", Rules = Rules.Rules.Where(r => r.Family != "Meteor Client").ToList() };
        var r = await Scan(fx, rules);
        Assert.DoesNotContain(r.Findings, f => f.Family == "Meteor Client");
        // Structural heuristic still catches the module layout.
        Assert.Contains(r.Findings, f => f.RuleId == Builtin.ModuleClasses);
    }

    [Fact]
    public async Task Prism_instances_and_forge_metadata_are_discovered()
    {
        using var fx = new FixtureBuilder();
        var inst = Path.Combine(fx.AppData, "PrismLauncher", "instances", "PvP 1.20", ".minecraft", "mods");
        fx.AddMod("bleach.jar", new FixtureBuilder.JarSpec { ForgeTomlId = "bleachhack", Classes = ["org/bleachhack/BleachHack"] }, inst);
        File.WriteAllText(Path.Combine(fx.AppData, "PrismLauncher", "instances", "PvP 1.20", "mmc-pack.json"),
            """{"components":[{"uid":"net.minecraft","version":"1.20.1"},{"uid":"net.minecraftforge","version":"47.2.0"}]}""");
        var r = await Scan(fx);
        Assert.Contains(r.Installations, i => ((string)i["launcher"]!).StartsWith("Prism Launcher: PvP 1.20") && ((string)i["versions"]!).Contains("Forge 47.2.0"));
        Assert.Contains(r.Findings, f => f.Family == "BleachHack" && f.Tier == EvidenceTier.ConfirmedArtifact);
    }

    [Fact]
    public async Task Findings_have_complete_documentation_fields()
    {
        using var fx = new FixtureBuilder();
        fx.AddMod("meteor.jar", Meteor);
        fx.AddMod("x.jar", new FixtureBuilder.JarSpec { FabricId = "x", Classes = ["a/B"], Manifest = new() { ["Agent-Class"] = "a.B" } });
        var r = await Scan(fx);
        Assert.NotEmpty(r.Findings);
        foreach (var f in r.Findings)
        {
            Assert.False(string.IsNullOrWhiteSpace(f.Method));
            Assert.False(string.IsNullOrWhiteSpace(f.WhyItMatters));
            Assert.False(string.IsNullOrWhiteSpace(f.Limitations));
            Assert.False(string.IsNullOrWhiteSpace(f.FalsePositiveNotes));
            Assert.False(string.IsNullOrWhiteSpace(f.AlternativeExplanations));
            Assert.NotEmpty(f.Evidence);
            Assert.Matches("^[A-Za-z0-9_-]{8,64}$", f.ClientFindingId);
        }
    }
}
