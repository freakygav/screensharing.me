using Screensharing.Scanner.Engine;
using Screensharing.Scanner.Model;
using Screensharing.Scanner.Tests.Fixtures;

namespace Screensharing.Scanner.Tests;

internal static class TestUtil
{
    public static readonly RuleSet Rules = RuleSet.LoadEmbedded();

    public static ScanOptions Options(FixtureBuilder fx, RuleSet? rules = null) => new()
    {
        Rules = rules ?? Rules,
        AppDataOverride = fx.AppData,
        UserProfileOverride = fx.UserProfile,
        IncludeSystemArtifacts = false,
        ModrinthLookup = false,
        MemoryScan = false,
    };

    public static async Task<ScanResult> Scan(FixtureBuilder fx, RuleSet? rules = null) =>
        await new ScanEngine(Options(fx, rules)).RunAsync();

    public static IEnumerable<Finding> AboveInconclusive(this ScanResult r) => r.Findings.Where(f => f.Tier != EvidenceTier.Inconclusive);

    public static readonly FixtureBuilder.JarSpec Sodium = new() { FabricId = "sodium", FabricName = "Sodium", Classes = ["net/caffeinemc/mods/sodium/client/SodiumClientMod", "net/caffeinemc/mods/sodium/client/render/chunk/RenderSection"] };
    public static readonly FixtureBuilder.JarSpec Lithium = new() { FabricId = "lithium", Classes = ["net/caffeinemc/mods/lithium/common/LithiumMod"] };
    public static readonly FixtureBuilder.JarSpec ModMenu = new() { FabricId = "modmenu", Classes = ["com/terraformersmc/modmenu/ModMenu"] };
    public static readonly FixtureBuilder.JarSpec FabricApi = new()
    {
        FabricId = "fabric-api", Classes = ["net/fabricmc/fabric/api/Thing"],
        Nested = [("META-INF/jars/fabric-api-base-0.4.42.jar", new FixtureBuilder.JarSpec { FabricId = "fabric-api-base", Classes = ["net/fabricmc/fabric/impl/base/Event"] })],
    };
    public static readonly FixtureBuilder.JarSpec Meteor = new()
    {
        FabricId = "meteor-client", FabricName = "Meteor Client",
        Classes = ["meteordevelopment/meteorclient/MeteorClient", "meteordevelopment/meteorclient/systems/modules/combat/KillAura", "meteordevelopment/meteorclient/systems/modules/combat/CrystalAura", "meteordevelopment/meteorclient/systems/modules/movement/NoFall"],
    };
}
