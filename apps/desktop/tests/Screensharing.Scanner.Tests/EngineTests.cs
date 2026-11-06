using Screensharing.Scanner.Engine;
using Screensharing.Scanner.Model;
using Screensharing.Scanner.Reporting;
using Screensharing.Scanner.Tests.Fixtures;
using static Screensharing.Scanner.Tests.TestUtil;

namespace Screensharing.Scanner.Tests;

public class EngineTests
{
    [Fact]
    public async Task Progress_is_monotonic_and_based_on_real_work_units()
    {
        using var fx = new FixtureBuilder();
        for (var i = 0; i < 12; i++) fx.AddMod($"mod{i}.jar", new FixtureBuilder.JarSpec { FabricId = i % 2 == 0 ? "sodium" : "lithium", Classes = ["a/B"] });
        var engine = new ScanEngine(Options(fx));
        var updates = new List<ScanProgress>();
        engine.Progress += p => updates.Add(p);
        var r = await engine.RunAsync();
        Assert.True(updates.Count > 5);
        for (var i = 1; i < updates.Count; i++) Assert.True(updates[i].Percent >= updates[i - 1].Percent, "progress never goes backwards");
        Assert.Equal(100, updates[^1].Percent);
        Assert.Equal(updates[^1].UnitsTotal, updates[^1].UnitsDone);
        Assert.True(updates.Max(u => u.UnitsTotal) >= 12, "planned units include each mod file");
        var mods = r.Coverage.Single(c => c.Key == "mods");
        Assert.Equal(CategoryStatus.Completed, mods.Status);
        Assert.True(mods.ItemsExamined >= 12);
    }

    [Fact]
    public async Task System_modules_report_skipped_with_reason_when_excluded()
    {
        using var fx = new FixtureBuilder();
        var r = await Scan(fx);
        foreach (var key in new[] { "processes", "execution", "deleted", "tamper" })
        {
            var c = r.Coverage.Single(x => x.Key == key);
            Assert.Equal(CategoryStatus.Skipped, c.Status);
            Assert.False(string.IsNullOrWhiteSpace(c.Message));
        }
    }

    [Fact]
    public async Task Chain_of_custody_records_read_only_operations()
    {
        using var fx = new FixtureBuilder();
        var p = fx.AddMod("meteor.jar", Meteor);
        var before = File.GetLastWriteTimeUtc(p);
        var bytesBefore = File.ReadAllBytes(p);
        var r = await Scan(fx);
        Assert.Contains(r.Custody, o => o.Action == "read-archive" && o.Target == p);
        Assert.Contains(r.Custody, o => o.Action == "hash-sha256" && o.Target == p);
        Assert.Equal(before, File.GetLastWriteTimeUtc(p));
        Assert.Equal(bytesBefore, File.ReadAllBytes(p)); // evidence preserved, never modified
    }

    [Fact]
    public void Finding_ids_are_deterministic()
    {
        Assert.Equal(Finding.MakeId("SSME-CL-0001", "C:\\a.jar"), Finding.MakeId("SSME-CL-0001", "c:\\A.JAR"));
        Assert.NotEqual(Finding.MakeId("SSME-CL-0001", "a"), Finding.MakeId("SSME-CL-0002", "a"));
    }

    [Fact]
    public void Manifest_matches_the_backend_algorithm()
    {
        Finding F(string id, string rule, Severity s, EvidenceTier t, int c, params (string Ref, string? Sha)[] ev) => new()
        {
            ClientFindingId = id, RuleId = rule, Name = "n", Description = "d", Category = "c", CategoryKey = "mods", Severity = s, Tier = t, Confidence = c,
            Method = "m", WhyItMatters = "w", Limitations = "l", FalsePositiveNotes = "f", AlternativeExplanations = "a",
            Evidence = ev.Select(e => new Evidence { Kind = "FILE", Source = "s", Reference = e.Ref, Sha256 = e.Sha }).ToList(),
        };
        var findings = new[]
        {
            F("fb", "SSME-CL-0001", Severity.Critical, EvidenceTier.ConfirmedArtifact, 96, ("C:/x/b.jar", "aa"), ("C:/x/a.jar!/meta", null)),
            F("fa", "SSME-H-UNRECOGNIZED_MOD", Severity.Info, EvidenceTier.Inconclusive, 0, ("Z\u00e9", null)),
        };
        // Expected value computed with the TypeScript implementation (apps/website/src/lib/manifest.ts).
        Assert.Equal("e292ff3f6be378f9fca647257454b203247ad24e1dc56101b16f92fc7382fff0", Manifest.Compute(findings));
    }

    [Fact]
    public void Embedded_ruleset_is_valid()
    {
        var rules = RuleSet.LoadEmbedded();
        Assert.True(rules.Rules.Count >= 100);
        Assert.Equal(rules.Rules.Count, rules.Rules.Select(r => r.Id).Distinct().Count());
        foreach (var r in rules.Rules.Where(r => r.Kind.EndsWith("_REGEX")))
            Assert.True(r.Regex is not null, $"{r.Id} has an invalid regex");
        foreach (var id in typeof(Builtin).GetFields().Select(f => (string)f.GetValue(null)!))
            Assert.NotNull(rules.Get(id));
    }

    [Fact]
    public void Command_line_secrets_are_redacted()
    {
        var cmd = "javaw.exe -Xmx4G -javaagent:C:\\a.jar net.minecraft.client.main.Main --username Steve --accessToken eyJhbGciOi.secret --uuid 1234 --gameDir C:\\mc";
        var red = Modules.ProcessModule.Redact(cmd);
        Assert.DoesNotContain("eyJhbGciOi", red);
        Assert.DoesNotContain("Steve", red);
        Assert.Contains("--accessToken [redacted]", red);
        Assert.Contains("-javaagent:C:\\a.jar", red);
    }
}
