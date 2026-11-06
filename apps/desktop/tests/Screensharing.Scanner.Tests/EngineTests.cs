using Screensharing.Scanner.Engine;
using Screensharing.Scanner.Model;
using Screensharing.Scanner.Reporting;
using Screensharing.Scanner.Tests.Fixtures;
using static Screensharing.Scanner.Tests.TestUtil;

namespace Screensharing.Scanner.Tests;

public class EngineTests
{
    [Fact]
    public async Task Progress_is_monotonic_and_reports_real_file_counts()
    {
        using var fx = new FixtureBuilder();
        for (var i = 0; i < 12; i++) fx.AddMod($"mod{i}.jar", new FixtureBuilder.JarSpec { FabricId = i % 2 == 0 ? "sodium" : "lithium", Classes = ["a/B"] });
        fx.AddText("config/a.json", "{}");
        fx.AddFile("screenshots/2026-11-06.png", [1, 2, 3, 4, 5]); // excluded folder
        var engine = new ScanEngine(Options(fx));
        var updates = new List<ScanProgress>();
        engine.Progress += p => updates.Add(p);
        var r = await engine.RunAsync();
        Assert.True(updates.Count > 5);
        for (var i = 1; i < updates.Count; i++)
        {
            Assert.True(updates[i].Percent >= updates[i - 1].Percent, "progress never goes backwards");
            Assert.True(updates[i].FilesExamined >= updates[i - 1].FilesExamined);
        }
        var last = updates[^1];
        Assert.Equal(100, last.Percent);
        Assert.Equal(last.UnitsTotal, last.UnitsDone);
        Assert.Equal("Complete", last.Stage);
        Assert.True(last.Elapsed > TimeSpan.Zero);
        Assert.Equal(r.Inspection["examined"], last.FilesExamined);
        Assert.Equal(last.FilesAnalyzed + last.FilesSkipped, r.InspectionRecords.Count);
        Assert.True(last.FilesAnalyzed >= 14); // 12 mods, config, options.txt, instance.cfg
        Assert.Contains(r.ExcludedLocations, e => e.StartsWith("screenshots/"));
        Assert.DoesNotContain(r.AccessedPaths, p => p.Contains("screenshots", StringComparison.OrdinalIgnoreCase) && p.EndsWith(".png"));
        var mods = r.Coverage.Single(c => c.Key == "mods");
        Assert.Equal(CategoryStatus.Completed, mods.Status);
        Assert.True(mods.ItemsExamined >= 12);
    }

    [Fact]
    public async Task Process_modules_are_skipped_with_a_reason_when_no_process_is_attached()
    {
        using var fx = new FixtureBuilder();
        var r = await Scan(fx);
        foreach (var key in new[] { "launch", "process", "gamefiles" })
        {
            var c = r.Coverage.Single(x => x.Key == key);
            Assert.Equal(CategoryStatus.Skipped, c.Status);
            Assert.False(string.IsNullOrWhiteSpace(c.Message));
        }
    }

    [Fact]
    public async Task Cancellation_stops_the_scan_safely_and_leaves_files_untouched()
    {
        using var fx = new FixtureBuilder();
        var paths = Enumerable.Range(0, 60).Select(i => fx.AddMod($"m{i}.jar", new FixtureBuilder.JarSpec { FabricId = $"m{i}", Classes = Enumerable.Range(0, 50).Select(c => $"p{i}/C{c}") })).ToList();
        var before = paths.ToDictionary(p => p, File.ReadAllBytes);
        using var cts = new CancellationTokenSource();
        var engine = new ScanEngine(Options(fx));
        var seen = 0;
        engine.Progress += p => { if (p.Stage == "Mod archives" && ++seen == 5) cts.Cancel(); };
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => engine.RunAsync(cts.Token));
        Assert.Null(ScanScope.Current); // scope released
        foreach (var (p, bytes) in before) Assert.Equal(bytes, File.ReadAllBytes(p));

        // An already-cancelled token never starts reading the instance.
        var r2 = new ScanEngine(Options(fx));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => r2.RunAsync(new CancellationToken(true)));
    }

    [Fact]
    public async Task Report_statistics_match_the_inspection_records_and_findings()
    {
        using var fx = new FixtureBuilder();
        fx.AddMod("meteor.jar", Meteor);
        fx.AddMod("sodium.jar", Sodium);
        fx.AddFile("mods/broken.jar", [0x50, 0x4B, 0x03, 0x04, 9, 9, 9, 9]);
        fx.AddFile("notes.bin", [1, 2, 3, 4, 5, 6]);
        var r = await Scan(fx);
        Assert.Equal(r.InspectionRecords.Count(x => x.Status == InspectionStatus.Analyzed), (int)r.Statistics["filesAnalyzed"]);
        Assert.Equal(r.InspectionRecords.Count(x => x.Status != InspectionStatus.Analyzed), (int)r.Statistics["filesSkipped"]);
        Assert.Contains(r.InspectionRecords, x => x.Location == "notes.bin" && x.Status == InspectionStatus.NotApplicable);
        // Every unable-to-inspect finding has a matching inspection record, and vice versa for archives.
        foreach (var f in r.Findings.Where(f => f.Outcome == FindingOutcome.UnableToInspect))
            Assert.Contains(r.InspectionRecords, x => x.Location == f.Location && x.Status != InspectionStatus.Analyzed);
        Assert.Equal(1, r.Count(FindingOutcome.Confirmed));
        Assert.Equal(1, r.Count(FindingOutcome.UnableToInspect));
        Assert.Equal(r.Findings.Count, r.Findings.Select(f => f.ClientFindingId).Distinct().Count());
        Assert.True(r.SignatureCount >= 90);
        Assert.Equal(r.SignatureCount, (int)r.Statistics["signatures"]);
    }

    [Fact]
    public async Task Chain_of_custody_records_read_only_operations()
    {
        using var fx = new FixtureBuilder();
        var p = fx.AddMod("meteor.jar", Meteor);
        var before = File.GetLastWriteTimeUtc(p);
        var bytesBefore = File.ReadAllBytes(p);
        var r = await Scan(fx);
        Assert.Contains(r.Custody, o => o.Action == "select-instance" && o.Target.Contains(fx.GameDir));
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
        Assert.True(rules.Rules.Count >= 200);
        Assert.Equal(rules.Rules.Count, rules.Rules.Select(r => r.Id).Distinct().Count());
        foreach (var r in rules.Rules.Where(r => r.Kind.EndsWith("_REGEX")))
            Assert.True(r.Regex is not null, $"{r.Id} has an invalid regex");
        foreach (var r in rules.Rules.Where(r => r.Kind == RuleKind.String))
        {
            Assert.NotEmpty(r.Scopes);
            Assert.True(r.Pattern.Length >= 6, r.Id);
            Assert.False(r.TierValue == EvidenceTier.ConfirmedArtifact && r.References.Count == 0, $"{r.Id}: confirmed without a source");
        }
        foreach (var id in typeof(Builtin).GetFields().Select(f => (string)f.GetValue(null)!))
            Assert.NotNull(rules.Get(id));
        Assert.True(rules.HighSignalFeatures.Count >= 40);
        Assert.Contains("combat", rules.ModuleSegments);
        Assert.Contains(rules.OfKind(RuleKind.KnownMod), k => k.Pattern == "sodium" && k.Packages.Count > 0);
    }
}
