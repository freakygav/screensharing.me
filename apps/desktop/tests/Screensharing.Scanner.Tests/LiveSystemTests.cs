using Screensharing.Scanner.Engine;
using Screensharing.Scanner.Instance;
using Screensharing.Scanner.Model;
using Xunit.Abstractions;

namespace Screensharing.Scanner.Tests;

/// <summary>
/// Real-machine check (opt-in with SSME_LIVE_INSTANCE=1): identifies the Minecraft instance that is running right now
/// and scans exactly that instance.
/// </summary>
public class LiveSystemTests(ITestOutputHelper output)
{
    [Fact]
    public async Task Running_instance_is_identified_and_only_it_is_scanned()
    {
        if (Environment.GetEnvironmentVariable("SSME_LIVE_INSTANCE") != "1") return;
        var detected = InstanceResolver.Detect();
        foreach (var d in detected) output.WriteLine($"{d.Launcher} | {d.Name} | {d.GameDirectory} | resolved={d.Resolved} | {d.Problem} | source={d.GameDirectorySource} | loader={d.Loader} | cp={d.ClassPath.Count}");
        var inst = detected.FirstOrDefault(d => d.Resolved);
        Assert.NotNull(inst);
        var engine = new ScanEngine(new ScanOptions
        {
            Rules = RuleSet.LoadEmbedded(), Target = inst, ModrinthLookup = Environment.GetEnvironmentVariable("SSME_LIVE_MODRINTH") == "1",
            MemoryScan = true, MemoryScanCapBytes = 1L << 30, Http = new HttpClient { Timeout = TimeSpan.FromSeconds(20) },
        });
        var r = await engine.RunAsync();
        output.WriteLine($"duration {r.Statistics["durationSeconds"]}s; examined {r.Inspection["examined"]}, analysed {r.Inspection["analyzed"]}, skipped {r.Inspection["skipped"]}, unable {r.Inspection["unableToInspect"]}");
        foreach (var c in r.Coverage) output.WriteLine($"  [{c.Status}] {c.Name}: {c.Message}");
        foreach (var f in r.Findings) output.WriteLine($"  {f.Outcome} | {f.Severity} | {f.Name} | {f.Location} | {f.Signature}");
        foreach (var e in r.ExcludedLocations) output.WriteLine($"  excluded: {e}");
        foreach (var x in r.InspectionRecords.Where(x => x.Status is not (InspectionStatus.Analyzed or InspectionStatus.NotApplicable))) output.WriteLine($"  not inspected: {x.Location} [{x.Status}] {x.Reason}");
        foreach (var g in r.InspectionRecords.Where(x => x.Status == InspectionStatus.NotApplicable).GroupBy(x => x.Reason)) output.WriteLine($"  not applicable x{g.Count()}: {g.Key}");
        Assert.Empty(r.ScopeViolations);
        Assert.DoesNotContain(r.Coverage, c => c.Status == CategoryStatus.Failed);
        var allowed = r.ScopeRoots;
        foreach (var p in r.AccessedPaths)
            Assert.True(allowed.Any(a => p.StartsWith(a, StringComparison.OrdinalIgnoreCase)) || inst.ClassPath.Contains(p, StringComparer.OrdinalIgnoreCase)
                || p.EndsWith(".json", StringComparison.OrdinalIgnoreCase) || p.EndsWith(".dll", StringComparison.OrdinalIgnoreCase), $"unexpected access: {p}");
    }
}
