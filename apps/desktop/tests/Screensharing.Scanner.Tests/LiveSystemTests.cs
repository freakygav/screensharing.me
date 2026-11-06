using Screensharing.Scanner.Engine;
using Screensharing.Scanner.Model;

namespace Screensharing.Scanner.Tests;

/// <summary>
/// Runs the full engine (all modules, including Windows artifacts) against the machine running the tests.
/// Asserts robustness only — never the presence or absence of findings on a developer's machine.
/// </summary>
public class LiveSystemTests(Xunit.Abstractions.ITestOutputHelper output)
{
    [Fact]
    public async Task Full_scan_on_this_machine_completes_without_module_failures()
    {
        var engine = new ScanEngine(new ScanOptions { Rules = RuleSet.LoadEmbedded(), ModrinthLookup = Environment.GetEnvironmentVariable("SSME_LIVE_MODRINTH") == "1", Http = Environment.GetEnvironmentVariable("SSME_LIVE_MODRINTH") == "1" ? ModrinthHttp() : null, MemoryScanCapBytes = 512L * 1024 * 1024 });
        var r = await engine.RunAsync();
        Assert.All(r.Coverage, c => Assert.NotEqual(CategoryStatus.Failed, c.Status));
        Assert.Equal(9, r.Coverage.Count);
        Assert.NotEmpty(r.Custody);
        Assert.Matches("^[0-9a-f]{64}$", r.ManifestSha256);
        // Report for false-positive measurement (visible with --logger "console;verbosity=detailed").
        output.WriteLine($"elevated={r.Elevated} installations={r.Installations.Count} mods={r.Mods.Count} findings={r.Findings.Count} custodyOps={r.Custody.Count}");
        foreach (var c in r.Coverage) output.WriteLine($"  [{c.Status}] {c.Name}: {c.Message}");
        foreach (var g in r.Findings.GroupBy(f => $"{f.Tier}/{f.RuleId}").OrderBy(g => g.Key)) output.WriteLine($"  COUNT {g.Count(),5} {g.Key}");
        foreach (var f in r.Findings.Where(f => f.Tier != EvidenceTier.Inconclusive)) output.WriteLine($"  FINDING {f.Severity}/{f.Tier} {f.RuleId} {f.Name} :: {f.Evidence[0].Reference}");
    }

    private static HttpClient ModrinthHttp()
    {
        var h = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
        h.DefaultRequestHeaders.UserAgent.ParseAdd("screensharing.me-tests/1.0 (forensic scanner test suite)");
        return h;
    }
}
