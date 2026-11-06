using System.Diagnostics;
using Screensharing.Scanner.Analysis;
using Screensharing.Scanner.Model;
using Screensharing.Scanner.Tests.Fixtures;
using Screensharing.Scanner.Windows;

namespace Screensharing.Scanner.Tests;

public class ArtifactParserTests
{
    [Fact]
    public void Aho_corasick_finds_overlapping_patterns()
    {
        var ac = new AhoCorasick(["he", "she", "his", "hers"]);
        var hits = ac.Search("ushers"u8.ToArray()).ToList();
        Assert.Contains(hits, h => h == (1, 1)); // she
        Assert.Contains(hits, h => h == (0, 2)); // he
        Assert.Contains(hits, h => h == (3, 2)); // hers
    }

    [Fact]
    public void Class_file_constant_pool_strings_are_extracted_and_separated()
    {
        var cls = FixtureBuilder.BuildClass("a/b/C", ["net/wurstclient/Hack", "hello world"]);
        using var ms = new MemoryStream();
        Assert.True(ClassFile.ExtractUtf8Constants(cls, ms));
        var text = System.Text.Encoding.UTF8.GetString(ms.ToArray());
        Assert.Contains("a/b/C\0", text);
        Assert.Contains("net/wurstclient/Hack\0", text);
        Assert.Contains("hello world\0", text);
        Assert.False(ClassFile.ExtractUtf8Constants("not a class"u8.ToArray(), new MemoryStream()));
    }

    [Fact]
    public void Signature_index_matches_by_scope_and_utf16_in_binaries()
    {
        var idx = new SignatureIndex(RuleSet.LoadEmbedded());
        var wide = System.Text.Encoding.Unicode.GetBytes("xx JNI_GetCreatedJavaVMs xx");
        Assert.Contains(idx.Match(SignatureScope.Binary, wide, "x.dll"), h => h.Rule.Pattern == "JNI_GetCreatedJavaVMs");
        // Log-only signatures do not fire in other scopes.
        Assert.Empty(idx.Match(SignatureScope.Class, "meteordevelopment.meteorclient.Foo"u8.ToArray(), "c"));
        Assert.NotEmpty(idx.Match(SignatureScope.Log, "at meteordevelopment.meteorclient.Foo"u8.ToArray(), "latest.log"));
    }

    [Fact]
    public void Png_transparency_is_measured_from_pixels()
    {
        Assert.Equal(1.0, PngAlpha.TransparentFraction(FixtureBuilder.BuildPng(true)));
        Assert.Equal(0.0, PngAlpha.TransparentFraction(FixtureBuilder.BuildPng(false)));
        Assert.Null(PngAlpha.TransparentFraction([1, 2, 3]));
    }

    [Fact]
    public void Archive_probe_recognises_polyglots()
    {
        var jar = FixtureBuilder.BuildJar(new FixtureBuilder.JarSpec { Classes = ["a/A"] });
        Assert.Equal(ArchiveKind.Zip, JarAnalyzer.Probe(new MemoryStream(jar)));
        Assert.Equal(ArchiveKind.ExecutableWithZip, JarAnalyzer.Probe(new MemoryStream([.. FixtureBuilder.BuildPe("x"), .. jar])));
        Assert.Equal(ArchiveKind.NotArchive, JarAnalyzer.Probe(new MemoryStream(FixtureBuilder.BuildPe("x"))));
        Assert.True(JarAnalyzer.LooksLikePe(FixtureBuilder.BuildPe("x")));
    }

    [Fact]
    public void Evidence_scoring_combines_indicators_without_overclaiming()
    {
        var rules = RuleSet.LoadEmbedded();
        Indicator I(string id) => new(rules.Get(id)!, new Evidence { Kind = "FILE", Source = "s", Reference = "r" }, "w", "s");
        // Four injection APIs: strong, never confirmed (generic indicators).
        var g = Assert.Single(EvidenceScoring.Score([I("SSME-IJ-0001"), I("SSME-IJ-0002"), I("SSME-IJ-0003"), I("SSME-IJ-0005")]));
        Assert.Equal(EvidenceTier.StrongIndicator, g.Tier);
        Assert.True(g.Report);
        // One weak generic indicator: below the reporting threshold.
        Assert.False(Assert.Single(EvidenceScoring.Score([I("SSME-IJ-0021")])).Report);
        // Mod id + package of a known client: confirmed.
        var m = Assert.Single(EvidenceScoring.Score([I("SSME-CL-0001"), I("SSME-CL-0002")]));
        Assert.Equal(EvidenceTier.ConfirmedArtifact, m.Tier);
        // Only a file name: never more than suspicious.
        var n = Assert.Single(EvidenceScoring.Score([I(rules.OfKind(RuleKind.FileNameRegex).First().Id)]));
        Assert.True(n.Tier >= EvidenceTier.SuspiciousConfiguration);
    }

    [Fact]
    public void Memory_scanner_reads_a_live_process()
    {
        using var p = Process.Start(new ProcessStartInfo("ping.exe", "-n 6 127.0.0.1") { CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true })!;
        try
        {
            Thread.Sleep(400);
            var r = MemoryScanner.Scan(p.Id, ["ping.exe", "NOT-PRESENT-STRING-XYZ"], 256L * 1024 * 1024, TimeSpan.FromSeconds(10), CancellationToken.None);
            Assert.Null(r.Error);
            Assert.True(r.BytesScanned > 0);
            Assert.DoesNotContain("NOT-PRESENT-STRING-XYZ", r.Hits.Keys);
        }
        finally { p.Kill(); }
    }

    [Fact]
    public void Module_heuristic_ignores_ordinary_mod_classes()
    {
        var rules = RuleSet.LoadEmbedded();
        var r = ModuleHeuristics.Evaluate(["net/example/entity/Speed", "net/example/attribute/Reach", "net/example/Velocity"], rules);
        Assert.Empty(r.Names);
        var c = ModuleHeuristics.Evaluate(["x/module/combat/KillAura", "x/module/movement/Fly", "x/module/render/ESP"], rules);
        Assert.Equal(3, c.Names.Count);
    }
}
