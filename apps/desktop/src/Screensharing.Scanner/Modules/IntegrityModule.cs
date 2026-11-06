using System.Security.Cryptography;
using System.Text.Json;
using Screensharing.Scanner.Discovery;
using Screensharing.Scanner.Engine;
using Screensharing.Scanner.Model;

namespace Screensharing.Scanner.Modules;

/// <summary>Verifies game client jars and libraries against the SHA-1 hashes declared in Mojang's version manifests.</summary>
public sealed class IntegrityModule : IScanModule
{
    public string Key => "integrity";
    public string Name => "Game file integrity";
    public string Activity => "Validating game files against published hashes…";
    public string? SkipReason(ScanContext ctx) => null;

    private const int MaxLibraries = 4000;
    private readonly List<Check> _checks = [];

    private sealed record Check(Installation Inst, string Version, string Path, string ExpectedSha1, bool IsClient);

    public int Plan(ScanContext ctx)
    {
        _checks.Clear();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var inst in ctx.Installations.Where(i => i.VersionsDirectory is not null))
        {
            foreach (var verDir in MinecraftLocator.SafeDirs(inst.VersionsDirectory!))
            {
                var id = System.IO.Path.GetFileName(verDir);
                var json = System.IO.Path.Combine(verDir, id + ".json");
                if (!File.Exists(json)) continue;
                try
                {
                    using var doc = JsonDocument.Parse(File.ReadAllText(json));
                    var root = doc.RootElement;
                    if (root.TryGetProperty("downloads", out var dl) && dl.TryGetProperty("client", out var client) && client.TryGetProperty("sha1", out var sha1))
                    {
                        var jar = System.IO.Path.Combine(verDir, id + ".jar");
                        if (File.Exists(jar) && seen.Add(jar)) _checks.Add(new Check(inst, id, jar, sha1.GetString()!, true));
                    }
                    if (inst.LibrariesDirectory is not null && root.TryGetProperty("libraries", out var libs))
                    {
                        foreach (var lib in libs.EnumerateArray())
                        {
                            if (_checks.Count > MaxLibraries) break;
                            if (!lib.TryGetProperty("downloads", out var ld) || !ld.TryGetProperty("artifact", out var art)) continue;
                            if (!art.TryGetProperty("path", out var p) || !art.TryGetProperty("sha1", out var s)) continue;
                            var full = System.IO.Path.Combine(inst.LibrariesDirectory, p.GetString()!.Replace('/', '\\'));
                            if (File.Exists(full) && seen.Add(full)) _checks.Add(new Check(inst, id, full, s.GetString()!, false));
                        }
                    }
                    ctx.Custody.Record("read-version-manifest", json);
                }
                catch (Exception e) when (e is JsonException or IOException or UnauthorizedAccessException or InvalidOperationException or KeyNotFoundException) { }
            }
        }
        return _checks.Count + 1;
    }

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        var mismatches = 0;
        foreach (var c in _checks)
        {
            ct.ThrowIfCancellationRequested();
            ctx.SetActivity($"Validating game files… {System.IO.Path.GetFileName(c.Path)}");
            string? actual = null;
            try
            {
                using var fs = ScanContext.OpenRead(c.Path);
                actual = Convert.ToHexStringLower(SHA1.HashData(fs));
                ctx.Custody.Record("hash-sha1", c.Path);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
            if (actual is not null && !string.Equals(actual, c.ExpectedSha1, StringComparison.OrdinalIgnoreCase))
            {
                mismatches++;
                var ev = ctx.FileEvidence(c.Path, c.IsClient ? "Minecraft client jar" : "Game library", new() { ["expectedSha1"] = c.ExpectedSha1, ["actualSha1"] = actual, ["version"] = c.Version });
                if (c.IsClient)
                    ctx.Report(Builtin.ClientJarModified, [c.Path],
                        $"The Minecraft {c.Version} client jar in {c.Inst.Launcher} does not match the SHA-1 published in its version manifest (expected {c.ExpectedSha1}, found {actual}).",
                        "SHA-1 comparison of versions/<id>/<id>.jar with downloads.client.sha1 in versions/<id>/<id>.json.",
                        "Injecting cheat code directly into the game jar is a way to avoid mod loaders entirely. An unmodified installation always matches Mojang's hash.",
                        "An interrupted download or disk corruption; the official launcher normally repairs mismatching files on the next launch.",
                        [ev]);
                else
                    ctx.Report(Builtin.LibraryModified, [c.Path],
                        $"Library {System.IO.Path.GetFileName(c.Path)} used by {c.Version} in {c.Inst.Launcher} does not match its published SHA-1.",
                        "SHA-1 comparison of each library jar with downloads.artifact.sha1 in the version manifest.",
                        "Replacing a library the game loads (e.g. a networking or rendering library) can inject code without any visible mod.",
                        "Interrupted downloads; some launchers patch libraries themselves.",
                        [ev]);
            }
            ctx.Advance();
        }
        ctx.Statistics["integrityChecks"] = _checks.Count;
        if (ctx.CurrentCategory is not null)
            ctx.CurrentCategory.Message = _checks.Count == 0 ? "No hash-verifiable game files found" : $"{_checks.Count} files verified, {mismatches} mismatches";
        ctx.Advance();
        return Task.CompletedTask;
    }
}
