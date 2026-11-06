using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using Screensharing.Scanner.Engine;
using Screensharing.Scanner.Model;

namespace Screensharing.Scanner.Modules;

/// <summary>
/// The jars the running game actually loads (its class path): the client jar and libraries are verified against the
/// SHA-1 hashes in the launcher's version manifest; anything that cannot be verified is analysed like a mod.
/// </summary>
public sealed partial class GameFilesModule : IScanModule
{
    public string Key => "gamefiles";
    public string Name => "Game files & class path";
    public string Activity => "Verifying the game's class path…";
    public string? SkipReason(ScanContext ctx) => ctx.Instance.ClassPath.Count == 0 ? "The class path of the game process is not available (no running process attached)" : null;

    private sealed record Expected(string Sha1, string Version, bool IsClient, string Manifest);
    private readonly List<string> _entries = [];
    private readonly Dictionary<string, Expected> _byPath = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, List<Expected>> _byName = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<string> _manifests = [];

    [GeneratedRegex(@"\\libraries\\com\\mojang\\minecraft\\(?<v>[^\\]+)\\minecraft-\k<v>-client\.jar$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex PrismClientJar();

    /// <summary>Version manifests the class path implies (sibling .json of a versions/&lt;id&gt;/&lt;id&gt;.jar, or Prism's meta/net.minecraft/&lt;v&gt;.json).</summary>
    public static IEnumerable<string> ManifestCandidates(IEnumerable<string> classPath)
    {
        foreach (var e in classPath)
        {
            var dir = Path.GetDirectoryName(e);
            var stem = Path.GetFileNameWithoutExtension(e);
            if (dir is not null && Path.GetFileName(dir).Equals(stem, StringComparison.OrdinalIgnoreCase)) yield return Path.Combine(dir, stem + ".json");
            var m = PrismClientJar().Match(e);
            if (m.Success)
            {
                var libs = e[..e.IndexOf(@"\libraries\", StringComparison.OrdinalIgnoreCase)];
                yield return Path.Combine(libs, "meta", "net.minecraft", m.Groups["v"].Value + ".json");
            }
        }
    }

    public int Plan(ScanContext ctx)
    {
        _entries.Clear(); _byPath.Clear(); _byName.Clear(); _manifests.Clear();
        _entries.AddRange(ctx.Instance.ClassPath.Distinct(StringComparer.OrdinalIgnoreCase));
        foreach (var manifest in ManifestCandidates(_entries).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (!ctx.Scope.Contains(manifest) || !File.Exists(manifest)) continue;
            try
            {
                using var fs = ctx.OpenRead(manifest);
                using var doc = JsonDocument.Parse(fs, new JsonDocumentOptions { AllowTrailingCommas = true });
                ctx.Custody.Record("read-version-manifest", manifest);
                _manifests.Add(manifest);
                var root = doc.RootElement;
                var version = root.TryGetProperty("id", out var id) ? id.GetString() ?? "?" : root.TryGetProperty("version", out var v) ? v.GetString() ?? "?" : "?";
                string? clientSha = null;
                if (root.TryGetProperty("downloads", out var dl) && dl.TryGetProperty("client", out var c) && c.TryGetProperty("sha1", out var s1)) clientSha = s1.GetString();
                else if (root.TryGetProperty("mainJar", out var mj) && mj.TryGetProperty("downloads", out var mjd) && mjd.TryGetProperty("artifact", out var mja) && mja.TryGetProperty("sha1", out var s2)) clientSha = s2.GetString();
                if (clientSha is not null)
                {
                    var jar = Path.ChangeExtension(manifest, ".jar");
                    if (_entries.Contains(jar, StringComparer.OrdinalIgnoreCase)) _byPath[jar] = new Expected(clientSha, version, true, manifest);
                    foreach (var e in _entries.Where(e => PrismClientJar().IsMatch(e) && e.Contains(version, StringComparison.OrdinalIgnoreCase)))
                        _byPath[e] = new Expected(clientSha, version, true, manifest);
                }
                if (root.TryGetProperty("libraries", out var libs) && libs.ValueKind == JsonValueKind.Array)
                    foreach (var lib in libs.EnumerateArray())
                    {
                        if (!lib.TryGetProperty("downloads", out var ld) || !ld.TryGetProperty("artifact", out var art) || !art.TryGetProperty("sha1", out var sha)) continue;
                        string? rel = art.TryGetProperty("path", out var p) ? p.GetString() : MavenPath(lib.TryGetProperty("name", out var n) ? n.GetString() : null);
                        if (rel is null) continue;
                        var exp = new Expected(sha.GetString()!, version, false, manifest);
                        var file = Path.GetFileName(rel.Replace('/', '\\'));
                        (_byName.TryGetValue(file, out var list) ? list : _byName[file] = []).Add(exp);
                        foreach (var e in _entries.Where(e => e.Replace('/', '\\').EndsWith("\\" + rel.Replace('/', '\\'), StringComparison.OrdinalIgnoreCase))) _byPath[e] = exp;
                    }
            }
            catch (Exception e) when (e is JsonException or IOException or UnauthorizedAccessException or InvalidOperationException or KeyNotFoundException) { }
        }
        return _entries.Count + 1;
    }

    private static string? MavenPath(string? coords)
    {
        if (coords is null) return null;
        var parts = coords.Split(':');
        if (parts.Length < 3) return null;
        var classifier = parts.Length > 3 ? "-" + parts[3] : "";
        return $"{parts[0].Replace('.', '/')}/{parts[1]}/{parts[2]}/{parts[1]}-{parts[2]}{classifier}.jar";
    }

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int verified = 0, mismatched = 0, analyzed = 0, missing = 0;
        foreach (var entry in _entries)
        {
            ct.ThrowIfCancellationRequested();
            ctx.SetActivity($"Verifying the game's class path… {Path.GetFileName(entry)}");
            ctx.Inspection.CountExamined();
            if (Directory.Exists(entry))
            {
                ctx.Inspection.Record(new InspectionRecord(entry, entry, FileRole.Archive, InspectionStatus.NotApplicable, "class-path directory (not an archive)"));
                ctx.Advance();
                continue;
            }
            if (!File.Exists(entry)) { missing++; ctx.Advance(); continue; }
            var expected = _byPath.GetValueOrDefault(entry) ?? (_byName.TryGetValue(Path.GetFileName(entry), out var cands) && cands.Count == 1 ? cands[0] : null);
            string? actual = null;
            if (expected is not null)
            {
                try
                {
                    using var fs = ctx.OpenRead(entry);
                    actual = Convert.ToHexStringLower(SHA1.HashData(fs));
                    ctx.Custody.Record("hash-sha1", entry);
                }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException) { ctx.Uninspectable(entry, FileRole.Archive, InspectionStatus.Unreadable, e.Message); ctx.Advance(); continue; }
                if (string.Equals(actual, expected.Sha1, StringComparison.OrdinalIgnoreCase))
                {
                    verified++;
                    ctx.Inspection.Record(new InspectionRecord(entry, ctx.Location(entry), FileRole.Archive, InspectionStatus.Analyzed, "hash matches the version manifest"));
                    ctx.Advance();
                    continue;
                }
                mismatched++;
                var ev = ctx.FileEvidence(entry, expected.IsClient ? "Minecraft client jar" : "Game library", new() { ["expectedSha1"] = expected.Sha1, ["actualSha1"] = actual!, ["version"] = expected.Version, ["manifest"] = expected.Manifest });
                if (expected.IsClient)
                    ctx.Report(Builtin.ClientJarModified, [entry],
                        $"The Minecraft {expected.Version} client jar loaded by the game ({entry}) does not match the SHA-1 in its version manifest (expected {expected.Sha1}, found {actual}).",
                        "SHA-1 of the client jar on the game's class path compared with the version manifest the launcher stores next to it.",
                        "Injecting cheat code directly into the game jar avoids mod loaders entirely. An unmodified installation always matches Mojang's hash.",
                        "An interrupted download or disk corruption; launchers normally repair mismatching files on the next launch.",
                        [ev], signature: "SHA-1 mismatch", location: entry);
                else
                    ctx.Report(Builtin.LibraryModified, [entry],
                        $"Library {Path.GetFileName(entry)} loaded by the game does not match the SHA-1 in the version manifest (expected {expected.Sha1}, found {actual}).",
                        "SHA-1 of each class-path library compared with downloads.artifact.sha1 in the version manifest.",
                        "Replacing a library the game loads (e.g. a networking or rendering library) can inject code without any visible mod.",
                        "Interrupted downloads; some launchers patch libraries themselves.",
                        [ev], signature: "SHA-1 mismatch", location: entry);
            }

            // Unverifiable or modified: analyse its content like a mod.
            var rec = ModsModule.AnalyzeArchive(ctx, entry, "Class path", FileRole.Archive, ct, classPath: true);
            analyzed++;
            var expectedLocation = ctx.Scope.Contains(entry) && (ctx.Instance.LibraryRoots.Any(r => entry.StartsWith(r + "\\", StringComparison.OrdinalIgnoreCase))
                || entry.StartsWith(ctx.Instance.InstanceRoot + "\\", StringComparison.OrdinalIgnoreCase));
            if (rec is not null && !expectedLocation && !LaunchModule.IsLauncherAgent(ctx, entry))
            {
                ctx.Report(Builtin.ClasspathUnexpected, [entry],
                    $"The game loads {entry} from outside the instance and the launcher's library folders, and the jar is not recognised as the launcher's own.",
                    "Every class-path entry of the game process is located and, when it is not hash-verified, analysed; its location is compared with the instance and the launcher's libraries/versions folders.",
                    "Adding a jar to the class path injects code without using the mods folder.",
                    "Custom launch scripts and some third-party launchers keep jars elsewhere.",
                    [ctx.FileEvidence(entry, "Class-path archive")], signature: "class path outside launcher folders", location: entry);
                foreach (var g in rec.PendingIndicators) ctx.Report(g.Primary.Id, [entry, g.Family], $"\"{entry}\" {string.Join("; ", g.Indicators.Select(i => i.What).Take(6))}.",
                    "String signatures matched in the class-path archive.", g.Primary.Description, "Each string has legitimate uses; only combinations are reported.",
                    [ctx.FileEvidence(entry, "Class-path archive"), .. g.Indicators.Select(i => i.Evidence)], tier: g.Tier, confidence: g.Confidence,
                    signature: string.Join(" + ", g.Indicators.Select(i => i.Signature).Take(4)), location: entry);
            }
            ctx.Advance();
        }
        ctx.Statistics["classPathEntries"] = _entries.Count;
        ctx.Statistics["integrityVerified"] = verified;
        ctx.Statistics["integrityMismatches"] = mismatched;
        if (ctx.CurrentCategory is not null)
            ctx.CurrentCategory.Message = $"{_entries.Count} class-path entries: {verified} hash-verified, {mismatched} mismatched, {analyzed} analysed by content" +
                (missing > 0 ? $", {missing} missing" : "") + (_manifests.Count == 0 ? " (no version manifest found — client jar not verifiable)" : "");
        ctx.Advance();
        return Task.CompletedTask;
    }
}
