using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;
using Screensharing.Scanner.Analysis;
using Screensharing.Scanner.Engine;
using Screensharing.Scanner.Model;

namespace Screensharing.Scanner.Modules;

/// <summary>
/// The instance's game logs and crash reports: the mod lists of previous sessions and string signatures in
/// non-chat lines (stack traces, loader and mixin output). Chat lines are excluded so that what players type
/// never matches.
/// </summary>
public sealed partial class LogsModule : IScanModule
{
    public string Key => "logs";
    public string Name => "Logs & crash reports";
    public string Activity => "Analyzing game logs and crash reports…";
    public string? SkipReason(ScanContext ctx) => null;

    private const int MaxLogs = 80;
    private static readonly TimeSpan Window = TimeSpan.FromDays(30);
    private readonly List<InstanceFile> _logs = [];
    private int _olderSkipped;

    // Fabric:  "[main/INFO]: Loading 57 mods:" then "\t- modid version"
    [GeneratedRegex(@"Loading \d+ mods:", RegexOptions.CultureInvariant)] private static partial Regex FabricHeader();
    [GeneratedRegex(@"^\s*-\s+(?<id>[a-z0-9_\-.]+)\s+(?<ver>\S+)", RegexOptions.CultureInvariant)] private static partial Regex FabricTop();
    [GeneratedRegex(@"^\s*\|--\s+(?<id>[a-z0-9_\-.]+)\s+(?<ver>\S+)", RegexOptions.CultureInvariant)] private static partial Regex FabricNested();
    // Forge/NeoForge: "Found mod file sodium.jar of type MOD with provider ..."
    [GeneratedRegex(@"Found mod file (?<file>.+?\.jar) of type", RegexOptions.CultureInvariant)] private static partial Regex ForgeFile();
    // Crash report (Fabric): "\tFabric Mods: " then "\t\tmodid: Name version"
    [GeneratedRegex(@"^\t\t(?<id>[a-z0-9_\-.]+): (?<name>.+?) (?<ver>\S+)\s*$", RegexOptions.CultureInvariant)] private static partial Regex CrashMod();

    public int Plan(ScanContext ctx)
    {
        _logs.Clear();
        var cutoff = (ctx.Now - Window).UtcDateTime;
        var all = ctx.FilesOf(FileRole.Log, FileRole.CrashReport).OrderByDescending(f => SafeTime(f.Path)).ToList();
        foreach (var f in all)
        {
            if (_logs.Count < MaxLogs && SafeTime(f.Path) >= cutoff) _logs.Add(f);
            else ctx.NotApplicable(f.Path, f.Role, $"older than {Window.TotalDays:N0} days or beyond the newest {MaxLogs} logs");
        }
        _olderSkipped = all.Count - _logs.Count;
        return _logs.Count + 1;
    }

    private static DateTime SafeTime(string p) { try { return File.GetLastWriteTimeUtc(p); } catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return DateTime.MinValue; } }

    private sealed record Session(string Log, DateTime Time, bool Crash, List<(string Id, string Version)> Mods, List<string> ForgeFiles);

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        var sessions = new List<Session>();
        foreach (var f in _logs)
        {
            ct.ThrowIfCancellationRequested();
            ctx.SetActivity($"Analyzing game logs… {f.GamePath}");
            string text;
            try { text = ReadLog(ctx, f.Path); ctx.Custody.Record("read-log", f.Path); }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidDataException)
            {
                ctx.Uninspectable(f.Path, f.Role, InspectionStatus.Unreadable, e.Message, report: false);
                ctx.Advance();
                continue;
            }
            var s = Parse(f, text);
            sessions.Add(s);
            Strings(ctx, f, text, s.Time);
            ctx.Analyzed(f.Path, f.Role);
            ctx.Advance();
        }

        var presentIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var m in ctx.Mods.Where(m => m.Jar is not null))
            foreach (var md in m.Jar!.AllMetadata()) presentIds.Add(md.Id);
        var presentFiles = new HashSet<string>(ctx.Mods.Select(m => m.FileName), StringComparer.OrdinalIgnoreCase);

        foreach (var s in sessions)
        {
            var source = s.Crash ? "Crash report (mod list)" : "Game log (Fabric mod list)";
            foreach (var (id, ver) in s.Mods)
            {
                var ev = new Evidence
                {
                    Kind = EvidenceKind.Log, Source = source, Reference = s.Log,
                    Sha256 = ctx.Sha256(s.Log), ModifiedTime = s.Time,
                    Details = new() { ["modId"] = id, ["version"] = ver, ["written"] = s.Time.ToString("u") },
                };
                if (ctx.Rules.ModIdRule(id) is { } rule && rule.SeverityValue <= Severity.High)
                {
                    ctx.Report(Builtin.LoggedCheatMod, [s.Log, id],
                        $"The {(s.Crash ? "crash report" : "game log")} \"{ctx.Location(s.Log)}\" written {s.Time:u} lists \"{id}\" {ver} ({rule.Family ?? rule.Name}) among the mods loaded in that session" + (presentIds.Contains(id) ? "." : ". The mod is no longer in the instance's mods folder."),
                        "Parsing of the Fabric loader's \"Loading N mods\" list and the mod list of crash reports in the instance (last 30 days).",
                        "The log is written by the game itself while it starts, so it shows the client was actually loaded in this instance — not merely downloaded.",
                        "Log files can be copied from another computer, which is uncommon.",
                        [ev], name: $"{rule.Family ?? rule.Name} loaded in a recent session of this instance", family: rule.Family, signature: $"mod id \"{id}\" in mod list");
                }
                else if (!presentIds.Contains(id) && !IsPlatformId(id) && ctx.Rules.KnownMod(id) is null)
                {
                    ctx.Report(Builtin.LoggedModMissing, [ctx.Instance.GameDirectory, id],
                        $"\"{id}\" {ver} was loaded in the session logged {s.Time:u} but no archive in the instance declares this mod id now.",
                        "Comparison of mod ids recorded in the instance's logs with mod ids declared by archives currently in its mods folder.",
                        "Removing a mod after playing and before a screenshare is a common concealment technique; the log preserves what was loaded.",
                        "Mods are routinely removed or replaced.",
                        [ev], signature: $"mod id \"{id}\" missing", location: ctx.Location(s.Log));
                }
            }
            foreach (var file in s.ForgeFiles.Where(f => !presentFiles.Contains(f)))
                foreach (var r in ctx.Rules.OfKind(RuleKind.FileNameRegex).Where(r => r.IsMatch(file)))
                    ctx.Report(r.Id, [s.Log, file],
                        $"The Forge/NeoForge log written {s.Time:u} shows the mod file \"{file}\" being loaded; it no longer exists in the mods folder.",
                        "Parsing of \"Found mod file\" lines in Forge/NeoForge logs.",
                        r.Description, "File names are user-controlled.",
                        [new Evidence { Kind = EvidenceKind.Log, Source = "Game log (Forge mod discovery)", Reference = s.Log, Sha256 = ctx.Sha256(s.Log), ModifiedTime = s.Time, Details = new() { ["fileName"] = file } }],
                        signature: $"file name \"{file}\"");
        }

        // Mods folder changed after the most recent session.
        var latest = sessions.Where(s => !s.Crash).Select(s => (DateTime?)s.Time).Max();
        if (latest is not null && latest >= (ctx.Now - TimeSpan.FromDays(7)).UtcDateTime)
        {
            foreach (var m in ctx.Mods.Where(m => m.Origin == "Mods folder"))
            {
                var fi = new FileInfo(m.Path);
                var changed = new[] { fi.CreationTimeUtc, fi.LastWriteTimeUtc }.Max();
                if (changed <= latest.Value.AddMinutes(1)) continue;
                ctx.Report(Builtin.ModChangedAfterSession, [m.Path],
                    $"\"{m.Location}\" was created or modified {changed:u}, after the instance's last game log was written ({latest:u}).",
                    "Comparison of NTFS creation/modification times in the mods folder with the newest game log timestamp.",
                    "Swapping mods between the last play session and the screenshare can hide what was actually used.",
                    "Installing or updating mods between sessions is normal; copying files resets creation time.",
                    [ctx.FileEvidence(m.Path, "Mod archive", new() { ["lastSessionLog"] = latest.Value.ToString("u") })], signature: "modified after last session");
            }
        }

        ctx.Statistics["logsParsed"] = sessions.Count;
        if (ctx.CurrentCategory is not null)
            ctx.CurrentCategory.Message = sessions.Count == 0 ? "No logs from the last 30 days in this instance" :
                $"{sessions.Count(s => !s.Crash)} logs and {sessions.Count(s => s.Crash)} crash reports" + (_olderSkipped > 0 ? $" ({_olderSkipped} older files not analysed)" : "");
        ctx.Advance();
        return Task.CompletedTask;
    }

    /// <summary>Matches log-scope signatures on every line except chat.</summary>
    private static void Strings(ScanContext ctx, InstanceFile f, string text, DateTime written)
    {
        if (!ctx.Signatures.Has(SignatureScope.Log)) return;
        var sb = new StringBuilder(text.Length);
        foreach (var line in text.Split('\n'))
            if (!line.Contains("[CHAT]", StringComparison.Ordinal)) sb.Append(line).Append('\n');
        var hits = ctx.Signatures.Match(SignatureScope.Log, Encoding.UTF8.GetBytes(sb.ToString()), f.GamePath);
        if (hits.Count == 0) return;
        var indicators = hits.Select(h => new Indicator(h.Rule,
            new Evidence { Kind = EvidenceKind.Log, Source = f.Role == FileRole.CrashReport ? "Crash report" : "Game log", Reference = f.Path, ModifiedTime = written, Details = new() { ["string"] = h.Rule.Pattern, ["excerpt"] = h.Excerpt ?? "" } },
            $"contains \"{h.Rule.Pattern}\" outside chat", $"string \"{h.Rule.Pattern}\"")).ToList();
        foreach (var g in EvidenceScoring.Score(indicators).Where(g => g.Report && g.Tier != EvidenceTier.Inconclusive))
            ctx.Report(g.Primary.Id, [f.Path, g.Family],
                $"The {(f.Role == FileRole.CrashReport ? "crash report" : "log")} \"{f.GamePath}\" (written {written:u}) {string.Join("; ", g.Indicators.Select(i => i.What).Take(5))}.",
                "String-signature matching of log lines; chat lines ([CHAT]) are excluded.",
                g.Primary.Description, "A copied log file would carry the same lines.",
                [.. g.Indicators.Select(i => i.Evidence)], tier: g.Tier, confidence: g.Confidence, family: g.Primary.Family,
                signature: string.Join(" + ", g.Indicators.Select(i => i.Signature).Take(4)), location: f.GamePath);
    }

    private static bool IsPlatformId(string id) =>
        id is "java" or "minecraft" or "fabricloader" or "mixinextras" or "quilt_loader" || id.StartsWith("fabric-", StringComparison.Ordinal) || id.StartsWith("fabric_", StringComparison.Ordinal);

    internal static string ReadLog(ScanContext ctx, string path)
    {
        using var fs = ctx.OpenRead(path);
        Stream s = path.EndsWith(".gz", StringComparison.OrdinalIgnoreCase) ? new GZipStream(fs, CompressionMode.Decompress) : fs;
        using var r = new StreamReader(s);
        var buf = new char[(int)Math.Min(ctx.Options.MaxTextBytes, 16 * 1024 * 1024)];
        var n = r.ReadBlock(buf, 0, buf.Length);
        return new string(buf, 0, n);
    }

    private static Session Parse(InstanceFile f, string text)
    {
        var mods = new List<(string, string)>();
        var forge = new List<string>();
        var lines = text.Split('\n');
        var crash = f.Role == FileRole.CrashReport;
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i].TrimEnd('\r');
            if (crash)
            {
                if (line.TrimStart().StartsWith("Fabric Mods:", StringComparison.Ordinal))
                {
                    for (var j = i + 1; j < lines.Length; j++)
                    {
                        var m = CrashMod().Match(lines[j].TrimEnd('\r'));
                        if (!m.Success) break;
                        mods.Add((m.Groups["id"].Value, m.Groups["ver"].Value));
                    }
                    break;
                }
                continue;
            }
            if (FabricHeader().IsMatch(line))
            {
                for (var j = i + 1; j < lines.Length; j++)
                {
                    var l = lines[j].TrimEnd('\r');
                    if (FabricNested().IsMatch(l)) continue;
                    var m = FabricTop().Match(l);
                    if (!m.Success) break;
                    mods.Add((m.Groups["id"].Value, m.Groups["ver"].Value));
                }
                break;
            }
            var fm = ForgeFile().Match(line);
            if (fm.Success) forge.Add(Path.GetFileName(fm.Groups["file"].Value.Trim()));
        }
        return new Session(f.Path, File.GetLastWriteTimeUtc(f.Path), crash, mods, forge);
    }
}
