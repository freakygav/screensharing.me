using System.IO.Compression;
using System.Text.RegularExpressions;
using Screensharing.Scanner.Discovery;
using Screensharing.Scanner.Engine;
using Screensharing.Scanner.Model;

namespace Screensharing.Scanner.Modules;

/// <summary>Recovers the mod list of previous game sessions from latest.log and archived logs.</summary>
public sealed partial class LogsModule : IScanModule
{
    public string Key => "logs";
    public string Name => "Game logs";
    public string Activity => "Analyzing game session logs…";
    public string? SkipReason(ScanContext ctx) => null;

    private const int MaxLogs = 60;
    private static readonly TimeSpan Window = TimeSpan.FromDays(14);
    private readonly List<(Installation Inst, string Path)> _logs = [];

    // Fabric:  "[main/INFO]: Loading 57 mods:" then "\t- modid version"
    [GeneratedRegex(@"Loading \d+ mods:", RegexOptions.CultureInvariant)] private static partial Regex FabricHeader();
    [GeneratedRegex(@"^\s*-\s+(?<id>[a-z0-9_\-.]+)\s+(?<ver>\S+)", RegexOptions.CultureInvariant)] private static partial Regex FabricTop();
    [GeneratedRegex(@"^\s*\|--\s+(?<id>[a-z0-9_\-.]+)\s+(?<ver>\S+)", RegexOptions.CultureInvariant)] private static partial Regex FabricNested();
    // Forge/NeoForge: "Found mod file sodium.jar of type MOD with provider ..."
    [GeneratedRegex(@"Found mod file (?<file>.+?\.jar) of type", RegexOptions.CultureInvariant)] private static partial Regex ForgeFile();

    public int Plan(ScanContext ctx)
    {
        _logs.Clear();
        var cutoff = ctx.Now - Window;
        foreach (var inst in ctx.Installations)
            foreach (var dir in inst.LogDirectories)
                foreach (var f in MinecraftLocator.SafeFiles(dir).Where(f => f.EndsWith(".log", StringComparison.OrdinalIgnoreCase) || f.EndsWith(".log.gz", StringComparison.OrdinalIgnoreCase))
                             .Where(f => File.GetLastWriteTimeUtc(f) >= cutoff.UtcDateTime)
                             .OrderByDescending(File.GetLastWriteTimeUtc).Take(MaxLogs))
                    _logs.Add((inst, f));
        return _logs.Count + 1;
    }

    private sealed record Session(Installation Inst, string Log, DateTime Time, List<(string Id, string Version)> Mods, List<string> ForgeFiles);

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        var sessions = new List<Session>();
        foreach (var (inst, path) in _logs)
        {
            ct.ThrowIfCancellationRequested();
            ctx.SetActivity($"Analyzing game session logs… {Path.GetFileName(path)}");
            try { sessions.Add(Parse(inst, path, ReadLog(path))); ctx.Custody.Record("read-log", path); }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidDataException) { }
            ctx.Advance();
        }

        var presentIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var m in ctx.Mods.Where(m => m.Jar is not null))
            foreach (var md in m.Jar!.AllMetadata()) presentIds.Add(md.Id);
        var presentFiles = new HashSet<string>(ctx.Mods.Select(m => m.FileName), StringComparer.OrdinalIgnoreCase);

        foreach (var s in sessions)
        {
            foreach (var (id, ver) in s.Mods)
            {
                var ev = new Evidence
                {
                    Kind = EvidenceKind.Log, Source = "Game log (Fabric mod list)", Reference = s.Log,
                    Sha256 = ctx.Sha256(s.Log), ModifiedTime = s.Time,
                    Details = new() { ["modId"] = id, ["version"] = ver, ["sessionLogWritten"] = s.Time.ToString("u") },
                };
                if (ctx.Rules.ModIdRule(id) is { } rule && rule.SeverityValue <= Severity.High)
                {
                    ctx.Report(Builtin.LoggedCheatMod, [s.Log, id],
                        $"The game log written {s.Time:u} lists \"{id}\" {ver} ({rule.Family ?? rule.Name}) among the mods loaded in that session" + (presentIds.Contains(id) ? "." : ". The mod is no longer present in any examined mods folder."),
                        "Parsing of the Fabric loader's \"Loading N mods\" list in latest.log and archived *.log.gz files from the last 14 days.",
                        "The log is written by the game itself while it starts, so it shows the client was actually loaded — not merely downloaded.",
                        "Log files can be copied from another computer, which is uncommon.",
                        [ev], name: $"{rule.Family ?? rule.Name} loaded in a recent game session");
                }
                else if (!presentIds.Contains(id) && !IsPlatformId(id) && ctx.Rules.KnownMod(id) is null)
                {
                    ctx.Report(Builtin.LoggedModMissing, [s.Inst.GameDirectory, id],
                        $"\"{id}\" {ver} was loaded in the session logged {s.Time:u} ({s.Inst.Launcher}) but no archive declaring this mod id exists now.",
                        "Comparison of mod ids recorded in game logs with mod ids declared by archives currently on disk.",
                        "Removing a mod after playing and before a screenshare is a common concealment technique; the log preserves what was loaded.",
                        "Mods are routinely removed or replaced, and logs may belong to an instance whose mods were since updated.",
                        [ev]);
                }
            }
            foreach (var file in s.ForgeFiles.Where(f => !presentFiles.Contains(f)))
            {
                foreach (var r in ctx.Rules.OfKind(RuleKind.FileNameRegex).Where(r => r.IsMatch(file)))
                    ctx.Report(r.Id, [s.Log, file],
                        $"The Forge/NeoForge log written {s.Time:u} shows the mod file \"{file}\" being loaded; it no longer exists in the mods folder.",
                        "Parsing of \"Found mod file\" lines in Forge/NeoForge logs.",
                        r.Description,
                        "File names are user-controlled.",
                        [new Evidence { Kind = EvidenceKind.Log, Source = "Game log (Forge mod discovery)", Reference = s.Log, Sha256 = ctx.Sha256(s.Log), ModifiedTime = s.Time, Details = new() { ["fileName"] = file } }]);
            }
        }

        // Mods folder changed after the most recent session.
        foreach (var inst in ctx.Installations)
        {
            var latest = sessions.Where(s => s.Inst == inst).Select(s => (DateTime?)s.Time).Max();
            if (latest is null || latest < (ctx.Now - TimeSpan.FromDays(7)).UtcDateTime) continue;
            foreach (var m in ctx.Mods.Where(m => m.Launcher == inst.Launcher))
            {
                var fi = new FileInfo(m.Path);
                var changed = new[] { fi.CreationTimeUtc, fi.LastWriteTimeUtc }.Max();
                if (changed <= latest.Value.AddMinutes(1)) continue;
                ctx.Report(Builtin.ModChangedAfterSession, [m.Path],
                    $"\"{m.FileName}\" was created or modified {changed:u}, after the last game log was written ({latest:u}).",
                    "Comparison of NTFS creation/modification times in the mods folder with the newest game log timestamp.",
                    "Swapping mods between the last play session and the screenshare can hide what was actually used.",
                    "Installing or updating mods between sessions is normal; copying files resets creation time.",
                    [ctx.FileEvidence(m.Path, "Mod archive", new() { ["lastSessionLog"] = latest.Value.ToString("u") })]);
            }
        }

        ctx.Statistics["logsParsed"] = sessions.Count;
        if (ctx.CurrentCategory is not null)
            ctx.CurrentCategory.Message = sessions.Count == 0 ? "No game logs from the last 14 days" : $"{sessions.Count} logs, {sessions.Count(s => s.Mods.Count > 0 || s.ForgeFiles.Count > 0)} with a mod list";
        ctx.Advance();
        return Task.CompletedTask;
    }

    private static bool IsPlatformId(string id) =>
        id is "java" or "minecraft" or "fabricloader" or "mixinextras" or "quilt_loader" || id.StartsWith("fabric-", StringComparison.Ordinal) || id.StartsWith("fabric_", StringComparison.Ordinal);

    internal static string ReadLog(string path)
    {
        using var fs = ScanContext.OpenRead(path);
        Stream s = path.EndsWith(".gz", StringComparison.OrdinalIgnoreCase) ? new GZipStream(fs, CompressionMode.Decompress) : fs;
        using var r = new StreamReader(s);
        var buf = new char[8 * 1024 * 1024]; // logs can be large; the mod list is near the top
        var n = r.ReadBlock(buf, 0, buf.Length);
        return new string(buf, 0, n);
    }

    private static Session Parse(Installation inst, string path, string text)
    {
        var mods = new List<(string, string)>();
        var forge = new List<string>();
        var lines = text.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            if (FabricHeader().IsMatch(lines[i]))
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
            var fm = ForgeFile().Match(lines[i]);
            if (fm.Success) forge.Add(Path.GetFileName(fm.Groups["file"].Value.Trim()));
        }
        return new Session(inst, path, File.GetLastWriteTimeUtc(path), mods, forge);
    }
}
