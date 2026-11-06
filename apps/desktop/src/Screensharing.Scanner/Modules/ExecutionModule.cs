using Microsoft.Win32;
using Screensharing.Scanner.Discovery;
using Screensharing.Scanner.Engine;
using Screensharing.Scanner.Model;
using Screensharing.Scanner.Windows;

namespace Screensharing.Scanner.Modules;

/// <summary>Execution artifacts: Windows Prefetch and Background Activity Moderator (BAM).</summary>
public sealed class ExecutionModule : IScanModule
{
    public string Key => "execution";
    public string Name => "Execution artifacts (Prefetch, BAM)";
    public string Activity => "Analyzing relevant application artifacts…";

    public string? SkipReason(ScanContext ctx) =>
        !ctx.Options.IncludeSystemArtifacts ? "System artifacts excluded by scan options"
        : !ctx.Elevated ? "Requires administrator rights (Prefetch and BAM are readable only by administrators)" : null;

    private readonly List<string> _pf = [];
    internal string PrefetchDirectory { get; init; } = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");

    public int Plan(ScanContext ctx)
    {
        _pf.Clear();
        _pf.AddRange(MinecraftLocator.SafeFiles(PrefetchDirectory, "*.pf"));
        return _pf.Count + 1;
    }

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        var volumes = VolumeMap();
        var parsed = 0;
        foreach (var file in _pf)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                var info = PrefetchParser.Parse(File.ReadAllBytes(file));
                ctx.Custody.Record("read-prefetch", file);
                parsed++;
                Evaluate(ctx, file, info, volumes);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidDataException or ArgumentException) { }
            ctx.Advance();
        }
        Bam(ctx);
        ctx.Advance();
        ctx.Statistics["prefetchParsed"] = parsed;
        if (ctx.CurrentCategory is not null) ctx.CurrentCategory.Message = $"{parsed} Prefetch files parsed; BAM examined";
        return Task.CompletedTask;
    }

    internal static Dictionary<uint, string> VolumeMap()
    {
        var map = new Dictionary<uint, string>();
        foreach (var d in DriveInfo.GetDrives().Where(d => d.DriveType is DriveType.Fixed or DriveType.Removable && d.IsReady))
        {
            unsafe
            {
                if (Native.GetVolumeInformation(d.Name, null, 0, out var serial, out _, out _, null, 0)) map[serial] = d.Name.TrimEnd('\\');
            }
        }
        return map;
    }

    internal static string ResolvePath(string pfPath, IReadOnlyList<(string Device, uint Serial)> pfVolumes, Dictionary<uint, string> volumes)
    {
        foreach (var (dev, serial) in pfVolumes)
        {
            if (dev.Length == 0 || !pfPath.StartsWith(dev, StringComparison.OrdinalIgnoreCase)) continue;
            if (volumes.TryGetValue(serial, out var letter)) return letter + pfPath[dev.Length..];
        }
        // \VOLUME{xxxxxxxxxxxxxxxx-SERIAL}\...
        var m = System.Text.RegularExpressions.Regex.Match(pfPath, @"^\\VOLUME\{[0-9a-f]+-(?<s>[0-9a-f]{8})\}", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        if (m.Success && volumes.TryGetValue(Convert.ToUInt32(m.Groups["s"].Value, 16), out var l)) return l + pfPath[m.Length..];
        return pfPath;
    }

    private static Evidence PfEvidence(ScanContext ctx, string file, PrefetchInfo info, Dictionary<string, string>? extra = null)
    {
        var details = new Dictionary<string, string>(extra ?? [])
        {
            ["executable"] = info.ExecutableName,
            ["runCount"] = info.RunCount.ToString(),
            ["lastRun"] = info.LastRunTimes.Count > 0 ? info.LastRunTimes.Max().ToString("u") : "",
            ["previousRuns"] = string.Join(", ", info.LastRunTimes.OrderDescending().Skip(1).Select(t => t.ToString("u"))),
            ["prefetchVersion"] = info.Version.ToString(),
        };
        var ev = ctx.FileEvidence(file, "Windows Prefetch", details, EvidenceKind.Prefetch);
        return ev;
    }

    private static void Evaluate(ScanContext ctx, string file, PrefetchInfo info, Dictionary<uint, string> volumes)
    {
        var lastRun = info.LastRunTimes.Count > 0 ? info.LastRunTimes.Max() : (DateTime?)null;
        foreach (var r in ctx.Rules.OfKind(RuleKind.ExecutableRegex).Concat(ctx.Rules.OfKind(RuleKind.FileNameRegex)))
        {
            if (!r.IsMatch(info.ExecutableName)) continue;
            ctx.Report(r.Id, [file],
                $"{info.ExecutableName} was executed {info.RunCount} time(s); last run {lastRun:u}.",
                "Parsing of Windows Prefetch (SCCA, MAM-compressed) execution records.",
                r.Description,
                "Prefetch records that a program with this name ran, not what it did. Names can be changed.",
                [PfEvidence(ctx, file, info)], name: $"{r.Name}: {info.ExecutableName}");
        }

        if (info.ExecutableName is not ("JAVAW.EXE" or "JAVA.EXE") || lastRun is null || lastRun < (ctx.Now - TimeSpan.FromDays(14)).UtcDateTime) return;
        foreach (var raw in info.ReferencedFiles.Where(f => f.EndsWith(".JAR", StringComparison.OrdinalIgnoreCase)))
        {
            var path = ResolvePath(raw, info.Volumes, volumes);
            var name = Path.GetFileName(path);
            var matched = false;
            foreach (var r in ctx.Rules.OfKind(RuleKind.FileNameRegex).Where(r => r.IsMatch(name)))
            {
                matched = true;
                ctx.Report(r.Id, [file, path],
                    $"Java ({info.ExecutableName}) opened \"{path}\" during a run in the last 14 days (last run {lastRun:u}){(File.Exists(path) ? "" : "; the file no longer exists")}.",
                    "Referenced-file list of the Java Prefetch record (files touched in the first seconds of execution).",
                    r.Description, "File names are user-controlled.",
                    [PfEvidence(ctx, file, info, new() { ["referencedJar"] = path, ["exists"] = File.Exists(path).ToString() })]);
            }
            if (matched || File.Exists(path)) continue;
            var lower = path.ToLowerInvariant();
            if (lower.Contains(@"\libraries\") || lower.Contains(@"\versions\") || lower.Contains(@"\.lunarclient\") || lower.Contains(@"\runtime\") || lower.Contains(@"\jre\") || lower.Contains(@"\.feather\") || lower.Contains(@"\badlion client\")) continue;
            ctx.Report(Builtin.PrefetchJarMissing, [file, path],
                $"Java ({info.ExecutableName}) opened \"{path}\" (last run {lastRun:u}) but the file no longer exists and is outside launcher library folders.",
                "Referenced-file list of the Java Prefetch record compared with the current file system.",
                "Ghost clients are often run from a jar that is deleted right after use; Prefetch preserves the reference.",
                "Installers and launchers run jars from temporary locations and delete them afterwards.",
                [PfEvidence(ctx, file, info, new() { ["referencedJar"] = path })]);
        }
    }

    private static void Bam(ScanContext ctx)
    {
        var sid = System.Security.Principal.WindowsIdentity.GetCurrent().User?.Value;
        if (sid is null) return;
        foreach (var root in new[] { @"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\", @"SYSTEM\CurrentControlSet\Services\bam\UserSettings\" })
        {
            try
            {
                using var k = Registry.LocalMachine.OpenSubKey(root + sid);
                if (k is null) continue;
                ctx.Custody.Record("read-registry", @"HKLM\" + root + sid);
                foreach (var name in k.GetValueNames())
                {
                    if (k.GetValue(name) is not byte[] data || data.Length < 8) continue;
                    var exeName = Path.GetFileName(name);
                    var when = DateTime.FromFileTimeUtc(BitConverter.ToInt64(data, 0));
                    foreach (var r in ctx.Rules.OfKind(RuleKind.ExecutableRegex).Concat(ctx.Rules.OfKind(RuleKind.FileNameRegex)))
                    {
                        if (!r.IsMatch(exeName)) continue;
                        ctx.Report(r.Id, ["bam", name],
                            $"BAM records that {name} last ran {when:u}.",
                            "Read of the Background Activity Moderator registry key for the current user.",
                            r.Description, "BAM records execution by path; names can be changed and entries expire after about a week.",
                            [new Evidence { Kind = EvidenceKind.Bam, Source = "Background Activity Moderator", Reference = $@"HKLM\{root}{sid}\{name}", ModifiedTime = when, Details = new() { ["path"] = name, ["lastExecution"] = when.ToString("u") } }],
                            name: $"{r.Name}: {exeName}");
                    }
                }
            }
            catch (Exception e) when (e is System.Security.SecurityException or UnauthorizedAccessException or IOException) { }
        }
    }
}
