using System.Collections.Concurrent;

namespace Screensharing.Scanner.Engine;

public enum FileRole { ModArchive, Archive, ResourcePack, ShaderPack, Config, Log, CrashReport, Script, Executable, NativeLibrary, Other }

/// <summary>A file (or pack folder) of the selected instance. <see cref="GamePath"/> is relative to the game directory with forward slashes.</summary>
public sealed record InstanceFile(string Path, string GamePath, long Size, FileRole Role, bool IsDirectory = false);

public enum InspectionStatus { Analyzed, NotApplicable, Unreadable, TooLarge, Encrypted, Corrupt, LinkNotFollowed }

public sealed record InspectionRecord(string Path, string Location, FileRole Role, InspectionStatus Status, string? Reason);

/// <summary>Counts what was examined, analysed and skipped — the numbers shown during and after the scan.</summary>
public sealed class InspectionLog
{
    private readonly ConcurrentDictionary<string, InspectionRecord> _records = new(StringComparer.OrdinalIgnoreCase);
    private int _examined;

    public int Examined => Volatile.Read(ref _examined);
    public int Analyzed => _records.Values.Count(r => r.Status == InspectionStatus.Analyzed);
    public int Skipped => _records.Values.Count(r => r.Status != InspectionStatus.Analyzed);
    /// <summary>Skipped because of a problem (not merely an irrelevant file type).</summary>
    public int UnableToInspect => _records.Values.Count(r => r.Status is not (InspectionStatus.Analyzed or InspectionStatus.NotApplicable));
    public IReadOnlyCollection<InspectionRecord> Records => _records.Values.ToList();

    internal void CountExamined(int n = 1) => Interlocked.Add(ref _examined, n);

    /// <summary>Records the final status of a file. A later Analyzed never hides an earlier problem with the same file.</summary>
    public void Record(InspectionRecord r) =>
        _records.AddOrUpdate(r.Path, r, (_, old) => old.Status is not (InspectionStatus.Analyzed or InspectionStatus.NotApplicable) && r.Status == InspectionStatus.Analyzed ? old : r);

    public Dictionary<string, object?> Summary(int maxListed = 300)
    {
        var problems = _records.Values.Where(r => r.Status is not (InspectionStatus.Analyzed or InspectionStatus.NotApplicable)).OrderBy(r => r.Location).ToList();
        return new()
        {
            ["examined"] = Examined,
            ["analyzed"] = Analyzed,
            ["skipped"] = Skipped,
            ["unableToInspect"] = problems.Count,
            ["byStatus"] = _records.Values.GroupBy(r => r.Status).ToDictionary(g => g.Key.ToString(), g => g.Count()),
            ["uninspected"] = problems.Take(maxListed).Select(r => new Dictionary<string, object?> { ["location"] = r.Location, ["status"] = r.Status.ToString(), ["reason"] = r.Reason }).ToList(),
        };
    }
}

/// <summary>
/// Enumerates the files of the selected instance. The walk never leaves the scope: links to other places are not
/// followed (except the content folders the game itself loads from, which are reported), launcher-shared folders
/// (versions, libraries, assets) and bulky irrelevant data (worlds, screenshots, caches) are excluded and listed as such.
/// </summary>
public static class InstanceFiles
{
    public const int MaxEntries = 100_000;
    private const int MaxDepth = 10;

    /// <summary>Top-level folders of the game directory that are not walked, with the reason shown in the report.</summary>
    public static readonly IReadOnlyDictionary<string, string> Excluded = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        ["saves"] = "world data (not loaded code)",
        ["screenshots"] = "images",
        ["assets"] = "launcher-shared vanilla assets",
        ["versions"] = "launcher-shared game versions (only the running version is verified)",
        ["libraries"] = "launcher-shared libraries (only libraries on the running class path are verified)",
        ["runtime"] = "bundled Java runtimes",
        ["backups"] = "world backups",
        ["schematics"] = "building schematics",
        ["replay_recordings"] = "replay recordings",
        [".replay_cache"] = "replay cache",
        ["webcache"] = "launcher web cache",
        ["webcache2"] = "launcher web cache",
        [".cache"] = "cache",
        ["cache"] = "cache",
        [".fabric"] = "Fabric's generated cache of remapped mods (the mods themselves are examined)",
        ["xaero"] = "map data",
        ["XaeroWaypoints"] = "map data",
        ["XaeroWorldMap"] = "map data",
        ["journeymap"] = "map data",
        ["distant_horizons_server_data"] = "terrain cache",
        ["Distant_Horizons"] = "terrain cache",
        [".mixin.out"] = "mixin debug export",
    };

    /// <summary>Folders whose links are followed because the game loads content from them.</summary>
    private static readonly HashSet<string> FollowedLinks = new(StringComparer.OrdinalIgnoreCase) { "mods", "config", "resourcepacks", "shaderpacks" };

    private static readonly HashSet<string> TextExtensions = new(StringComparer.OrdinalIgnoreCase)
        { ".json", ".json5", ".jsonc", ".toml", ".txt", ".cfg", ".conf", ".properties", ".yml", ".yaml", ".ini", ".xml", ".snbt", ".lang", ".csv", ".kts" };
    private static readonly HashSet<string> ScriptExtensions = new(StringComparer.OrdinalIgnoreCase)
        { ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".sh", ".ahk", ".py", ".lua", ".au3" };
    private static readonly HashSet<string> ExecutableExtensions = new(StringComparer.OrdinalIgnoreCase)
        { ".exe", ".dll", ".sys", ".scr", ".com", ".cpl", ".ocx", ".drv" };

    public sealed record Linked(string Folder, string Target);

    public static (List<InstanceFile> Files, List<string> ExcludedNotes, List<Linked> Links, bool Truncated) Discover(ScanContext ctx, CancellationToken ct)
    {
        var inst = ctx.Instance;
        var files = new List<InstanceFile>();
        var excluded = new List<string>();
        var links = new List<Linked>();
        var truncated = false;
        var game = ScanScope.Normalize(inst.GameDirectory);

        // Instance metadata next to the game directory (Prism/MultiMC instance.cfg, mmc-pack.json, natives).
        var root = ScanScope.Normalize(inst.InstanceRoot);
        if (!root.Equals(game, StringComparison.OrdinalIgnoreCase))
        {
            foreach (var f in ctx.Fs.Files(root)) files.Add(Classify(ctx, f, "../" + Path.GetFileName(f), new FileInfo(f).Length, inGame: false));
            foreach (var d in ctx.Fs.Directories(root))
            {
                if (ScanScope.Normalize(d).Equals(game, StringComparison.OrdinalIgnoreCase)) continue;
                Walk(ctx, d, "../" + Path.GetFileName(d), 1, files, excluded, links, ref truncated, ct, inGame: false);
            }
        }
        Walk(ctx, game, "", 0, files, excluded, links, ref truncated, ct, inGame: true);
        ctx.Inspection.CountExamined(files.Count);
        return (files, excluded, links, truncated);
    }

    private static void Walk(ScanContext ctx, string dir, string rel, int depth, List<InstanceFile> files, List<string> excluded, List<Linked> links, ref bool truncated, CancellationToken ct, bool inGame)
    {
        ct.ThrowIfCancellationRequested();
        if (files.Count >= MaxEntries) { truncated = true; return; }
        var top = rel.Split('/')[0];

        // Pack folders are inspected as a unit by the packs module.
        if (inGame && depth == 1 && (top.Equals("resourcepacks", StringComparison.OrdinalIgnoreCase) || top.Equals("shaderpacks", StringComparison.OrdinalIgnoreCase)))
        {
            var role = top.Equals("resourcepacks", StringComparison.OrdinalIgnoreCase) ? FileRole.ResourcePack : FileRole.ShaderPack;
            foreach (var f in ctx.Fs.Files(dir)) files.Add(new InstanceFile(f, rel + "/" + Path.GetFileName(f), SafeLength(f), Path.GetExtension(f).Equals(".txt", StringComparison.OrdinalIgnoreCase) ? FileRole.Config : role));
            foreach (var d in ctx.Fs.Directories(dir))
            {
                if (IsOutsideLink(ctx, d, out _)) { NotFollowed(ctx, d, rel + "/" + Path.GetFileName(d)); continue; }
                files.Add(new InstanceFile(d, rel + "/" + Path.GetFileName(d) + "/", 0, role, IsDirectory: true));
            }
            return;
        }

        foreach (var f in ctx.Fs.Files(dir))
        {
            if (files.Count >= MaxEntries) { truncated = true; return; }
            var frel = rel.Length == 0 ? Path.GetFileName(f) : rel + "/" + Path.GetFileName(f);
            if (IsOutsideLink(ctx, f, out var target)) { NotFollowed(ctx, f, frel, target); continue; }
            files.Add(Classify(ctx, f, frel, SafeLength(f), inGame));
        }
        if (depth >= MaxDepth) { excluded.Add($"{rel}/ (deeper than {MaxDepth} levels)"); return; }
        foreach (var d in ctx.Fs.Directories(dir))
        {
            var name = Path.GetFileName(d);
            var drel = rel.Length == 0 ? name : rel + "/" + name;
            if (inGame && depth == 0 && Excluded.TryGetValue(name, out var why)) { excluded.Add($"{drel}/ — {why}"); continue; }
            if (IsOutsideLink(ctx, d, out var target))
            {
                if (inGame && depth == 0 && FollowedLinks.Contains(name) && target is not null && Directory.Exists(target))
                {
                    // The game loads this folder's content, so it belongs to the running instance.
                    ctx.Scope.AddRoot(target, name);
                    ctx.Custody.Record("follow-content-link", $"{d} -> {target}");
                    links.Add(new Linked(name, target));
                    Walk(ctx, target, drel, depth + 1, files, excluded, links, ref truncated, ct, inGame);
                }
                else NotFollowed(ctx, d, drel + "/", target);
                continue;
            }
            Walk(ctx, d, drel, depth + 1, files, excluded, links, ref truncated, ct, inGame);
        }
    }

    private static long SafeLength(string f)
    {
        try { return new FileInfo(f).Length; } catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return -1; }
    }

    private static void NotFollowed(ScanContext ctx, string path, string rel, string? target = null)
    {
        ctx.Inspection.CountExamined();
        ctx.Inspection.Record(new InspectionRecord(path, rel, FileRole.Other, InspectionStatus.LinkNotFollowed,
            $"Link to a location outside the instance{(target is null ? "" : $" ({target})")}; not followed."));
    }

    private static bool IsOutsideLink(ScanContext ctx, string path, out string? target)
    {
        target = null;
        try
        {
            FileSystemInfo fsi = Directory.Exists(path) ? new DirectoryInfo(path) : new FileInfo(path);
            if (!fsi.Attributes.HasFlag(FileAttributes.ReparsePoint)) return false;
            var t = fsi.ResolveLinkTarget(true);
            if (t is null) return false; // reparse point that is not a link (e.g. OneDrive placeholder)
            target = t.FullName;
            return !ctx.Scope.Contains(t.FullName);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException) { return false; }
    }

    private static InstanceFile Classify(ScanContext ctx, string path, string rel, long size, bool inGame)
    {
        var name = Path.GetFileName(path);
        var ext = Path.GetExtension(name);
        var lower = rel.ToLowerInvariant();
        var top = lower.Split('/')[0];
        // Content first: executables and archives are recognised by their magic bytes whatever their extension.
        var magic = Magic(ctx, path, size);
        FileRole role;
        if (inGame && top == "mods" && (ext.Equals(".jar", StringComparison.OrdinalIgnoreCase) || name.EndsWith(".disabled", StringComparison.OrdinalIgnoreCase)))
            role = FileRole.ModArchive;
        else if (lower.Contains("/natives/") || lower.StartsWith("natives/") || lower.StartsWith("../natives/"))
            role = FileRole.NativeLibrary;
        else if (magic == FileRole.Executable || ExecutableExtensions.Contains(ext))
            role = FileRole.Executable;
        else if (magic == FileRole.Archive)
            role = inGame && top == "mods" ? FileRole.ModArchive : FileRole.Archive;
        else if (inGame && top == "logs" && (lower.EndsWith(".log") || lower.EndsWith(".log.gz") || lower.EndsWith(".txt")))
            role = FileRole.Log;
        else if (inGame && top == "crash-reports" && ext.Equals(".txt", StringComparison.OrdinalIgnoreCase))
            role = FileRole.CrashReport;
        else if (ScriptExtensions.Contains(ext))
            role = FileRole.Script;
        else if (TextExtensions.Contains(ext))
            role = FileRole.Config;
        else if (ext.Equals(".jar", StringComparison.OrdinalIgnoreCase) || ext.Equals(".zip", StringComparison.OrdinalIgnoreCase))
            role = inGame && top == "mods" ? FileRole.ModArchive : FileRole.Archive;
        else
            role = FileRole.Other;
        return new InstanceFile(path, rel, size, role);
    }

    /// <summary>Magic-byte sniffing: "MZ" = executable, "PK" = archive; anything else returns Other.</summary>
    private static FileRole Magic(ScanContext ctx, string path, long size)
    {
        if (size < 4) return FileRole.Other;
        try
        {
            using var fs = ctx.OpenRead(path);
            Span<byte> head = stackalloc byte[4];
            if (fs.Read(head) < 4) return FileRole.Other;
            if (head[0] == 'M' && head[1] == 'Z') return FileRole.Executable;
            if (head[0] == 'P' && head[1] == 'K' && head[2] == 3 && head[3] == 4) return FileRole.Archive;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
        return FileRole.Other;
    }
}
