using Screensharing.Scanner.Analysis;
using Screensharing.Scanner.Discovery;
using Screensharing.Scanner.Engine;
using Screensharing.Scanner.Model;
using Screensharing.Scanner.Windows;

namespace Screensharing.Scanner.Modules;

/// <summary>Deleted evidence: the current user's Recycle Bin and the NTFS change journal.</summary>
public sealed class DeletedModule : IScanModule
{
    public string Key => "deleted";
    public string Name => "Deleted & recycled files";
    public string Activity => "Looking for recently deleted archives…";

    public string? SkipReason(ScanContext ctx) => ctx.Options.IncludeSystemArtifacts ? null : "System artifacts excluded by scan options";

    private readonly List<string> _index = [];
    private readonly List<string> _drives = [];
    private static readonly string[] Interesting = [".jar", ".exe", ".dll"];

    public int Plan(ScanContext ctx)
    {
        _index.Clear();
        _drives.Clear();
        var sid = System.Security.Principal.WindowsIdentity.GetCurrent().User?.Value;
        foreach (var d in DriveInfo.GetDrives().Where(d => d.DriveType == DriveType.Fixed && d.IsReady))
        {
            if (sid is not null) _index.AddRange(MinecraftLocator.SafeFiles(Path.Combine(d.Name, "$Recycle.Bin", sid), "$I*"));
            if (ctx.Elevated && d.DriveFormat.Equals("NTFS", StringComparison.OrdinalIgnoreCase)) _drives.Add(d.Name[..1]);
        }
        return _index.Count + _drives.Count * 20 + 1;
    }

    private static bool MinecraftRelated(string path)
    {
        var l = path.ToLowerInvariant();
        return l.Contains(@"\.minecraft\") || l.Contains(@"\mods\") || l.Contains("prismlauncher") || l.Contains("multimc") || l.Contains("curseforge")
               || l.Contains("modrinth") || l.Contains(".lunarclient") || l.Contains(".feather") || l.Contains("badlion") || l.Contains("tlauncher");
    }

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        var now = ctx.Now.UtcDateTime;
        foreach (var idx in _index)
        {
            ct.ThrowIfCancellationRequested();
            ctx.Advance();
            RecycledItem item;
            try { item = RecycleBinParser.Parse(idx, File.ReadAllBytes(idx)); ctx.Custody.Record("read-recycle-index", idx); }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidDataException) { continue; }
            var name = Path.GetFileName(item.OriginalPath);
            if (!Interesting.Any(x => name.EndsWith(x, StringComparison.OrdinalIgnoreCase)) || item.DeletedAt < now.AddDays(-30)) continue;

            var details = new Dictionary<string, string> { ["originalPath"] = item.OriginalPath, ["deletedAt"] = item.DeletedAt.ToString("u"), ["originalSize"] = item.Size.ToString(), ["recoverable"] = (item.ContentFile is not null).ToString() };
            var evidence = new List<Evidence> { ctx.FileEvidence(idx, "Recycle Bin index ($I)", details, EvidenceKind.RecycleBin) };
            if (item.ContentFile is not null) evidence.Add(ctx.FileEvidence(item.ContentFile, "Recycle Bin content ($R, recoverable copy)", null, EvidenceKind.RecycleBin));

            var matched = false;
            foreach (var r in ctx.Rules.OfKind(RuleKind.FileNameRegex).Where(r => r.IsMatch(name)))
            {
                matched = true;
                ctx.Report(r.Id, [idx],
                    $"\"{item.OriginalPath}\" was deleted {item.DeletedAt:u} and is in the Recycle Bin{(item.ContentFile is null ? "" : " (still recoverable)")}.",
                    "Parsing of $I index records in the current user's Recycle Bin.",
                    r.Description, "Deleting a file is not proof it was used; names are user-controlled.", evidence);
            }

            // A recoverable jar is analysed like any mod archive — cheat signatures survive deletion.
            if (item.ContentFile is not null && name.EndsWith(".jar", StringComparison.OrdinalIgnoreCase) && new FileInfo(item.ContentFile).Length < 100L * 1024 * 1024)
            {
                var rec = new ModRecord { Path = item.ContentFile, Launcher = "Recycle Bin", SizeBytes = new FileInfo(item.ContentFile).Length, Jar = JarAnalyzer.Analyze(item.ContentFile) };
                rec.Sha256 = ctx.Sha256(item.ContentFile);
                ctx.Custody.Record("read-archive", item.ContentFile);
                var before = ctx.Findings.Count;
                ModsModule.EvaluateArchive(ctx, rec, item.ContentFile, $"Recycle Bin copy of {item.OriginalPath}");
                ModsModule.DeferredChecks(ctx, rec);
                matched |= ctx.Findings.Count > before;
            }

            if (!matched && name.EndsWith(".jar", StringComparison.OrdinalIgnoreCase) && MinecraftRelated(item.OriginalPath) && item.DeletedAt >= now.AddDays(-7))
            {
                ctx.Report(Builtin.RecycledArchive, [idx],
                    $"\"{item.OriginalPath}\" was deleted from a Minecraft folder {item.DeletedAt:u}.",
                    "Parsing of $I index records in the current user's Recycle Bin.",
                    "Removing mods shortly before a screenshare can conceal what was used; the Recycle Bin keeps a record.",
                    "Users routinely delete outdated mods.", evidence);
            }
        }

        foreach (var drive in _drives)
        {
            ct.ThrowIfCancellationRequested();
            ctx.SetActivity($"Reading NTFS change journal of {drive}:…");
            Usn(ctx, drive, ct);
            ctx.Advance(20);
        }
        if (ctx.CurrentCategory is not null)
            ctx.CurrentCategory.Message = $"{_index.Count} Recycle Bin entries examined" + (ctx.Elevated ? $"; change journal read on {_drives.Count} volume(s)" : "; change journal skipped (requires administrator)");
        ctx.Advance();
        return Task.CompletedTask;
    }

    private static void Usn(ScanContext ctx, string drive, CancellationToken ct)
    {
        IEnumerable<UsnRecord> records;
        try
        {
            records = UsnJournal.Read(drive, ctx.Now.UtcDateTime.AddHours(-48),
                n => Interesting.Any(x => n.EndsWith(x, StringComparison.OrdinalIgnoreCase)), 1L << 30, ct);
            ctx.Custody.Record("read-usn-journal", $@"\\.\{drive}: (last 48 hours, .jar/.exe/.dll records)");
        }
        catch (Exception e) when (e is UnauthorizedAccessException or InvalidOperationException or IOException)
        {
            ctx.Custody.Record("read-usn-journal-failed", $"{drive}: {e.Message}");
            return;
        }
        var parentCache = new Dictionary<long, string?>();
        var reported = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var rec in records.Where(r => (r.Reason & (UsnJournal.REASON_FILE_DELETE | UsnJournal.REASON_RENAME_OLD_NAME)) != 0))
        {
            var action = (rec.Reason & UsnJournal.REASON_FILE_DELETE) != 0 ? "deleted" : "renamed";
            if (!parentCache.TryGetValue(rec.ParentRef, out var parent) && parentCache.Count < 2000)
                parentCache[rec.ParentRef] = parent = UsnJournal.ResolveDirectory(drive, rec.ParentRef);
            var full = parent is null ? $"{drive}:\\<unresolved>\\{rec.FileName}" : Path.Combine(parent, rec.FileName);
            if (!reported.Add(action + full)) continue;
            var ev = new Evidence
            {
                Kind = EvidenceKind.Usn, Source = $"NTFS change journal ({drive}:)", Reference = full, ModifiedTime = rec.Time,
                Details = new() { ["usn"] = rec.Usn.ToString(), ["reason"] = $"0x{rec.Reason:X8}", ["action"] = action, ["time"] = rec.Time.ToString("u") },
            };
            var matched = false;
            foreach (var r in ctx.Rules.OfKind(RuleKind.FileNameRegex).Where(r => r.IsMatch(rec.FileName)))
            {
                matched = true;
                ctx.Report(r.Id, ["usn", full, action],
                    $"\"{full}\" was {action} at {rec.Time:u} (NTFS change journal).",
                    "Read of the volume's USN change journal for archive/executable delete and rename records in the last 48 hours.",
                    r.Description, "File names are user-controlled; the journal does not keep content.", [ev]);
            }
            if (!matched && rec.FileName.EndsWith(".jar", StringComparison.OrdinalIgnoreCase) && parent is not null
                && parent.Split('\\').Any(s => s.Equals("mods", StringComparison.OrdinalIgnoreCase)))
            {
                ctx.Report(Builtin.UsnArchiveDeleted, ["usn", full, action],
                    $"\"{full}\" was {action} from a mods folder at {rec.Time:u}.",
                    "Read of the volume's USN change journal for .jar delete/rename records in mods folders during the last 48 hours.",
                    "Removing or renaming mods right before a screenshare is a concealment technique; the journal records it even after permanent deletion.",
                    "Mod updates replace files routinely.", [ev]);
            }
        }
    }
}
