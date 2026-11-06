using Screensharing.Scanner.Analysis;
using Screensharing.Scanner.Engine;
using Screensharing.Scanner.Model;
using Screensharing.Scanner.Windows;

namespace Screensharing.Scanner.Modules;

/// <summary>Everything else in the instance: cheat-client artifact paths, configuration files, scripts and executables.</summary>
public sealed class FilesModule : IScanModule
{
    public string Key => "files";
    public string Name => "Configuration, scripts & executables";
    public string Activity => "Examining instance files…";
    public string? SkipReason(ScanContext ctx) => null;

    private readonly List<InstanceFile> _content = [];

    public int Plan(ScanContext ctx)
    {
        _content.Clear();
        _content.AddRange(ctx.FilesOf(FileRole.Config, FileRole.Script, FileRole.Executable, FileRole.NativeLibrary, FileRole.Other));
        return _content.Count + 1;
    }

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        InstancePaths(ctx);
        foreach (var link in ctx.Links)
        {
            ctx.Report(Builtin.LinkedFolder, [link.Folder, link.Target],
                $"The instance folder \"{link.Folder}\" is a link to {link.Target}. The game loads its content from there, so it was inspected as part of the instance.",
                "Reparse-point inspection of the instance's content folders during file discovery.",
                "Keeping mods behind a link hides them from a quick look at the instance folder and lets them be swapped by renaming one directory.",
                "Players sometimes share one folder between several instances.",
                [new Evidence { Kind = EvidenceKind.File, Source = "Instance folder link", Reference = Path.Combine(ctx.Instance.GameDirectory, link.Folder), Details = new() { ["target"] = link.Target } }],
                signature: "folder link", location: link.Folder + "/");
        }

        ctx.Advance();
        int configs = 0, scripts = 0, executables = 0;
        foreach (var f in _content)
        {
            ct.ThrowIfCancellationRequested();
            ctx.SetActivity($"Examining instance files… {f.GamePath}");
            switch (f.Role)
            {
                case FileRole.Config: Text(ctx, f, SignatureScope.Config); configs++; break;
                case FileRole.Script: Text(ctx, f, SignatureScope.Script); scripts++; break;
                case FileRole.Executable: Executable(ctx, f); executables++; break;
                case FileRole.NativeLibrary: ctx.NotApplicable(f.Path, f.Role, "native library folder of the launcher (game natives)"); break;
                default: ctx.NotApplicable(f.Path, f.Role, "file type not analysed"); break;
            }
            ctx.Advance();
        }
        ctx.Statistics["configFiles"] = configs;
        ctx.Statistics["scripts"] = scripts;
        ctx.Statistics["executables"] = executables;
        if (ctx.CurrentCategory is not null)
            ctx.CurrentCategory.Message = $"{configs:N0} configuration files, {scripts:N0} scripts, {executables:N0} executables";
        return Task.CompletedTask;
    }

    /// <summary>INSTANCE_PATH_REGEX rules over every discovered path and its parent folders.</summary>
    private static void InstancePaths(ScanContext ctx)
    {
        var rules = ctx.Rules.OfKind(RuleKind.InstancePathRegex).ToList();
        if (rules.Count == 0) return;
        var paths = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var f in ctx.Files.Where(f => !f.GamePath.StartsWith("../", StringComparison.Ordinal)))
        {
            paths.Add(f.GamePath);
            var p = f.GamePath.TrimEnd('/');
            for (var i = p.LastIndexOf('/'); i > 0; i = p.LastIndexOf('/', i - 1)) paths.Add(p[..(i + 1)]);
        }
        // Empty folders created by a client still count.
        foreach (var d in ctx.Fs.Directories(ctx.Instance.GameDirectory)) paths.Add(Path.GetFileName(d) + "/");
        foreach (var r in rules)
        {
            var hits = paths.Where(r.IsMatch).ToList();
            if (hits.Count == 0) continue;
            var first = hits[0];
            var full = Path.Combine(ctx.Instance.GameDirectory, first.TrimEnd('/').Replace('/', '\\'));
            var isFile = File.Exists(full) && ctx.Scope.Contains(full);
            var ev = new List<Evidence>
            {
                isFile ? ctx.FileEvidence(full, "Instance artifact") : new Evidence
                {
                    Kind = EvidenceKind.File, Source = "Instance artifact folder", Reference = full,
                    CreatedTime = Directory.Exists(full) ? Directory.GetCreationTimeUtc(full) : null,
                    ModifiedTime = Directory.Exists(full) ? Directory.GetLastWriteTimeUtc(full) : null,
                    Details = new() { ["matchingPaths"] = string.Join(", ", hits.Take(10)), ["count"] = hits.Count.ToString() },
                },
            };
            ctx.Report(r.Id, [ctx.Instance.GameDirectory, r.Id],
                $"The instance contains \"{first}\"{(hits.Count > 1 ? $" and {hits.Count - 1} more matching path(s)" : "")}. {r.Description}",
                "Every path of the instance was compared with the instance-artifact database (files and folders that clients create in the game directory).",
                r.Description,
                "The folder can be left over from a client that was used once and removed, or copied with an instance from elsewhere.",
                ev, family: r.Family, signature: $"path \"{first}\"", location: first);
        }
    }

    private static void Text(ScanContext ctx, InstanceFile f, string scope)
    {
        if (!ctx.Signatures.Has(scope)) { ctx.Analyzed(f.Path, f.Role); return; }
        if (f.Size > ctx.Options.MaxTextBytes) { ctx.Uninspectable(f.Path, f.Role, InspectionStatus.TooLarge, $"{f.Size / (1024 * 1024):N0} MiB is above the text limit", report: f.Role == FileRole.Script); return; }
        byte[] data;
        try { using var fs = ctx.OpenRead(f.Path); data = new byte[fs.Length]; fs.ReadExactly(data); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { ctx.Uninspectable(f.Path, f.Role, InspectionStatus.Unreadable, e.Message, report: f.Role == FileRole.Script); return; }
        ctx.Custody.Record(scope == SignatureScope.Script ? "read-script" : "read-config", f.Path);
        var hits = ctx.Signatures.Match(scope, data, f.GamePath);
        ReportStringHits(ctx, f, hits, scope == SignatureScope.Script ? "Script" : "Configuration file");
        ctx.Analyzed(f.Path, f.Role);
    }

    private static void ReportStringHits(ScanContext ctx, InstanceFile f, List<SignatureHit> hits, string source)
    {
        if (hits.Count == 0) return;
        var indicators = hits.Select(h => new Indicator(h.Rule,
            new Evidence { Kind = EvidenceKind.Config, Source = source, Reference = f.Path, Details = new() { ["string"] = h.Rule.Pattern, ["excerpt"] = h.Excerpt ?? "" } },
            $"contains \"{h.Rule.Pattern}\"", $"string \"{h.Rule.Pattern}\"")).ToList();
        foreach (var g in EvidenceScoring.Score(indicators).Where(g => g.Report && g.Tier != EvidenceTier.Inconclusive))
        {
            var p = g.Primary;
            ctx.Report(p.Id, [f.Path, g.Family],
                $"{source} \"{f.GamePath}\" {string.Join("; ", g.Indicators.Select(i => i.What).Take(6))}.",
                $"String-signature matching of the file content ({g.Indicators.Count} signature(s), score {g.Score}/100).",
                p.Description, "Configuration and script files can mention client names without the client being present.",
                [ctx.FileEvidence(f.Path, source), .. g.Indicators.Select(i => i.Evidence)],
                tier: g.Tier, confidence: g.Confidence, signature: string.Join(" + ", g.Indicators.Select(i => i.Signature).Take(4)), location: f.GamePath);
        }
    }

    private static void Executable(ScanContext ctx, InstanceFile f)
    {
        if (f.Size > ctx.Options.MaxBinaryBytes) { ctx.Uninspectable(f.Path, f.Role, InspectionStatus.TooLarge, $"{f.Size / (1024 * 1024):N0} MiB is above the executable limit"); return; }
        byte[] data;
        try { using var fs = ctx.OpenRead(f.Path); data = new byte[fs.Length]; fs.ReadExactly(data); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { ctx.Uninspectable(f.Path, f.Role, InspectionStatus.Unreadable, e.Message); return; }
        ctx.Custody.Record("read-executable", f.Path);
        var ext = Path.GetExtension(f.Path);
        var isPe = JarAnalyzer.LooksLikePe(data);
        if (!isPe) { ctx.NotApplicable(f.Path, f.Role, "executable extension but no PE image"); return; }
        var disguised = !new[] { ".exe", ".dll", ".sys", ".scr", ".com", ".cpl", ".ocx", ".drv" }.Contains(ext, StringComparer.OrdinalIgnoreCase);
        var signed = Authenticode.IsSigned(f.Path);
        ctx.Custody.Record("verify-signature", f.Path);
        var hits = ctx.Signatures.Match(SignatureScope.Binary, data, f.GamePath);
        ReportStringHits(ctx, f, hits, "Executable");
        foreach (var r in ctx.Rules.OfKind(RuleKind.ExecutableRegex).Where(r => r.IsMatch(Path.GetFileName(f.Path))))
            ctx.Report(r.Id, [f.Path],
                $"The instance contains the executable \"{f.GamePath}\", whose name matches \"{r.Name}\".",
                "Executable names inside the instance compared with the executable-name database.",
                r.Description, "Names are user-controlled; the file content was also string-matched.",
                [ctx.FileEvidence(f.Path, "Executable in instance", new() { ["signed"] = signed.ToString() })],
                signature: $"executable name \"{Path.GetFileName(f.Path)}\"", location: f.GamePath);
        if (!signed || disguised)
            ctx.Report(Builtin.ExecutableInInstance, [f.Path],
                disguised ? $"\"{f.GamePath}\" is a Windows executable disguised with the extension \"{ext}\"." : $"The instance contains the unsigned executable \"{f.GamePath}\".",
                "Every file of the instance is checked for a PE header and executables are Authenticode-verified (WinVerifyTrust).",
                "Injectors, auto-clickers and loaders are often kept next to the game so that they are at hand; a disguised extension hides them from a quick look.",
                disguised ? "Rare for legitimate software." : "Some mods extract unsigned helper DLLs into the instance.",
                [ctx.FileEvidence(f.Path, "Executable in instance", new() { ["signed"] = signed.ToString(), ["extension"] = ext })],
                tier: disguised ? EvidenceTier.StrongIndicator : null, severity: disguised ? Severity.High : null, confidence: disguised ? 85 : null,
                signature: disguised ? "PE image with non-executable extension" : "unsigned PE image", location: f.GamePath);
        ctx.Analyzed(f.Path, f.Role);
    }
}
