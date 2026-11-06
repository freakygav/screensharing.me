using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using Screensharing.Scanner.Analysis;
using Screensharing.Scanner.Discovery;
using Screensharing.Scanner.Engine;
using Screensharing.Scanner.Model;

namespace Screensharing.Scanner.Modules;

/// <summary>Opens every mod archive and evaluates catalog rules plus structural heuristics.</summary>
public sealed class ModsModule : IScanModule
{
    public string Key => "mods";
    public string Name => "Mod archive analysis";
    public string Activity => "Examining installed modifications…";
    public string? SkipReason(ScanContext ctx) => null;

    private readonly List<(Installation Inst, string File)> _files = [];
    private readonly List<(Installation Inst, string Entry)> _packs = [];

    public int Plan(ScanContext ctx)
    {
        _files.Clear();
        _packs.Clear();
        foreach (var i in ctx.Installations)
        {
            foreach (var dir in i.ModsDirectories.Distinct(StringComparer.OrdinalIgnoreCase))
                foreach (var f in MinecraftLocator.SafeFiles(dir))
                    _files.Add((i, f));
            if (i.ResourcePacksDirectory is { } rp)
            {
                foreach (var f in MinecraftLocator.SafeFiles(rp)) _packs.Add((i, f));
                foreach (var d in MinecraftLocator.SafeDirs(rp)) _packs.Add((i, d));
            }
        }
        return _files.Count + _packs.Count + 1;
    }

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        foreach (var (inst, file) in _files)
        {
            ct.ThrowIfCancellationRequested();
            ctx.SetActivity($"Examining installed modifications… {Path.GetFileName(file)}");
            AnalyzeFile(ctx, inst, file);
            ctx.Advance();
        }
        foreach (var i in ctx.Installations)
            i.ModCount = ctx.Mods.Count(m => m.Launcher == i.Launcher);

        DuplicateIds(ctx);
        await VerifyWithModrinthAsync(ctx, ct).ConfigureAwait(false);
        foreach (var m in ctx.Mods) DeferredChecks(ctx, m);
        ReportUnrecognised(ctx);
        ctx.Advance();

        foreach (var (inst, entry) in _packs)
        {
            ResourcePack(ctx, inst, entry);
            ctx.Advance();
        }
        ctx.Statistics["modArchives"] = ctx.Mods.Count;
    }

    private static void AnalyzeFile(ScanContext ctx, Installation inst, string file)
    {
        var name = Path.GetFileName(file);
        var lower = name.ToLowerInvariant();
        var isJarExt = lower.EndsWith(".jar");
        var disabled = lower.EndsWith(".jar.disabled") || lower.EndsWith(".disabled");
        if (!isJarExt && !disabled && !JarAnalyzer.LooksLikeZip(file)) return; // configs, txt, etc.
        if (!JarAnalyzer.LooksLikeZip(file)) return;

        ctx.Custody.Record("read-archive", file);
        var fi = new FileInfo(file);
        var rec = new ModRecord { Path = file, Launcher = inst.Launcher, SizeBytes = fi.Length, Disabled = disabled };
        rec.Jar = JarAnalyzer.Analyze(file);
        rec.Sha256 = ctx.Sha256(file);
        ctx.Mods.Add(rec);

        if (!isJarExt && !disabled)
        {
            ctx.Report(Builtin.NonJarArchive, [file],
                $"\"{name}\" in {Path.GetDirectoryName(file)} is a Java archive with a non-standard extension.",
                "File signature inspection (ZIP local-file header 50 4B 03 04) of every file in mod folders.",
                "Hiding a jar behind another extension can keep it out of casual inspection while injectors or custom loaders still read it.",
                "Some tools store archives with other extensions; a non-.jar file is not loaded by Fabric/Forge.",
                [ctx.FileEvidence(file, "Mods folder")]);
        }

        EvaluateArchive(ctx, rec, file, "Mod archive");
    }

    /// <summary>Evaluates catalog rules and heuristics for one archive. Also used for recoverable Recycle Bin copies.</summary>
    internal static void EvaluateArchive(ScanContext ctx, ModRecord rec, string file, string source)
    {
        var jar = rec.Jar!;
        var name = Path.GetFileName(file);
        var ids = jar.AllMetadata().ToList();
        var classes = jar.AllClasses().ToList();

        // --- Catalog matches grouped per family (one finding per family per file).
        var matches = new List<(DetectionRule Rule, Evidence Ev, string What)>();
        foreach (var r in ctx.Rules.OfKind(RuleKind.ModId))
        {
            var hit = ids.FirstOrDefault(m => string.Equals(m.Id, r.Pattern, StringComparison.OrdinalIgnoreCase));
            if (hit is not null)
                matches.Add((r, Entry(file, hit.Loader + " metadata", $"mod id \"{hit.Id}\"", new() { ["modId"] = hit.Id, ["name"] = hit.Name ?? "", ["version"] = hit.Version ?? "", ["loader"] = hit.Loader }), $"declares mod id \"{hit.Id}\""));
        }
        foreach (var r in ctx.Rules.OfKind(RuleKind.ModIdRegex))
        {
            var hit = ids.FirstOrDefault(m => r.IsMatch(m.Id) || (m.Name is not null && r.IsMatch(m.Name)));
            if (hit is not null)
                matches.Add((r, Entry(file, hit.Loader + " metadata", $"mod \"{hit.Id}\" ({hit.Name})", new() { ["modId"] = hit.Id, ["name"] = hit.Name ?? "" }), $"declares mod \"{hit.Id}\" ({hit.Name})"));
        }
        foreach (var r in ctx.Rules.OfKind(RuleKind.PackagePrefix))
        {
            var hits = classes.Where(c => c.Class.StartsWith(r.Pattern, StringComparison.Ordinal)).ToList();
            if (hits.Count > 0)
            {
                var sample = hits[0];
                matches.Add((r, Entry(file, "Compiled class package", (sample.Container.Length > 0 ? sample.Container + "!/" : "") + sample.Class + ".class",
                    new() { ["package"] = r.Pattern, ["matchingClasses"] = hits.Count.ToString(), ["sample"] = string.Join(", ", hits.Take(5).Select(h => h.Class)) }),
                    $"contains {hits.Count} compiled classes under {r.Pattern.Replace('/', '.').TrimEnd('.')}"));
            }
        }
        foreach (var r in ctx.Rules.OfKind(RuleKind.Sha256))
            if (rec.Sha256 is not null && string.Equals(rec.Sha256, r.Pattern, StringComparison.OrdinalIgnoreCase))
                matches.Add((r, Entry(file, "File hash", "sha256 " + rec.Sha256, new() { ["sha256"] = rec.Sha256 }), "matches a catalogued SHA-256 fingerprint"));
        foreach (var r in ctx.Rules.OfKind(RuleKind.FileNameRegex))
            if (r.IsMatch(name))
                matches.Add((r, Entry(file, "File name", name, new() { ["fileName"] = name }), $"has the file name \"{name}\""));

        var module = ModuleHeuristics.Evaluate(classes.Select(c => c.Class));
        var fileEv = ctx.FileEvidence(file, source, new Dictionary<string, string>
        {
            ["modIds"] = string.Join(", ", ids.Select(i => i.Id).Distinct().Take(20)),
            ["classCount"] = classes.Count.ToString(),
            ["nestedArchives"] = jar.Nested.Count.ToString(),
        });

        // A file-name match only adds evidence when content already identified a family.
        var familyKey = matches.Where(m => m.Rule.Kind != RuleKind.FileNameRegex && m.Rule.Family is not null)
                               .OrderBy(m => m.Rule.TierValue).Select(m => m.Rule.Family).FirstOrDefault();
        foreach (var group in matches.GroupBy(m => m.Rule.Kind == RuleKind.FileNameRegex && familyKey is not null ? familyKey : m.Rule.Family ?? m.Rule.Id))
        {
            var ordered = group.OrderBy(g => g.Rule.TierValue).ThenByDescending(g => g.Rule.Confidence).ToList();
            var primary = ordered[0].Rule;
            var corroborated = ordered.Select(o => o.Rule.Kind).Distinct().Count() > 1;
            var evidence = new List<Evidence> { fileEv };
            evidence.AddRange(ordered.Select(o => o.Ev));
            if (module.Names.Count > 0)
                evidence.Add(Entry(file, "Feature classes", string.Join(", ", module.Names.Take(15)), new() { ["examples"] = string.Join(", ", module.Examples.Take(6)) }));
            var conf = Math.Min(99, primary.Confidence + (corroborated ? 3 : 0));
            ctx.Report(primary.Id, [file, group.Key],
                $"\"{name}\" {string.Join("; ", ordered.Select(o => o.What).Distinct())}." +
                (primary.Features.Count > 0 ? $" Known capabilities of {primary.Family ?? primary.Name}: {string.Join(", ", primary.Features.Take(12))}." : ""),
                "Static archive analysis: mod metadata (fabric.mod.json / quilt.mod.json / mods.toml / mcmod.info), compiled class package paths, file hash and name compared with the detection catalog" +
                (corroborated ? ". Multiple independent identifiers matched." : "."),
                primary.Description.Length > 0 ? primary.Description : $"The archive matches the catalog entry for {primary.Family ?? primary.Name}.",
                rec.Disabled ? "The file is disabled (.disabled extension) and would not be loaded by the launcher in its current state." :
                    "The archive's presence does not show when, or on which server, it was used. A file can be downloaded and never run.",
                evidence,
                name: $"{primary.Family ?? primary.Name}: {(primary.Category.Length > 0 ? primary.Category.ToLowerInvariant() : "match")} in {(source == "Mod archive" ? "mods folder" : source.ToLowerInvariant())}",
                confidence: conf);
            rec.Classification = primary.SeverityValue <= Severity.High ? "prohibited" : "restricted";
        }

        if (matches.Count == 0)
        {
            // Structural cheat-module heuristic.
            var total = module.Names.Count;
            if (total >= 3 || module.HighSignalCount >= 2)
            {
                var strong = total >= 3;
                ctx.Report(Builtin.ModuleClasses, [file],
                    $"\"{name}\" contains classes named after {total} distinct cheat features: {string.Join(", ", module.Names.Take(15))}.",
                    "Class-name analysis of every compiled class (including nested archives) against curated cheat-feature names; ambiguous names (Speed, Reach, Velocity…) only count inside module/feature packages.",
                    "Hacked clients implement each cheat as its own module class. Several such classes in one archive is a structural fingerprint of a cheat client, even when its name and metadata are unknown.",
                    "A legitimate mod could contain one or two similarly named classes (e.g. a Reach attribute or Speed potion helper).",
                    [fileEv, Entry(file, "Feature classes", string.Join(", ", module.Examples.Take(8)), new() { ["featureNames"] = string.Join(", ", module.Names) })],
                    tier: strong ? null : EvidenceTier.WeakIndicator,
                    severity: strong ? null : Severity.Low,
                    confidence: strong ? (total >= 5 ? 88 : 78) : 40);
                rec.Classification = strong ? "suspicious" : rec.Classification;
            }
            else if (jar.Primary is { } primaryMeta && ctx.Rules.KnownMod(primaryMeta.Id) is { } known)
            {
                rec.Classification = known.Classification ?? "known";
            }
        }

        if (jar.ClassEntries.Count >= 25 && jar.ObfuscationRatio >= 0.6)
        {
            ctx.Report(Builtin.ObfuscatedArchive, [file],
                $"{jar.ObfuscatedClassCount} of {jar.ClassEntries.Count} classes in \"{name}\" ({jar.ObfuscationRatio:P0}) have one/two-character or non-ASCII names.",
                "Class-name entropy analysis of the archive's own (non-nested) classes.",
                "Paid cheat clients are distributed heavily obfuscated to resist signature detection.",
                "Some closed-source legitimate mods are obfuscated as well.",
                [fileEv]);
        }

        if (jar.Primary is not null) rec.DisguiseCheckPending = true;

        var agentKeys = new[] { "Premain-Class", "Agent-Class", "Launcher-Agent-Class" };
        var agent = agentKeys.FirstOrDefault(k => jar.Manifest.ContainsKey(k));
        if (agent is not null && !KnownLibraryAgents.Contains(jar.Manifest[agent]))
            rec.PendingAgent = (agent, jar.Manifest[agent], fileEv);
    }

    /// <summary>Agent entry points shipped by widely used libraries (not by cheat clients).</summary>
    private static readonly HashSet<string> KnownLibraryAgents = new(StringComparer.Ordinal)
    {
        "kotlinx.coroutines.debug.AgentPremain",
        "kotlinx.coroutines.debug.internal.AgentPremain",
        "net.bytebuddy.agent.Installer",
    };

    /// <summary>Heuristics that must not fire for archives verified as published mods; run after Modrinth verification.</summary>
    internal static void DeferredChecks(ScanContext ctx, ModRecord rec)
    {
        var jar = rec.Jar;
        if (jar is null) return;
        var name = rec.FileName;
        var verified = rec.ModrinthProject is not null;
        if (rec.PendingAgent is { } ag && !verified)
        {
            ctx.Report(Builtin.JavaAgentManifest, [rec.Path],
                $"\"{name}\" declares a Java agent entry point ({ag.Key}: {ag.Value}).",
                "META-INF/MANIFEST.MF inspection for Premain-Class, Agent-Class and Launcher-Agent-Class attributes (well-known library agents and Modrinth-verified archives excluded).",
                "Java agents can be attached to the running game and rewrite Minecraft classes in memory, which is how several injectable clients operate without a mod loader.",
                "Profilers, debuggers and a few developer tools ship agent manifests.",
                [ag.Ev, Entry(rec.Path, "JAR manifest", $"META-INF/MANIFEST.MF {ag.Key}", new() { [ag.Key] = ag.Value })]);
        }

        // Disguise: file name starts with a well-known mod id but the metadata declares something unrelated.
        if (!rec.DisguiseCheckPending || verified || jar.Primary is not { } pm) return;
        static string Norm(string x) => x.ToLowerInvariant().Replace("-", "").Replace("_", "").Replace(" ", "");
        var lowerName = name.ToLowerInvariant();
        var ids = jar.AllMetadata().ToList();
        if (ids.Any(i => ctx.Rules.KnownMod(i.Id) is not null)) return; // it declares a known mod itself
        foreach (var km in ctx.Rules.OfKind(RuleKind.KnownMod).Where(k => k.Pattern.Length >= 4 && k.Classification != "library"))
        {
            var token = km.Pattern.ToLowerInvariant();
            if (!lowerName.StartsWith(token, StringComparison.Ordinal) || lowerName.Length <= token.Length || char.IsLetterOrDigit(lowerName[token.Length])) continue;
            if (ids.Any(i => Norm(i.Id).Contains(Norm(token)) || Norm(token).Contains(Norm(i.Id)))) return;
            ctx.Report(Builtin.DisguisedArchive, [rec.Path, token],
                $"\"{name}\" is named like {km.Name} (\"{token}\") but its metadata declares \"{pm.Id}\"{(pm.Name is null ? "" : $" ({pm.Name})")}.",
                "Comparison of the file name against the archive's declared mod ids, for file names beginning with a known mod id (archives published on Modrinth are excluded).",
                "Renaming a cheat client to look like a popular performance mod is a common way to evade a visual inspection of the mods folder.",
                "Repackaged forks or modpack builds sometimes keep upstream file names.",
                [ctx.FileEvidence(rec.Path, "Mod archive"), Entry(rec.Path, pm.Loader + " metadata", $"declared mod id \"{pm.Id}\"", new() { ["fileNameClaims"] = token, ["declaredModId"] = pm.Id })]);
            return;
        }
    }

    private static Evidence Entry(string file, string source, string what, Dictionary<string, string> details) => new()
    {
        Kind = EvidenceKind.JarEntry,
        Source = source,
        Reference = $"{file}!/{what}",
        Details = details,
    };

    private static void DuplicateIds(ScanContext ctx)
    {
        foreach (var g in ctx.Mods.Where(m => !m.Disabled && m.ModId is not null)
                     .GroupBy(m => (Folder: Path.GetDirectoryName(m.Path)!.ToLowerInvariant(), Id: m.ModId!.ToLowerInvariant()))
                     .Where(g => g.Count() > 1))
        {
            ctx.Report(Builtin.DuplicateModId, [g.Key.Folder, g.Key.Id],
                $"{g.Count()} archives in {g.Key.Folder} declare the mod id \"{g.Key.Id}\": {string.Join(", ", g.Select(m => m.FileName))}.",
                "Cross-reference of declared mod ids per mods folder.",
                "A second archive claiming an existing mod's id can be a swapped or disguised copy.",
                "An old version left next to an update; mod loaders refuse to start with duplicates.",
                g.Select(m => ctx.FileEvidence(m.Path, "Mod archive")).ToList());
        }
    }

    private static async Task VerifyWithModrinthAsync(ScanContext ctx, CancellationToken ct)
    {
        if (!ctx.Options.ModrinthLookup || ctx.Options.Http is null) return;
        var candidates = ctx.Mods.Where(m => m.Classification == "unrecognised").ToList();
        if (candidates.Count == 0) return;
        ctx.SetActivity("Checking known modification fingerprints…");
        foreach (var m in candidates)
        {
            try
            {
                await using var fs = ScanContext.OpenRead(m.Path);
                m.Sha512 = Convert.ToHexStringLower(await SHA512.HashDataAsync(fs, ct).ConfigureAwait(false));
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
        }
        var hashes = candidates.Where(m => m.Sha512 is not null).Select(m => m.Sha512!).Distinct().ToList();
        try
        {
            ctx.Custody.Record("modrinth-hash-lookup", $"{hashes.Count} SHA-512 hashes sent to api.modrinth.com");
            using var resp = await ctx.Options.Http.PostAsJsonAsync("https://api.modrinth.com/v2/version_files", new { hashes, algorithm = "sha512" }, ct).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode) return;
            using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false));
            var projectByHash = new Dictionary<string, string>();
            foreach (var p in doc.RootElement.EnumerateObject())
                if (p.Value.TryGetProperty("project_id", out var pid) && pid.GetString() is { } id) projectByHash[p.Name] = id;
            var titles = new Dictionary<string, string>();
            var ids = projectByHash.Values.Distinct().ToList();
            if (ids.Count > 0)
            {
                var url = "https://api.modrinth.com/v2/projects?ids=" + Uri.EscapeDataString(JsonSerializer.Serialize(ids));
                using var pr = await ctx.Options.Http.GetAsync(url, ct).ConfigureAwait(false);
                if (pr.IsSuccessStatusCode)
                {
                    using var pd = JsonDocument.Parse(await pr.Content.ReadAsStringAsync(ct).ConfigureAwait(false));
                    foreach (var p in pd.RootElement.EnumerateArray())
                        if (p.TryGetProperty("id", out var i) && p.TryGetProperty("title", out var t)) titles[i.GetString()!] = t.GetString() ?? "";
                }
            }
            foreach (var m in candidates)
            {
                if (m.Sha512 is null || !projectByHash.TryGetValue(m.Sha512, out var pid)) continue;
                m.Classification = "published (Modrinth)";
                m.ModrinthProject = titles.GetValueOrDefault(pid, pid);
            }
            ctx.Statistics["modrinthVerified"] = candidates.Count(c => c.ModrinthProject is not null);
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException or JsonException)
        {
            ctx.Custody.Record("modrinth-hash-lookup-failed", e.Message);
        }
    }

    private static void ReportUnrecognised(ScanContext ctx)
    {
        foreach (var m in ctx.Mods.Where(m => m.Classification == "unrecognised"))
        {
            ctx.Report(Builtin.UnrecognizedMod, [m.Path],
                $"\"{m.FileName}\" ({m.ModId ?? "no mod metadata"}) is not in the catalog of known mods" + (ctx.Options.ModrinthLookup ? " and its hash is not published on Modrinth." : "."),
                "Catalog lookup by declared mod id" + (ctx.Options.ModrinthLookup ? " and SHA-512 lookup against the public Modrinth registry." : "."),
                "Listed so the investigator can review it manually. Unrecognised does not mean malicious.",
                "Niche, private, CurseForge-only or self-built mods are commonly unrecognised.",
                [ctx.FileEvidence(m.Path, "Mod archive", new() { ["modId"] = m.ModId ?? "", ["name"] = m.Jar?.Primary?.Name ?? "", ["version"] = m.Jar?.Primary?.Version ?? "", ["loader"] = m.Jar?.Primary?.Loader ?? "" })]);
        }
    }

    private static void ResourcePack(ScanContext ctx, Installation inst, string entry)
    {
        var name = Path.GetFileName(entry);
        foreach (var r in ctx.Rules.OfKind(RuleKind.ResourcePackRegex))
        {
            if (!r.IsMatch(name)) continue;
            var isFile = File.Exists(entry);
            ctx.Report(r.Id, [entry],
                $"Resource pack \"{name}\" in {inst.Launcher} matches \"{r.Family ?? r.Name}\".",
                "Resource pack folder name inspection against catalog patterns.",
                r.Description,
                "Pack names are user-controlled and the pack may never have been enabled; options.txt lists active packs.",
                [isFile ? ctx.FileEvidence(entry, "Resource pack") : new Evidence { Kind = EvidenceKind.File, Source = "Resource pack folder", Reference = entry, ModifiedTime = Directory.GetLastWriteTimeUtc(entry) }]);
        }
    }
}
