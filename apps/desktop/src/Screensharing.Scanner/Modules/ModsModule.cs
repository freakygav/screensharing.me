using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using Screensharing.Scanner.Analysis;
using Screensharing.Scanner.Engine;
using Screensharing.Scanner.Model;

namespace Screensharing.Scanner.Modules;

/// <summary>Opens every Java archive of the instance (mods folder and archives stored elsewhere in it) and evaluates the signature database and structural heuristics.</summary>
public sealed class ModsModule : IScanModule
{
    public string Key => "mods";
    public string Name => "Mod archives";
    public string Activity => "Examining mod archives…";
    public string? SkipReason(ScanContext ctx) => null;

    private readonly List<InstanceFile> _files = [];

    public int Plan(ScanContext ctx)
    {
        _files.Clear();
        _files.AddRange(ctx.FilesOf(FileRole.ModArchive, FileRole.Archive));
        return _files.Count + 1;
    }

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        foreach (var f in _files)
        {
            ct.ThrowIfCancellationRequested();
            ctx.SetActivity($"Examining mod archives… {f.GamePath}");
            AnalyzeArchive(ctx, f.Path, f.Role == FileRole.ModArchive ? "Mods folder" : "Instance archive", f.Role, ct);
            ctx.Advance();
        }
        DuplicateIds(ctx);
        await VerifyWithModrinthAsync(ctx, ct).ConfigureAwait(false);
        foreach (var m in ctx.Mods) DeferredChecks(ctx, m);
        ReportUnrecognised(ctx);
        ctx.Advance();
        ctx.Statistics["modArchives"] = ctx.Mods.Count(m => m.Origin == "Mods folder");
        if (ctx.CurrentCategory is not null)
            ctx.CurrentCategory.Message = $"{ctx.Mods.Count(m => m.Origin == "Mods folder"):N0} mod archives, {ctx.Mods.Count(m => m.Origin == "Instance archive"):N0} other archives";
    }

    /// <summary>Analyses one archive. Used for the mods folder, archives elsewhere in the instance and class-path jars.</summary>
    internal static ModRecord? AnalyzeArchive(ScanContext ctx, string path, string origin, FileRole role, CancellationToken ct, bool classPath = false)
    {
        var name = Path.GetFileName(path);
        var lower = name.ToLowerInvariant();
        var disabled = lower.EndsWith(".disabled");
        long size;
        try { size = new FileInfo(path).Length; } catch (Exception e) when (e is IOException or UnauthorizedAccessException) { size = -1; }
        if (size > ctx.Options.MaxArchiveBytes)
        {
            ctx.Uninspectable(path, role, InspectionStatus.TooLarge, $"archive is {size / (1024 * 1024):N0} MiB, above the {ctx.Options.MaxArchiveBytes / (1024 * 1024):N0} MiB limit");
            return null;
        }
        FileStream fs;
        try { fs = ctx.OpenRead(path); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            ctx.Uninspectable(path, role, InspectionStatus.Unreadable, e.Message);
            return null;
        }
        using (fs)
        {
            ctx.Custody.Record("read-archive", path);
            var kind = JarAnalyzer.Probe(fs);
            if (kind == ArchiveKind.NotArchive)
            {
                if (role == FileRole.ModArchive && !disabled) NotAnArchive(ctx, path, fs);
                else ctx.NotApplicable(path, role, "not a ZIP/JAR archive");
                return null;
            }
            if (kind is ArchiveKind.ExecutableWithZip or ArchiveKind.ZipWithPrefix)
            {
                ctx.Report(Builtin.PolyglotArchive, [path],
                    kind == ArchiveKind.ExecutableWithZip
                        ? $"\"{ctx.Location(path)}\" is a Windows executable with a ZIP/JAR archive appended — it can be loaded as a Java archive and run as a program."
                        : $"\"{ctx.Location(path)}\" has unknown data in front of its ZIP/JAR archive.",
                    "File-structure inspection: header bytes compared with the position of the ZIP end-of-central-directory record.",
                    "Polyglot files hide an executable (for example an injector) inside something that looks like a mod, or hide a mod inside something that looks like a program.",
                    "Self-extracting installers have this structure, but do not belong in a Minecraft instance.",
                    [ctx.FileEvidence(path, origin, new() { ["structure"] = kind.ToString() })],
                    family: null, signature: kind == ArchiveKind.ExecutableWithZip ? "PE image + ZIP directory" : "data before ZIP header");
            }
            fs.Position = 0;
            using var zipStream = JarAnalyzer.Tolerant(fs, ctx.Options.MaxArchiveBytes, out var normalized);
            if (normalized) ctx.Custody.Record("normalize-zip-directory", $"{path} (non-zero disk numbers in end-of-central-directory; inspected from an in-memory copy)");
            var jar = JarAnalyzer.Analyze(zipStream, new JarAnalyzer.Options { Signatures = ctx.Signatures, LibraryPackages = ctx.Rules.LibraryPackages, Cancellation = ct });
            if (jar.Malformed && jar.ClassEntries.Count == 0 && jar.Metadata.Count == 0 && jar.EntryNames.Count == 0)
            {
                ctx.Uninspectable(path, role, InspectionStatus.Corrupt, $"the archive could not be opened ({jar.Error ?? "damaged ZIP structure"})", report: role == FileRole.ModArchive || classPath);
                return null;
            }
            if (role == FileRole.Archive && !classPath && jar.ClassEntries.Count == 0 && jar.Metadata.Count == 0 && jar.Nested.Count == 0)
            {
                // A plain ZIP (configs, backups…): its text resources were still string-matched.
                ReportHits(ctx, path, origin, jar);
                ctx.Analyzed(path, role);
                return null;
            }

            var rec = new ModRecord { Path = path, Location = ctx.Location(path), Origin = origin, SizeBytes = size, Disabled = disabled, Jar = jar };
            rec.Sha256 = ctx.Sha256(path);
            ctx.Mods.Add(rec);

            if (role == FileRole.ModArchive && !lower.EndsWith(".jar") && !disabled)
            {
                ctx.Report(Builtin.NonJarArchive, [path],
                    $"\"{rec.Location}\" is a Java archive with a non-standard extension.",
                    "File signature inspection (ZIP header) of every file in the mods folder.",
                    "Hiding a jar behind another extension can keep it out of casual inspection while injectors or custom loaders still read it.",
                    "Some tools store archives with other extensions; a non-.jar file is not loaded by Fabric/Forge.",
                    [ctx.FileEvidence(path, origin)], signature: "ZIP header in non-.jar file");
            }

            EvaluateArchive(ctx, rec, path, origin, fullHeuristics: !classPath);

            var skipped = jar.AllSkipped().ToList();
            var encrypted = jar.AllEncrypted();
            if (encrypted > 0)
                ctx.Uninspectable(path, role, InspectionStatus.Encrypted, $"{encrypted} password-protected entr{(encrypted == 1 ? "y" : "ies")} cannot be read (e.g. {string.Join(", ", skipped.Take(3).Select(s => s.Entry))})");
            else if (skipped.Count > 0)
                ctx.Uninspectable(path, role, InspectionStatus.TooLarge, $"{skipped.Count} entr{(skipped.Count == 1 ? "y was" : "ies were")} not inspected: {string.Join("; ", skipped.Take(3).Select(s => $"{s.Entry} ({s.Reason})"))}", report: skipped.Any(s => s.Entry.EndsWith(".class") || s.Entry.EndsWith(".jar")));
            else if (jar.AnyMalformed())
                ctx.Uninspectable(path, role, InspectionStatus.Corrupt, $"part of the archive could not be read ({jar.Error ?? "malformed metadata or nested archive"})", report: false);
            else ctx.Analyzed(path, role);
            return rec;
        }
    }

    private static void NotAnArchive(ScanContext ctx, string path, FileStream fs)
    {
        var head = new byte[Math.Min(4096, fs.Length)];
        fs.Position = 0;
        _ = fs.Read(head, 0, head.Length);
        if (JarAnalyzer.LooksLikePe(head))
        {
            ctx.Report(Builtin.ExecutableInInstance, [path],
                $"\"{ctx.Location(path)}\" in the mods folder is a Windows executable, not a Java archive.",
                "Magic-byte inspection of every file in the mods folder.",
                "A program disguised as a mod file can be an injector or loader that the player runs separately while the mods folder looks normal.",
                "None for a file in the mods folder; mod loaders cannot load it.",
                [ctx.FileEvidence(path, "Mods folder", new() { ["format"] = "PE executable" })],
                tier: EvidenceTier.StrongIndicator, severity: Severity.High, confidence: 85, signature: "PE header in .jar file");
            ctx.Analyzed(path, FileRole.ModArchive);
        }
        else ctx.Uninspectable(path, FileRole.ModArchive, InspectionStatus.Corrupt, "the file has a mod extension but is not a ZIP/JAR archive");
    }

    private static Evidence Entry(string file, string source, string what, Dictionary<string, string> details) => new()
    {
        Kind = EvidenceKind.JarEntry,
        Source = source,
        Reference = $"{file}!/{what}",
        Details = details,
    };

    private static string Readable(string pkg) => pkg.Replace('/', '.').TrimEnd('.');

    private static List<Indicator> StringIndicators(string file, JarInfo jar) =>
        jar.AllHits().Select(h => new Indicator(h.Rule,
            Entry(file, h.Scope switch { SignatureScope.Class => "Class constant pool", SignatureScope.Binary => "Embedded executable", _ => "Archive resource" }, h.Where,
                new() { ["string"] = h.Rule.Pattern, ["entry"] = h.Where, ["scope"] = h.Scope, ["excerpt"] = h.Excerpt ?? "" }),
            $"contains \"{h.Rule.Pattern}\" in {h.Where}", $"string \"{h.Rule.Pattern}\"")).ToList();

    /// <summary>Plain archives without classes: only string hits can be reported.</summary>
    private static void ReportHits(ScanContext ctx, string path, string origin, JarInfo jar)
    {
        var groups = EvidenceScoring.Score(StringIndicators(path, jar));
        foreach (var g in groups.Where(g => g.Report && g.Tier != EvidenceTier.Inconclusive))
            ReportGroup(ctx, g, path, origin, null);
    }

    private static void ReportGroup(ScanContext ctx, ScoredGroup g, string path, string origin, Evidence? fileEv, ModuleHeuristics.Result? module = null, bool disabled = false)
    {
        var p = g.Primary;
        var location = ctx.Location(path);
        var evidence = new List<Evidence> { fileEv ?? ctx.FileEvidence(path, origin) };
        evidence.AddRange(g.Indicators.Select(i => i.Evidence));
        if (module is { Names.Count: > 0 })
            evidence.Add(Entry(path, "Feature classes", string.Join(", ", module.Names.Take(15)), new() { ["examples"] = string.Join(", ", module.Examples.Take(6)) }));
        var family = p.Family ?? p.Name;
        ctx.Report(p.Id, [path, g.Family],
            $"\"{location}\" {string.Join("; ", g.Indicators.Select(i => i.What).Distinct().Take(8))}." +
            (p.Features.Count > 0 ? $" Known capabilities of {family}: {string.Join(", ", p.Features.Take(12))}." : "") +
            (g.Indicators.Count > 1 ? $" {g.Indicators.Count} independent indicators matched (score {g.Score}/100)." : ""),
            "Static archive analysis: mod metadata, compiled class packages, class constant-pool strings, archive resources and embedded executables compared with the signature database" +
            (g.Corroborated ? "; several indicators were combined." : "."),
            p.Description.Length > 0 ? p.Description : $"The archive matches the signature database entry for {family}.",
            disabled ? "The file is disabled (.disabled extension) and would not be loaded by the launcher in its current state." :
                "The archive's presence does not show when, or on which server, it was used. A file can be downloaded and never run.",
            evidence,
            name: $"{family}: {(p.Category.Length > 0 ? p.Category.ToLowerInvariant() : "match")} in {(origin == "Mods folder" ? "mods folder" : origin.ToLowerInvariant())}",
            tier: g.Tier, confidence: g.Confidence, family: p.Family,
            signature: string.Join(" + ", g.Indicators.Select(i => i.Signature).Distinct().Take(4)), location: location);
    }

    /// <summary>Evaluates the signature database and heuristics for one archive.</summary>
    internal static void EvaluateArchive(ScanContext ctx, ModRecord rec, string file, string source, bool fullHeuristics = true)
    {
        var jar = rec.Jar!;
        var name = Path.GetFileName(file);
        var ids = jar.AllMetadata().ToList();
        var classes = jar.AllClasses().ToList();

        var indicators = new List<Indicator>();
        foreach (var r in ctx.Rules.OfKind(RuleKind.ModId))
        {
            var hit = ids.FirstOrDefault(m => string.Equals(m.Id, r.Pattern, StringComparison.OrdinalIgnoreCase));
            if (hit is not null)
                indicators.Add(new(r, Entry(file, hit.Loader + " metadata", $"mod id \"{hit.Id}\"", new() { ["modId"] = hit.Id, ["name"] = hit.Name ?? "", ["version"] = hit.Version ?? "", ["loader"] = hit.Loader }), $"declares mod id \"{hit.Id}\"", $"mod id \"{hit.Id}\""));
        }
        foreach (var r in ctx.Rules.OfKind(RuleKind.ModIdRegex))
        {
            var hit = ids.FirstOrDefault(m => r.IsMatch(m.Id) || (m.Name is not null && r.IsMatch(m.Name)));
            if (hit is not null)
                indicators.Add(new(r, Entry(file, hit.Loader + " metadata", $"mod \"{hit.Id}\" ({hit.Name})", new() { ["modId"] = hit.Id, ["name"] = hit.Name ?? "" }), $"declares mod \"{hit.Id}\" ({hit.Name})", $"mod \"{hit.Id}\" ({hit.Name})"));
        }
        foreach (var r in ctx.Rules.OfKind(RuleKind.PackagePrefix))
        {
            var hits = classes.Where(c => c.Class.StartsWith(r.Pattern, StringComparison.Ordinal)).ToList();
            if (hits.Count == 0) continue;
            var sample = hits[0];
            indicators.Add(new(r, Entry(file, "Compiled class package", (sample.Container.Length > 0 ? sample.Container + "!/" : "") + sample.Class + ".class",
                new() { ["package"] = r.Pattern, ["matchingClasses"] = hits.Count.ToString(), ["sample"] = string.Join(", ", hits.Take(5).Select(h => h.Class)) }),
                $"contains {hits.Count} compiled classes under {Readable(r.Pattern)}", $"package {Readable(r.Pattern)}"));
        }
        foreach (var r in ctx.Rules.OfKind(RuleKind.Sha256))
            if (rec.Sha256 is not null && string.Equals(rec.Sha256, r.Pattern, StringComparison.OrdinalIgnoreCase))
                indicators.Add(new(r, Entry(file, "File hash", "sha256 " + rec.Sha256, new() { ["sha256"] = rec.Sha256 }), "matches a catalogued SHA-256 fingerprint", "SHA-256 " + rec.Sha256[..16] + "…"));
        foreach (var r in ctx.Rules.OfKind(RuleKind.FileNameRegex))
            if (r.IsMatch(name))
                indicators.Add(new(r, Entry(file, "File name", name, new() { ["fileName"] = name }), $"has the file name \"{name}\"", $"file name \"{name}\""));
        indicators.AddRange(StringIndicators(file, jar));

        var module = ModuleHeuristics.Evaluate(classes.Select(c => c.Class), ctx.Rules);
        var fileEv = ctx.FileEvidence(file, source, new Dictionary<string, string>
        {
            ["modIds"] = string.Join(", ", ids.Select(i => i.Id).Distinct().Take(20)),
            ["classCount"] = classes.Count.ToString(),
            ["nestedArchives"] = jar.Nested.Count.ToString(),
        });

        var contentFamily = indicators.Where(i => i.Rule.Kind != RuleKind.FileNameRegex && i.Rule.Family is not null && !i.Rule.IsIndicator)
                                      .OrderBy(i => i.Rule.TierValue).Select(i => i.Rule.Family).FirstOrDefault();
        var groups = EvidenceScoring.Score(indicators, contentFamily);
        var reported = 0;
        foreach (var g in groups)
        {
            if (g.Indicators.All(i => i.Rule.IsIndicator)) { if (g.Report) rec.PendingIndicators.Add(g); continue; }
            if (g.Tier == EvidenceTier.Inconclusive) continue;
            ReportGroup(ctx, g, file, source, fileEv, module, rec.Disabled);
            reported++;
            rec.Classification = g.Primary.SeverityValue <= Severity.High && g.Tier <= EvidenceTier.StrongIndicator ? "prohibited" : "restricted";
        }

        if (reported == 0)
        {
            var total = module.Names.Count;
            if (total >= 3 || module.HighSignalCount >= 2)
            {
                var strong = total >= 3;
                ctx.Report(Builtin.ModuleClasses, [file],
                    $"\"{rec.Location}\" contains classes named after {total} distinct cheat features: {string.Join(", ", module.Names.Take(15))}.",
                    "Class-name analysis of every compiled class (including nested archives) against the cheat-module name database; ambiguous names (Speed, Reach, Velocity…) only count inside module/feature packages.",
                    "Hacked clients implement each cheat as its own module class. Several such classes in one archive is a structural fingerprint of a cheat client, even when its name and metadata are unknown.",
                    "A legitimate mod could contain one or two similarly named classes (e.g. a Reach attribute or Speed potion helper).",
                    [fileEv, Entry(file, "Feature classes", string.Join(", ", module.Examples.Take(8)), new() { ["featureNames"] = string.Join(", ", module.Names) })],
                    tier: strong ? null : EvidenceTier.WeakIndicator, severity: strong ? null : Severity.Low,
                    confidence: strong ? (total >= 5 ? 88 : 78) : 40, family: "Unidentified cheat client",
                    signature: "feature classes " + string.Join(", ", module.Names.Take(6)));
                rec.Classification = strong ? "suspicious" : rec.Classification;
            }
            else if (fullHeuristics && jar.Primary is { } primaryMeta && ctx.Rules.KnownMod(primaryMeta.Id) is { } known)
            {
                rec.Classification = known.Classification ?? "known";
            }
        }

        // ---- Evasion-aware structural checks
        var invalid = jar.AllInvalidClasses().ToList();
        if (invalid.Count > 0)
        {
            var share = classes.Count == 0 ? 1 : (double)invalid.Count / Math.Max(1, classes.Count);
            var strong = invalid.Count >= 5 || share >= 0.1;
            ctx.Report(Builtin.EncryptedClasses, [file],
                $"{invalid.Count} of {classes.Count} class entries in \"{rec.Location}\" are not valid Java class files (no CAFEBABE header), e.g. {string.Join(", ", invalid.Take(3))}.",
                "Every *.class entry is read and its header validated.",
                "Classes that the JVM cannot load directly must be decrypted at runtime by the archive's own class loader — a common way to hide a cheat's code and strings from scanners.",
                "A broken build or a resource mis-named .class; with only a few entries this is a weak indicator.",
                [fileEv, Entry(file, "Class entries", invalid[0], new() { ["invalidClassEntries"] = invalid.Count.ToString(), ["examples"] = string.Join(", ", invalid.Take(8)) })],
                tier: strong ? null : EvidenceTier.WeakIndicator, severity: strong ? null : Severity.Low, confidence: strong ? 80 : 40,
                signature: $"{invalid.Count} class entries without CAFEBABE");
        }

        foreach (var exe in jar.AllExecutables().Where(e => e.Disguised || e.Entry.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)).Take(5))
        {
            ctx.Report(Builtin.EmbeddedExecutable, [file, exe.Entry],
                exe.Disguised
                    ? $"\"{rec.Location}\" contains a Windows executable disguised as \"{exe.Entry}\" ({exe.Size:N0} bytes)."
                    : $"\"{rec.Location}\" contains the Windows program \"{exe.Entry}\" ({exe.Size:N0} bytes).",
                "Every archive entry is checked for a PE header regardless of its name; the image is also string-matched for injection indicators.",
                "Executables hidden inside a mod can be dropped and run (injectors, loaders) without appearing in the mods folder.",
                exe.Disguised ? "Rare: legitimate mods name their native libraries .dll." : "Some mods ship helper programs (updaters, browsers).",
                [fileEv, Entry(file, "Embedded executable", exe.Entry, new() { ["entry"] = exe.Entry, ["sizeBytes"] = exe.Size.ToString(), ["disguised"] = exe.Disguised.ToString() })],
                tier: exe.Disguised ? EvidenceTier.StrongIndicator : null, severity: exe.Disguised ? Severity.High : null, confidence: exe.Disguised ? 82 : null,
                signature: exe.Disguised ? "PE image with non-executable name" : "PE program inside archive");
        }

        if (!fullHeuristics) return;

        if (jar.ClassEntries.Count >= 25 && jar.ObfuscationRatio >= 0.6)
        {
            ctx.Report(Builtin.ObfuscatedArchive, [file],
                $"{jar.ObfuscatedClassCount} of {jar.ClassEntries.Count} classes in \"{rec.Location}\" ({jar.ObfuscationRatio:P0}) have one/two-character or non-ASCII names.",
                "Class-name analysis of the archive's own (non-nested) classes.",
                "Paid cheat clients are distributed heavily obfuscated to resist signature detection.",
                "Some closed-source legitimate mods are obfuscated as well.",
                [fileEv], signature: $"{jar.ObfuscationRatio:P0} obfuscated class names");
        }

        // Inconsistent metadata: referenced entrypoints / mixin configs that do not exist.
        var classSet = new HashSet<string>(classes.Select(c => c.Class), StringComparer.Ordinal);
        var missingEntrypoints = jar.Entrypoints.Select(e => e.Split("::")[0]).Where(e => e.Contains('.') && !classSet.Contains(e.Replace('.', '/'))).Distinct().ToList();
        var allEntries = new HashSet<string>(jar.EntryNames.Concat(jar.Nested.SelectMany(n => n.Info.EntryNames)), StringComparer.Ordinal);
        var missingMixins = jar.MixinConfigs.Where(m => !allEntries.Contains(m)).ToList();
        if (missingEntrypoints.Count > 0 || missingMixins.Count > 0)
        {
            ctx.Report(Builtin.MetadataInconsistent, [file],
                $"The metadata of \"{rec.Location}\" references " +
                string.Join(" and ", new[] { missingEntrypoints.Count > 0 ? $"entrypoint classes that are not in the archive ({string.Join(", ", missingEntrypoints.Take(4))})" : null, missingMixins.Count > 0 ? $"mixin configurations that are not in the archive ({string.Join(", ", missingMixins.Take(4))})" : null }.OfType<string>()) + ".",
                "fabric.mod.json entrypoints and mixin configurations cross-checked against the archive's entries (including nested archives).",
                "Metadata copied from another mod (to look legitimate) usually does not match the code actually shipped.",
                "Broken or partially stripped builds; entrypoints provided by another mod.",
                [fileEv], signature: "metadata/content mismatch");
        }

        // Impersonation of a well-known mod: deferred until Modrinth verification has run.
        if (jar.Primary is { } pm && ctx.Rules.KnownMod(pm.Id) is { Packages.Count: > 0 } km && classes.Count > 0
            && !classes.Any(c => km.Packages.Any(p => c.Class.StartsWith(p, StringComparison.Ordinal))))
            rec.PendingImpersonation = km;

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
        "org.spongepowered.tools.agent.MixinAgent",
    };

    /// <summary>Checks that must not fire for archives verified as published mods; run after Modrinth verification.</summary>
    internal static void DeferredChecks(ScanContext ctx, ModRecord rec)
    {
        var jar = rec.Jar;
        if (jar is null) return;
        var name = rec.FileName;
        var verified = rec.ModrinthProject is not null;

        if (rec.PendingImpersonation is { } km && !verified)
        {
            var pm = jar.Primary!;
            ctx.Report(Builtin.ModImpersonation, [rec.Path, km.Pattern],
                $"\"{rec.Location}\" declares the mod id \"{pm.Id}\" ({km.Name}) but contains none of the packages genuine {km.Name} builds ship ({string.Join(", ", km.Packages.Select(p => p.Replace('/', '.').TrimEnd('.')))}). Its classes are under: {string.Join(", ", jar.AllClasses().Select(c => c.Class.Contains('/') ? c.Class[..c.Class.LastIndexOf('/')] : c.Class).Distinct().Take(5))}.",
                "Declared mod id compared with the class packages expected for that mod in the known-mods database (Modrinth-verified archives excluded).",
                "Cheat clients adopt the id of a popular mod so that mod lists and logs look harmless.",
                "An unofficial fork re-packaged under a new namespace.",
                [ctx.FileEvidence(rec.Path, rec.Origin), Entry(rec.Path, pm.Loader + " metadata", $"mod id \"{pm.Id}\"", new() { ["declaredModId"] = pm.Id, ["expectedPackages"] = string.Join(", ", km.Packages) })],
                family: null, signature: $"mod id \"{pm.Id}\" without {km.Packages[0].Replace('/', '.').TrimEnd('.')}");
            rec.Classification = "suspicious";
        }

        // Generic indicator combinations are not reported for verified or genuinely known mods.
        var genuineKnown = rec.PendingImpersonation is null && rec.Classification is not ("unrecognised" or "suspicious" or "prohibited" or "restricted");
        if (!verified && !genuineKnown)
            foreach (var g in rec.PendingIndicators)
                ReportGroup(ctx, g, rec.Path, rec.Origin, null, null, rec.Disabled);

        if (rec.PendingAgent is { } ag && !verified)
        {
            ctx.Report(Builtin.JavaAgentManifest, [rec.Path],
                $"\"{rec.Location}\" declares a Java agent entry point ({ag.Key}: {ag.Value}).",
                "META-INF/MANIFEST.MF inspection for Premain-Class, Agent-Class and Launcher-Agent-Class attributes (well-known library agents and Modrinth-verified archives excluded).",
                "Java agents can be attached to the running game and rewrite Minecraft classes in memory, which is how several injectable clients operate without a mod loader.",
                "Profilers, debuggers and a few developer tools ship agent manifests.",
                [ag.Ev, Entry(rec.Path, "JAR manifest", $"META-INF/MANIFEST.MF {ag.Key}", new() { [ag.Key] = ag.Value })],
                signature: $"{ag.Key}: {ag.Value}");
        }

        // Disguise: file name starts with a well-known mod id but the metadata declares something unrelated.
        if (!rec.DisguiseCheckPending || verified || jar.Primary is not { } p) return;
        static string Norm(string x) => x.ToLowerInvariant().Replace("-", "").Replace("_", "").Replace(" ", "");
        var lowerName = name.ToLowerInvariant();
        var ids = jar.AllMetadata().ToList();
        if (ids.Any(i => ctx.Rules.KnownMod(i.Id) is not null)) return; // it declares a known mod itself (impersonation is checked separately)
        foreach (var known in ctx.Rules.OfKind(RuleKind.KnownMod).Where(k => k.Pattern.Length >= 4 && k.Classification != "library"))
        {
            var token = known.Pattern.ToLowerInvariant();
            if (!lowerName.StartsWith(token, StringComparison.Ordinal) || lowerName.Length <= token.Length || char.IsLetterOrDigit(lowerName[token.Length])) continue;
            if (ids.Any(i => Norm(i.Id).Contains(Norm(token)) || Norm(token).Contains(Norm(i.Id)))) return;
            ctx.Report(Builtin.DisguisedArchive, [rec.Path, token],
                $"\"{rec.Location}\" is named like {known.Name} (\"{token}\") but its metadata declares \"{p.Id}\"{(p.Name is null ? "" : $" ({p.Name})")}.",
                "Comparison of the file name against the archive's declared mod ids, for file names beginning with a known mod id (archives published on Modrinth are excluded).",
                "Renaming a cheat client to look like a popular performance mod is a common way to evade a visual inspection of the mods folder.",
                "Repackaged forks or modpack builds sometimes keep upstream file names.",
                [ctx.FileEvidence(rec.Path, rec.Origin), Entry(rec.Path, p.Loader + " metadata", $"declared mod id \"{p.Id}\"", new() { ["fileNameClaims"] = token, ["declaredModId"] = p.Id })],
                signature: $"file name \"{token}…\" vs mod id \"{p.Id}\"");
            return;
        }
    }

    private static void DuplicateIds(ScanContext ctx)
    {
        foreach (var g in ctx.Mods.Where(m => !m.Disabled && m.ModId is not null && m.Origin == "Mods folder")
                     .GroupBy(m => (Folder: Path.GetDirectoryName(m.Path)!.ToLowerInvariant(), Id: m.ModId!.ToLowerInvariant()))
                     .Where(g => g.Count() > 1))
        {
            ctx.Report(Builtin.DuplicateModId, [g.Key.Folder, g.Key.Id],
                $"{g.Count()} archives in {ctx.Location(g.First().Path)[..^g.First().FileName.Length].TrimEnd('/')} declare the mod id \"{g.Key.Id}\": {string.Join(", ", g.Select(m => m.FileName))}.",
                "Cross-reference of declared mod ids in the mods folder.",
                "A second archive claiming an existing mod's id can be a swapped or disguised copy.",
                "An old version left next to an update; mod loaders refuse to start with duplicates.",
                g.Select(m => ctx.FileEvidence(m.Path, "Mod archive")).ToList(), signature: $"duplicate mod id \"{g.Key.Id}\"");
        }
    }

    private static async Task VerifyWithModrinthAsync(ScanContext ctx, CancellationToken ct)
    {
        if (!ctx.Options.ModrinthLookup || ctx.Options.Http is null) return;
        var candidates = ctx.Mods.Where(m => m.Classification == "unrecognised" || m.PendingImpersonation is not null).ToList();
        if (candidates.Count == 0) return;
        ctx.SetActivity("Checking mod fingerprints against Modrinth…");
        foreach (var m in candidates)
        {
            try
            {
                await using var fs = ctx.OpenRead(m.Path);
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
                if (m.Classification == "unrecognised") m.Classification = "published (Modrinth)";
                m.ModrinthProject = titles.GetValueOrDefault(pid, pid);
            }
            ctx.Statistics["modrinthVerified"] = candidates.Count(c => c.ModrinthProject is not null);
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException or JsonException)
        {
            if (ct.IsCancellationRequested) throw;
            ctx.Custody.Record("modrinth-hash-lookup-failed", e.Message);
        }
    }

    private static void ReportUnrecognised(ScanContext ctx)
    {
        foreach (var m in ctx.Mods.Where(m => m.Classification == "unrecognised" && m.Origin != "Class path"))
        {
            ctx.Report(Builtin.UnrecognizedMod, [m.Path],
                $"\"{m.Location}\" ({m.ModId ?? "no mod metadata"}) is not in the database of known mods" + (ctx.Options.ModrinthLookup ? " and its hash is not published on Modrinth." : "."),
                "Known-mod database lookup by declared mod id" + (ctx.Options.ModrinthLookup ? " and SHA-512 lookup against the public Modrinth registry." : "."),
                "Listed so the investigator can review it manually. Unrecognised does not mean malicious; every signature and heuristic was still applied to it.",
                "Niche, private, CurseForge-only or self-built mods are commonly unrecognised.",
                [ctx.FileEvidence(m.Path, m.Origin, new() { ["modId"] = m.ModId ?? "", ["name"] = m.Jar?.Primary?.Name ?? "", ["version"] = m.Jar?.Primary?.Version ?? "", ["loader"] = m.Jar?.Primary?.Loader ?? "" })],
                signature: "no known-mod or Modrinth match");
        }
    }
}
