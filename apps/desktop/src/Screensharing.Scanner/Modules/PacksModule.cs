using System.IO.Compression;
using System.Text.Json;
using Screensharing.Scanner.Analysis;
using Screensharing.Scanner.Engine;
using Screensharing.Scanner.Model;

namespace Screensharing.Scanner.Modules;

/// <summary>Resource and shader packs: name signatures, content-based X-ray detection, string signatures and hidden code.</summary>
public sealed class PacksModule : IScanModule
{
    public string Key => "packs";
    public string Name => "Resource & shader packs";
    public string Activity => "Examining resource and shader packs…";
    public string? SkipReason(ScanContext ctx) => null;

    private readonly List<InstanceFile> _packs = [];

    /// <summary>Terrain blocks that hide ores; an X-ray pack makes these transparent or empty.</summary>
    internal static readonly string[] TerrainBlocks =
        ["stone", "deepslate", "dirt", "netherrack", "andesite", "diorite", "granite", "tuff", "cobblestone", "gravel", "sand", "grass_block_side", "end_stone", "blackstone", "basalt_side", "calcite", "cobbled_deepslate", "soul_sand", "soul_soil"];

    public int Plan(ScanContext ctx)
    {
        _packs.Clear();
        _packs.AddRange(ctx.FilesOf(FileRole.ResourcePack, FileRole.ShaderPack));
        return _packs.Count + 1;
    }

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        var active = ActivePacks(ctx);
        foreach (var p in _packs)
        {
            ct.ThrowIfCancellationRequested();
            ctx.SetActivity($"Examining packs… {p.GamePath}");
            Inspect(ctx, p, active, ct);
            ctx.Advance();
        }
        ctx.Statistics["resourcePacks"] = _packs.Count(p => p.Role == FileRole.ResourcePack);
        ctx.Statistics["shaderPacks"] = _packs.Count(p => p.Role == FileRole.ShaderPack);
        if (ctx.CurrentCategory is not null)
            ctx.CurrentCategory.Message = $"{_packs.Count(p => p.Role == FileRole.ResourcePack)} resource packs ({active.Count} enabled in options.txt), {_packs.Count(p => p.Role == FileRole.ShaderPack)} shader packs";
        ctx.Advance();
        return Task.CompletedTask;
    }

    /// <summary>Enabled resource packs from options.txt (resourcePacks:["vanilla","file/xray.zip"]).</summary>
    private static HashSet<string> ActivePacks(ScanContext ctx)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var options = Path.Combine(ctx.Instance.GameDirectory, "options.txt");
        if (!ctx.Scope.Contains(options) || !File.Exists(options)) return set;
        try
        {
            using var fs = ctx.OpenRead(options);
            using var r = new StreamReader(fs);
            while (r.ReadLine() is { } line)
            {
                if (!line.StartsWith("resourcePacks:", StringComparison.Ordinal)) continue;
                using var doc = JsonDocument.Parse(line[14..]);
                foreach (var e in doc.RootElement.EnumerateArray())
                    if (e.GetString() is { } s && s.StartsWith("file/", StringComparison.Ordinal)) set.Add(s[5..]);
            }
            ctx.Custody.Record("read-config", options);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or JsonException or InvalidOperationException) { }
        return set;
    }

    private interface IPack : IDisposable
    {
        IEnumerable<string> Entries { get; }
        byte[]? Read(string entry, long max = 4 * 1024 * 1024);
    }

    private sealed class ZipPack(ZipArchive zip) : IPack
    {
        public IEnumerable<string> Entries => zip.Entries.Select(e => e.FullName.Replace('\\', '/'));
        public byte[]? Read(string entry, long max)
        {
            var e = zip.GetEntry(entry);
            if (e is null || e.Length > max || e.IsEncrypted) return null;
            using var s = e.Open();
            var buf = new byte[e.Length];
            s.ReadExactly(buf);
            return buf;
        }
        public void Dispose() => zip.Dispose();
    }

    private sealed class FolderPack(ScanContext ctx, string root) : IPack
    {
        public IEnumerable<string> Entries
        {
            get
            {
                // Bounded walk of the pack folder (only names are needed).
                var list = new List<string>();
                var stack = new Stack<(string Dir, string Rel, int Depth)>();
                stack.Push((root, "", 0));
                while (stack.Count > 0 && list.Count < 50_000)
                {
                    var (dir, rel, depth) = stack.Pop();
                    foreach (var f in ctx.Fs.Files(dir)) list.Add(rel + Path.GetFileName(f));
                    if (depth < 8) foreach (var d in ctx.Fs.Directories(dir)) stack.Push((d, rel + Path.GetFileName(d) + "/", depth + 1));
                }
                return list;
            }
        }
        public byte[]? Read(string entry, long max)
        {
            var path = Path.Combine(root, entry.Replace('/', '\\'));
            if (!ctx.Scope.Contains(path) || !File.Exists(path) || new FileInfo(path).Length > max) return null;
            using var fs = ctx.OpenRead(path);
            var buf = new byte[fs.Length];
            fs.ReadExactly(buf);
            return buf;
        }
        public void Dispose() { }
    }

    private static void Inspect(ScanContext ctx, InstanceFile p, HashSet<string> active, CancellationToken ct)
    {
        var name = Path.GetFileName(p.Path.TrimEnd('\\'));
        var enabled = active.Contains(name);
        var shader = p.Role == FileRole.ShaderPack;
        Evidence PackEvidence(Dictionary<string, string>? extra = null)
        {
            var details = new Dictionary<string, string>(extra ?? []) { ["enabledInOptions"] = shader ? "n/a" : enabled.ToString() };
            return p.IsDirectory
                ? new Evidence { Kind = EvidenceKind.File, Source = shader ? "Shader pack folder" : "Resource pack folder", Reference = p.Path, ModifiedTime = Directory.GetLastWriteTimeUtc(p.Path), Details = details }
                : ctx.FileEvidence(p.Path, shader ? "Shader pack" : "Resource pack", details);
        }

        foreach (var r in ctx.Rules.OfKind(shader ? RuleKind.ShaderPackRegex : RuleKind.ResourcePackRegex).Where(r => r.IsMatch(name)))
            ctx.Report(r.Id, [p.Path],
                $"{(shader ? "Shader" : "Resource")} pack \"{p.GamePath}\" matches \"{r.Family ?? r.Name}\"{(shader ? "" : enabled ? " and is enabled in options.txt" : " (not enabled in options.txt)")}.",
                "Pack name compared with the pack-name signature database.",
                r.Description,
                "Pack names are user-controlled; the content check below is independent of the name.",
                [PackEvidence()], signature: $"pack name \"{name}\"", location: p.GamePath);

        if (!p.IsDirectory && p.Size > ctx.Options.MaxArchiveBytes) { ctx.Uninspectable(p.Path, p.Role, InspectionStatus.TooLarge, "pack is above the archive size limit", report: false); return; }

        IPack pack;
        try
        {
            if (p.IsDirectory) pack = new FolderPack(ctx, p.Path);
            else
            {
                var fs = ctx.OpenRead(p.Path);
                if (JarAnalyzer.Probe(fs) == ArchiveKind.NotArchive) { fs.Dispose(); ctx.NotApplicable(p.Path, p.Role, "not a ZIP pack"); return; }
                fs.Position = 0;
                var zs = JarAnalyzer.Tolerant(fs, ctx.Options.MaxArchiveBytes, out _);
                if (!ReferenceEquals(zs, fs)) fs.Dispose();
                pack = new ZipPack(new ZipArchive(zs, ZipArchiveMode.Read));
            }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            ctx.Uninspectable(p.Path, p.Role, InspectionStatus.Corrupt, $"the pack could not be opened ({e.Message})", report: false);
            return;
        }
        using (pack)
        {
            ctx.Custody.Record("read-pack", p.Path);
            var entries = pack.Entries.ToList();
            ct.ThrowIfCancellationRequested();

            // Code hidden in a pack: analyse it like a mod.
            if (entries.Any(e => e.EndsWith(".class", StringComparison.OrdinalIgnoreCase)) && !p.IsDirectory)
                ModsModule.AnalyzeArchive(ctx, p.Path, shader ? "Shader pack" : "Resource pack", FileRole.Archive, ct);

            // String signatures in text resources.
            var texts = entries.Where(e => e.EndsWith(".json", StringComparison.OrdinalIgnoreCase) || e.EndsWith(".mcmeta", StringComparison.OrdinalIgnoreCase) || e.EndsWith(".txt", StringComparison.OrdinalIgnoreCase) || e.EndsWith(".properties", StringComparison.OrdinalIgnoreCase)).Take(5000);
            var hits = new List<SignatureHit>();
            foreach (var t in texts)
                if (pack.Read(t, 1024 * 1024) is { } data) hits.AddRange(ctx.Signatures.Match(SignatureScope.Resource, data, t));
            foreach (var g in EvidenceScoring.Score(hits.Select(h => new Indicator(h.Rule, new Evidence { Kind = EvidenceKind.JarEntry, Source = "Pack resource", Reference = $"{p.Path}!/{h.Where}", Details = new() { ["string"] = h.Rule.Pattern } }, $"contains \"{h.Rule.Pattern}\" in {h.Where}", $"string \"{h.Rule.Pattern}\""))).Where(g => g.Report && g.Tier != EvidenceTier.Inconclusive))
                ctx.Report(g.Primary.Id, [p.Path, g.Family], $"Pack \"{p.GamePath}\" {string.Join("; ", g.Indicators.Select(i => i.What).Take(5))}.",
                    "String-signature matching of the pack's text resources.", g.Primary.Description, "Packs can mention client names without containing the client.",
                    [PackEvidence(), .. g.Indicators.Select(i => i.Evidence)], tier: g.Tier, confidence: g.Confidence,
                    signature: string.Join(" + ", g.Indicators.Select(i => i.Signature).Take(4)), location: p.GamePath);

            if (!shader) XrayTextures(ctx, p, pack, entries, enabled, PackEvidence);
        }
        ctx.Analyzed(p.Path, p.Role);
    }

    private static void XrayTextures(ScanContext ctx, InstanceFile p, IPack pack, List<string> entries, bool enabled, Func<Dictionary<string, string>?, Evidence> packEvidence)
    {
        var byLower = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var e in entries) byLower.TryAdd(e, e);
        byte[]? Read(string entry, long max = 512 * 1024) => byLower.TryGetValue(entry, out var real) ? pack.Read(real, max) : null;

        var transparent = new List<string>();
        var hollow = new List<string>();
        var fullbright = 0;
        foreach (var block in TerrainBlocks)
        {
            foreach (var tex in new[] { $"assets/minecraft/textures/block/{block}.png", $"assets/minecraft/textures/blocks/{block}.png" })
                if (Read(tex, 1024 * 1024) is { } png && PngAlpha.TransparentFraction(png) is >= 0.9) { transparent.Add(block); break; }

            // The model the block actually renders with: blockstate variant -> model -> parents (inside the pack).
            var modelName = BlockstateModel(Read($"assets/minecraft/blockstates/{block}.json")) ?? $"minecraft:block/{block}";
            var geometry = ResolveGeometry(Read, modelName, 0, out var emits);
            if (emits) fullbright++;
            if (geometry is { } elements && IsSeeThrough(elements)) hollow.Add(block);
        }
        var hidden = transparent.Union(hollow).Distinct().ToList();
        if (hidden.Count < 2) return;
        var strong = hidden.Count >= 3;
        var how = new List<string>();
        if (transparent.Count > 0) how.Add($"transparent textures: {string.Join(", ", transparent.Take(8))}");
        if (hollow.Count > 0) how.Add($"empty or outline-only block models: {string.Join(", ", hollow.Take(8))}");
        ctx.Report(Builtin.XrayTextures, [p.Path],
            $"Resource pack \"{p.GamePath}\" makes {hidden.Count} terrain blocks see-through ({string.Join("; ", how)}){(fullbright > 0 ? $"; {fullbright} also emit full light" : "")}{(enabled ? ". It is enabled in options.txt." : ". It is not enabled in options.txt at the moment.")}",
            "For common terrain blocks the pack's blockstates, block models (with their parent chain) and textures were resolved: PNG alpha decoded (≥90% transparent pixels) and model geometry measured (no elements, or only slivers ≤2/16 thick, renders the block hollow).",
            "Making stone and other terrain transparent or hollow while ores stay solid is how X-ray resource packs work. This check reads the pack's content, so renaming the pack does not hide it.",
            "Creative/map-making packs occasionally hide blocks on purpose.",
            [packEvidence(new() { ["transparentTextures"] = string.Join(", ", transparent), ["hollowModels"] = string.Join(", ", hollow), ["fullbrightBlocks"] = fullbright.ToString() })],
            tier: strong ? null : EvidenceTier.WeakIndicator, severity: strong ? null : Severity.Low, confidence: strong ? (hidden.Count >= 5 ? 92 : 85) : 45,
            family: "X-ray", signature: $"{hidden.Count} see-through terrain blocks", location: p.GamePath);
    }

    private static JsonDocumentOptions JsonOpts => new() { AllowTrailingCommas = true, CommentHandling = JsonCommentHandling.Skip };

    /// <summary>First model referenced by a blockstate file (variants or multipart).</summary>
    private static string? BlockstateModel(byte[]? json)
    {
        if (json is null) return null;
        try
        {
            using var doc = JsonDocument.Parse(json, JsonOpts);
            var root = doc.RootElement;
            JsonElement first = default;
            if (root.TryGetProperty("variants", out var v) && v.ValueKind == JsonValueKind.Object)
                first = v.EnumerateObject().Select(x => x.Value).FirstOrDefault();
            else if (root.TryGetProperty("multipart", out var mp) && mp.ValueKind == JsonValueKind.Array && mp.GetArrayLength() > 0 && mp[0].TryGetProperty("apply", out var ap))
                first = ap;
            if (first.ValueKind == JsonValueKind.Array && first.GetArrayLength() > 0) first = first[0];
            return first.ValueKind == JsonValueKind.Object && first.TryGetProperty("model", out var m) ? m.GetString() : null;
        }
        catch (Exception e) when (e is JsonException or InvalidOperationException) { return null; }
    }

    private sealed record Box(double[] From, double[] To);

    /// <summary>
    /// Elements of a model, following parents defined inside the pack. Null when the geometry comes from a vanilla
    /// model the pack does not override (i.e. a normal solid block).
    /// </summary>
    private static List<Box>? ResolveGeometry(Func<string, long, byte[]?> read, string model, int depth, out bool emitsLight)
    {
        emitsLight = false;
        if (depth > 8) return null;
        var name = model.Contains(':') ? model : "minecraft:" + model;
        var ns = name[..name.IndexOf(':')];
        var path = name[(name.IndexOf(':') + 1)..];
        var json = read($"assets/{ns}/models/{path}.json", 512 * 1024);
        if (json is null) return null;
        try
        {
            using var doc = JsonDocument.Parse(json, JsonOpts);
            var root = doc.RootElement;
            if (root.TryGetProperty("elements", out var els) && els.ValueKind == JsonValueKind.Array)
            {
                var boxes = new List<Box>();
                foreach (var el in els.EnumerateArray())
                {
                    if (el.TryGetProperty("light_emission", out var le) && le.ValueKind == JsonValueKind.Number && le.GetDouble() >= 10) emitsLight = true;
                    if (!el.TryGetProperty("from", out var f) || !el.TryGetProperty("to", out var t) || f.GetArrayLength() != 3 || t.GetArrayLength() != 3) continue;
                    var from = f.EnumerateArray().Select(x => x.GetDouble()).ToArray();
                    var to = t.EnumerateArray().Select(x => x.GetDouble()).ToArray();
                    // Faceless elements render nothing.
                    if (el.TryGetProperty("faces", out var faces) && faces.ValueKind == JsonValueKind.Object && !faces.EnumerateObject().Any()) continue;
                    boxes.Add(new Box(from, to));
                }
                return boxes;
            }
            if (root.TryGetProperty("parent", out var parent) && parent.GetString() is { } pn)
            {
                var g = ResolveGeometry(read, pn, depth + 1, out var e2);
                emitsLight = e2;
                return g;
            }
        }
        catch (Exception e) when (e is JsonException or InvalidOperationException or FormatException) { }
        return null;
    }

    /// <summary>No geometry, or only thin slivers (every element ≤ 2/16 thick in some axis) — the block renders hollow.</summary>
    private static bool IsSeeThrough(List<Box> elements) =>
        elements.Count == 0 || elements.All(b => Enumerable.Range(0, 3).Any(i => Math.Abs(b.To[i] - b.From[i]) <= 2.0));
}
