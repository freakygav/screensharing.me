using System.IO.Compression;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Screensharing.Scanner.Analysis;

public sealed record ModMetadata(string Loader, string Id, string? Name, string? Version);

public sealed class JarInfo
{
    public List<ModMetadata> Metadata { get; } = [];
    public ModMetadata? Primary => Metadata.FirstOrDefault();
    public List<string> ClassEntries { get; } = [];
    public Dictionary<string, string> Manifest { get; } = new(StringComparer.OrdinalIgnoreCase);
    public List<(string EntryName, JarInfo Info)> Nested { get; } = [];
    public int ObfuscatedClassCount { get; set; }
    public bool Malformed { get; set; }
    public string? Error { get; set; }

    public double ObfuscationRatio => ClassEntries.Count == 0 ? 0 : (double)ObfuscatedClassCount / ClassEntries.Count;

    /// <summary>All metadata ids including nested (Jar-in-Jar) archives.</summary>
    public IEnumerable<ModMetadata> AllMetadata() => Metadata.Concat(Nested.SelectMany(n => n.Info.AllMetadata()));

    /// <summary>Class entries including nested archives, prefixed with the nested entry name.</summary>
    public IEnumerable<(string Container, string Class)> AllClasses(string container = "")
    {
        foreach (var c in ClassEntries) yield return (container, c);
        foreach (var (name, info) in Nested)
            foreach (var x in info.AllClasses(container.Length == 0 ? name : container + "!/" + name))
                yield return x;
    }
}

/// <summary>
/// Static analysis of Java archives (mods, clients, agents). Nothing is executed or extracted to disk.
/// </summary>
public static class JarAnalyzer
{
    private const int MaxNestedDepth = 2;
    private const long MaxNestedBytes = 64L * 1024 * 1024;
    private const int MaxClassEntries = 200_000;
    private static readonly JsonDocumentOptions JsonOpts = new() { AllowTrailingCommas = true, CommentHandling = JsonCommentHandling.Skip };

    public static bool LooksLikeZip(string path)
    {
        try
        {
            using var fs = Engine.ScanContext.OpenRead(path);
            Span<byte> head = stackalloc byte[4];
            return fs.Read(head) == 4 && head[0] == 0x50 && head[1] == 0x4B && head[2] == 0x03 && head[3] == 0x04;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return false; }
    }

    public static JarInfo Analyze(string path)
    {
        try
        {
            using var fs = Engine.ScanContext.OpenRead(path);
            return Analyze(fs, 0);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return new JarInfo { Malformed = true, Error = e.Message };
        }
    }

    public static JarInfo Analyze(Stream stream, int depth = 0)
    {
        var info = new JarInfo();
        try
        {
            using var zip = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: true);
            foreach (var e in zip.Entries)
            {
                var name = e.FullName.Replace('\\', '/');
                if (name.EndsWith(".class", StringComparison.OrdinalIgnoreCase))
                {
                    if (info.ClassEntries.Count < MaxClassEntries)
                    {
                        var cls = name[..^6];
                        info.ClassEntries.Add(cls);
                        if (IsObfuscatedName(cls)) info.ObfuscatedClassCount++;
                    }
                    continue;
                }
                switch (name)
                {
                    case "fabric.mod.json": ReadFabric(e, info); break;
                    case "quilt.mod.json": ReadQuilt(e, info); break;
                    case "META-INF/mods.toml": ReadToml(e, info, "forge"); break;
                    case "META-INF/neoforge.mods.toml": ReadToml(e, info, "neoforge"); break;
                    case "mcmod.info": ReadMcmod(e, info); break;
                    case "META-INF/MANIFEST.MF": ReadManifest(e, info); break;
                }
                if (depth < MaxNestedDepth && name.EndsWith(".jar", StringComparison.OrdinalIgnoreCase) && e.Length is > 0 and < MaxNestedBytes)
                {
                    using var es = e.Open();
                    var ms = new MemoryStream((int)e.Length);
                    es.CopyTo(ms);
                    ms.Position = 0;
                    info.Nested.Add((name, Analyze(ms, depth + 1)));
                }
            }
        }
        catch (Exception e) when (e is InvalidDataException or IOException or NotSupportedException)
        {
            info.Malformed = true;
            info.Error = e.Message;
        }
        return info;
    }

    /// <summary>One- or two-character simple class names, or names with non-ASCII characters, typical of obfuscators.</summary>
    internal static bool IsObfuscatedName(string classPath)
    {
        var simple = classPath[(classPath.LastIndexOf('/') + 1)..];
        var outer = simple.Split('$')[0];
        if (outer is "package-info" or "module-info") return false;
        if (outer.Any(c => c > 0x7F)) return true;
        return outer.Length <= 2;
    }

    private static string ReadText(ZipArchiveEntry e, int max = 1 << 20)
    {
        using var s = e.Open();
        using var r = new StreamReader(s, Encoding.UTF8);
        var buf = new char[Math.Min(max, (int)Math.Max(1, Math.Min(e.Length, max)))];
        var n = r.ReadBlock(buf, 0, buf.Length);
        return new string(buf, 0, n);
    }

    private static string? Str(JsonElement el, string prop) =>
        el.ValueKind == JsonValueKind.Object && el.TryGetProperty(prop, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    private static void ReadFabric(ZipArchiveEntry e, JarInfo info)
    {
        try
        {
            using var doc = JsonDocument.Parse(ReadText(e), JsonOpts);
            var id = Str(doc.RootElement, "id");
            if (!string.IsNullOrWhiteSpace(id)) info.Metadata.Add(new ModMetadata("fabric", id!, Str(doc.RootElement, "name"), Str(doc.RootElement, "version")));
        }
        catch (JsonException) { info.Malformed = true; }
    }

    private static void ReadQuilt(ZipArchiveEntry e, JarInfo info)
    {
        try
        {
            using var doc = JsonDocument.Parse(ReadText(e), JsonOpts);
            if (!doc.RootElement.TryGetProperty("quilt_loader", out var ql)) return;
            var id = Str(ql, "id");
            var meta = ql.TryGetProperty("metadata", out var m) ? m : default;
            if (!string.IsNullOrWhiteSpace(id)) info.Metadata.Add(new ModMetadata("quilt", id!, meta.ValueKind == JsonValueKind.Object ? Str(meta, "name") : null, Str(ql, "version")));
        }
        catch (JsonException) { info.Malformed = true; }
    }

    private static readonly Regex TomlMod = new(@"\[\[\s*mods\s*\]\](?<body>.*?)(?=\[\[|\z)", RegexOptions.Singleline | RegexOptions.CultureInvariant);
    private static readonly Regex TomlKey = new(@"^\s*(?<k>modId|displayName|version)\s*=\s*[""'](?<v>[^""']*)[""']", RegexOptions.Multiline | RegexOptions.CultureInvariant);

    private static void ReadToml(ZipArchiveEntry e, JarInfo info, string loader)
    {
        foreach (Match m in TomlMod.Matches(ReadText(e)))
        {
            string? id = null, name = null, ver = null;
            foreach (Match kv in TomlKey.Matches(m.Groups["body"].Value))
            {
                switch (kv.Groups["k"].Value)
                {
                    case "modId": id = kv.Groups["v"].Value; break;
                    case "displayName": name = kv.Groups["v"].Value; break;
                    case "version": ver = kv.Groups["v"].Value; break;
                }
            }
            if (!string.IsNullOrWhiteSpace(id)) info.Metadata.Add(new ModMetadata(loader, id!, name, ver));
        }
    }

    private static void ReadMcmod(ZipArchiveEntry e, JarInfo info)
    {
        try
        {
            using var doc = JsonDocument.Parse(ReadText(e), JsonOpts);
            var arr = doc.RootElement.ValueKind == JsonValueKind.Array ? doc.RootElement
                : doc.RootElement.TryGetProperty("modList", out var ml) ? ml : default;
            if (arr.ValueKind != JsonValueKind.Array) return;
            foreach (var m in arr.EnumerateArray())
            {
                var id = Str(m, "modid");
                if (!string.IsNullOrWhiteSpace(id)) info.Metadata.Add(new ModMetadata("forge-legacy", id!, Str(m, "name"), Str(m, "version")));
            }
        }
        catch (JsonException) { info.Malformed = true; }
    }

    private static void ReadManifest(ZipArchiveEntry e, JarInfo info)
    {
        string? key = null;
        foreach (var raw in ReadText(e, 256 * 1024).Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            if (line.StartsWith(' ') && key is not null) { info.Manifest[key] += line[1..]; continue; }
            var idx = line.IndexOf(':');
            if (idx <= 0) { key = null; continue; }
            key = line[..idx].Trim();
            info.Manifest[key] = line[(idx + 1)..].Trim();
        }
    }
}
