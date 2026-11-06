using System.IO.Compression;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Screensharing.Scanner.Model;

namespace Screensharing.Scanner.Analysis;

public sealed record ModMetadata(string Loader, string Id, string? Name, string? Version);

public sealed record EmbeddedExecutable(string Entry, long Size, bool Disguised);

public sealed class JarInfo
{
    public List<ModMetadata> Metadata { get; } = [];
    public ModMetadata? Primary => Metadata.FirstOrDefault();
    public List<string> ClassEntries { get; } = [];
    public HashSet<string> EntryNames { get; } = new(StringComparer.Ordinal);
    public Dictionary<string, string> Manifest { get; } = new(StringComparer.OrdinalIgnoreCase);
    public List<(string EntryName, JarInfo Info)> Nested { get; } = [];
    public int ObfuscatedClassCount { get; set; }
    /// <summary>*.class entries that are not valid class files (encrypted or disguised data).</summary>
    public List<string> InvalidClasses { get; } = [];
    public List<EmbeddedExecutable> Executables { get; } = [];
    public List<SignatureHit> Hits { get; } = [];
    public List<string> Entrypoints { get; } = [];
    public List<string> MixinConfigs { get; } = [];
    public int EncryptedEntries { get; set; }
    /// <summary>Entries whose content was not inspected, with the reason.</summary>
    public List<(string Entry, string Reason)> Skipped { get; } = [];
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

    public IEnumerable<SignatureHit> AllHits() => Hits.Concat(Nested.SelectMany(n => n.Info.AllHits().Select(h => h with { Where = n.EntryName + "!/" + h.Where })));
    public IEnumerable<string> AllInvalidClasses(string container = "") =>
        InvalidClasses.Select(c => container.Length == 0 ? c : container + "!/" + c)
            .Concat(Nested.SelectMany(n => n.Info.AllInvalidClasses(container.Length == 0 ? n.EntryName : container + "!/" + n.EntryName)));
    public IEnumerable<EmbeddedExecutable> AllExecutables(string container = "") =>
        Executables.Select(e => container.Length == 0 ? e : e with { Entry = container + "!/" + e.Entry })
            .Concat(Nested.SelectMany(n => n.Info.AllExecutables(container.Length == 0 ? n.EntryName : container + "!/" + n.EntryName)));
    public int AllEncrypted() => EncryptedEntries + Nested.Sum(n => n.Info.AllEncrypted());
    public IEnumerable<(string Entry, string Reason)> AllSkipped() => Skipped.Concat(Nested.SelectMany(n => n.Info.AllSkipped().Select(s => (n.EntryName + "!/" + s.Entry, s.Reason))));
    public bool AnyMalformed() => Malformed || Nested.Any(n => n.Info.AnyMalformed());
}

public enum ArchiveKind { NotArchive, Zip, ExecutableWithZip, ZipWithPrefix }

/// <summary>
/// Static analysis of Java archives (mods, clients, agents). Entries are read into memory only; nothing is
/// extracted to disk or executed.
/// </summary>
public static class JarAnalyzer
{
    private const int MaxNestedDepth = 3;
    private const long MaxNestedBytes = 96L * 1024 * 1024;
    private const int MaxClassEntries = 250_000;
    private const long MaxEntryBytes = 16L * 1024 * 1024;
    private static readonly JsonDocumentOptions JsonOpts = new() { AllowTrailingCommas = true, CommentHandling = JsonCommentHandling.Skip };

    private static readonly HashSet<string> TextResourceExtensions = new(StringComparer.OrdinalIgnoreCase)
        { ".json", ".json5", ".txt", ".properties", ".cfg", ".toml", ".yml", ".yaml", ".mf", ".xml", ".js", ".info", ".accesswidener", ".classtweaker" };
    private static readonly HashSet<string> NativeExtensions = new(StringComparer.OrdinalIgnoreCase) { ".dll", ".exe", ".sys", ".node" };

    public sealed class Options
    {
        public SignatureIndex? Signatures { get; init; }
        public IReadOnlyList<string> LibraryPackages { get; init; } = [];
        public CancellationToken Cancellation { get; init; }
        /// <summary>When false only names and metadata are read (fast path for verified libraries).</summary>
        public bool ReadContent { get; init; } = true;
    }

    /// <summary>Determines whether a file is a ZIP/JAR, including executables with an appended archive.</summary>
    public static ArchiveKind Probe(Stream s)
    {
        Span<byte> head = stackalloc byte[4];
        s.Position = 0;
        if (s.Read(head) < 4) return ArchiveKind.NotArchive;
        if (head[0] == 'P' && head[1] == 'K' && head[2] == 3 && head[3] == 4) return ArchiveKind.Zip;
        if (!HasEndOfCentralDirectory(s)) return ArchiveKind.NotArchive;
        return head[0] == 'M' && head[1] == 'Z' ? ArchiveKind.ExecutableWithZip : ArchiveKind.ZipWithPrefix;
    }

    /// <summary>
    /// Returns a stream .NET's ZIP reader accepts. Archives whose end-of-central-directory record carries non-zero
    /// "disk number" fields (written by some tools, and ignored by Java's own ZIP reader, so the game still loads them)
    /// are copied into memory with those fields cleared. The file on disk is never modified.
    /// </summary>
    public static Stream Tolerant(Stream s, long maxBytes, out bool normalized)
    {
        normalized = false;
        var len = s.Length;
        if (len < 22 || len > maxBytes) return s;
        var tail = (int)Math.Min(len, 65_557);
        var buf = new byte[tail];
        s.Position = len - tail;
        s.ReadExactly(buf);
        var at = -1;
        for (var i = tail - 22; i >= 0; i--)
            if (buf[i] == 'P' && buf[i + 1] == 'K' && buf[i + 2] == 5 && buf[i + 3] == 6) { at = i; break; }
        s.Position = 0;
        if (at < 0) return s;
        var disks = buf[at + 4] | buf[at + 5] | buf[at + 6] | buf[at + 7];
        int onDisk = BitConverter.ToUInt16(buf, at + 8), total = BitConverter.ToUInt16(buf, at + 10);
        var cdSize = BitConverter.ToUInt32(buf, at + 12);
        var cdOffset = BitConverter.ToUInt32(buf, at + 16);
        if (disks == 0 && onDisk == total && total != 0) return s;
        if (cdOffset == 0xFFFFFFFF || cdSize == 0xFFFFFFFF || cdOffset + (long)cdSize > len) return s; // ZIP64 or inconsistent: leave to the reader
        var ms = new MemoryStream((int)len);
        s.CopyTo(ms);
        var bytes = ms.GetBuffer();
        // Count the real central-directory records ("anti-unzip" archives zero these counts; Java ignores them).
        var count = 0;
        for (var i = (int)cdOffset; i + 4 <= cdOffset + cdSize; i++)
            if (bytes[i] == 'P' && bytes[i + 1] == 'K' && bytes[i + 2] == 1 && bytes[i + 3] == 2) count++;
        if (count == 0 || count > 0xFFFF) { s.Position = 0; return s; }
        var eocd = (int)(len - tail) + at;
        bytes[eocd + 4] = bytes[eocd + 5] = bytes[eocd + 6] = bytes[eocd + 7] = 0; // this disk, disk with central directory
        BitConverter.GetBytes((ushort)count).CopyTo(bytes, eocd + 8);
        BitConverter.GetBytes((ushort)count).CopyTo(bytes, eocd + 10);
        ms.Position = 0;
        normalized = true;
        return ms;
    }

    private static bool HasEndOfCentralDirectory(Stream s)
    {
        var len = s.Length;
        if (len < 22) return false;
        var tail = (int)Math.Min(len, 65_557);
        var buf = new byte[tail];
        s.Position = len - tail;
        var read = 0;
        while (read < tail) { var n = s.Read(buf, read, tail - read); if (n <= 0) break; read += n; }
        for (var i = read - 22; i >= 0; i--)
            if (buf[i] == 'P' && buf[i + 1] == 'K' && buf[i + 2] == 5 && buf[i + 3] == 6) return true;
        return false;
    }

    public static JarInfo Analyze(Stream stream, Options? options = null, int depth = 0)
    {
        options ??= new Options();
        var info = new JarInfo();
        try
        {
            using var zip = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: true);
            using var constants = new MemoryStream();
            foreach (var e in zip.Entries)
            {
                options.Cancellation.ThrowIfCancellationRequested();
                var name = e.FullName.Replace('\\', '/');
                info.EntryNames.Add(name);
                if (name.EndsWith('/')) continue;
                if (e.IsEncrypted) { info.EncryptedEntries++; info.Skipped.Add((name, "password-protected entry")); continue; }
                var isClass = name.EndsWith(".class", StringComparison.OrdinalIgnoreCase);
                if (isClass && info.ClassEntries.Count < MaxClassEntries)
                {
                    var cls = name[..^6];
                    info.ClassEntries.Add(cls);
                    if (IsObfuscatedName(cls)) info.ObfuscatedClassCount++;
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
                if (depth < MaxNestedDepth && name.EndsWith(".jar", StringComparison.OrdinalIgnoreCase))
                {
                    if (e.Length is > 0 and < MaxNestedBytes)
                    {
                        using var es = e.Open();
                        var ms = new MemoryStream((int)e.Length);
                        es.CopyTo(ms);
                        ms.Position = 0;
                        info.Nested.Add((name, Analyze(ms, options, depth + 1)));
                    }
                    else if (e.Length >= MaxNestedBytes) info.Skipped.Add((name, $"nested archive larger than {MaxNestedBytes / (1024 * 1024)} MiB"));
                    continue;
                }
                if (!options.ReadContent || e.Length == 0) continue;
                var ext = Path.GetExtension(name);
                var text = TextResourceExtensions.Contains(ext);
                if (!isClass && !text && e.Length < 64) continue;
                if (e.Length > MaxEntryBytes) { info.Skipped.Add((name, $"entry larger than {MaxEntryBytes / (1024 * 1024)} MiB")); continue; }
                byte[] data;
                try
                {
                    using var es = e.Open();
                    data = new byte[e.Length];
                    var read = 0;
                    while (read < data.Length) { var n = es.Read(data, read, data.Length - read); if (n <= 0) break; read += n; }
                    if (read < data.Length) data = data[..read];
                }
                catch (InvalidDataException) { info.Skipped.Add((name, "entry data is corrupt")); continue; }

                if (isClass)
                {
                    if (!ClassFile.HasMagic(data)) { info.InvalidClasses.Add(name); continue; }
                    if (options.Signatures?.Has(SignatureScope.Class) == true)
                    {
                        constants.SetLength(0);
                        if (ClassFile.ExtractUtf8Constants(data, constants))
                        {
                            var exempt = options.LibraryPackages.Any(p => name.StartsWith(p, StringComparison.Ordinal));
                            foreach (var h in options.Signatures.Match(SignatureScope.Class, constants.GetBuffer().AsSpan(0, (int)constants.Length), name))
                                if (!(exempt && h.Rule.IsIndicator)) info.Hits.Add(h);
                        }
                    }
                    continue;
                }
                if (data.Length >= 64 && data[0] == 'M' && data[1] == 'Z' && LooksLikePe(data))
                {
                    info.Executables.Add(new EmbeddedExecutable(name, data.Length, !NativeExtensions.Contains(ext)));
                    if (options.Signatures?.Has(SignatureScope.Binary) == true) info.Hits.AddRange(options.Signatures.Match(SignatureScope.Binary, data, name));
                    continue;
                }
                if (text && options.Signatures?.Has(SignatureScope.Resource) == true)
                    info.Hits.AddRange(options.Signatures.Match(SignatureScope.Resource, data, name));
            }
        }
        catch (Exception e) when (e is InvalidDataException or IOException or NotSupportedException or ArgumentException)
        {
            info.Malformed = true;
            info.Error = e.Message;
        }
        // Entry names are evidence too (e.g. a client's mixin configuration file kept after its metadata was stripped).
        if (options.ReadContent && options.Signatures?.Has(SignatureScope.Resource) == true && info.EntryNames.Count > 0)
        {
            var names = Encoding.UTF8.GetBytes(string.Join('\n', info.EntryNames));
            foreach (var h in options.Signatures.Match(SignatureScope.Resource, names, "entry names"))
                if (!info.Hits.Any(x => x.Rule.Id == h.Rule.Id))
                    info.Hits.Add(h with { Where = info.EntryNames.FirstOrDefault(n => n.Contains(h.Rule.Pattern, StringComparison.Ordinal)) ?? "entry names", Excerpt = "entry name" });
        }
        return info;
    }

    /// <summary>A real PE image: "MZ" header whose e_lfanew points at "PE\0\0".</summary>
    public static bool LooksLikePe(ReadOnlySpan<byte> data)
    {
        if (data.Length < 64 || data[0] != 'M' || data[1] != 'Z') return false;
        var lfanew = BitConverter.ToInt32(data[0x3C..]);
        return lfanew > 0 && lfanew + 4 <= data.Length && data[lfanew] == 'P' && data[lfanew + 1] == 'E' && data[lfanew + 2] == 0 && data[lfanew + 3] == 0;
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
            var root = doc.RootElement;
            var id = Str(root, "id");
            if (!string.IsNullOrWhiteSpace(id)) info.Metadata.Add(new ModMetadata("fabric", id!, Str(root, "name"), Str(root, "version")));
            if (root.TryGetProperty("entrypoints", out var eps) && eps.ValueKind == JsonValueKind.Object)
                foreach (var group in eps.EnumerateObject())
                    if (group.Value.ValueKind == JsonValueKind.Array)
                        foreach (var ep in group.Value.EnumerateArray())
                        {
                            // Only plain Java entrypoints can be checked; language adapters (Kotlin, Scala) resolve differently.
                            var value = ep.ValueKind == JsonValueKind.String ? ep.GetString() : Str(ep, "adapter") is null or "default" ? Str(ep, "value") : null;
                            if (!string.IsNullOrWhiteSpace(value)) info.Entrypoints.Add(value!);
                        }
            if (root.TryGetProperty("mixins", out var mixins) && mixins.ValueKind == JsonValueKind.Array)
                foreach (var m in mixins.EnumerateArray())
                {
                    var cfg = m.ValueKind == JsonValueKind.String ? m.GetString() : Str(m, "config");
                    if (!string.IsNullOrWhiteSpace(cfg)) info.MixinConfigs.Add(cfg!);
                }
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
