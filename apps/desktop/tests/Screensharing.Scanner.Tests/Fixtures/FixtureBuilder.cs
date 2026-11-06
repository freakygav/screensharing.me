using System.Buffers.Binary;
using System.Diagnostics;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Screensharing.Scanner.Instance;

namespace Screensharing.Scanner.Tests.Fixtures;

/// <summary>
/// Builds synthetic Minecraft instances on disk so detection can be tested on realistic layouts without any real
/// cheat binaries. Layout (all under a temp root):
///   launcher/instances/Selected/.minecraft   ← the instance under investigation (Prism-style, with instance.cfg)
///   launcher/instances/Other/.minecraft      ← a second instance that must never be touched
///   launcher/libraries, launcher/versions     ← launcher-shared data (only class-path entries are in scope)
///   Unrelated/                                ← "the rest of the computer" (documents, downloads)
/// </summary>
public sealed class FixtureBuilder : IDisposable
{
    public string Root { get; }
    public string Launcher => Path.Combine(Root, "launcher");
    public string InstanceRoot => Path.Combine(Launcher, "instances", "Selected");
    public string GameDir => Path.Combine(InstanceRoot, ".minecraft");
    public string Mods => Path.Combine(GameDir, "mods");
    public string Logs => Path.Combine(GameDir, "logs");
    public string OtherInstance => Path.Combine(Launcher, "instances", "Other", ".minecraft");
    public string Unrelated => Path.Combine(Root, "Unrelated");
    public List<string> ClassPath { get; } = [];
    public string? Version { get; private set; }

    public FixtureBuilder()
    {
        Root = Path.Combine(Path.GetTempPath(), "ssme-fixture-" + Guid.NewGuid().ToString("N")[..10]);
        Directory.CreateDirectory(Mods);
        Directory.CreateDirectory(Logs);
        File.WriteAllText(Path.Combine(GameDir, "options.txt"), "version:3955\nresourcePacks:[\"vanilla\"]\n");
        File.WriteAllText(Path.Combine(InstanceRoot, "instance.cfg"), "[General]\nname=Selected PvP\nInstanceType=OneSix\n");
        Directory.CreateDirectory(Path.Combine(OtherInstance, "mods"));
        File.WriteAllText(Path.Combine(OtherInstance, "options.txt"), "version:3955\n");
        File.WriteAllText(Path.Combine(Path.GetDirectoryName(OtherInstance)!, "instance.cfg"), "[General]\nname=Other\n");
        Directory.CreateDirectory(Unrelated);
    }

    /// <summary>The selected instance as the scanner would receive it from the resolver.</summary>
    public GameInstance Target() => GameInstance.ForDirectory(GameDir, "Prism Launcher", "Selected PvP", InstanceRoot, ClassPath.ToList(), Version);

    // ------------------------------------------------------------------ jars

    public sealed class JarSpec
    {
        public string? FabricId { get; init; }
        public string? FabricName { get; init; }
        public string Version { get; init; } = "1.0.0";
        public string? ForgeTomlId { get; init; }
        public IEnumerable<string> Classes { get; init; } = [];
        /// <summary>Extra UTF-8 constants per class (string literals, referenced class names).</summary>
        public Dictionary<string, string[]> ClassStrings { get; init; } = [];
        public Dictionary<string, string>? Manifest { get; init; }
        public Dictionary<string, string> Resources { get; init; } = [];
        public Dictionary<string, byte[]> RawEntries { get; init; } = [];
        public string[] Entrypoints { get; init; } = [];
        public string[] Mixins { get; init; } = [];
        public IEnumerable<(string Name, JarSpec Spec)> Nested { get; init; } = [];
    }

    /// <summary>A minimal, structurally valid Java class file (never executed) whose constant pool holds the given strings.</summary>
    public static byte[] BuildClass(string className, IEnumerable<string>? strings = null)
    {
        var utf8 = new List<string> { className, "java/lang/Object" };
        utf8.AddRange(strings ?? []);
        using var ms = new MemoryStream();
        void U2(int v) { Span<byte> b = stackalloc byte[2]; BinaryPrimitives.WriteUInt16BigEndian(b, (ushort)v); ms.Write(b); }
        ms.Write([0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 65]);
        // #1 Utf8 class, #2 Class #1, #3 Utf8 Object, #4 Class #3, then Utf8 + String pairs for each string.
        var extra = utf8.Count - 2;
        U2(5 + extra * 2);
        void Utf8(string s) { var bytes = Encoding.UTF8.GetBytes(s); ms.WriteByte(1); U2(bytes.Length); ms.Write(bytes); }
        Utf8(className); ms.WriteByte(7); U2(1);
        Utf8("java/lang/Object"); ms.WriteByte(7); U2(3);
        for (var i = 0; i < extra; i++) { Utf8(utf8[i + 2]); ms.WriteByte(8); U2(5 + i * 2); }
        U2(0x21); U2(2); U2(4); U2(0); U2(0); U2(0); U2(0);
        return ms.ToArray();
    }

    public static byte[] BuildJar(JarSpec spec)
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            if (spec.FabricId is not null)
            {
                var meta = new Dictionary<string, object?> { ["schemaVersion"] = 1, ["id"] = spec.FabricId, ["name"] = spec.FabricName ?? spec.FabricId, ["version"] = spec.Version };
                if (spec.Entrypoints.Length > 0) meta["entrypoints"] = new Dictionary<string, object> { ["main"] = spec.Entrypoints };
                if (spec.Mixins.Length > 0) meta["mixins"] = spec.Mixins;
                Write(zip, "fabric.mod.json", JsonSerializer.Serialize(meta));
            }
            if (spec.ForgeTomlId is not null)
                Write(zip, "META-INF/mods.toml", $"modLoader=\"javafml\"\nloaderVersion=\"[47,)\"\n[[mods]]\nmodId=\"{spec.ForgeTomlId}\"\nversion=\"{spec.Version}\"\ndisplayName=\"{spec.ForgeTomlId}\"\n");
            var mf = new StringBuilder("Manifest-Version: 1.0\r\n");
            foreach (var (k, v) in spec.Manifest ?? []) mf.Append($"{k}: {v}\r\n");
            Write(zip, "META-INF/MANIFEST.MF", mf.ToString());
            foreach (var c in spec.Classes)
            {
                var e = zip.CreateEntry(c + ".class");
                using var s = e.Open();
                s.Write(BuildClass(c, spec.ClassStrings.GetValueOrDefault(c)));
            }
            foreach (var (name, text) in spec.Resources) Write(zip, name, text);
            foreach (var (name, bytes) in spec.RawEntries)
            {
                var e = zip.CreateEntry(name);
                using var s = e.Open();
                s.Write(bytes);
            }
            foreach (var (name, nested) in spec.Nested)
            {
                var e = zip.CreateEntry(name);
                using var s = e.Open();
                s.Write(BuildJar(nested));
            }
        }
        return ms.ToArray();
    }

    private static void Write(ZipArchive zip, string name, string text)
    {
        var e = zip.CreateEntry(name);
        using var w = new StreamWriter(e.Open());
        w.Write(text);
    }

    public string AddMod(string fileName, JarSpec spec, string? dir = null)
    {
        var path = Path.Combine(dir ?? Mods, fileName);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, BuildJar(spec));
        Age(path, TimeSpan.FromDays(3));
        return path;
    }

    public string AddFile(string relative, byte[] content, string? root = null)
    {
        var path = Path.Combine(root ?? GameDir, relative.Replace('/', '\\'));
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, content);
        Age(path, TimeSpan.FromDays(3));
        return path;
    }

    public string AddText(string relative, string text, string? root = null) => AddFile(relative, Encoding.UTF8.GetBytes(text), root);

    public static void Age(string path, TimeSpan age)
    {
        var t = DateTime.UtcNow - age;
        File.SetCreationTimeUtc(path, t);
        File.SetLastWriteTimeUtc(path, t);
    }

    /// <summary>A fake Windows PE image (valid MZ/PE headers, never executed) that contains the given strings.</summary>
    public static byte[] BuildPe(params string[] strings)
    {
        var body = Encoding.ASCII.GetBytes(string.Join("\0", strings) + "\0");
        var pe = new byte[0x200 + body.Length];
        pe[0] = (byte)'M'; pe[1] = (byte)'Z';
        BitConverter.GetBytes(0x80).CopyTo(pe, 0x3C);
        pe[0x80] = (byte)'P'; pe[0x81] = (byte)'E';
        body.CopyTo(pe, 0x200);
        return pe;
    }

    /// <summary>
    /// Adds a game version in the launcher's versions folder plus one library, and puts both on the class path
    /// (as the running game would). The manifest hash matches, or deliberately mismatches, the jar.
    /// </summary>
    public string AddVersion(string id, bool tampered = false)
    {
        var dir = Path.Combine(Launcher, "versions", id);
        Directory.CreateDirectory(dir);
        var jar = BuildJar(new JarSpec { Classes = ["net/minecraft/client/main/Main", "a", "b"] });
        var jarPath = Path.Combine(dir, id + ".jar");
        File.WriteAllBytes(jarPath, tampered ? [.. jar, 0x00] : jar);
        var libRel = "org/example/lib/1.0/lib-1.0.jar";
        var libPath = Path.Combine(Launcher, "libraries", libRel.Replace('/', '\\'));
        Directory.CreateDirectory(Path.GetDirectoryName(libPath)!);
        var lib = BuildJar(new JarSpec { Classes = ["org/example/lib/Thing"] });
        File.WriteAllBytes(libPath, lib);
        var manifest = new
        {
            id,
            downloads = new { client = new { sha1 = Convert.ToHexStringLower(SHA1.HashData(jar)), size = jar.Length } },
            libraries = new[] { new { name = "org.example:lib:1.0", downloads = new { artifact = new { path = libRel, sha1 = Convert.ToHexStringLower(SHA1.HashData(lib)) } } } },
        };
        File.WriteAllText(Path.Combine(dir, id + ".json"), JsonSerializer.Serialize(manifest));
        ClassPath.Add(libPath);
        ClassPath.Add(jarPath);
        Version = id;
        return dir;
    }

    /// <summary>Writes a Fabric latest.log listing the given mods.</summary>
    public string AddFabricLog(IEnumerable<(string Id, string Version)> mods, string name = "latest.log", TimeSpan? age = null, IEnumerable<string>? extraLines = null)
    {
        var list = mods.ToList();
        var sb = new StringBuilder();
        sb.AppendLine("[12:00:00] [main/INFO]: Loading Minecraft 1.21.1 with Fabric Loader 0.16.5");
        sb.AppendLine($"[12:00:00] [main/INFO]: Loading {list.Count + 3} mods:");
        sb.AppendLine("\t- fabricloader 0.16.5");
        sb.AppendLine("\t- java 21");
        sb.AppendLine("\t- minecraft 1.21.1");
        foreach (var (id, ver) in list)
        {
            sb.AppendLine($"\t- {id} {ver}");
            if (id == "fabric-api") sb.AppendLine("\t   |-- fabric-api-base 0.4.42");
        }
        sb.AppendLine("[12:00:01] [main/INFO]: SpongePowered MIXIN Subsystem Version=0.8.7");
        foreach (var l in extraLines ?? []) sb.AppendLine(l);
        var path = Path.Combine(Logs, name);
        File.WriteAllText(path, sb.ToString());
        Age(path, age ?? TimeSpan.FromDays(1));
        return path;
    }

    /// <summary>A minimal 16x16 RGBA PNG, fully transparent or fully opaque.</summary>
    public static byte[] BuildPng(bool transparent)
    {
        const int w = 16, h = 16;
        var raw = new byte[(w * 4 + 1) * h];
        for (var y = 0; y < h; y++)
            for (var x = 0; x < w; x++)
            {
                var o = y * (w * 4 + 1) + 1 + x * 4;
                raw[o] = 120; raw[o + 1] = 120; raw[o + 2] = 120; raw[o + 3] = transparent ? (byte)0 : (byte)255;
            }
        using var z = new MemoryStream();
        using (var zl = new ZLibStream(z, CompressionLevel.Optimal, leaveOpen: true)) zl.Write(raw);
        using var png = new MemoryStream();
        png.Write([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
        void Chunk(string type, byte[] data)
        {
            Span<byte> len = stackalloc byte[4]; BinaryPrimitives.WriteUInt32BigEndian(len, (uint)data.Length); png.Write(len);
            png.Write(Encoding.ASCII.GetBytes(type)); png.Write(data); png.Write([0, 0, 0, 0]); // CRC not validated by the scanner
        }
        var ihdr = new byte[13];
        BinaryPrimitives.WriteUInt32BigEndian(ihdr, w); BinaryPrimitives.WriteUInt32BigEndian(ihdr.AsSpan(4), h);
        ihdr[8] = 8; ihdr[9] = 6;
        Chunk("IHDR", ihdr); Chunk("IDAT", z.ToArray()); Chunk("IEND", []);
        return png.ToArray();
    }

    /// <summary>Creates a directory junction (no administrator rights needed).</summary>
    public static void Junction(string link, string target)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(link)!);
        using var p = Process.Start(new ProcessStartInfo("cmd.exe", $"/c mklink /J \"{link}\" \"{target}\"") { CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true })!;
        p.WaitForExit();
        if (!Directory.Exists(link)) throw new InvalidOperationException("Could not create junction " + link);
    }

    public void Dispose()
    {
        // Remove junctions first so deleting never follows them into their targets.
        foreach (var d in Directory.EnumerateDirectories(Root, "*", SearchOption.AllDirectories).Where(d => new DirectoryInfo(d).Attributes.HasFlag(FileAttributes.ReparsePoint)).ToList())
            try { Directory.Delete(d); } catch (IOException) { }
        try { Directory.Delete(Root, true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }
}
