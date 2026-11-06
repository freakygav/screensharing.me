using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Screensharing.Scanner.Tests.Fixtures;

/// <summary>
/// Builds synthetic Minecraft installations on disk (under a temp "AppData") so detection
/// can be tested on realistic layouts without any real cheat binaries.
/// </summary>
public sealed class FixtureBuilder : IDisposable
{
    public string Root { get; }
    public string AppData => Path.Combine(Root, "AppData", "Roaming");
    public string UserProfile => Path.Combine(Root, "User");
    public string GameDir => Path.Combine(AppData, ".minecraft");
    public string Mods => Path.Combine(GameDir, "mods");
    public string Logs => Path.Combine(GameDir, "logs");

    public FixtureBuilder()
    {
        Root = Path.Combine(Path.GetTempPath(), "ssme-fixture-" + Guid.NewGuid().ToString("N")[..10]);
        Directory.CreateDirectory(Mods);
        Directory.CreateDirectory(Logs);
        Directory.CreateDirectory(UserProfile);
    }

    public sealed class JarSpec
    {
        public string? FabricId { get; init; }
        public string? FabricName { get; init; }
        public string Version { get; init; } = "1.0.0";
        public string? ForgeTomlId { get; init; }
        public IEnumerable<string> Classes { get; init; } = [];
        public Dictionary<string, string>? Manifest { get; init; }
        public IEnumerable<(string Name, JarSpec Spec)> Nested { get; init; } = [];
    }

    public static byte[] BuildJar(JarSpec spec)
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            if (spec.FabricId is not null)
                Write(zip, "fabric.mod.json", JsonSerializer.Serialize(new Dictionary<string, object?> { ["schemaVersion"] = 1, ["id"] = spec.FabricId, ["name"] = spec.FabricName ?? spec.FabricId, ["version"] = spec.Version }));
            if (spec.ForgeTomlId is not null)
                Write(zip, "META-INF/mods.toml", $"modLoader=\"javafml\"\nloaderVersion=\"[47,)\"\n[[mods]]\nmodId=\"{spec.ForgeTomlId}\"\nversion=\"{spec.Version}\"\ndisplayName=\"{spec.ForgeTomlId}\"\n");
            var mf = new StringBuilder("Manifest-Version: 1.0\r\n");
            foreach (var (k, v) in spec.Manifest ?? []) mf.Append($"{k}: {v}\r\n");
            Write(zip, "META-INF/MANIFEST.MF", mf.ToString());
            foreach (var c in spec.Classes)
            {
                var e = zip.CreateEntry(c + ".class");
                using var s = e.Open();
                s.Write([0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 65]); // class-file magic only; never executed
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

    public static void Age(string path, TimeSpan age)
    {
        var t = DateTime.UtcNow - age;
        File.SetCreationTimeUtc(path, t);
        File.SetLastWriteTimeUtc(path, t);
    }

    /// <summary>Adds a vanilla version whose manifest hash matches (or deliberately mismatches) the jar.</summary>
    public string AddVersion(string id, bool tampered = false)
    {
        var dir = Path.Combine(GameDir, "versions", id);
        Directory.CreateDirectory(dir);
        var jar = BuildJar(new JarSpec { Classes = ["net/minecraft/client/main/Main", "a", "b"] });
        File.WriteAllBytes(Path.Combine(dir, id + ".jar"), tampered ? [.. jar, 0x00] : jar);
        var libRel = "org/example/lib/1.0/lib-1.0.jar";
        var libPath = Path.Combine(GameDir, "libraries", libRel.Replace('/', '\\'));
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
        return dir;
    }

    /// <summary>Writes a Fabric latest.log listing the given mods, timestamped after the mods were installed.</summary>
    public string AddFabricLog(IEnumerable<(string Id, string Version)> mods, string name = "latest.log", TimeSpan? age = null)
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
        var path = Path.Combine(Logs, name);
        File.WriteAllText(path, sb.ToString());
        Age(path, age ?? TimeSpan.FromDays(1));
        return path;
    }

    public void Dispose()
    {
        try { Directory.Delete(Root, true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }
}
