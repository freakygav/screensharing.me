using System.Text.Json;
using Screensharing.Scanner.Engine;

namespace Screensharing.Scanner.Discovery;

/// <summary>
/// Finds Minecraft game directories for the official launcher and common third-party launchers/clients.
/// Only directory metadata is read here.
/// </summary>
public static class MinecraftLocator
{
    private const int MaxInstances = 250;

    public static void Discover(ScanContext ctx)
    {
        var o = ctx.Options;
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        void Add(Installation i)
        {
            if (ctx.Installations.Count >= MaxInstances) return;
            var full = Path.GetFullPath(i.GameDirectory).TrimEnd('\\');
            if (!seen.Add(full)) return;
            Populate(i, ctx);
            ctx.Installations.Add(i);
            ctx.Custody.Record("enumerate-directory", full);
        }

        var appData = o.AppData;
        var home = o.UserProfile;

        var official = Path.Combine(appData, ".minecraft");
        if (Directory.Exists(official))
        {
            var launcher = Directory.Exists(Path.Combine(appData, ".tlauncher")) ? "Official launcher / TLauncher (.minecraft)" : "Official launcher (.minecraft)";
            Add(new Installation { Launcher = launcher, GameDirectory = official });
        }

        foreach (var (label, root) in new[]
        {
            ("Prism Launcher", Path.Combine(appData, "PrismLauncher", "instances")),
            ("PolyMC", Path.Combine(appData, "PolyMC", "instances")),
            ("MultiMC", Path.Combine(appData, "MultiMC", "instances")),
        })
        {
            foreach (var inst in SafeDirs(root))
            {
                var game = new[] { ".minecraft", "minecraft" }.Select(n => Path.Combine(inst, n)).FirstOrDefault(Directory.Exists);
                if (game is null) continue;
                var i = new Installation { Launcher = $"{label}: {Path.GetFileName(inst)}", GameDirectory = game };
                var libs = Path.Combine(Path.GetDirectoryName(root)!, "libraries");
                if (Directory.Exists(libs)) i.LibrariesDirectory = libs;
                ReadMmcPack(Path.Combine(inst, "mmc-pack.json"), i);
                Add(i);
            }
        }

        foreach (var inst in SafeDirs(Path.Combine(home, "curseforge", "minecraft", "Instances")))
            Add(new Installation { Launcher = $"CurseForge: {Path.GetFileName(inst)}", GameDirectory = inst });
        foreach (var root in new[] { Path.Combine(appData, "ModrinthApp", "profiles"), Path.Combine(appData, "com.modrinth.theseus", "profiles") })
            foreach (var inst in SafeDirs(root))
                Add(new Installation { Launcher = $"Modrinth App: {Path.GetFileName(inst)}", GameDirectory = inst });
        foreach (var inst in SafeDirs(Path.Combine(appData, "ATLauncher", "instances")))
            Add(new Installation { Launcher = $"ATLauncher: {Path.GetFileName(inst)}", GameDirectory = inst });
        foreach (var inst in SafeDirs(Path.Combine(appData, "gdlauncher_next", "instances")))
            Add(new Installation { Launcher = $"GDLauncher: {Path.GetFileName(inst)}", GameDirectory = inst });
        foreach (var inst in SafeDirs(Path.Combine(appData, "gdlauncher_carbon", "data", "instances")))
        {
            var game = Path.Combine(inst, "instance");
            if (Directory.Exists(game)) Add(new Installation { Launcher = $"GDLauncher: {Path.GetFileName(inst)}", GameDirectory = game });
        }

        // Clients with their own data layout: discover any mods/log folders within bounded depth.
        foreach (var (label, root) in new[]
        {
            ("Lunar Client", Path.Combine(home, ".lunarclient")),
            ("Feather Client", Path.Combine(appData, ".feather")),
            ("Badlion Client", Path.Combine(appData, "Badlion Client")),
        })
        {
            if (!Directory.Exists(root)) continue;
            var i = new Installation { Launcher = label, GameDirectory = root, Note = "Client-managed layout; user mod folders discovered automatically." };
            foreach (var d in FindNamedDirs(root, ["mods", "user-mods"], 5)) i.ModsDirectories.Add(d);
            foreach (var d in FindNamedDirs(root, ["logs"], 3)) i.LogDirectories.Add(d);
            Add(i);
        }

        foreach (var extra in o.ExtraGameDirectories.Where(Directory.Exists))
            Add(new Installation { Launcher = "Investigator-specified folder", GameDirectory = extra });
    }

    private static void Populate(Installation i, ScanContext ctx)
    {
        var g = i.GameDirectory;
        var mods = Path.Combine(g, "mods");
        if (Directory.Exists(mods) && !i.ModsDirectories.Contains(mods, StringComparer.OrdinalIgnoreCase))
        {
            i.ModsDirectories.Add(mods);
            // Some loaders also read version-specific subfolders (mods/1.21.1).
            foreach (var sub in SafeDirs(mods)) i.ModsDirectories.Add(sub);
        }
        var versions = Path.Combine(g, "versions");
        if (Directory.Exists(versions))
        {
            i.VersionsDirectory = versions;
            foreach (var v in SafeDirs(versions))
            {
                var id = Path.GetFileName(v);
                if (File.Exists(Path.Combine(v, id + ".json")) && !i.Versions.Contains(id)) i.Versions.Add(id);
            }
        }
        i.LibrariesDirectory ??= Directory.Exists(Path.Combine(g, "libraries")) ? Path.Combine(g, "libraries") : null;
        var logs = Path.Combine(g, "logs");
        if (Directory.Exists(logs) && !i.LogDirectories.Contains(logs, StringComparer.OrdinalIgnoreCase)) i.LogDirectories.Add(logs);
        var rp = Path.Combine(g, "resourcepacks");
        if (Directory.Exists(rp)) i.ResourcePacksDirectory = rp;
    }

    private static void ReadMmcPack(string path, Installation i)
    {
        try
        {
            if (!File.Exists(path)) return;
            using var doc = JsonDocument.Parse(File.ReadAllText(path), new JsonDocumentOptions { AllowTrailingCommas = true, CommentHandling = JsonCommentHandling.Skip });
            if (!doc.RootElement.TryGetProperty("components", out var comps)) return;
            foreach (var c in comps.EnumerateArray())
            {
                var uid = c.TryGetProperty("uid", out var u) ? u.GetString() : null;
                var ver = c.TryGetProperty("version", out var v) ? v.GetString() : null;
                var name = uid switch
                {
                    "net.minecraft" => "Minecraft",
                    "net.fabricmc.fabric-loader" => "Fabric Loader",
                    "org.quiltmc.quilt-loader" => "Quilt Loader",
                    "net.minecraftforge" => "Forge",
                    "net.neoforged" => "NeoForge",
                    _ => null,
                };
                if (name is not null && ver is not null) i.Versions.Add($"{name} {ver}");
            }
        }
        catch (Exception e) when (e is IOException or JsonException or UnauthorizedAccessException or InvalidOperationException) { }
    }

    public static IEnumerable<string> SafeDirs(string root)
    {
        if (!Directory.Exists(root)) return [];
        try { return Directory.GetDirectories(root); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return []; }
    }

    public static IEnumerable<string> SafeFiles(string root, string pattern = "*")
    {
        if (!Directory.Exists(root)) return [];
        try { return Directory.GetFiles(root, pattern); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return []; }
    }

    private static List<string> FindNamedDirs(string root, string[] names, int maxDepth)
    {
        var found = new List<string>();
        var stack = new Stack<(string Dir, int Depth)>();
        stack.Push((root, 0));
        var visited = 0;
        while (stack.Count > 0 && visited++ < 5000)
        {
            var (dir, depth) = stack.Pop();
            foreach (var d in SafeDirs(dir))
            {
                var n = Path.GetFileName(d);
                if (names.Contains(n, StringComparer.OrdinalIgnoreCase)) found.Add(d);
                else if (depth + 1 < maxDepth && !n.StartsWith('.') && !n.Equals("jre", StringComparison.OrdinalIgnoreCase) && !n.Equals("assets", StringComparison.OrdinalIgnoreCase))
                    stack.Push((d, depth + 1));
            }
        }
        return found;
    }
}
