using System.Text.Json;
using System.Text.RegularExpressions;

namespace Screensharing.Scanner.Instance;

/// <summary>
/// Identifies the Minecraft instance of each running game process from the process itself: main class,
/// --gameDir, working directory, launcher brand, parent process and class path. Never falls back to a
/// default folder: an instance that cannot be identified with confidence is returned unresolved with the reason.
/// </summary>
public static partial class InstanceResolver
{
    /// <summary>Main classes that start the Minecraft client directly or through a mod loader / launcher entry point.</summary>
    private static readonly Dictionary<string, string> GameMainClasses = new(StringComparer.Ordinal)
    {
        ["net.minecraft.client.main.Main"] = "Vanilla",
        ["net.fabricmc.loader.impl.launch.knot.KnotClient"] = "Fabric",
        ["net.fabricmc.loader.launch.knot.KnotClient"] = "Fabric",
        ["org.quiltmc.loader.impl.launch.knot.KnotClient"] = "Quilt",
        ["cpw.mods.bootstraplauncher.BootstrapLauncher"] = "Forge/NeoForge",
        ["cpw.mods.modlauncher.Launcher"] = "Forge",
        ["net.minecraftforge.bootstrap.ForgeBootstrap"] = "Forge",
        ["net.neoforged.fml.startup.Client"] = "NeoForge",
        ["net.minecraft.launchwrapper.Launch"] = "LaunchWrapper (legacy Forge/OptiFine)",
        ["org.prismlauncher.EntryPoint"] = "",
        ["org.multimc.EntryPoint"] = "",
        ["com.moonsworth.lunar.genesis.Genesis"] = "Lunar Client",
    };

    /// <summary>Entry points that receive the launch parameters on standard input and run the game in the instance folder.</summary>
    private static readonly HashSet<string> WorkingDirectoryLaunchers = new(StringComparer.Ordinal) { "org.prismlauncher.EntryPoint", "org.multimc.EntryPoint" };

    private static readonly string[] Markers = ["options.txt", "logs", "mods", "config", "saves", "resourcepacks", "servers.dat"];

    public static IReadOnlyList<GameInstance> Detect() => ProcessInspector.EnumerateJava().Select(Resolve).OfType<GameInstance>().ToList();

    [GeneratedRegex(@"(--(accessToken|session|uuid|xuid|clientId|username|userProperties|profileProperties)\s+)(""[^""]*""|\S+)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex Sensitive();

    /// <summary>Removes account identifiers and session tokens from a command line.</summary>
    public static string Redact(string commandLine) => Sensitive().Replace(commandLine, "$1[redacted]");

    /// <summary>Returns null when the process is not a Minecraft client.</summary>
    public static GameInstance? Resolve(JavaProcessInfo p)
    {
        if (p.CommandLine is null)
        {
            return new GameInstance
            {
                ProcessId = p.Pid, ProcessName = p.Name, ProcessStartedAt = p.StartedAt, Launcher = "Unknown", Name = $"{p.Name} (PID {p.Pid})",
                GameDirectory = "", InstanceRoot = "", GameDirectorySource = "unknown", Resolved = false,
                Problem = p.ReadError ?? "The command line of the Java process could not be read, so it is unknown whether it is Minecraft or which folder it uses.",
            };
        }
        var launch = JavaLaunch.Parse(ProcessInspector.SplitCommandLine(p.CommandLine));
        var main = launch.EffectiveMainClass ?? launch.MainClass;
        var knownMain = main is not null && GameMainClasses.ContainsKey(main);
        var gameArgs = launch.HasArg("--gameDir") || launch.HasArg("--assetsDir") || launch.HasArg("--accessToken");
        if (!knownMain && !gameArgs) return null;

        var notes = new List<string>();
        string? gameDir = null, source = null, problem = null;
        var argDir = launch.Arg("--gameDir");
        if (argDir is not null)
        {
            if (Path.IsPathFullyQualified(argDir)) { gameDir = argDir; source = "--gameDir argument"; }
            else if (p.WorkingDirectory is not null) { gameDir = Path.GetFullPath(Path.Combine(p.WorkingDirectory, argDir)); source = "--gameDir argument (relative to the process working directory)"; }
            else problem = $"The game was started with a relative --gameDir \"{argDir}\" and the process working directory could not be read: {p.ReadError ?? "unknown error"}.";
        }
        else if (p.WorkingDirectory is not null)
        {
            gameDir = p.WorkingDirectory;
            source = main is not null && WorkingDirectoryLaunchers.Contains(main) ? "process working directory (launcher starts the game in the instance folder)" : "process working directory (no --gameDir argument)";
        }
        else
        {
            problem = "The game was started without a --gameDir argument and its working directory could not be read" + (p.ReadError is null ? "." : $": {p.ReadError}");
        }

        if (gameDir is not null && problem is null)
        {
            gameDir = Path.GetFullPath(gameDir.Trim().Trim('"')).TrimEnd('\\');
            if (!Directory.Exists(gameDir)) problem = $"The game directory \"{gameDir}\" reported by the process does not exist.";
            else
            {
                var found = Markers.Where(m => File.Exists(Path.Combine(gameDir, m)) || Directory.Exists(Path.Combine(gameDir, m))).ToList();
                if (found.Count == 0) problem = $"\"{gameDir}\" does not look like a Minecraft game directory (no options.txt, logs, mods, config or saves).";
                else if (argDir is not null && p.WorkingDirectory is not null && !string.Equals(Path.GetFullPath(p.WorkingDirectory).TrimEnd('\\'), gameDir, StringComparison.OrdinalIgnoreCase))
                    notes.Add($"Working directory {p.WorkingDirectory} differs from --gameDir; --gameDir is authoritative.");
            }
        }

        var classPath = launch.ClassPath.Select(c => c.Trim('"')).Where(c => c.Length > 0).Select(c => Path.IsPathFullyQualified(c) || p.WorkingDirectory is null ? c : Path.GetFullPath(Path.Combine(p.WorkingDirectory, c))).ToList();
        var (launcher, name, instanceRoot) = Identify(p, launch, gameDir ?? "");
        var version = launch.Arg("--version") ?? VersionFromInstance(instanceRoot, gameDir);
        var loader = LoaderOf(launch, main, classPath);
        var cmd = Redact(p.CommandLine);
        return new GameInstance
        {
            ProcessId = p.Pid, ProcessName = p.Name, ProcessStartedAt = p.StartedAt,
            Launcher = launcher, Name = name, GameDirectory = gameDir ?? "", InstanceRoot = instanceRoot ?? gameDir ?? "",
            GameDirectorySource = source ?? "unknown", MinecraftVersion = version, Loader = loader,
            JavaExecutable = p.ExecutablePath ?? launch.Executable, MainClass = main, RedactedCommandLine = cmd.Length > 4000 ? cmd[..4000] + "…" : cmd,
            WorkingDirectory = p.WorkingDirectory, ClassPath = classPath, Agents = launch.Agents, JavaEnvironment = p.JavaEnvironment,
            LibraryRoots = LibraryRoots(classPath), NativesDirectory = launch.SystemProperties.GetValueOrDefault("java.library.path"),
            Notes = notes, Resolved = problem is null && gameDir is not null, Problem = problem,
        };
    }

    private static (string Launcher, string Name, string? InstanceRoot) Identify(JavaProcessInfo p, JavaLaunch l, string gameDir)
    {
        var brand = l.SystemProperties.GetValueOrDefault("minecraft.launcher.brand") ?? "";
        var parent = (p.ParentName ?? "").ToLowerInvariant();
        var dir = gameDir.Replace('/', '\\');
        var leaf = Path.GetFileName(dir);
        var parentDir = Path.GetDirectoryName(dir);

        // Prism / MultiMC / PolyMC: <launcher>\instances\<id>\(.)minecraft, with instance.cfg in <id>.
        if (leaf is ".minecraft" or "minecraft" && parentDir is not null && File.Exists(Path.Combine(parentDir, "instance.cfg")))
        {
            var label = dir.Contains(@"\PrismLauncher\", StringComparison.OrdinalIgnoreCase) || parent.Contains("prism") || l.MainClass == "org.prismlauncher.EntryPoint" ? "Prism Launcher"
                : dir.Contains(@"\PolyMC\", StringComparison.OrdinalIgnoreCase) || parent.Contains("polymc") ? "PolyMC" : "MultiMC";
            return (label, InstanceCfgName(Path.Combine(parentDir, "instance.cfg")) ?? Path.GetFileName(parentDir), parentDir);
        }
        if (Regex.IsMatch(dir, @"\\(ModrinthApp|com\.modrinth\.theseus)\\profiles\\[^\\]+$", RegexOptions.IgnoreCase) || brand == "theseus" || parent.Contains("modrinth"))
            return ("Modrinth App", leaf, gameDir);
        if (Regex.IsMatch(dir, @"\\curseforge\\minecraft\\Instances\\[^\\]+$", RegexOptions.IgnoreCase) || parent.Contains("curseforge"))
            return ("CurseForge", JsonName(Path.Combine(dir, "minecraftinstance.json")) ?? leaf, gameDir);
        if (Regex.IsMatch(dir, @"\\ATLauncher\\instances\\[^\\]+$", RegexOptions.IgnoreCase) || brand.Equals("ATLauncher", StringComparison.OrdinalIgnoreCase))
            return ("ATLauncher", leaf, gameDir);
        if (dir.Contains(@"\gdlauncher", StringComparison.OrdinalIgnoreCase) && leaf == "instance" && parentDir is not null)
            return ("GDLauncher", Path.GetFileName(parentDir), parentDir);
        if (l.MainClass?.StartsWith("com.moonsworth.lunar", StringComparison.Ordinal) == true || parent.Contains("lunar"))
            return ("Lunar Client", $"Lunar Client {l.Arg("--version") ?? ""}".Trim(), gameDir);
        if (parent.Contains("badlion")) return ("Badlion Client", leaf, gameDir);
        if (parent.Contains("feather") || brand.Contains("feather", StringComparison.OrdinalIgnoreCase)) return ("Feather Client", leaf, gameDir);
        if (brand == "minecraft-launcher" || parent is "minecraftlauncher" or "minecraft")
            return ("Official Minecraft Launcher", leaf == ".minecraft" ? $"{l.Arg("--version") ?? "Minecraft"} (.minecraft)" : leaf, gameDir);
        return (brand.Length > 0 ? brand : p.ParentName ?? "Unknown launcher", leaf, gameDir);
    }

    private static string? InstanceCfgName(string cfg)
    {
        try
        {
            foreach (var line in File.ReadLines(cfg))
                if (line.StartsWith("name=", StringComparison.Ordinal)) return line[5..].Trim();
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
        return null;
    }

    private static string? JsonName(string path)
    {
        try
        {
            if (!File.Exists(path)) return null;
            using var doc = JsonDocument.Parse(File.ReadAllText(path));
            return doc.RootElement.TryGetProperty("name", out var n) && n.ValueKind == JsonValueKind.String ? n.GetString() : null;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or JsonException) { return null; }
    }

    private static string? VersionFromInstance(string? instanceRoot, string? gameDir)
    {
        if (instanceRoot is null) return null;
        var pack = Path.Combine(instanceRoot, "mmc-pack.json");
        try
        {
            if (!File.Exists(pack)) return null;
            using var doc = JsonDocument.Parse(File.ReadAllText(pack), new JsonDocumentOptions { AllowTrailingCommas = true });
            foreach (var c in doc.RootElement.GetProperty("components").EnumerateArray())
                if (c.TryGetProperty("uid", out var u) && u.GetString() == "net.minecraft" && c.TryGetProperty("version", out var v)) return v.GetString();
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or JsonException or KeyNotFoundException or InvalidOperationException) { }
        return null;
    }

    private static string? LoaderOf(JavaLaunch l, string? main, List<string> cp)
    {
        if (main is not null && GameMainClasses.TryGetValue(main, out var loader) && loader.Length > 0 && loader != "Vanilla") return loader;
        bool Has(string fragment) => cp.Any(c => c.Contains(fragment, StringComparison.OrdinalIgnoreCase));
        if (Has("fabric-loader")) return "Fabric";
        if (Has("quilt-loader")) return "Quilt";
        if (Has("neoforge") || Has(@"\net\neoforged\")) return "NeoForge";
        if (Has(@"\net\minecraftforge\") || Has("fmlloader")) return "Forge";
        if (Has("launchwrapper")) return "LaunchWrapper (legacy Forge/OptiFine)";
        return main == "net.minecraft.client.main.Main" ? "Vanilla" : null;
    }

    /// <summary>Folders that contain a "libraries", "versions" or "meta" directory on the class path (launcher-managed data).</summary>
    public static List<string> LibraryRoots(IEnumerable<string> classPath)
    {
        var roots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in classPath)
        {
            var dir = Path.GetDirectoryName(entry);
            while (dir is not null)
            {
                var n = Path.GetFileName(dir);
                if (n.Equals("libraries", StringComparison.OrdinalIgnoreCase) || n.Equals("versions", StringComparison.OrdinalIgnoreCase))
                {
                    roots.Add(dir);
                    break;
                }
                dir = Path.GetDirectoryName(dir);
            }
        }
        return roots.ToList();
    }
}
