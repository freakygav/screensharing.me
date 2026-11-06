namespace Screensharing.Scanner.Instance;

/// <summary>
/// A Minecraft instance identified from a running game process. Only instances with
/// <see cref="Resolved"/> = true can be scanned; otherwise <see cref="Problem"/> explains what is missing.
/// </summary>
public sealed class GameInstance
{
    public int? ProcessId { get; init; }
    public string? ProcessName { get; init; }
    public DateTimeOffset? ProcessStartedAt { get; init; }
    public required string Launcher { get; init; }
    public required string Name { get; init; }
    /// <summary>The game directory (where mods, config, logs live).</summary>
    public required string GameDirectory { get; init; }
    /// <summary>The instance folder: the game directory, or its parent for Prism/MultiMC-style instances (instance.cfg, natives).</summary>
    public required string InstanceRoot { get; init; }
    /// <summary>How the game directory was determined, e.g. "--gameDir argument".</summary>
    public required string GameDirectorySource { get; init; }
    public string? MinecraftVersion { get; init; }
    public string? Loader { get; init; }
    public string? JavaExecutable { get; init; }
    public string? MainClass { get; init; }
    public string? RedactedCommandLine { get; init; }
    public string? WorkingDirectory { get; init; }
    public IReadOnlyList<string> ClassPath { get; init; } = [];
    public IReadOnlyList<(string Kind, string Value)> Agents { get; init; } = [];
    public IReadOnlyDictionary<string, string> JavaEnvironment { get; init; } = new Dictionary<string, string>();
    /// <summary>Launcher data folders (parents of libraries/versions/meta folders) that the class path loads from.</summary>
    public IReadOnlyList<string> LibraryRoots { get; init; } = [];
    public string? NativesDirectory { get; init; }
    public IReadOnlyList<string> Notes { get; init; } = [];
    public bool Resolved { get; init; }
    public string? Problem { get; init; }

    public string DisplayName => $"{Name} — {Launcher}";

    /// <summary>Builds an instance for a folder without a running process (tests and fixtures only).</summary>
    public static GameInstance ForDirectory(string gameDirectory, string launcher = "Test fixture", string? name = null, string? instanceRoot = null,
        IReadOnlyList<string>? classPath = null, string? version = null) => new()
    {
        Launcher = launcher,
        Name = name ?? Path.GetFileName(gameDirectory.TrimEnd('\\')),
        GameDirectory = Path.GetFullPath(gameDirectory),
        InstanceRoot = Path.GetFullPath(instanceRoot ?? gameDirectory),
        GameDirectorySource = "specified directory",
        ClassPath = classPath ?? [],
        LibraryRoots = InstanceResolver.LibraryRoots(classPath ?? []),
        MinecraftVersion = version,
        Resolved = true,
    };

    public Dictionary<string, object?> ToInventory() => new()
    {
        ["launcher"] = Launcher,
        ["name"] = Name,
        ["path"] = GameDirectory,
        ["instanceRoot"] = InstanceRoot,
        ["source"] = GameDirectorySource,
        ["versions"] = MinecraftVersion ?? "—",
        ["loader"] = Loader,
        ["processId"] = ProcessId,
        ["processStartedAt"] = ProcessStartedAt?.ToString("u"),
        ["java"] = JavaExecutable,
        ["mainClass"] = MainClass,
        ["classPathEntries"] = ClassPath.Count,
    };
}
