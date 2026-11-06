using Screensharing.Scanner.Model;

namespace Screensharing.Scanner.Engine;

public sealed class ScanOptions
{
    public required RuleSet Rules { get; init; }

    /// <summary>Verify unrecognised mod hashes against the public Modrinth API (sends SHA-512 hashes only).</summary>
    public bool ModrinthLookup { get; init; } = true;

    /// <summary>Scan memory of running Java game processes for known class paths.</summary>
    public bool MemoryScan { get; init; } = true;

    /// <summary>Upper bound of bytes read from one process during memory scanning.</summary>
    public long MemoryScanCapBytes { get; init; } = 3L * 1024 * 1024 * 1024;

    /// <summary>When false, only Minecraft folders are examined (used by tests and "folder-only" scans).</summary>
    public bool IncludeSystemArtifacts { get; init; } = true;

    /// <summary>Overrides for %APPDATA% and %USERPROFILE% (synthetic fixtures in tests).</summary>
    public string? AppDataOverride { get; init; }
    public string? UserProfileOverride { get; init; }

    /// <summary>Additional Minecraft game directories supplied by the investigator.</summary>
    public IReadOnlyList<string> ExtraGameDirectories { get; init; } = [];

    /// <summary>Clock used for "recent" windows; overridable for deterministic tests.</summary>
    public Func<DateTimeOffset> Now { get; init; } = () => DateTimeOffset.UtcNow;

    public HttpClient? Http { get; init; }

    public string AppData => AppDataOverride ?? Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
    public string UserProfile => UserProfileOverride ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
}
