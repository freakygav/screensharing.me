using Screensharing.Scanner.Instance;
using Screensharing.Scanner.Model;

namespace Screensharing.Scanner.Engine;

public sealed class ScanOptions
{
    public required RuleSet Rules { get; init; }

    /// <summary>The instance to examine. Must be resolved; the engine never chooses or widens the target itself.</summary>
    public required GameInstance Target { get; init; }

    /// <summary>Verify unrecognised mod hashes against the public Modrinth API (sends SHA-512 hashes only).</summary>
    public bool ModrinthLookup { get; init; } = true;

    /// <summary>Scan the memory of the selected game process for known class paths and strings.</summary>
    public bool MemoryScan { get; init; } = true;

    /// <summary>Upper bound of bytes read from the game process during memory scanning.</summary>
    public long MemoryScanCapBytes { get; init; } = 3L * 1024 * 1024 * 1024;

    /// <summary>Largest archive that is opened (bigger archives are reported as not inspected).</summary>
    public long MaxArchiveBytes { get; init; } = 512L * 1024 * 1024;

    /// <summary>Largest text file (config, script, log) whose content is matched.</summary>
    public long MaxTextBytes { get; init; } = 16L * 1024 * 1024;

    /// <summary>Largest standalone executable whose content is matched.</summary>
    public long MaxBinaryBytes { get; init; } = 96L * 1024 * 1024;

    /// <summary>Clock used for "recent" windows; overridable for deterministic tests.</summary>
    public Func<DateTimeOffset> Now { get; init; } = () => DateTimeOffset.UtcNow;

    public HttpClient? Http { get; init; }
}
