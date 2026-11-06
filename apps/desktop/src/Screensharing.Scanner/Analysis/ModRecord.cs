namespace Screensharing.Scanner.Analysis;

public sealed class ModRecord
{
    public required string Path { get; init; }
    /// <summary>Location relative to the game directory (e.g. mods/sodium.jar).</summary>
    public required string Location { get; init; }
    /// <summary>Where the archive was found: mods folder, elsewhere in the instance, or the game's class path.</summary>
    public required string Origin { get; init; }
    public string FileName => System.IO.Path.GetFileName(Path);
    public long SizeBytes { get; init; }
    public string? Sha256 { get; set; }
    public string? Sha512 { get; set; }
    public bool Disabled { get; init; }
    public JarInfo? Jar { get; set; }
    public string Classification { get; set; } = "unrecognised";
    public string? ModrinthProject { get; set; }
    /// <summary>Hash-verified against the launcher's version manifest (class path libraries).</summary>
    public bool HashVerified { get; set; }

    public string? ModId => Jar?.Primary?.Id;

    internal bool DisguiseCheckPending { get; set; }
    internal (string Key, string Value, Model.Evidence Ev)? PendingAgent { get; set; }
    /// <summary>Generic indicator groups whose reporting waits for Modrinth verification.</summary>
    internal List<ScoredGroup> PendingIndicators { get; } = [];
    /// <summary>Known mod whose id the archive declares without shipping its packages (reported after Modrinth verification).</summary>
    internal Model.DetectionRule? PendingImpersonation { get; set; }

    public Dictionary<string, object?> ToInventory() => new()
    {
        ["modId"] = Jar?.Primary?.Id,
        ["name"] = Jar?.Primary?.Name ?? FileName,
        ["version"] = Jar?.Primary?.Version,
        ["loader"] = Jar?.Primary?.Loader,
        ["classification"] = Disabled ? $"{Classification} (disabled)" : Classification,
        ["modrinthProject"] = ModrinthProject,
        ["fileName"] = FileName,
        ["location"] = Location,
        ["origin"] = Origin,
        ["path"] = Path,
        ["sha256"] = Sha256,
        ["sizeBytes"] = SizeBytes,
        ["nestedMods"] = Jar is null ? 0 : Jar.Nested.Count,
        ["classes"] = Jar is null ? 0 : Jar.ClassEntries.Count,
    };
}
