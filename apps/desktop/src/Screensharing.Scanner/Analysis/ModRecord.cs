namespace Screensharing.Scanner.Analysis;

public sealed class ModRecord
{
    public required string Path { get; init; }
    public required string Launcher { get; init; }
    public string FileName => System.IO.Path.GetFileName(Path);
    public long SizeBytes { get; init; }
    public string? Sha256 { get; set; }
    public string? Sha512 { get; set; }
    public bool Disabled { get; init; }
    public JarInfo? Jar { get; set; }
    public string Classification { get; set; } = "unrecognised";
    public string? ModrinthProject { get; set; }

    public string? ModId => Jar?.Primary?.Id;

    internal bool DisguiseCheckPending { get; set; }
    internal (string Key, string Value, Model.Evidence Ev)? PendingAgent { get; set; }

    public Dictionary<string, object?> ToInventory() => new()
    {
        ["modId"] = Jar?.Primary?.Id,
        ["name"] = Jar?.Primary?.Name ?? FileName,
        ["version"] = Jar?.Primary?.Version,
        ["loader"] = Jar?.Primary?.Loader,
        ["classification"] = Disabled ? $"{Classification} (disabled)" : Classification,
        ["modrinthProject"] = ModrinthProject,
        ["fileName"] = FileName,
        ["path"] = Path,
        ["sha256"] = Sha256,
        ["sizeBytes"] = SizeBytes,
        ["nestedMods"] = Jar is null ? 0 : Jar.Nested.Count,
        ["launcher"] = Launcher,
    };
}
