namespace Screensharing.Scanner.Discovery;

public sealed class Installation
{
    public required string Launcher { get; init; }
    public required string GameDirectory { get; init; }
    public List<string> ModsDirectories { get; } = [];
    public string? VersionsDirectory { get; set; }
    public string? LibrariesDirectory { get; set; }
    public List<string> LogDirectories { get; } = [];
    public string? ResourcePacksDirectory { get; set; }
    public List<string> Versions { get; } = [];
    public int ModCount { get; set; }
    public string? Note { get; set; }

    public Dictionary<string, object?> ToInventory() => new()
    {
        ["launcher"] = Launcher,
        ["path"] = GameDirectory,
        ["versions"] = Versions.Count == 0 ? "—" : string.Join(", ", Versions.Take(40)),
        ["modCount"] = ModCount,
        ["note"] = Note,
    };
}
