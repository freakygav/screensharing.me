using Screensharing.Scanner.Model;

namespace Screensharing.Scanner.Engine;

public sealed class CategoryState
{
    public required string Key { get; init; }
    public required string Name { get; init; }
    public CategoryStatus Status { get; set; } = CategoryStatus.Pending;
    public int ItemsExamined { get; set; }
    public int FindingsCount { get; set; }
    public string? Message { get; set; }
    public CategoryState Clone() => (CategoryState)MemberwiseClone();
}

public sealed record ScanProgress(int Percent, string? Activity, IReadOnlyList<CategoryState> Categories, long UnitsDone, long UnitsTotal);
