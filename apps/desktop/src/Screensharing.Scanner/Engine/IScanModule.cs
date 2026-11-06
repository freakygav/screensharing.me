namespace Screensharing.Scanner.Engine;

/// <summary>
/// A collection module. Modules first plan their work (counting real work items such as files,
/// processes or records), then run. Progress is the ratio of completed to planned work units,
/// so the percentage reflects actual work.
/// </summary>
public interface IScanModule
{
    string Key { get; }
    string Name { get; }

    /// <summary>Activity text shown while the module runs.</summary>
    string Activity { get; }

    /// <summary>Returns a reason when the module cannot run (e.g. requires administrator rights), else null.</summary>
    string? SkipReason(ScanContext ctx);

    /// <summary>Counts work units. Must be cheap relative to the work itself.</summary>
    int Plan(ScanContext ctx);

    Task RunAsync(ScanContext ctx, CancellationToken ct);
}
