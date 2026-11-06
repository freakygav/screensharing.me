using Screensharing.Scanner.Engine;

namespace Screensharing.Scanner.Modules;

/// <summary>Inventory of Minecraft installations. Produces context, not findings.</summary>
public sealed class InstallationsModule : IScanModule
{
    public string Key => "installations";
    public string Name => "Minecraft installations";
    public string Activity => "Scanning Minecraft installations…";
    public string? SkipReason(ScanContext ctx) => null;
    public int Plan(ScanContext ctx) => Math.Max(1, ctx.Installations.Count);

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        foreach (var i in ctx.Installations)
        {
            ct.ThrowIfCancellationRequested();
            ctx.SetActivity($"Scanning Minecraft installations… {i.Launcher}");
            ctx.Advance();
        }
        ctx.Statistics["installations"] = ctx.Installations.Count;
        if (ctx.CurrentCategory is not null)
            ctx.CurrentCategory.Message = ctx.Installations.Count == 0 ? "No Minecraft installation found in standard locations" : $"{ctx.Installations.Count} installation(s) found";
        return Task.CompletedTask;
    }
}
