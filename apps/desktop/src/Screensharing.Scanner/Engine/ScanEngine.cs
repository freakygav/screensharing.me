using System.Diagnostics;
using System.Security.Principal;
using Screensharing.Scanner.Discovery;
using Screensharing.Scanner.Model;
using Screensharing.Scanner.Modules;
using Screensharing.Scanner.Reporting;

namespace Screensharing.Scanner.Engine;

public sealed class ScanResult
{
    public required List<Finding> Findings { get; init; }
    public required List<Dictionary<string, object?>> Installations { get; init; }
    public required List<Dictionary<string, object?>> Mods { get; init; }
    public required List<Dictionary<string, object?>> JavaRuntimes { get; init; }
    public required Dictionary<string, double> Statistics { get; init; }
    public required List<CategoryState> Coverage { get; init; }
    public required List<CustodyOperation> Custody { get; init; }
    public required DateTimeOffset StartedAt { get; init; }
    public required DateTimeOffset CompletedAt { get; init; }
    public required string EngineVersion { get; init; }
    public required string RulesetVersion { get; init; }
    public required string OsVersion { get; init; }
    public required bool Elevated { get; init; }
    public string ManifestSha256 => Manifest.Compute(Findings);
}

/// <summary>Orchestrates the collection modules. Read-only: no module writes to the examined system.</summary>
public sealed class ScanEngine
{
    public static string EngineVersion => typeof(ScanEngine).Assembly.GetName().Version is { } v ? $"{v.Major}.{v.Minor}.{v.Build}" : "1.0.0";

    public event Action<ScanProgress>? Progress;
    public event Action<Finding>? FindingReported;

    private readonly ScanOptions _options;
    private readonly IReadOnlyList<IScanModule> _modules;

    public ScanEngine(ScanOptions options, IReadOnlyList<IScanModule>? modules = null)
    {
        _options = options;
        _modules = modules ?? DefaultModules();
    }

    public static IReadOnlyList<IScanModule> DefaultModules() =>
    [
        new InstallationsModule(),
        new ModsModule(),
        new IntegrityModule(),
        new LogsModule(),
        new JvmModule(),
        new Modules.ProcessModule(),
        new ExecutionModule(),
        new DeletedModule(),
        new TamperModule(),
    ];

    public IReadOnlyList<(string Key, string Name)> Categories => _modules.Select(m => (m.Key, m.Name)).ToList();

    public static bool IsElevated()
    {
        using var id = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
    }

    public static string OsDescription() =>
        $"{System.Runtime.InteropServices.RuntimeInformation.OSDescription} ({System.Runtime.InteropServices.RuntimeInformation.OSArchitecture})";

    public async Task<ScanResult> RunAsync(CancellationToken ct = default)
    {
        var started = DateTimeOffset.UtcNow;
        var ctx = new ScanContext { Options = _options, Elevated = IsElevated() };
        var states = _modules.Select(m => new CategoryState { Key = m.Key, Name = m.Name }).ToList();
        long done = 0, total = 0;
        string? activity = "Preparing investigation…";
        var lastEmit = Stopwatch.StartNew();
        var gate = new object();

        void Emit(bool force = false)
        {
            lock (gate)
            {
                if (!force && lastEmit.ElapsedMilliseconds < 120) return;
                lastEmit.Restart();
                var pct = total == 0 ? 0 : (int)Math.Min(99, done * 100 / total);
                Progress?.Invoke(new ScanProgress(pct, activity, states.Select(s => s.Clone()).ToList(), done, total));
            }
        }

        ctx.OnFinding = f => { FindingReported?.Invoke(f); Emit(true); };
        ctx.OnUnits = (key, units) =>
        {
            if (key.StartsWith("@activity:", StringComparison.Ordinal)) { activity = key[10..]; Emit(); return; }
            Interlocked.Add(ref done, units);
            Emit();
        };

        // Discovery happens first because nearly every module depends on it.
        MinecraftLocator.Discover(ctx);

        // Plan: real work-unit counts per module.
        var plans = new Dictionary<IScanModule, int>();
        foreach (var (m, s) in _modules.Zip(states))
        {
            var skip = m.SkipReason(ctx);
            if (skip is not null) { s.Status = CategoryStatus.Skipped; s.Message = skip; plans[m] = 0; continue; }
            try { plans[m] = Math.Max(1, m.Plan(ctx)); }
            catch (Exception e) { plans[m] = 1; s.Message = "Planning error: " + e.Message; }
            total += plans[m];
        }
        Emit(true);

        foreach (var (m, s) in _modules.Zip(states))
        {
            ct.ThrowIfCancellationRequested();
            if (s.Status == CategoryStatus.Skipped) continue;
            s.Status = CategoryStatus.Running;
            ctx.CurrentCategory = s;
            activity = m.Activity;
            var before = Interlocked.Read(ref done);
            Emit(true);
            try
            {
                await m.RunAsync(ctx, ct).ConfigureAwait(false);
                s.Status = CategoryStatus.Completed;
                s.Message ??= $"{s.ItemsExamined:N0} items examined";
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception e)
            {
                s.Status = CategoryStatus.Failed;
                s.Message = $"Module error: {e.GetType().Name}: {e.Message}";
            }
            // Reconcile: any unconsumed planned units are completed when the module finishes.
            var used = Interlocked.Read(ref done) - before;
            if (used < plans[m]) Interlocked.Add(ref done, plans[m] - used);
            ctx.CurrentCategory = null;
            Emit(true);
        }

        activity = "Validating forensic evidence…";
        Emit(true);
        var findings = ctx.Findings.OrderBy(f => f.Severity).ThenByDescending(f => f.Confidence).ToList();
        var result = new ScanResult
        {
            Findings = findings,
            Installations = ctx.Installations.Select(i => i.ToInventory()).ToList(),
            Mods = ctx.Mods.Select(m => m.ToInventory()).ToList(),
            JavaRuntimes = ctx.JavaRuntimes,
            Statistics = ctx.Statistics,
            Coverage = states,
            Custody = ctx.Custody.Snapshot(),
            StartedAt = started,
            CompletedAt = DateTimeOffset.UtcNow,
            EngineVersion = EngineVersion,
            RulesetVersion = _options.Rules.Version,
            OsVersion = OsDescription(),
            Elevated = ctx.Elevated,
        };
        Progress?.Invoke(new ScanProgress(100, "Investigation complete", states.Select(s => s.Clone()).ToList(), total, total));
        return result;
    }
}
