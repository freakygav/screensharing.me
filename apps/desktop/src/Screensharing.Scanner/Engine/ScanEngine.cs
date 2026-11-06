using System.Diagnostics;
using System.Security.Principal;
using Screensharing.Scanner.Instance;
using Screensharing.Scanner.Model;
using Screensharing.Scanner.Modules;
using Screensharing.Scanner.Reporting;

namespace Screensharing.Scanner.Engine;

public sealed class InstanceNotResolvedException(string message) : InvalidOperationException(message);

public sealed class ScanResult
{
    public required List<Finding> Findings { get; init; }
    public required GameInstance Instance { get; init; }
    public required List<Dictionary<string, object?>> Installations { get; init; }
    public required List<Dictionary<string, object?>> Mods { get; init; }
    public required List<Dictionary<string, object?>> JavaRuntimes { get; init; }
    public required Dictionary<string, double> Statistics { get; init; }
    public required Dictionary<string, object?> Inspection { get; init; }
    public required IReadOnlyCollection<InspectionRecord> InspectionRecords { get; init; }
    public required List<string> ExcludedLocations { get; init; }
    public required List<CategoryState> Coverage { get; init; }
    public required List<CustodyOperation> Custody { get; init; }
    public required IReadOnlyCollection<string> ScopeViolations { get; init; }
    /// <summary>Every path that passed the scope check during the scan.</summary>
    public required IReadOnlyCollection<string> AccessedPaths { get; init; }
    public required IReadOnlyList<string> ScopeRoots { get; init; }
    public required int SignatureCount { get; init; }
    public required DateTimeOffset StartedAt { get; init; }
    public required DateTimeOffset CompletedAt { get; init; }
    public required string EngineVersion { get; init; }
    public required string RulesetVersion { get; init; }
    public required string OsVersion { get; init; }
    public required bool Elevated { get; init; }
    public string ManifestSha256 => Manifest.Compute(Findings);

    public int Count(FindingOutcome o) => Findings.Count(f => f.Outcome == o);
}

/// <summary>
/// Orchestrates the scan of ONE selected Minecraft instance. Read-only: no module writes to the examined system,
/// and every file access is checked against the <see cref="ScanScope"/> built from the instance and its running process.
/// </summary>
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
        new LaunchModule(),
        new ModsModule(),
        new GameFilesModule(),
        new FilesModule(),
        new PacksModule(),
        new LogsModule(),
        new Modules.ProcessModule(),
    ];

    public IReadOnlyList<(string Key, string Name)> Categories => [("discovery", "Instance discovery"), .. _modules.Select(m => (m.Key, m.Name))];

    public static bool IsElevated()
    {
        using var id = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
    }

    public static string OsDescription() =>
        $"{System.Runtime.InteropServices.RuntimeInformation.OSDescription} ({System.Runtime.InteropServices.RuntimeInformation.OSArchitecture})";

    /// <summary>The scope implied by an instance: its folders plus the files its running process attests to.</summary>
    public static ScanScope BuildScope(GameInstance inst)
    {
        var roots = new List<string> { inst.InstanceRoot, inst.GameDirectory };
        try
        {
            // If the game directory itself is a link, the instance physically lives at the target.
            var di = new DirectoryInfo(inst.GameDirectory);
            if (di.Attributes.HasFlag(FileAttributes.ReparsePoint) && di.ResolveLinkTarget(true) is { } t) roots.Add(t.FullName);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
        var files = new List<(string, string)>();
        foreach (var c in inst.ClassPath) files.Add((c, "class path of the game process"));
        foreach (var m in GameFilesModule.ManifestCandidates(inst.ClassPath)) files.Add((m, "version manifest of the class path"));
        foreach (var (kind, value) in inst.Agents) files.Add((value.Trim('"').Split('=')[0], $"-{kind} argument of the game process"));
        return new ScanScope(roots, files);
    }

    public async Task<ScanResult> RunAsync(CancellationToken ct = default)
    {
        var inst = _options.Target;
        if (!inst.Resolved || string.IsNullOrWhiteSpace(inst.GameDirectory))
            throw new InstanceNotResolvedException(inst.Problem ?? "The Minecraft instance has not been identified; refusing to scan.");
        if (!Directory.Exists(inst.GameDirectory))
            throw new InstanceNotResolvedException($"The instance folder \"{inst.GameDirectory}\" no longer exists.");

        var started = DateTimeOffset.UtcNow;
        var clock = Stopwatch.StartNew();
        var scope = BuildScope(inst);
        var previous = ScanScope.Current;
        ScanScope.Current = scope;
        try
        {
            var ctx = new ScanContext { Options = _options, Elevated = IsElevated(), Instance = inst, Scope = scope };
            var discovery = new CategoryState { Key = "discovery", Name = "Instance discovery" };
            var states = new List<CategoryState> { discovery };
            states.AddRange(_modules.Select(m => new CategoryState { Key = m.Key, Name = m.Name }));
            long done = 0, total = 0;
            string? activity = "Preparing the investigation…";
            var stage = "Discovery";
            var lastEmit = Stopwatch.StartNew();
            var gate = new object();

            void Emit(bool force = false)
            {
                lock (gate)
                {
                    if (!force && lastEmit.ElapsedMilliseconds < 120) return;
                    lastEmit.Restart();
                    var pct = total == 0 ? 0 : (int)Math.Min(99, done * 100 / total);
                    Progress?.Invoke(new ScanProgress(pct, activity, states.Select(s => s.Clone()).ToList(), done, total)
                    {
                        Stage = stage, FilesExamined = ctx.Inspection.Examined, FilesAnalyzed = ctx.Inspection.Analyzed, FilesSkipped = ctx.Inspection.Skipped,
                        UnableToInspect = ctx.Inspection.UnableToInspect, Findings = ctx.Findings.Count, Elapsed = clock.Elapsed,
                    });
                }
            }

            ctx.OnFinding = f => { FindingReported?.Invoke(f); Emit(true); };
            ctx.OnUnits = (key, units) =>
            {
                if (key.StartsWith("@activity:", StringComparison.Ordinal)) { activity = key[10..]; Emit(); return; }
                Interlocked.Add(ref done, units);
                Emit();
            };

            // 1. Discovery of the instance's files (inside the scope only).
            discovery.Status = CategoryStatus.Running;
            activity = $"Discovering files of {inst.Name}…";
            Emit(true);
            ctx.Custody.Record("select-instance", $"{inst.Launcher}: {inst.GameDirectory} (PID {inst.ProcessId?.ToString() ?? "none"}, {inst.GameDirectorySource})");
            var (files, excluded, links, truncated) = InstanceFiles.Discover(ctx, ct);
            ctx.Files.AddRange(files);
            ctx.ExcludedLocations.AddRange(excluded);
            ctx.Links.AddRange(links);
            discovery.ItemsExamined = files.Count;
            discovery.Status = CategoryStatus.Completed;
            discovery.Message = $"{files.Count:N0} files and pack folders in {inst.GameDirectory}" + (excluded.Count > 0 ? $"; {excluded.Count} folders excluded" : "") +
                                (truncated ? $"; stopped at {InstanceFiles.MaxEntries:N0} entries — remaining files NOT examined" : "");
            if (truncated) ctx.Statistics["discoveryTruncated"] = 1;

            // 2. Plan: real work-unit counts per module.
            var plans = new Dictionary<IScanModule, int>();
            foreach (var (m, s) in _modules.Zip(states.Skip(1)))
            {
                var skip = m.SkipReason(ctx);
                if (skip is not null) { s.Status = CategoryStatus.Skipped; s.Message = skip; plans[m] = 0; continue; }
                try { plans[m] = Math.Max(1, m.Plan(ctx)); }
                catch (ScopeViolationException) { throw; }
                catch (Exception e) when (e is not OperationCanceledException) { plans[m] = 1; s.Message = "Planning error: " + e.Message; }
                total += plans[m];
            }
            Emit(true);

            // 3. Run.
            foreach (var (m, s) in _modules.Zip(states.Skip(1)))
            {
                ct.ThrowIfCancellationRequested();
                if (s.Status == CategoryStatus.Skipped) continue;
                s.Status = CategoryStatus.Running;
                ctx.CurrentCategory = s;
                activity = m.Activity;
                stage = m.Name;
                var before = Interlocked.Read(ref done);
                Emit(true);
                try
                {
                    await m.RunAsync(ctx, ct).ConfigureAwait(false);
                    s.Status = CategoryStatus.Completed;
                    s.Message ??= $"{s.ItemsExamined:N0} items examined";
                }
                catch (OperationCanceledException) { throw; }
                catch (ScopeViolationException e)
                {
                    // A module tried to leave the instance: the attempt was blocked; record it loudly.
                    s.Status = CategoryStatus.Failed;
                    s.Message = "Stopped: " + e.Message;
                }
                catch (Exception e)
                {
                    s.Status = CategoryStatus.Failed;
                    s.Message = $"Module error: {e.GetType().Name}: {e.Message}";
                }
                var used = Interlocked.Read(ref done) - before;
                if (used < plans[m]) Interlocked.Add(ref done, plans[m] - used);
                ctx.CurrentCategory = null;
                Emit(true);
            }

            activity = "Validating forensic evidence…";
            stage = "Report";
            Emit(true);
            ctx.Statistics["filesExamined"] = ctx.Inspection.Examined;
            ctx.Statistics["filesAnalyzed"] = ctx.Inspection.Analyzed;
            ctx.Statistics["filesSkipped"] = ctx.Inspection.Skipped;
            ctx.Statistics["filesUnableToInspect"] = ctx.Inspection.UnableToInspect;
            ctx.Statistics["signatures"] = SignatureCount(_options.Rules);
            ctx.Statistics["durationSeconds"] = Math.Round(clock.Elapsed.TotalSeconds, 1);
            var findings = ctx.Findings.OrderBy(f => f.Outcome).ThenBy(f => f.Severity).ThenByDescending(f => f.Confidence).ToList();
            var result = new ScanResult
            {
                Findings = findings,
                Instance = inst,
                Installations = [inst.ToInventory()],
                Mods = ctx.Mods.Select(m => m.ToInventory()).ToList(),
                JavaRuntimes = inst.JavaExecutable is null ? [] : [new() { ["path"] = inst.JavaExecutable, ["source"] = "Java runtime of the game process" }],
                Statistics = ctx.Statistics,
                Inspection = ctx.Inspection.Summary(),
                InspectionRecords = ctx.Inspection.Records,
                ExcludedLocations = ctx.ExcludedLocations,
                Coverage = states,
                Custody = ctx.Custody.Snapshot(),
                ScopeViolations = scope.Violations,
                AccessedPaths = scope.Accessed,
                ScopeRoots = scope.Roots,
                SignatureCount = SignatureCount(_options.Rules),
                StartedAt = started,
                CompletedAt = DateTimeOffset.UtcNow,
                EngineVersion = EngineVersion,
                RulesetVersion = _options.Rules.Version,
                OsVersion = OsDescription(),
                Elevated = ctx.Elevated,
            };
            Progress?.Invoke(new ScanProgress(100, "Investigation complete", states.Select(s => s.Clone()).ToList(), total, total)
            {
                Stage = "Complete", FilesExamined = ctx.Inspection.Examined, FilesAnalyzed = ctx.Inspection.Analyzed, FilesSkipped = ctx.Inspection.Skipped,
                UnableToInspect = ctx.Inspection.UnableToInspect, Findings = findings.Count, Elapsed = clock.Elapsed,
            });
            return result;
        }
        finally { ScanScope.Current = previous; }
    }

    /// <summary>Number of detection signatures (rules that can produce findings; classification-only entries excluded).</summary>
    public static int SignatureCount(RuleSet rules) => rules.Rules.Count(r => r.Kind is not (RuleKind.KnownMod or RuleKind.FeatureName or RuleKind.ModulePackage or RuleKind.LibraryPackage));
}
