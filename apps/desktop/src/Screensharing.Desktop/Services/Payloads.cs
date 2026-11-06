using Screensharing.Scanner.Engine;
using Screensharing.Scanner.Model;

namespace Screensharing.Desktop.Services;

/// <summary>Converts scanner output into the exact shapes the backend validates (apps/website/src/lib/validation.ts).</summary>
public static class Payloads
{
    private static string Cut(string? s, int max) => s is null ? "" : s.Length <= max ? s : s[..max];

    public static object Finding(Finding f) => new
    {
        clientFindingId = f.ClientFindingId,
        ruleId = f.RuleId,
        name = Cut(f.Name, 200),
        description = Cut(f.Description, 2000),
        category = Cut(f.Category, 80),
        categoryKey = f.CategoryKey,
        severity = f.Severity.Api(),
        tier = f.Tier.Api(),
        confidence = f.Confidence,
        method = Cut(f.Method, 1000),
        whyItMatters = Cut(f.WhyItMatters, 2000),
        limitations = Cut(f.Limitations, 2000),
        falsePositiveNotes = Cut(f.FalsePositiveNotes, 2000),
        alternativeExplanations = Cut(f.AlternativeExplanations, 2000),
        detectedAt = f.DetectedAt,
        evidence = f.Evidence.Take(25).Select(e => new
        {
            kind = e.Kind,
            source = Cut(e.Source, 120),
            reference = Cut(e.Reference, 1024),
            sha256 = e.Sha256,
            sizeBytes = e.SizeBytes,
            createdTime = e.CreatedTime,
            modifiedTime = e.ModifiedTime,
            accessedTime = e.AccessedTime,
            observedAt = e.ObservedAt,
            details = e.Details?.Take(40).ToDictionary(k => Cut(k.Key, 64), k => Cut(k.Value, 2000)),
        }).ToList(),
    };

    public static object Progress(ScanProgress p) => new
    {
        progress = Math.Clamp(p.Percent, 0, 100),
        currentActivity = Cut(p.Activity, 200),
        categories = p.Categories.Select(c => new
        {
            key = c.Key,
            status = Status(c.Status),
            itemsExamined = c.ItemsExamined,
            findingsCount = c.FindingsCount,
            message = c.Message is null ? null : Cut(c.Message, 300),
        }).ToList(),
    };

    public static string Status(CategoryStatus s) => s switch
    {
        CategoryStatus.Running => "RUNNING", CategoryStatus.Completed => "COMPLETED", CategoryStatus.Skipped => "SKIPPED", CategoryStatus.Failed => "FAILED", _ => "PENDING",
    };

    private static List<Dictionary<string, object?>> Items(IEnumerable<Dictionary<string, object?>> items, int max) =>
        items.Take(max).Select(d => d.Take(40).ToDictionary(k => Cut(k.Key, 64), k => k.Value switch
        {
            null => null,
            string s => (object?)Cut(s, 1024),
            bool b => b,
            int or long or double or float => k.Value,
            _ => Cut(k.Value.ToString(), 1024),
        })).ToList();

    public static object Complete(ScanResult r) => new
    {
        manifestSha256 = r.ManifestSha256,
        findingCount = r.Findings.Count,
        summary = new
        {
            installations = Items(r.Installations, 200),
            mods = Items(r.Mods, 3000),
            javaRuntimes = Items(r.JavaRuntimes, 100),
            statistics = r.Statistics,
        },
        coverage = r.Coverage.Select(c => new { key = c.Key, name = c.Name, status = Status(c.Status), note = c.Message is null ? null : Cut(c.Message, 500) }).ToList(),
        chainOfCustody = new
        {
            engineVersion = r.EngineVersion,
            rulesetVersion = Cut(r.RulesetVersion, 40),
            osVersion = Cut(r.OsVersion, 120),
            elevated = r.Elevated,
            startedAt = r.StartedAt,
            completedAt = r.CompletedAt,
            readOnly = true,
            operations = r.Custody.Take(2000).Select(o => new { at = o.At, action = Cut(o.Action, 120), target = Cut(o.Target, 1024) }).ToList(),
        },
    };
}
