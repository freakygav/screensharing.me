using System.Collections.Concurrent;
using System.Security.Cryptography;
using Screensharing.Scanner.Discovery;
using Screensharing.Scanner.Model;
using Screensharing.Scanner.Analysis;

namespace Screensharing.Scanner.Engine;

public sealed class ScanContext
{
    public required ScanOptions Options { get; init; }
    public RuleSet Rules => Options.Rules;
    public required bool Elevated { get; init; }
    public CustodyLog Custody { get; } = new();
    public List<Installation> Installations { get; } = [];
    public List<ModRecord> Mods { get; } = [];
    public List<Dictionary<string, object?>> JavaRuntimes { get; } = [];
    public Dictionary<string, double> Statistics { get; } = new();

    internal Action<Finding>? OnFinding;
    internal Action<string, int>? OnUnits;
    internal CategoryState? CurrentCategory;

    private readonly ConcurrentDictionary<string, Finding> _findings = new();
    public IReadOnlyCollection<Finding> Findings => _findings.Values.ToList();

    public DateTimeOffset Now => Options.Now();

    /// <summary>Marks work units complete and counts items examined in the current category.</summary>
    public void Advance(int units = 1, int itemsExamined = -1)
    {
        if (CurrentCategory is not null) CurrentCategory.ItemsExamined += itemsExamined < 0 ? units : itemsExamined;
        OnUnits?.Invoke(CurrentCategory?.Key ?? "", units);
    }

    public void SetActivity(string text) => OnUnits?.Invoke("@activity:" + text, 0);

    /// <summary>
    /// Creates a finding from a catalog rule. Returns null when the rule is not in the active
    /// ruleset (disabled by an administrator), so disabled heuristics never report.
    /// </summary>
    public Finding? Report(
        string ruleId,
        string[] discriminators,
        string description,
        string method,
        string whyItMatters,
        string alternativeExplanations,
        List<Evidence> evidence,
        string? name = null,
        EvidenceTier? tier = null,
        Severity? severity = null,
        int? confidence = null)
    {
        var rule = Rules.Get(ruleId);
        if (rule is null || evidence.Count == 0) return null;
        var f = new Finding
        {
            ClientFindingId = Finding.MakeId(ruleId, discriminators),
            RuleId = rule.Id,
            Name = Trim(name ?? rule.Name, 200),
            Description = Trim(description, 2000),
            Category = Trim(string.IsNullOrWhiteSpace(rule.Category) ? "General" : rule.Category, 80),
            CategoryKey = CurrentCategory?.Key ?? "general",
            Severity = severity ?? rule.SeverityValue,
            Tier = tier ?? rule.TierValue,
            Confidence = Math.Clamp(confidence ?? rule.Confidence, 0, 100),
            Method = Trim(method, 1000),
            WhyItMatters = Trim(whyItMatters, 2000),
            Limitations = Trim(string.IsNullOrWhiteSpace(rule.Limitations) ? "See detection catalog." : rule.Limitations, 2000),
            FalsePositiveNotes = Trim(string.IsNullOrWhiteSpace(rule.FalsePositives) ? "See detection catalog." : rule.FalsePositives, 2000),
            AlternativeExplanations = Trim(alternativeExplanations, 2000),
            DetectedAt = DateTimeOffset.UtcNow,
            Evidence = evidence.Take(25).ToList(),
            Family = rule.Family,
        };
        if (_findings.TryAdd(f.ClientFindingId, f))
        {
            if (CurrentCategory is not null) CurrentCategory.FindingsCount++;
            OnFinding?.Invoke(f);
        }
        return f;
    }

    private static string Trim(string s, int max) => s.Length <= max ? s : s[..(max - 1)] + "…";

    // ------------------------------------------------------------------ files
    private readonly ConcurrentDictionary<string, (long Size, DateTime Mtime, string Sha)> _hashCache = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Opens a file strictly read-only, never blocking other writers and never changing it.</summary>
    public static FileStream OpenRead(string path) =>
        new(path, new FileStreamOptions { Mode = FileMode.Open, Access = FileAccess.Read, Share = FileShare.ReadWrite | FileShare.Delete, Options = FileOptions.SequentialScan, BufferSize = 1 << 16 });

    public string? Sha256(string path)
    {
        try
        {
            var fi = new FileInfo(path);
            if (!fi.Exists) return null;
            if (_hashCache.TryGetValue(path, out var c) && c.Size == fi.Length && c.Mtime == fi.LastWriteTimeUtc) return c.Sha;
            using var fs = OpenRead(path);
            var sha = Convert.ToHexStringLower(SHA256.HashData(fs));
            _hashCache[path] = (fi.Length, fi.LastWriteTimeUtc, sha);
            Custody.Record("hash-sha256", path);
            return sha;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return null; }
    }

    /// <summary>File evidence with SHA-256, size and NTFS timestamps.</summary>
    public Evidence FileEvidence(string path, string source, Dictionary<string, string>? details = null, string kind = EvidenceKind.File, bool hash = true)
    {
        var fi = new FileInfo(path);
        return new Evidence
        {
            Kind = kind,
            Source = source,
            Reference = path,
            Sha256 = hash && fi.Exists ? Sha256(path) : null,
            SizeBytes = fi.Exists ? fi.Length : null,
            CreatedTime = fi.Exists ? fi.CreationTimeUtc : null,
            ModifiedTime = fi.Exists ? fi.LastWriteTimeUtc : null,
            AccessedTime = fi.Exists ? fi.LastAccessTimeUtc : null,
            Details = details,
        };
    }
}
