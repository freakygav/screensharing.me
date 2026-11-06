using System.Collections.Concurrent;
using System.Security.Cryptography;
using Screensharing.Scanner.Analysis;
using Screensharing.Scanner.Instance;
using Screensharing.Scanner.Model;

namespace Screensharing.Scanner.Engine;

/// <summary>Directory enumeration that goes through the scan scope.</summary>
public sealed class ScopedFileSystem(ScanScope scope)
{
    public IEnumerable<string> Files(string dir, string pattern = "*")
    {
        scope.Demand(dir, "enumerate");
        if (!Directory.Exists(dir)) return [];
        try { return Directory.GetFiles(dir, pattern).OrderBy(f => f, StringComparer.OrdinalIgnoreCase).ToList(); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return []; }
    }

    public IEnumerable<string> Directories(string dir)
    {
        scope.Demand(dir, "enumerate");
        if (!Directory.Exists(dir)) return [];
        try { return Directory.GetDirectories(dir).OrderBy(f => f, StringComparer.OrdinalIgnoreCase).ToList(); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return []; }
    }

    public bool FileExists(string path) { scope.Demand(path, "stat"); return File.Exists(path); }
    public bool DirectoryExists(string path) { scope.Demand(path, "stat"); return Directory.Exists(path); }
}

public sealed class ScanContext
{
    public required ScanOptions Options { get; init; }
    public RuleSet Rules => Options.Rules;
    public required bool Elevated { get; init; }
    public required GameInstance Instance { get; init; }
    public required ScanScope Scope { get; init; }
    public ScopedFileSystem Fs => _fs ??= new ScopedFileSystem(Scope);
    private ScopedFileSystem? _fs;
    public SignatureIndex Signatures => _signatures ??= new SignatureIndex(Rules);
    private SignatureIndex? _signatures;

    public CustodyLog Custody { get; } = new();
    public InspectionLog Inspection { get; } = new();
    public List<InstanceFile> Files { get; } = [];
    public List<string> ExcludedLocations { get; } = [];
    public List<InstanceFiles.Linked> Links { get; } = [];
    public List<ModRecord> Mods { get; } = [];
    public Dictionary<string, double> Statistics { get; } = new();

    internal Action<Finding>? OnFinding;
    internal Action<string, int>? OnUnits;
    internal CategoryState? CurrentCategory;

    private readonly ConcurrentDictionary<string, Finding> _findings = new();
    public IReadOnlyCollection<Finding> Findings => _findings.Values.ToList();

    public DateTimeOffset Now => Options.Now();

    public IEnumerable<InstanceFile> FilesOf(params FileRole[] roles) => Files.Where(f => roles.Contains(f.Role));

    /// <summary>Marks work units complete and counts items examined in the current category.</summary>
    public void Advance(int units = 1, int itemsExamined = -1)
    {
        if (CurrentCategory is not null) CurrentCategory.ItemsExamined += itemsExamined < 0 ? units : itemsExamined;
        OnUnits?.Invoke(CurrentCategory?.Key ?? "", units);
    }

    public void SetActivity(string text) => OnUnits?.Invoke("@activity:" + text, 0);

    /// <summary>Instance-relative location for reports: relative to the game directory, else to the instance folder, else the full path.</summary>
    public string Location(string path)
    {
        try
        {
            var n = ScanScope.Normalize(path);
            var game = ScanScope.Normalize(Instance.GameDirectory);
            if (n.StartsWith(game + "\\", StringComparison.OrdinalIgnoreCase)) return n[(game.Length + 1)..].Replace('\\', '/');
            var rel = Scope.Relative(n);
            return rel;
        }
        catch (Exception e) when (e is ArgumentException or NotSupportedException or PathTooLongException) { return path; }
    }

    public void Analyzed(string path, FileRole role) => Inspection.Record(new InspectionRecord(path, Location(path), role, InspectionStatus.Analyzed, null));
    public void NotApplicable(string path, FileRole role, string reason) => Inspection.Record(new InspectionRecord(path, Location(path), role, InspectionStatus.NotApplicable, reason));

    /// <summary>Records a file that could not be inspected and, for files that can carry code, reports it so the investigator sees the gap.</summary>
    public void Uninspectable(string path, FileRole role, InspectionStatus status, string reason, bool report = true)
    {
        Inspection.Record(new InspectionRecord(path, Location(path), role, status, reason));
        if (!report) return;
        Report(Builtin.Uninspectable, [path],
            $"\"{Location(path)}\" could not be inspected: {reason}",
            "The file was discovered in the selected instance but its content could not be read completely.",
            "A file that cannot be inspected cannot be cleared. Review it manually if it matters to the investigation.",
            "Files in use, very large files or damaged downloads are the usual causes.",
            [new Evidence { Kind = EvidenceKind.File, Source = "Instance file", Reference = path, Details = new() { ["status"] = status.ToString(), ["reason"] = reason } }],
            name: $"Unable to inspect: {Path.GetFileName(path)}", location: Location(path));
    }

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
        int? confidence = null,
        string? family = null,
        string? signature = null,
        string? location = null)
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
            Family = family ?? rule.Family,
            Signature = signature is null ? null : Trim(signature, 300),
            Location = location is null ? (evidence[0].Kind is EvidenceKind.File or EvidenceKind.JarEntry or EvidenceKind.Log or EvidenceKind.Config ? Trim(Location(evidence[0].Reference.Split("!/")[0]), 500) : null) : Trim(location, 500),
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

    /// <summary>Opens a file strictly read-only (after the scope check), never blocking other writers and never changing it.</summary>
    public FileStream OpenRead(string path)
    {
        Scope.Demand(path, "read");
        return OpenUnchecked(path);
    }

    internal static FileStream OpenUnchecked(string path) =>
        new(path, new FileStreamOptions { Mode = FileMode.Open, Access = FileAccess.Read, Share = FileShare.ReadWrite | FileShare.Delete, Options = FileOptions.SequentialScan, BufferSize = 1 << 16 });

    public string? Sha256(string path)
    {
        try
        {
            Scope.Demand(path, "hash");
            var fi = new FileInfo(path);
            if (!fi.Exists) return null;
            if (_hashCache.TryGetValue(path, out var c) && c.Size == fi.Length && c.Mtime == fi.LastWriteTimeUtc) return c.Sha;
            using var fs = OpenUnchecked(path);
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
        Scope.Demand(path, "stat");
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
