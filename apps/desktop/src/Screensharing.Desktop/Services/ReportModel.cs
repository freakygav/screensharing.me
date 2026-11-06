using System.Text.Json;
using Screensharing.Scanner.Engine;
using Screensharing.Scanner.Model;

namespace Screensharing.Desktop.Services;

public sealed record EvidenceItem(string Kind, string Source, string Reference, string? Sha256, long? SizeBytes, DateTimeOffset? CreatedTime, DateTimeOffset? ModifiedTime, DateTimeOffset ObservedAt, IReadOnlyDictionary<string, string> Details);

public sealed record FindingItem(
    string Id, string RuleId, string Name, string Description, string Category, string Severity, string Tier, int Confidence,
    string Method, string WhyItMatters, string Limitations, string FalsePositiveNotes, string AlternativeExplanations,
    DateTimeOffset DetectedAt, IReadOnlyList<EvidenceItem> Evidence)
{
    public string TierLabel => Tier switch
    {
        "CONFIRMED_ARTIFACT" => "Confirmed artifact", "STRONG_INDICATOR" => "Strong indicator", "SUSPICIOUS_CONFIGURATION" => "Suspicious config",
        "WEAK_INDICATOR" => "Weak indicator", _ => "Inconclusive",
    };
    public string PrimaryReference => Evidence.Count > 0 ? Evidence[0].Reference : "";
    public int SeverityRank => Severity switch { "CRITICAL" => 0, "HIGH" => 1, "MEDIUM" => 2, "LOW" => 3, _ => 4 };
}

public sealed record CoverageItem(string Name, string Status, string? Note);

/// <summary>A report, either produced locally by this scan or downloaded from the server (staff view).</summary>
public sealed class ReportModel
{
    public required string InvestigationId { get; init; }
    public required string Reference { get; init; }
    public required string Subject { get; init; }
    public string? Server { get; init; }
    public string? RequestedBy { get; init; }
    public DateTimeOffset? StartedAt { get; init; }
    public DateTimeOffset? CompletedAt { get; init; }
    public string EngineVersion { get; init; } = "";
    public string RulesetVersion { get; init; } = "";
    public bool Elevated { get; init; }
    public string? ManifestSha256 { get; init; }
    public bool? ManifestVerified { get; set; }
    public required List<FindingItem> Findings { get; init; }
    public required List<CoverageItem> Coverage { get; init; }
    public List<Dictionary<string, object?>> Installations { get; init; } = [];
    public List<Dictionary<string, object?>> Mods { get; init; } = [];
    public List<(DateTimeOffset At, string Action, string Target)> Custody { get; init; } = [];
    public string Source { get; init; } = "local";

    public int Count(string severity) => Findings.Count(f => f.Severity == severity);
    public int CountTier(string tier) => Findings.Count(f => f.Tier == tier);

    public (string Title, string Explanation, string Level) Verdict()
    {
        if (CountTier("CONFIRMED_ARTIFACT") > 0) return ("Confirmed artifact match", "At least one artifact matched a verified signature of a prohibited modification. Review the evidence and its timing before taking action.", "confirmed");
        if (CountTier("STRONG_INDICATOR") > 0) return ("Strong forensic indicators", "Evidence strongly indicates a prohibited modification, but no artifact matched a verified signature. Manual review is required.", "strong");
        if (CountTier("SUSPICIOUS_CONFIGURATION") > 0) return ("Suspicious configuration", "Configurations commonly associated with prohibited modifications or concealment were found. They have legitimate explanations; review each finding.", "suspicious");
        if (CountTier("WEAK_INDICATOR") > 0) return ("Weak indicators only", "Only weak indicators were found. On their own they do not support a conclusion.", "review");
        return ("No indicators found", "No examined artifact matched a detection rule. This does not prove the absence of modifications outside the examined scope.", "clear");
    }

    public static ReportModel FromLocal(ScanResult r, InvestigationInfo inv, bool? manifestVerified) => new()
    {
        InvestigationId = inv.Id,
        Reference = inv.Reference,
        Subject = inv.SubjectName,
        Server = inv.ServerName,
        RequestedBy = inv.RequestedBy,
        StartedAt = r.StartedAt,
        CompletedAt = r.CompletedAt,
        EngineVersion = r.EngineVersion,
        RulesetVersion = r.RulesetVersion,
        Elevated = r.Elevated,
        ManifestSha256 = r.ManifestSha256,
        ManifestVerified = manifestVerified,
        Findings = r.Findings.Select(f => new FindingItem(
            f.ClientFindingId, f.RuleId, f.Name, f.Description, f.Category, f.Severity.Api(), f.Tier.Api(), f.Confidence,
            f.Method, f.WhyItMatters, f.Limitations, f.FalsePositiveNotes, f.AlternativeExplanations, f.DetectedAt,
            f.Evidence.Select(e => new EvidenceItem(e.Kind, e.Source, e.Reference, e.Sha256, e.SizeBytes, e.CreatedTime, e.ModifiedTime, e.ObservedAt,
                (IReadOnlyDictionary<string, string>?)e.Details ?? new Dictionary<string, string>())).ToList()))
            .OrderBy(f => f.SeverityRank).ThenByDescending(f => f.Confidence).ToList(),
        Coverage = r.Coverage.Select(c => new CoverageItem(c.Name, Payloads.Status(c.Status), c.Message)).ToList(),
        Installations = r.Installations,
        Mods = r.Mods,
        Custody = r.Custody.Select(o => (o.At, o.Action, o.Target)).ToList(),
    };

    /// <summary>Builds a report from the server snapshot JSON (GET /api/desktop/staff/investigations/{id}).</summary>
    public static ReportModel FromServer(JsonElement s)
    {
        static string? Str(JsonElement e, string p) => e.TryGetProperty(p, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
        static DateTimeOffset? Date(JsonElement e, string p) => Str(e, p) is { } x ? DateTimeOffset.Parse(x) : null;
        var scan = s.TryGetProperty("scan", out var sc) && sc.ValueKind == JsonValueKind.Object ? sc : default;
        var findings = new List<FindingItem>();
        if (s.TryGetProperty("detections", out var dets))
            foreach (var d in dets.EnumerateArray())
            {
                var ev = d.GetProperty("evidence").EnumerateArray().Select(e => new EvidenceItem(
                    Str(e, "kind") ?? "", Str(e, "source") ?? "", Str(e, "reference") ?? "", Str(e, "sha256"),
                    e.TryGetProperty("sizeBytes", out var sz) && sz.ValueKind == JsonValueKind.Number ? sz.GetInt64() : null,
                    Date(e, "createdTime"), Date(e, "modifiedTime"), Date(e, "observedAt") ?? DateTimeOffset.MinValue,
                    e.TryGetProperty("details", out var det) && det.ValueKind == JsonValueKind.Object
                        ? det.EnumerateObject().ToDictionary(p => p.Name, p => p.Value.ToString()) : new Dictionary<string, string>())).ToList();
                findings.Add(new FindingItem(Str(d, "id") ?? "", Str(d, "ruleId") ?? "", Str(d, "name") ?? "", Str(d, "description") ?? "", Str(d, "category") ?? "",
                    Str(d, "severity") ?? "INFO", Str(d, "tier") ?? "INCONCLUSIVE", d.GetProperty("confidence").GetInt32(), Str(d, "method") ?? "", Str(d, "whyItMatters") ?? "",
                    Str(d, "limitations") ?? "", Str(d, "falsePositiveNotes") ?? "", Str(d, "alternativeExplanations") ?? "", Date(d, "detectedAt") ?? DateTimeOffset.MinValue, ev));
            }
        var coverage = new List<CoverageItem>();
        if (scan.ValueKind == JsonValueKind.Object && scan.TryGetProperty("coverage", out var cov) && cov.ValueKind == JsonValueKind.Array)
            coverage.AddRange(cov.EnumerateArray().Select(c => new CoverageItem(Str(c, "name") ?? "", Str(c, "status") ?? "", Str(c, "note"))));
        else if (scan.ValueKind == JsonValueKind.Object)
            coverage.AddRange(scan.GetProperty("categories").EnumerateArray().Select(c => new CoverageItem(Str(c, "name") ?? "", Str(c, "status") ?? "", Str(c, "message"))));

        List<Dictionary<string, object?>> Inv(string key)
        {
            if (scan.ValueKind != JsonValueKind.Object || !scan.TryGetProperty("summary", out var sum) || sum.ValueKind != JsonValueKind.Object || !sum.TryGetProperty(key, out var arr)) return [];
            return arr.EnumerateArray().Select(o => o.EnumerateObject().ToDictionary(p => p.Name, p => (object?)p.Value.ToString())).ToList();
        }
        var custody = new List<(DateTimeOffset, string, string)>();
        if (scan.ValueKind == JsonValueKind.Object && scan.TryGetProperty("chainOfCustody", out var coc) && coc.ValueKind == JsonValueKind.Object && coc.TryGetProperty("operations", out var ops))
            custody.AddRange(ops.EnumerateArray().Select(o => (Date(o, "at") ?? DateTimeOffset.MinValue, Str(o, "action") ?? "", Str(o, "target") ?? "")));

        return new ReportModel
        {
            InvestigationId = Str(s, "id") ?? "",
            Reference = Str(s, "reference") ?? "",
            Subject = Str(s, "subjectName") ?? "",
            Server = Str(s, "serverName"),
            RequestedBy = s.TryGetProperty("owner", out var ow) ? Str(ow, "displayName") : null,
            StartedAt = scan.ValueKind == JsonValueKind.Object ? Date(scan, "startedAt") : null,
            CompletedAt = scan.ValueKind == JsonValueKind.Object ? Date(scan, "completedAt") : null,
            EngineVersion = scan.ValueKind == JsonValueKind.Object ? Str(scan, "engineVersion") ?? "" : "",
            RulesetVersion = scan.ValueKind == JsonValueKind.Object ? Str(scan, "rulesetVersion") ?? "" : "",
            Elevated = scan.ValueKind == JsonValueKind.Object && scan.TryGetProperty("elevated", out var el) && el.ValueKind == JsonValueKind.True,
            ManifestSha256 = scan.ValueKind == JsonValueKind.Object ? Str(scan, "manifestSha256") : null,
            ManifestVerified = scan.ValueKind == JsonValueKind.Object && scan.TryGetProperty("manifestVerified", out var mv) && mv.ValueKind is JsonValueKind.True or JsonValueKind.False ? mv.GetBoolean() : null,
            Findings = findings.OrderBy(f => f.SeverityRank).ThenByDescending(f => f.Confidence).ToList(),
            Coverage = coverage,
            Installations = Inv("installations"),
            Mods = Inv("mods"),
            Custody = custody,
            Source = "server",
        };
    }
}
