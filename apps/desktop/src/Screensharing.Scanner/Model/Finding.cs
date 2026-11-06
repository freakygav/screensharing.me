using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;

namespace Screensharing.Scanner.Model;

public static class EvidenceKind
{
    public const string File = "FILE", JarEntry = "JAR_ENTRY", Log = "LOG", Prefetch = "PREFETCH", Bam = "BAM", Registry = "REGISTRY",
        Process = "PROCESS", Module = "MODULE", Memory = "MEMORY", EventLog = "EVENT_LOG", RecycleBin = "RECYCLE_BIN", Usn = "USN",
        Environment = "ENVIRONMENT", Config = "CONFIG", Service = "SERVICE";
}

/// <summary>One piece of evidence. Field names match the backend contract (apps/website/src/lib/validation.ts).</summary>
public sealed class Evidence
{
    public required string Kind { get; init; }
    public required string Source { get; init; }
    public required string Reference { get; init; }
    public string? Sha256 { get; init; }
    public long? SizeBytes { get; init; }
    public DateTimeOffset? CreatedTime { get; init; }
    public DateTimeOffset? ModifiedTime { get; init; }
    public DateTimeOffset? AccessedTime { get; init; }
    public DateTimeOffset ObservedAt { get; init; } = DateTimeOffset.UtcNow;
    public Dictionary<string, string>? Details { get; init; }
}

public sealed class Finding
{
    public required string ClientFindingId { get; init; }
    public required string RuleId { get; init; }
    public required string Name { get; init; }
    public required string Description { get; init; }
    public required string Category { get; init; }
    public required string CategoryKey { get; init; }
    public required Severity Severity { get; init; }
    public required EvidenceTier Tier { get; init; }
    public required int Confidence { get; init; }
    public required string Method { get; init; }
    public required string WhyItMatters { get; init; }
    public required string Limitations { get; init; }
    public required string FalsePositiveNotes { get; init; }
    public required string AlternativeExplanations { get; init; }
    public DateTimeOffset DetectedAt { get; init; } = DateTimeOffset.UtcNow;
    public required List<Evidence> Evidence { get; init; }

    [JsonIgnore] public string? Family { get; init; }

    /// <summary>Deterministic id so a retried upload of the same observation is de-duplicated server-side.</summary>
    public static string MakeId(string ruleId, params string[] discriminators)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(ruleId + "\u001f" + string.Join("\u001f", discriminators).ToLowerInvariant()));
        return "f" + Convert.ToHexStringLower(bytes)[..31];
    }
}
