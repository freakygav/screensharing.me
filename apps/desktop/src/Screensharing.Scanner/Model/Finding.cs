using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;

namespace Screensharing.Scanner.Model;

public static class EvidenceKind
{
    public const string File = "FILE", JarEntry = "JAR_ENTRY", Log = "LOG", Registry = "REGISTRY",
        Process = "PROCESS", Module = "MODULE", Memory = "MEMORY", Environment = "ENVIRONMENT", Config = "CONFIG";
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

/// <summary>How an investigator should read a finding.</summary>
public enum FindingOutcome
{
    /// <summary>Direct match of a verified signature of a known cheat or prohibited modification.</summary>
    Confirmed,
    /// <summary>Strong evidence, but not a verified signature match. Needs manual review.</summary>
    HighConfidence,
    /// <summary>Weak or policy-dependent evidence. Needs manual review and corroboration.</summary>
    LowConfidence,
    /// <summary>A relevant file could not be inspected.</summary>
    UnableToInspect,
    /// <summary>Listed for completeness (e.g. an unrecognised mod).</summary>
    Informational,
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

    /// <summary>Suspected cheat, client or component (e.g. "Meteor Client"), when one could be identified.</summary>
    public string? Family { get; init; }

    /// <summary>The signature or indicator that matched, in readable form (e.g. package "net.wurstclient").</summary>
    public string? Signature { get; init; }

    /// <summary>Where the evidence is, relative to the instance root when inside it.</summary>
    public string? Location { get; init; }

    [JsonIgnore]
    public FindingOutcome Outcome => RuleId == Builtin.Uninspectable ? FindingOutcome.UnableToInspect : Tier switch
    {
        EvidenceTier.ConfirmedArtifact => FindingOutcome.Confirmed,
        EvidenceTier.StrongIndicator => FindingOutcome.HighConfidence,
        EvidenceTier.SuspiciousConfiguration or EvidenceTier.WeakIndicator => FindingOutcome.LowConfidence,
        _ => FindingOutcome.Informational,
    };

    [JsonIgnore] public bool RequiresManualReview => Outcome != FindingOutcome.Confirmed;

    /// <summary>Deterministic id so a retried upload of the same observation is de-duplicated server-side.</summary>
    public static string MakeId(string ruleId, params string[] discriminators)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(ruleId + "\u001f" + string.Join("\u001f", discriminators).ToLowerInvariant()));
        return "f" + Convert.ToHexStringLower(bytes)[..31];
    }
}

public static class OutcomeText
{
    public static string Api(this FindingOutcome o) => o switch
    {
        FindingOutcome.Confirmed => "CONFIRMED", FindingOutcome.HighConfidence => "HIGH_CONFIDENCE", FindingOutcome.LowConfidence => "LOW_CONFIDENCE",
        FindingOutcome.UnableToInspect => "UNABLE_TO_INSPECT", _ => "INFORMATIONAL",
    };

    public static string Label(this FindingOutcome o) => o switch
    {
        FindingOutcome.Confirmed => "Confirmed detection", FindingOutcome.HighConfidence => "High-confidence finding", FindingOutcome.LowConfidence => "Low-confidence finding",
        FindingOutcome.UnableToInspect => "Unable to inspect", _ => "Informational",
    };
}
