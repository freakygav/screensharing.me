using System.Text.Json.Serialization;

namespace Screensharing.Scanner.Model;

[JsonConverter(typeof(JsonStringEnumConverter<Severity>))]
public enum Severity
{
    [JsonStringEnumMemberName("CRITICAL")] Critical,
    [JsonStringEnumMemberName("HIGH")] High,
    [JsonStringEnumMemberName("MEDIUM")] Medium,
    [JsonStringEnumMemberName("LOW")] Low,
    [JsonStringEnumMemberName("INFO")] Info,
}

/// <summary>Strength of the evidence, independent of how serious the matched behaviour is.</summary>
[JsonConverter(typeof(JsonStringEnumConverter<EvidenceTier>))]
public enum EvidenceTier
{
    [JsonStringEnumMemberName("CONFIRMED_ARTIFACT")] ConfirmedArtifact,
    [JsonStringEnumMemberName("STRONG_INDICATOR")] StrongIndicator,
    [JsonStringEnumMemberName("SUSPICIOUS_CONFIGURATION")] SuspiciousConfiguration,
    [JsonStringEnumMemberName("WEAK_INDICATOR")] WeakIndicator,
    [JsonStringEnumMemberName("INCONCLUSIVE")] Inconclusive,
}

[JsonConverter(typeof(JsonStringEnumConverter<CategoryStatus>))]
public enum CategoryStatus
{
    [JsonStringEnumMemberName("PENDING")] Pending,
    [JsonStringEnumMemberName("RUNNING")] Running,
    [JsonStringEnumMemberName("COMPLETED")] Completed,
    [JsonStringEnumMemberName("SKIPPED")] Skipped,
    [JsonStringEnumMemberName("FAILED")] Failed,
}

public static class EnumText
{
    public static string Api(this Severity s) => s switch
    {
        Severity.Critical => "CRITICAL", Severity.High => "HIGH", Severity.Medium => "MEDIUM", Severity.Low => "LOW", _ => "INFO",
    };

    public static string Api(this EvidenceTier t) => t switch
    {
        EvidenceTier.ConfirmedArtifact => "CONFIRMED_ARTIFACT",
        EvidenceTier.StrongIndicator => "STRONG_INDICATOR",
        EvidenceTier.SuspiciousConfiguration => "SUSPICIOUS_CONFIGURATION",
        EvidenceTier.WeakIndicator => "WEAK_INDICATOR",
        _ => "INCONCLUSIVE",
    };

    public static string Label(this EvidenceTier t) => t switch
    {
        EvidenceTier.ConfirmedArtifact => "Confirmed artifact match",
        EvidenceTier.StrongIndicator => "Strong forensic indicator",
        EvidenceTier.SuspiciousConfiguration => "Suspicious configuration",
        EvidenceTier.WeakIndicator => "Weak indicator",
        _ => "Inconclusive",
    };

    public static Severity ParseSeverity(string s) => s.ToUpperInvariant() switch
    {
        "CRITICAL" => Severity.Critical, "HIGH" => Severity.High, "MEDIUM" => Severity.Medium, "LOW" => Severity.Low, _ => Severity.Info,
    };

    public static EvidenceTier ParseTier(string s) => s.ToUpperInvariant() switch
    {
        "CONFIRMED_ARTIFACT" => EvidenceTier.ConfirmedArtifact,
        "STRONG_INDICATOR" => EvidenceTier.StrongIndicator,
        "SUSPICIOUS_CONFIGURATION" => EvidenceTier.SuspiciousConfiguration,
        "WEAK_INDICATOR" => EvidenceTier.WeakIndicator,
        _ => EvidenceTier.Inconclusive,
    };
}
