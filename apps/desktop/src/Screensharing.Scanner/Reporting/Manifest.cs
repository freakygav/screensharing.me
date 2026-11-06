using System.Security.Cryptography;
using System.Text;
using Screensharing.Scanner.Model;

namespace Screensharing.Scanner.Reporting;

/// <summary>
/// Integrity manifest over all findings. Must match apps/website/src/lib/manifest.ts exactly:
/// one line per finding sorted by clientFindingId (ordinal):
///   id|ruleId|SEVERITY|TIER|confidence|ref#sha,ref#sha   (evidence entries sorted ordinally)
/// joined by "\n", SHA-256 hex (lowercase) over UTF-8.
/// </summary>
public static class Manifest
{
    public static string Line(Finding f) =>
        $"{f.ClientFindingId}|{f.RuleId}|{f.Severity.Api()}|{f.Tier.Api()}|{f.Confidence}|" +
        string.Join(",", f.Evidence.Select(e => $"{e.Reference}#{e.Sha256 ?? ""}").OrderBy(s => s, StringComparer.Ordinal));

    public static string Compute(IEnumerable<Finding> findings)
    {
        var lines = findings.OrderBy(f => f.ClientFindingId, StringComparer.Ordinal).Select(Line);
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join("\n", lines))));
    }
}
