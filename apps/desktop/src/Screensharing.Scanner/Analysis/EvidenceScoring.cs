using Screensharing.Scanner.Model;

namespace Screensharing.Scanner.Analysis;

/// <summary>One matched indicator for an artifact, before aggregation.</summary>
public sealed record Indicator(DetectionRule Rule, Evidence Evidence, string What, string Signature);

public sealed record ScoredGroup(string Family, DetectionRule Primary, IReadOnlyList<Indicator> Indicators, EvidenceTier Tier, int Score, int Confidence, bool Corroborated, bool Report);

/// <summary>
/// Combines the indicators matched for one artifact into one result per suspected family.
///
/// * Every distinct rule contributes its weight (rule.Weight, or a default derived from its tier); the score is capped at 100.
/// * The tier is the strongest of (a) the strongest single rule and (b) the score tier: 100 with at least two independent
///   kinds of content evidence = confirmed, 60 = strong, 30 = weak.
/// * Generic indicator families (classification "indicator") need a score of 30 to be reported at all and are never confirmed.
/// * File-name rules never confirm anything and never raise a tier on their own.
/// </summary>
public static class EvidenceScoring
{
    public static List<ScoredGroup> Score(IEnumerable<Indicator> indicators, string? contentFamily = null)
    {
        var list = indicators.ToList();
        // A file-name match only joins a family that content already identified.
        var groups = list.GroupBy(i => i.Rule.Kind == RuleKind.FileNameRegex && contentFamily is not null ? contentFamily : i.Rule.Family ?? i.Rule.Id);
        var result = new List<ScoredGroup>();
        foreach (var g in groups)
        {
            var distinct = g.GroupBy(i => i.Rule.Id).Select(x => x.First()).OrderBy(i => i.Rule.TierValue).ThenByDescending(i => i.Rule.Confidence).ToList();
            var primary = distinct[0].Rule;
            var indicatorFamily = distinct.All(i => i.Rule.IsIndicator);
            var score = Math.Min(100, distinct.Where(i => i.Rule.Kind != RuleKind.FileNameRegex).Sum(i => i.Rule.EffectiveWeight));
            var contentKinds = distinct.Where(i => i.Rule.Kind != RuleKind.FileNameRegex).Select(i => i.Rule.Kind).Distinct().Count();
            var scoreTier = score >= 100 && contentKinds >= 2 ? EvidenceTier.ConfirmedArtifact
                : score >= 60 ? EvidenceTier.StrongIndicator
                : score >= 30 ? EvidenceTier.WeakIndicator : EvidenceTier.Inconclusive;
            var best = distinct.Min(i => i.Rule.TierValue);
            var tier = (EvidenceTier)Math.Min((int)best, (int)scoreTier);
            if (indicatorFamily && tier == EvidenceTier.ConfirmedArtifact) tier = EvidenceTier.StrongIndicator;
            if (distinct.All(i => i.Rule.Kind == RuleKind.FileNameRegex)) tier = (EvidenceTier)Math.Max((int)best, (int)EvidenceTier.SuspiciousConfiguration);
            var corroborated = contentKinds > 1 || distinct.Count > 1;
            var confidence = Math.Min(indicatorFamily ? 85 : 99, distinct.Max(i => i.Rule.Confidence) + 3 * (distinct.Count - 1));
            if (indicatorFamily) confidence = Math.Max(confidence, Math.Min(85, 30 + score / 2));
            var report = !indicatorFamily || score >= 30;
            result.Add(new ScoredGroup(g.Key, primary, distinct, tier, score, confidence, corroborated, report));
        }
        return result;
    }
}
