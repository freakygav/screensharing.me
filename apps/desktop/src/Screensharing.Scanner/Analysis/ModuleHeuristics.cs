using Screensharing.Scanner.Model;

namespace Screensharing.Scanner.Analysis;

/// <summary>
/// Detects the "module system" layout used by hacked clients: one class per cheat feature
/// (KillAura, Scaffold, …), often grouped into combat/movement/render packages. The feature names and
/// package segments come from the signature database (FEATURE_NAME / MODULE_PACKAGE rules).
/// </summary>
public static class ModuleHeuristics
{
    public sealed record Result(IReadOnlyList<string> Names, int HighSignalCount, IReadOnlyList<string> Examples);

    public static Result Evaluate(IEnumerable<string> classPaths, RuleSet rules)
    {
        var high = rules.HighSignalFeatures;
        var ambiguous = rules.AmbiguousFeatures;
        var segments = rules.ModuleSegments;
        var names = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        var examples = new List<string>();
        var highCount = 0;
        foreach (var path in classPaths)
        {
            var slash = path.LastIndexOf('/');
            var simple = path[(slash + 1)..];
            if (simple.Contains('$')) continue; // inner classes duplicate their outer class
            var stripped = StripSuffix(simple);
            var moduleLike = slash > 0 && path[..slash].Split('/').Any(segments.Contains);
            var counted = false;
            if (high.Contains(stripped)) { if (names.Add(stripped)) { highCount++; counted = true; } }
            else if (moduleLike && ambiguous.Contains(stripped)) { counted = names.Add(stripped); }
            if (counted && examples.Count < 12) examples.Add(path);
        }
        return new Result(names.ToList(), highCount, examples);
    }

    private static string StripSuffix(string simple)
    {
        foreach (var suffix in new[] { "Module", "Hack", "Feature", "Mod", "Cheat" })
            if (simple.Length > suffix.Length + 2 && simple.EndsWith(suffix, StringComparison.Ordinal))
                return simple[..^suffix.Length];
        return simple;
    }
}
