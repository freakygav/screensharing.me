using System.Text;
using Screensharing.Scanner.Model;

namespace Screensharing.Scanner.Analysis;

public sealed record SignatureHit(DetectionRule Rule, string Scope, string Where, string? Excerpt);

/// <summary>
/// Compiled STRING (and MEMORY_STRING) signatures, one automaton per scope. Binary scope also matches the
/// UTF-16LE form of each string, because Windows executables store many strings as wide characters.
/// </summary>
public sealed class SignatureIndex
{
    private sealed record Compiled(AhoCorasick Matcher, List<DetectionRule> Rules);
    private readonly Dictionary<string, Compiled> _byScope = new(StringComparer.Ordinal);

    public SignatureIndex(RuleSet rules)
    {
        var strings = rules.OfKind(RuleKind.String).ToList();
        foreach (var scope in new[] { SignatureScope.Class, SignatureScope.Resource, SignatureScope.Config, SignatureScope.Log, SignatureScope.Script, SignatureScope.Binary, SignatureScope.Memory })
        {
            var list = strings.Where(r => r.Scopes.Contains(scope, StringComparer.OrdinalIgnoreCase)).ToList();
            if (scope == SignatureScope.Memory) list.AddRange(rules.OfKind(RuleKind.MemoryString).Where(r => r.Pattern.Length >= 8));
            if (list.Count == 0) continue;
            var patterns = new List<byte[]>();
            var owners = new List<DetectionRule>();
            foreach (var r in list)
            {
                patterns.Add(Encoding.UTF8.GetBytes(r.Pattern)); owners.Add(r);
                if (scope is SignatureScope.Binary or SignatureScope.Memory) { patterns.Add(Encoding.Unicode.GetBytes(r.Pattern)); owners.Add(r); }
            }
            _byScope[scope] = new Compiled(new AhoCorasick(patterns), owners);
        }
    }

    public bool Has(string scope) => _byScope.ContainsKey(scope);

    public IEnumerable<DetectionRule> RulesFor(string scope) => _byScope.TryGetValue(scope, out var c) ? c.Rules.Distinct() : [];

    /// <summary>Matches <paramref name="data"/> and returns the distinct rules hit, with a short excerpt around the first hit.</summary>
    public List<SignatureHit> Match(string scope, ReadOnlySpan<byte> data, string where)
    {
        var hits = new List<SignatureHit>();
        if (!_byScope.TryGetValue(scope, out var c)) return hits;
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var found = new List<(int Pattern, int Pos)>();
        c.Matcher.Search(data, (p, pos) => { if (seen.Add(c.Rules[p].Id)) found.Add((p, pos)); });
        foreach (var (p, pos) in found)
            hits.Add(new SignatureHit(c.Rules[p], scope, where, Excerpt(data, pos, Encoding.UTF8.GetByteCount(c.Rules[p].Pattern))));
        return hits;
    }

    private static string? Excerpt(ReadOnlySpan<byte> data, int pos, int len)
    {
        var start = Math.Max(0, pos - 40);
        var end = Math.Min(data.Length, pos + len + 40);
        if (start >= end) return null;
        var sb = new StringBuilder();
        foreach (var b in data[start..end]) sb.Append(b is >= 0x20 and < 0x7F ? (char)b : '·');
        return sb.ToString();
    }
}
