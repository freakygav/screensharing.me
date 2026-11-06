using System.Text;

namespace Screensharing.Scanner.Analysis;

/// <summary>Multi-pattern byte search (case-sensitive) in linear time.</summary>
public sealed class AhoCorasick
{
    private readonly List<int[]> _goto = [];
    private readonly List<int> _fail = [];
    private readonly List<List<int>> _out = [];
    private readonly int[] _lengths;

    public int PatternCount => _lengths.Length;

    public AhoCorasick(IReadOnlyList<string> patterns) : this(patterns.Select(p => Encoding.UTF8.GetBytes(p)).ToList()) { }

    public AhoCorasick(IReadOnlyList<byte[]> patterns)
    {
        _lengths = patterns.Select(p => p.Length).ToArray();
        NewState();
        for (var i = 0; i < patterns.Count; i++)
        {
            if (patterns[i].Length == 0) continue;
            var s = 0;
            foreach (var b in patterns[i])
            {
                if (_goto[s][b] == 0) { _goto[s][b] = NewState(); }
                s = _goto[s][b];
            }
            _out[s].Add(i);
        }
        var q = new Queue<int>();
        for (var b = 0; b < 256; b++)
            if (_goto[0][b] != 0) { _fail[_goto[0][b]] = 0; q.Enqueue(_goto[0][b]); }
        while (q.Count > 0)
        {
            var r = q.Dequeue();
            for (var b = 0; b < 256; b++)
            {
                var u = _goto[r][b];
                if (u == 0) { _goto[r][b] = _goto[_fail[r]][b]; continue; }
                q.Enqueue(u);
                _fail[u] = _goto[_fail[r]][b];
                _out[u].AddRange(_out[_fail[u]]);
            }
        }
    }

    private int NewState()
    {
        _goto.Add(new int[256]);
        _fail.Add(0);
        _out.Add([]);
        return _goto.Count - 1;
    }

    /// <summary>Yields (patternIndex, startOffset) for every match.</summary>
    public IEnumerable<(int Pattern, int Position)> Search(ReadOnlySpan<byte> data)
    {
        var results = new List<(int, int)>();
        Search(data, (p, pos) => results.Add((p, pos)));
        return results;
    }

    /// <summary>Invokes <paramref name="onMatch"/> for every match without allocating a result list.</summary>
    public void Search(ReadOnlySpan<byte> data, Action<int, int> onMatch)
    {
        if (_lengths.Length == 0) return;
        var s = 0;
        for (var i = 0; i < data.Length; i++)
        {
            s = _goto[s][data[i]];
            var outs = _out[s];
            if (outs.Count == 0) continue;
            foreach (var p in outs) onMatch(p, i - _lengths[p] + 1);
        }
    }
}
