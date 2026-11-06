using System.Collections.Concurrent;

namespace Screensharing.Scanner.Engine;

public sealed record CustodyOperation(DateTimeOffset At, string Action, string Target);

/// <summary>
/// Read-only collection log (chain of custody). Every artifact access is recorded with a timestamp.
/// The first 1,800 operations are kept verbatim; beyond that operations are counted per action.
/// </summary>
public sealed class CustodyLog
{
    private const int MaxDetailed = 1800;
    private readonly ConcurrentQueue<CustodyOperation> _ops = new();
    private readonly ConcurrentDictionary<string, int> _overflow = new();
    private int _count;

    public void Record(string action, string target)
    {
        if (Interlocked.Increment(ref _count) <= MaxDetailed)
            _ops.Enqueue(new CustodyOperation(DateTimeOffset.UtcNow, action, target.Length > 1000 ? target[..1000] : target));
        else
            _overflow.AddOrUpdate(action, 1, (_, n) => n + 1);
    }

    public int Count => _count;

    public List<CustodyOperation> Snapshot()
    {
        var list = _ops.ToList();
        foreach (var (action, n) in _overflow.OrderBy(k => k.Key))
            list.Add(new CustodyOperation(DateTimeOffset.UtcNow, "summary", $"{n} further '{action}' operations (not itemised)"));
        return list;
    }
}
