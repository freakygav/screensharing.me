using System.Collections.Concurrent;

namespace Screensharing.Scanner.Engine;

public sealed class ScopeViolationException(string path, string operation)
    : InvalidOperationException($"Refused to {operation} \"{path}\": it is outside the selected Minecraft instance.")
{
    public string Path { get; } = path;
}

/// <summary>
/// The hard boundary of a scan. Every file the scanner opens, hashes, enumerates or stats is checked here first:
/// it must lie inside one of the instance <see cref="Roots"/> or be one of the explicitly attested <see cref="Files"/>
/// (jars on the running game's class path, Java agents in its arguments, native modules loaded into it).
/// Anything else throws <see cref="ScopeViolationException"/> and is recorded as a violation.
/// </summary>
public sealed class ScanScope
{
    private static readonly AsyncLocal<ScanScope?> CurrentScope = new();

    /// <summary>The scope of the scan running on this logical call context, if any.</summary>
    public static ScanScope? Current { get => CurrentScope.Value; internal set => CurrentScope.Value = value; }

    private readonly List<string> _roots = [];
    private readonly ConcurrentDictionary<string, string> _files = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentQueue<string> _violations = new();
    private readonly ConcurrentDictionary<string, byte> _accessed = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();

    public ScanScope(IEnumerable<string> roots, IEnumerable<(string Path, string Reason)>? files = null)
    {
        foreach (var r in roots.Where(r => !string.IsNullOrWhiteSpace(r))) AddRoot(r);
        foreach (var (p, why) in files ?? []) AllowFile(p, why);
    }

    public IReadOnlyList<string> Roots { get { lock (_gate) return _roots.ToList(); } }
    public IReadOnlyDictionary<string, string> Files => _files;
    public IReadOnlyCollection<string> Violations => _violations.ToArray();
    /// <summary>Every path that passed the check (bounded; used by tests and the coverage summary).</summary>
    public IReadOnlyCollection<string> Accessed => _accessed.Keys.ToArray();

    public static string Normalize(string path) => System.IO.Path.GetFullPath(path).TrimEnd('\\', '/');

    private readonly Dictionary<string, string> _aliases = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Adds an in-scope directory. <paramref name="alias"/> is its instance-relative name when it is a followed link target.</summary>
    internal void AddRoot(string root, string? alias = null)
    {
        var n = Normalize(root);
        lock (_gate)
        {
            if (!_roots.Contains(n, StringComparer.OrdinalIgnoreCase)) _roots.Add(n);
            if (alias is not null) _aliases[n] = alias;
        }
    }

    /// <summary>Adds a single file attested by the running game process (class path entry, agent, loaded module).</summary>
    public void AllowFile(string path, string reason)
    {
        if (string.IsNullOrWhiteSpace(path)) return;
        try { _files.TryAdd(Normalize(path), reason); } catch (Exception e) when (e is ArgumentException or NotSupportedException or PathTooLongException) { }
    }

    public bool Contains(string path)
    {
        string n;
        try { n = Normalize(path); } catch (Exception e) when (e is ArgumentException or NotSupportedException or PathTooLongException) { return false; }
        if (_files.ContainsKey(n)) return true;
        lock (_gate)
            return _roots.Any(r => n.Equals(r, StringComparison.OrdinalIgnoreCase) || (n.StartsWith(r, StringComparison.OrdinalIgnoreCase) && n.Length > r.Length && n[r.Length] == '\\'));
    }

    /// <summary>Throws unless the path (and, for links, its target) is in scope.</summary>
    public void Demand(string path, string operation)
    {
        if (!Contains(path)) Violation(path, operation);
        // A link inside the instance must not lead outside of it.
        try
        {
            var fi = new FileInfo(path);
            if (fi.Exists && fi.Attributes.HasFlag(FileAttributes.ReparsePoint) && fi.ResolveLinkTarget(true) is { } target && !Contains(target.FullName))
                Violation($"{path} -> {target.FullName}", operation);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException) { }
        if (_accessed.Count < 200_000) _accessed.TryAdd(Normalize(path), 0);
    }

    private void Violation(string path, string operation)
    {
        _violations.Enqueue($"{operation}: {path}");
        throw new ScopeViolationException(path, operation);
    }

    /// <summary>Returns the path relative to the instance root it belongs to, or the full path for attested files.</summary>
    public string Relative(string path)
    {
        var n = Normalize(path);
        lock (_gate)
            foreach (var r in _roots.OrderByDescending(r => r.Length))
                if (n.StartsWith(r, StringComparison.OrdinalIgnoreCase) && n.Length > r.Length && n[r.Length] == '\\')
                {
                    var rel = n[(r.Length + 1)..].Replace('\\', '/');
                    return _aliases.TryGetValue(r, out var a) ? a + "/" + rel : rel;
                }
        return n;
    }
}
