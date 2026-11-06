using System.Diagnostics;
using Screensharing.Scanner.Analysis;

namespace Screensharing.Scanner.Windows;

/// <summary>Reads committed, readable private/mapped memory of a process and searches for byte patterns.</summary>
public static class MemoryScanner
{
    public sealed record Result(Dictionary<string, (long Address, string Region)> Hits, long BytesScanned, int Regions, bool Truncated, string? Error);

    public static unsafe Result Scan(int pid, IReadOnlyList<string> patterns, long capBytes, TimeSpan timeBudget, CancellationToken ct)
    {
        // Each pattern is searched as UTF-8 (JVM class names, modified UTF-8 constants) and UTF-16LE (java.lang.String contents).
        var bytes = new List<byte[]>();
        var owner = new List<string>();
        foreach (var p in patterns)
        {
            bytes.Add(System.Text.Encoding.UTF8.GetBytes(p)); owner.Add(p);
            bytes.Add(System.Text.Encoding.Unicode.GetBytes(p)); owner.Add(p);
        }
        var ac = new AhoCorasick(bytes);
        var hits = new Dictionary<string, (long, string)>();
        using var h = Native.OpenProcess(Native.PROCESS_QUERY_INFORMATION | Native.PROCESS_VM_READ, false, pid);
        if (h.IsInvalid) return new Result(hits, 0, 0, false, $"OpenProcess failed (error {System.Runtime.InteropServices.Marshal.GetLastPInvokeError()})");
        const int chunk = 4 * 1024 * 1024;
        const int overlap = 256;
        var buffer = new byte[chunk + overlap];
        long scanned = 0;
        var regions = 0;
        var sw = Stopwatch.StartNew();
        nint addr = 0;
        var truncated = false;
        var mbiSize = (nint)System.Runtime.CompilerServices.Unsafe.SizeOf<Native.MEMORY_BASIC_INFORMATION>();
        while (Native.VirtualQueryEx(h, addr, out var mbi, mbiSize) != 0)
        {
            ct.ThrowIfCancellationRequested();
            var next = mbi.BaseAddress + mbi.RegionSize;
            if (next <= addr) break;
            var readable = mbi.State == Native.MEM_COMMIT && (mbi.Protect & (Native.PAGE_GUARD | Native.PAGE_NOACCESS)) == 0 && mbi.Protect != 0
                           && (mbi.Type == Native.MEM_PRIVATE || mbi.Type == Native.MEM_MAPPED);
            if (readable && hits.Count < patterns.Count)
            {
                regions++;
                long offset = 0;
                var size = (long)mbi.RegionSize;
                while (offset < size)
                {
                    if (scanned >= capBytes || sw.Elapsed > timeBudget) { truncated = true; break; }
                    var len = (int)Math.Min(chunk + overlap, size - offset);
                    fixed (byte* p = buffer)
                    {
                        if (!Native.ReadProcessMemory(h, mbi.BaseAddress + (nint)offset, p, len, out var read) || read == 0) break;
                        foreach (var (idx, pos) in ac.Search(buffer.AsSpan(0, (int)read)))
                            hits.TryAdd(owner[idx], (mbi.BaseAddress + (nint)offset + pos, $"0x{mbi.BaseAddress:X} ({(mbi.Type == Native.MEM_PRIVATE ? "private" : "mapped")})"));
                        scanned += read;
                    }
                    offset += chunk;
                }
                if (truncated) break;
            }
            addr = next;
        }
        return new Result(hits, scanned, regions, truncated, null);
    }
}
