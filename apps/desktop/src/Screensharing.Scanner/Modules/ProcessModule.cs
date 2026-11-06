using System.Diagnostics;
using Screensharing.Scanner.Engine;
using Screensharing.Scanner.Model;
using Screensharing.Scanner.Windows;

namespace Screensharing.Scanner.Modules;

/// <summary>The selected game process only: native modules loaded into it and a bounded, read-only scan of its memory.</summary>
public sealed class ProcessModule : IScanModule
{
    public string Key => "process";
    public string Name => "Game process & memory";
    public string Activity => "Analyzing the running game process…";

    public string? SkipReason(ScanContext ctx) => ctx.Instance.ProcessId is null ? "No running game process is attached to this scan" : null;
    public int Plan(ScanContext ctx) => 2;

    private static readonly string[] KnownNatives = ["lwjgl", "glfw", "openal", "jemalloc", "jinput", "tinyfd", "stb", "nanovg", "nvg", "freetype", "jcocoa", "discord", "rtss", "graphics-hook", "obs", "overlay", "steam", "nvd3d", "nvwgf", "nvoglv", "atio", "amdxc", "igxe", "ig9icd", "ig7icd",
        // Natives extracted by common legitimate libraries/mods (JNA, Simple Voice Chat codecs, compression, SQLite).
        "jna", "lame4j", "opus4j", "speex4j", "rnnoise4j", "sqlite", "zstd", "lz4", "snappy", "netty", "conscrypt"];

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        var pid = ctx.Instance.ProcessId!.Value;
        var procRef = $"{ctx.Instance.ProcessName} (PID {pid})";
        var running = IsSameProcess(ctx, pid);
        if (!running)
        {
            if (ctx.CurrentCategory is not null) ctx.CurrentCategory.Message = $"{procRef} has exited since it was selected — no live module or memory evidence";
            ctx.Advance(2);
            return Task.CompletedTask;
        }
        ctx.SetActivity($"Inspecting modules loaded into {procRef}…");
        var modules = Modules(ctx, pid, procRef);
        ctx.Advance();
        var scanned = 0L;
        if (ctx.Options.MemoryScan) scanned = Memory(ctx, pid, procRef, ct);
        ctx.Advance();
        if (ctx.CurrentCategory is not null)
            ctx.CurrentCategory.Message = $"{procRef}: {modules} native modules examined" + (ctx.Options.MemoryScan ? $", {scanned / (1024 * 1024):N0} MiB of memory scanned" : ", memory scan disabled in settings");
        return Task.CompletedTask;
    }

    /// <summary>Guards against a recycled process id: the process must still have the start time recorded at selection.</summary>
    private static bool IsSameProcess(ScanContext ctx, int pid)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            if (ctx.Instance.ProcessStartedAt is { } t && Math.Abs((p.StartTime.ToUniversalTime() - t.UtcDateTime).TotalSeconds) > 2) return false;
            return !p.HasExited;
        }
        catch (Exception e) when (e is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception) { return false; }
    }

    private static int Modules(ScanContext ctx, int pid, string procRef)
    {
        ProcessModuleCollection mods;
        try { mods = Process.GetProcessById(pid).Modules; }
        catch (Exception e) when (e is InvalidOperationException or System.ComponentModel.Win32Exception or ArgumentException) { return 0; }
        ctx.Custody.Record("enumerate-modules", procRef);
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var exe = ctx.Instance.JavaExecutable;
        var javaHome = exe is null ? null : Path.GetDirectoryName(Path.GetDirectoryName(exe));
        string[] trustedRoots = [windows, Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86)];
        var count = 0;
        foreach (System.Diagnostics.ProcessModule m in mods)
        {
            var path = m.FileName;
            if (string.IsNullOrEmpty(path)) continue;
            count++;
            if (trustedRoots.Any(r => path.StartsWith(r, StringComparison.OrdinalIgnoreCase))) continue;
            if (javaHome is not null && path.StartsWith(javaHome, StringComparison.OrdinalIgnoreCase)) continue;
            // A module loaded into the selected game process is part of the running instance.
            ctx.Scope.AllowFile(path, $"native module loaded into {procRef}");
            var file = Path.GetFileName(path);
            foreach (var r in ctx.Rules.OfKind(RuleKind.FileNameRegex).Where(r => r.IsMatch(file)))
                ctx.Report(r.Id, [procRef, path],
                    $"{procRef} has the native module \"{file}\" loaded from {Path.GetDirectoryName(path)}.",
                    "Enumeration of modules loaded in the selected game process.",
                    r.Description, "Module names are controlled by whoever built the DLL.",
                    [ctx.FileEvidence(path, "Loaded native module", new() { ["process"] = procRef }, EvidenceKind.Module)], signature: $"module name \"{file}\"", location: path);
            if (KnownNatives.Any(k => file.Contains(k, StringComparison.OrdinalIgnoreCase))) continue;
            if (Authenticode.IsSigned(path)) continue;
            ctx.Report(Builtin.UnsignedModule, [procRef, path],
                $"{procRef} has an unsigned native module loaded from a user-writable location: {path}.",
                "Module enumeration of the selected game process, Authenticode verification (WinVerifyTrust), and exclusion of Windows, Program Files, the Java runtime and known game natives (LWJGL, GLFW, OpenAL, JNA, voice-chat codecs).",
                "Injected cheats are commonly unsigned DLLs dropped in AppData/Temp and loaded into javaw.exe by an injector.",
                "Overlays, recording tools and some mods extract unsigned natives to temporary folders.",
                [ctx.FileEvidence(path, "Loaded native module", new() { ["process"] = procRef, ["signed"] = "false" }, EvidenceKind.Module)], signature: "unsigned DLL in game process", location: path);
        }
        ctx.Statistics["nativeModules"] = count;
        return count;
    }

    private static long Memory(ScanContext ctx, int pid, string procRef, CancellationToken ct)
    {
        var rules = ctx.Signatures.RulesFor(SignatureScope.Memory).ToList();
        var features = ctx.Rules.MemoryFeatures.ToList();
        var patterns = rules.Select(r => r.Pattern).Concat(features).Distinct().ToList();
        if (patterns.Count == 0) return 0;
        ctx.SetActivity($"Scanning the memory of {procRef}…");
        ctx.Custody.Record("read-process-memory", $"{procRef} (bounded scan, {patterns.Count} patterns)");
        var res = MemoryScanner.Scan(pid, patterns, ctx.Options.MemoryScanCapBytes, TimeSpan.FromSeconds(90), ct);
        ctx.Statistics["memoryBytesScanned"] = res.BytesScanned;
        if (res.Error is not null) { ctx.Custody.Record("read-process-memory-failed", $"{procRef}: {res.Error}"); return 0; }

        foreach (var r in rules)
        {
            if (!res.Hits.TryGetValue(r.Pattern, out var hit)) continue;
            ctx.Report(r.Id, [procRef, r.Pattern],
                r.Kind == RuleKind.MemoryString
                    ? $"The class path \"{r.Pattern}\" ({r.Family}) is present in the memory of {procRef} — its classes were loaded into the running game."
                    : $"The string \"{r.Pattern}\" ({r.Family}) is present in the memory of {procRef}.",
                $"Bounded read-only scan of committed private/mapped memory ({res.BytesScanned / (1024 * 1024):N0} MiB in {res.Regions:N0} regions{(res.Truncated ? ", truncated at cap" : "")}) using multi-pattern matching (UTF-8 and UTF-16).",
                r.Description,
                "Strings can be in memory without the client running, e.g. when another program inside the game opened the file or a chat message contained them.",
                [new Evidence { Kind = EvidenceKind.Memory, Source = "Process memory", Reference = $"{procRef} @ 0x{hit.Address:X}", Details = new() { ["pattern"] = r.Pattern, ["region"] = hit.Region, ["bytesScanned"] = res.BytesScanned.ToString() } }],
                name: $"{r.Family ?? r.Name}: found in the running game's memory", signature: $"memory string \"{r.Pattern}\"", location: procRef);
        }
        var cluster = features.Where(res.Hits.ContainsKey).ToList();
        if (cluster.Count >= 4)
        {
            ctx.Report(Builtin.MemoryFeatureCluster, [procRef],
                $"{cluster.Count} distinct cheat-feature names were found in the memory of {procRef}: {string.Join(", ", cluster)}.",
                "Bounded memory scan for the distinctive cheat-feature names of the module database (names that are also ordinary game words are excluded).",
                "Hacked clients keep their module names in memory for their GUI and configuration.",
                "Chat messages, server text or player discussion of cheats put the same words in memory.",
                [new Evidence { Kind = EvidenceKind.Memory, Source = "Process memory", Reference = procRef, Details = cluster.Take(40).ToDictionary(c => c, c => $"0x{res.Hits[c].Address:X}") }],
                signature: string.Join(", ", cluster.Take(6)), location: procRef);
        }
        return res.BytesScanned;
    }
}
