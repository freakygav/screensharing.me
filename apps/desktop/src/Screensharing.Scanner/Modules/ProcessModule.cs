using System.Diagnostics;
using System.Management;
using System.Text.RegularExpressions;
using Screensharing.Scanner.Engine;
using Screensharing.Scanner.Model;
using Screensharing.Scanner.Windows;

namespace Screensharing.Scanner.Modules;

/// <summary>Running Java game processes: launch arguments, loaded native modules and bounded memory scanning.</summary>
public sealed partial class ProcessModule : IScanModule
{
    public string Key => "processes";
    public string Name => "Running processes & memory";
    public string Activity => "Analyzing running Minecraft processes…";

    public string? SkipReason(ScanContext ctx) => ctx.Options.IncludeSystemArtifacts ? null : "System artifacts excluded by scan options";

    private readonly List<(int Pid, string Name, string? Exe, string? CommandLine)> _procs = [];

    internal static readonly string[] FeatureNames =
    [
        "KillAura", "AimAssist", "TriggerBot", "AutoClicker", "CrystalAura", "AutoCrystal", "Scaffold", "AntiKnockback",
        "Criticals", "AutoTotem", "ChestESP", "PlayerESP", "BowAimbot", "AnchorAura", "NoFall", "LongJump",
    ];

    // Values that must never leave the machine (session tokens etc.).
    [GeneratedRegex(@"(--(accessToken|session|uuid|xuid|clientId|username|userProperties|profileProperties)\s+)(\S+)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex Sensitive();

    public static string Redact(string commandLine) => Sensitive().Replace(commandLine, "$1[redacted]");

    public int Plan(ScanContext ctx)
    {
        _procs.Clear();
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT ProcessId, Name, ExecutablePath, CommandLine FROM Win32_Process WHERE Name='javaw.exe' OR Name='java.exe'");
            foreach (ManagementObject o in searcher.Get())
                _procs.Add((Convert.ToInt32(o["ProcessId"]), (string)o["Name"], o["ExecutablePath"] as string, o["CommandLine"] as string));
        }
        catch (Exception e) when (e is ManagementException or UnauthorizedAccessException or System.Runtime.InteropServices.COMException)
        {
            foreach (var p in Process.GetProcessesByName("javaw").Concat(Process.GetProcessesByName("java")))
                _procs.Add((p.Id, p.ProcessName + ".exe", null, null));
        }
        ctx.Custody.Record("enumerate-processes", $"{_procs.Count} Java processes");
        return Math.Max(1, _procs.Count * 3);
    }

    private static bool IsMinecraft(string? cmd) => cmd is not null &&
        (cmd.Contains("net.minecraft", StringComparison.OrdinalIgnoreCase) || cmd.Contains("--gameDir", StringComparison.OrdinalIgnoreCase)
         || cmd.Contains("minecraft", StringComparison.OrdinalIgnoreCase) || cmd.Contains("lunar", StringComparison.OrdinalIgnoreCase)
         || cmd.Contains("fabric", StringComparison.OrdinalIgnoreCase) || cmd.Contains("badlion", StringComparison.OrdinalIgnoreCase));

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        var games = 0;
        foreach (var (pid, name, exe, cmd) in _procs)
        {
            ct.ThrowIfCancellationRequested();
            var game = IsMinecraft(cmd);
            var procRef = $"{name} (PID {pid})";
            var redacted = cmd is null ? null : Redact(cmd);
            if (game) games++;
            ctx.SetActivity($"Analyzing running Minecraft processes… {procRef}");

            if (cmd is not null)
            {
                ctx.Custody.Record("read-process-commandline", procRef);
                JvmModule.ReportAgents(ctx, procRef, $"Running process {procRef}", cmd, EvidenceKind.Process, new() { ["executable"] = exe ?? "", ["isMinecraft"] = game.ToString() });
            }
            ctx.Advance();

            if (game) Modules(ctx, pid, procRef, exe);
            ctx.Advance();

            if (game && ctx.Options.MemoryScan) Memory(ctx, pid, procRef, ct);
            ctx.Advance();
        }
        ctx.Statistics["javaProcesses"] = _procs.Count;
        ctx.Statistics["minecraftProcesses"] = games;
        if (ctx.CurrentCategory is not null)
            ctx.CurrentCategory.Message = games == 0 ? "Minecraft was not running — no live memory or module evidence available" : $"{games} running Minecraft process(es) examined";
        return Task.CompletedTask;
    }

    private static readonly string[] KnownNatives = ["lwjgl", "glfw", "openal", "jemalloc", "jinput", "tinyfd", "stb", "nanovg", "nvg", "freetype", "jcocoa", "discord", "rtss", "graphics-hook", "obs", "overlay", "steam", "nvd3d", "nvwgf", "nvoglv", "atio", "amdxc", "igxe", "ig9icd", "ig7icd",
        // Natives extracted by common legitimate libraries/mods (JNA, Simple Voice Chat codecs, compression, SQLite).
        "jna", "lame4j", "opus4j", "speex4j", "rnnoise4j", "sqlite", "zstd", "lz4", "snappy", "netty", "conscrypt"];

    private static void Modules(ScanContext ctx, int pid, string procRef, string? exe)
    {
        ProcessModuleCollection mods;
        try { mods = Process.GetProcessById(pid).Modules; }
        catch (Exception e) when (e is InvalidOperationException or System.ComponentModel.Win32Exception or ArgumentException) { return; }
        ctx.Custody.Record("enumerate-modules", procRef);
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var javaHome = exe is null ? null : Path.GetDirectoryName(Path.GetDirectoryName(exe));
        string[] trustedRoots = [windows, Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86)];
        foreach (System.Diagnostics.ProcessModule m in mods)
        {
            var path = m.FileName;
            if (string.IsNullOrEmpty(path)) continue;
            if (trustedRoots.Any(r => path.StartsWith(r, StringComparison.OrdinalIgnoreCase))) continue;
            if (javaHome is not null && path.StartsWith(javaHome, StringComparison.OrdinalIgnoreCase)) continue;
            var file = Path.GetFileName(path);
            foreach (var r in ctx.Rules.OfKind(RuleKind.FileNameRegex).Where(r => r.IsMatch(file)))
                ctx.Report(r.Id, [procRef, path],
                    $"{procRef} has the native module \"{file}\" loaded from {Path.GetDirectoryName(path)}.",
                    "Enumeration of modules loaded in running Minecraft processes.",
                    r.Description, "Module names are controlled by whoever built the DLL.",
                    [ctx.FileEvidence(path, "Loaded native module", new() { ["process"] = procRef }, EvidenceKind.Module)]);
            if (KnownNatives.Any(k => file.Contains(k, StringComparison.OrdinalIgnoreCase))) continue;
            if (Authenticode.IsSigned(path)) continue;
            ctx.Report(Builtin.UnsignedModule, [procRef, path],
                $"{procRef} has an unsigned native module loaded from a user-writable location: {path}.",
                "Module enumeration of running Minecraft processes, Authenticode verification (WinVerifyTrust), and exclusion of Windows, Program Files, the Java runtime and known game natives (LWJGL, GLFW, OpenAL).",
                "Injected cheats are commonly unsigned DLLs dropped in AppData/Temp and loaded into javaw.exe by an injector.",
                "Overlays, recording tools and some mods extract unsigned natives to temporary folders.",
                [ctx.FileEvidence(path, "Loaded native module", new() { ["process"] = procRef, ["signed"] = "false" }, EvidenceKind.Module)]);
        }
    }

    private static void Memory(ScanContext ctx, int pid, string procRef, CancellationToken ct)
    {
        var classRules = ctx.Rules.OfKind(RuleKind.MemoryString).Where(r => r.Pattern.Length >= 8).ToList();
        var patterns = classRules.Select(r => r.Pattern).Concat(FeatureNames).Distinct().ToList();
        ctx.SetActivity($"Scanning memory of {procRef}…");
        ctx.Custody.Record("read-process-memory", $"{procRef} (bounded scan, {patterns.Count} patterns)");
        var res = MemoryScanner.Scan(pid, patterns, ctx.Options.MemoryScanCapBytes, TimeSpan.FromSeconds(60), ct);
        ctx.Statistics["memoryBytesScanned"] = ctx.Statistics.GetValueOrDefault("memoryBytesScanned") + res.BytesScanned;
        if (res.Error is not null) { ctx.Custody.Record("read-process-memory-failed", $"{procRef}: {res.Error}"); return; }

        foreach (var r in classRules)
        {
            if (!res.Hits.TryGetValue(r.Pattern, out var hit)) continue;
            ctx.Report(r.Id, [procRef, r.Pattern],
                $"The class path \"{r.Pattern}\" ({r.Family}) is present in the memory of {procRef} — its classes were loaded into the running game.",
                $"Bounded read-only scan of committed private/mapped memory ({res.BytesScanned / (1024 * 1024):N0} MiB in {res.Regions:N0} regions{(res.Truncated ? ", truncated at cap" : "")}) using multi-pattern matching.",
                r.Description,
                "The string could be present without the client running if another Java tool inside the game process opened its jar.",
                [new Evidence { Kind = EvidenceKind.Memory, Source = "Process memory", Reference = $"{procRef} @ 0x{hit.Address:X}", Details = new() { ["pattern"] = r.Pattern, ["region"] = hit.Region, ["bytesScanned"] = res.BytesScanned.ToString() } }],
                name: $"{r.Family ?? r.Name}: classes loaded in running game");
        }
        var cluster = FeatureNames.Where(res.Hits.ContainsKey).ToList();
        if (cluster.Count >= 4)
        {
            ctx.Report(Builtin.MemoryFeatureCluster, [procRef],
                $"{cluster.Count} distinct cheat-feature names were found in the memory of {procRef}: {string.Join(", ", cluster)}.",
                "Bounded memory scan for curated cheat-feature names.",
                "Hacked clients keep their module names in memory for their GUI and configuration.",
                "Chat messages, server text or player discussion of cheats put the same words in memory.",
                [new Evidence { Kind = EvidenceKind.Memory, Source = "Process memory", Reference = procRef, Details = cluster.ToDictionary(c => c, c => $"0x{res.Hits[c].Address:X}") }]);
        }
    }
}
