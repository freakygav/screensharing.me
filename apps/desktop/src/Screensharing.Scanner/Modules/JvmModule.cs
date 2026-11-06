using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using Screensharing.Scanner.Discovery;
using Screensharing.Scanner.Engine;
using Screensharing.Scanner.Model;

namespace Screensharing.Scanner.Modules;

/// <summary>JVM option injection (environment variables, launcher profiles) and Java runtime inventory.</summary>
public sealed partial class JvmModule : IScanModule
{
    public string Key => "jvm";
    public string Name => "JVM & launch configuration";
    public string Activity => "Inspecting Java launch configuration…";
    public string? SkipReason(ScanContext ctx) => null;
    public int Plan(ScanContext ctx) => 4 + ctx.Installations.Count;

    [GeneratedRegex(@"-(javaagent|agentpath|agentlib)[:=]\s*(""[^""]+""|\S+)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    internal static partial Regex AgentArg();

    internal static readonly string[] EnvVars = ["JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS"];

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        if (ctx.Options.IncludeSystemArtifacts)
        {
            foreach (var target in new[] { EnvironmentVariableTarget.Process, EnvironmentVariableTarget.User, EnvironmentVariableTarget.Machine })
            {
                foreach (var name in EnvVars)
                {
                    var value = Environment.GetEnvironmentVariable(name, target);
                    ctx.Custody.Record("read-environment", $"{target}:{name}");
                    if (string.IsNullOrWhiteSpace(value) || !AgentArg().IsMatch(value)) continue;
                    ctx.Report(Builtin.JavaOptionsEnv, [target.ToString(), name],
                        $"The {target.ToString().ToLowerInvariant()} environment variable {name} forces every Java process to load: {AgentArg().Match(value).Value}",
                        "Read of JAVA_TOOL_OPTIONS, _JAVA_OPTIONS and JDK_JAVA_OPTIONS at process, user and machine scope.",
                        "The JVM reads these variables at start-up, so an agent configured here is injected into Minecraft regardless of launcher, mods folder or client.",
                        "Developers sometimes configure profilers or monitoring agents globally.",
                        [new Evidence { Kind = EvidenceKind.Environment, Source = $"Environment ({target})", Reference = name, Details = new() { ["value"] = value.Length > 1500 ? value[..1500] : value } }]);
                }
            }
        }
        ctx.Advance(3);

        foreach (var inst in ctx.Installations)
        {
            ct.ThrowIfCancellationRequested();
            CheckLauncherProfiles(ctx, inst);
            ctx.Advance();
        }

        if (ctx.Options.IncludeSystemArtifacts) InventoryJava(ctx);
        ctx.Advance();
        return Task.CompletedTask;
    }

    private static void CheckLauncherProfiles(ScanContext ctx, Installation inst)
    {
        // Official launcher profiles. launcher_accounts*.json (authentication data) is deliberately never opened.
        var profiles = Path.Combine(inst.GameDirectory, "launcher_profiles.json");
        if (File.Exists(profiles))
        {
            try
            {
                ctx.Custody.Record("read-config", profiles);
                using var doc = JsonDocument.Parse(File.ReadAllText(profiles));
                if (doc.RootElement.TryGetProperty("profiles", out var ps))
                    foreach (var p in ps.EnumerateObject())
                        if (p.Value.TryGetProperty("javaArgs", out var ja) && ja.GetString() is { } args)
                            ReportAgents(ctx, profiles, $"profile \"{(p.Value.TryGetProperty("name", out var n) ? n.GetString() : p.Name)}\"", args);
            }
            catch (Exception e) when (e is JsonException or IOException or UnauthorizedAccessException or InvalidOperationException) { }
        }
        // Prism / MultiMC instance.cfg (JvmArgs=...)
        var cfg = Path.Combine(Path.GetDirectoryName(inst.GameDirectory)!, "instance.cfg");
        if (File.Exists(cfg))
        {
            ctx.Custody.Record("read-config", cfg);
            foreach (var line in File.ReadLines(cfg))
                if (line.StartsWith("JvmArgs=", StringComparison.OrdinalIgnoreCase))
                    ReportAgents(ctx, cfg, "instance JVM arguments", line[8..]);
        }
    }

    internal static bool IsLauncherOwned(ScanContext ctx, string agentPath)
    {
        var p = agentPath.Trim('"');
        string[] trusted =
        [
            Path.Combine(ctx.Options.UserProfile, ".lunarclient"),
            Path.Combine(ctx.Options.AppData, ".feather"),
            Path.Combine(ctx.Options.AppData, "Badlion Client"),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
        ];
        if (trusted.Any(t => t.Length > 3 && p.StartsWith(t, StringComparison.OrdinalIgnoreCase))) return true;
        // Content-based allowlist for launcher agents extracted to temporary folders (e.g. Modrinth App's theseus.jar):
        // every class must belong to the launcher's own package, so a renamed cheat agent does not pass.
        if (!File.Exists(p)) return false;
        var jar = Analysis.JarAnalyzer.Analyze(p);
        ctx.Custody.Record("read-archive", p);
        return jar.ClassEntries.Count > 0 && LauncherAgentPackages.Any(pkg => jar.ClassEntries.All(c => c.StartsWith(pkg, StringComparison.Ordinal)));
    }

    private static readonly string[] LauncherAgentPackages = ["com/modrinth/theseus/"];

    internal static void ReportAgents(ScanContext ctx, string source, string label, string args, string evidenceKind = EvidenceKind.Config, Dictionary<string, string>? extra = null)
    {
        foreach (Match m in AgentArg().Matches(args))
        {
            var target = m.Groups[2].Value.Trim('"').Split('=')[0];
            if (m.Groups[1].Value.Equals("javaagent", StringComparison.OrdinalIgnoreCase) && IsLauncherOwned(ctx, target)) continue;
            var details = new Dictionary<string, string>(extra ?? []) { ["argument"] = m.Value, ["agentPath"] = target, ["agentExists"] = File.Exists(target).ToString() };
            var evidence = new List<Evidence> { new() { Kind = evidenceKind, Source = source.EndsWith(".json") || source.EndsWith(".cfg") ? "Launcher configuration" : "Process command line", Reference = source, Details = details } };
            if (File.Exists(target)) evidence.Add(ctx.FileEvidence(target, "Java agent archive"));
            ctx.Report(Builtin.JavaAgentArgument, [source, target],
                $"{label} launches Java with {m.Value}" + (File.Exists(target) ? "." : " (the agent file no longer exists)."),
                "Inspection of launcher profile JVM arguments and running Java process command lines for -javaagent/-agentpath/-agentlib.",
                "A Java agent runs inside the game before Minecraft starts and can rewrite any game class — the mechanism used by injectable clients that leave the mods folder untouched.",
                "Agents shipped inside a launcher's own installation are treated as legitimate and not reported; developer profilers also use agents.",
                evidence);
        }
    }

    private static void InventoryJava(ScanContext ctx)
    {
        var homes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var root in new[] { @"SOFTWARE\JavaSoft\JDK", @"SOFTWARE\JavaSoft\JRE", @"SOFTWARE\JavaSoft\Java Runtime Environment", @"SOFTWARE\JavaSoft\Java Development Kit", @"SOFTWARE\Eclipse Adoptium\JDK", @"SOFTWARE\Eclipse Adoptium\JRE", @"SOFTWARE\Microsoft\JDK" })
        {
            try
            {
                using var k = Registry.LocalMachine.OpenSubKey(root);
                if (k is null) continue;
                ctx.Custody.Record("read-registry", @"HKLM\" + root);
                foreach (var sub in k.GetSubKeyNames())
                {
                    using var v = k.OpenSubKey(sub);
                    var home = v?.GetValue("JavaHome") as string ?? (v?.OpenSubKey(@"hotspot\MSI")?.GetValue("Path") as string);
                    if (home is not null && Directory.Exists(home)) homes.Add(home.TrimEnd('\\'));
                }
            }
            catch (Exception e) when (e is System.Security.SecurityException or UnauthorizedAccessException or IOException) { }
        }
        foreach (var dir in new[] { Path.Combine(ctx.Options.AppData, ".minecraft", "runtime"), Path.Combine(ctx.Options.UserProfile, ".lunarclient", "jre") })
            foreach (var java in SafeFind(dir, "java.exe", 5)) homes.Add(Path.GetDirectoryName(Path.GetDirectoryName(java))!);
        foreach (var pf in new[] { Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles) })
            foreach (var vendor in new[] { "Java", "Eclipse Adoptium", "Microsoft", "Zulu", "BellSoft", "Amazon Corretto" })
                foreach (var d in MinecraftLocator.SafeDirs(Path.Combine(pf, vendor)))
                    if (File.Exists(Path.Combine(d, "bin", "java.exe"))) homes.Add(d);

        foreach (var h in homes.Take(60))
        {
            string? version = null;
            var release = Path.Combine(h, "release");
            if (File.Exists(release))
            {
                var line = File.ReadLines(release).FirstOrDefault(l => l.StartsWith("JAVA_VERSION="));
                version = line?[13..].Trim('"');
            }
            var source = h.Contains(".minecraft", StringComparison.OrdinalIgnoreCase) ? "Minecraft launcher runtime"
                : h.Contains(".lunarclient", StringComparison.OrdinalIgnoreCase) ? "Lunar Client runtime" : "System installation";
            ctx.JavaRuntimes.Add(new Dictionary<string, object?> { ["path"] = h, ["version"] = version, ["source"] = source });
        }
    }

    private static IEnumerable<string> SafeFind(string root, string name, int depth)
    {
        if (!Directory.Exists(root)) yield break;
        var stack = new Stack<(string, int)>();
        stack.Push((root, 0));
        while (stack.Count > 0)
        {
            var (d, lvl) = stack.Pop();
            foreach (var f in MinecraftLocator.SafeFiles(d, name)) yield return f;
            if (lvl < depth) foreach (var s in MinecraftLocator.SafeDirs(d)) stack.Push((s, lvl + 1));
        }
    }
}
