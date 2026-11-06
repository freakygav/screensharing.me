using System.Text.RegularExpressions;
using Screensharing.Scanner.Analysis;
using Screensharing.Scanner.Engine;
using Screensharing.Scanner.Model;

namespace Screensharing.Scanner.Modules;

/// <summary>How the selected game process was started: Java agents, JVM option variables in its environment, redirected content folders.</summary>
public sealed partial class LaunchModule : IScanModule
{
    public string Key => "launch";
    public string Name => "Launch configuration";
    public string Activity => "Inspecting how the game was launched…";

    public string? SkipReason(ScanContext ctx) => ctx.Instance.ProcessId is null ? "No running game process is attached to this scan" : null;
    public int Plan(ScanContext ctx) => 2 + ctx.Instance.Agents.Count;

    [GeneratedRegex(@"-(javaagent|agentpath|agentlib)[:=]\s*(""[^""]+""|\S+)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    internal static partial Regex AgentArg();

    /// <summary>Launcher agents allowlisted by content: every class of the agent jar must be in one of these packages.</summary>
    private static readonly string[] LauncherAgentPackages = ["com/modrinth/theseus/"];

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        var inst = ctx.Instance;
        var procRef = $"{inst.ProcessName} (PID {inst.ProcessId})";
        ctx.Custody.Record("read-process-commandline", procRef);

        foreach (var (kind, value) in inst.Agents)
        {
            ct.ThrowIfCancellationRequested();
            var target = value.Trim('"').Split('=')[0];
            var exists = File.Exists(target) && ctx.Scope.Contains(target);
            if (kind.Equals("javaagent", StringComparison.OrdinalIgnoreCase) && exists && IsLauncherAgent(ctx, target))
            {
                ctx.Custody.Record("launcher-agent-allowlisted", target);
                ctx.Advance();
                continue;
            }
            var evidence = new List<Evidence> { new() { Kind = EvidenceKind.Process, Source = "Game process command line", Reference = procRef, Details = new() { ["argument"] = $"-{kind}:{value}", ["agentPath"] = target, ["agentExists"] = exists.ToString() } } };
            if (exists) evidence.Add(ctx.FileEvidence(target, "Java agent archive"));
            ctx.Report(Builtin.JavaAgentArgument, [procRef, target],
                $"The game process {procRef} was started with -{kind}:{value}" + (exists ? "." : " (the agent file no longer exists)."),
                "The command line of the selected game process was parsed for -javaagent, -agentpath and -agentlib.",
                "A Java agent runs inside the game before Minecraft starts and can rewrite any game class — the mechanism used by injectable clients that leave the mods folder untouched.",
                "Profilers and some launchers use agents; launcher agents are allowlisted by their class content.",
                evidence, signature: $"-{kind}", location: target);
            if (exists && kind.Equals("javaagent", StringComparison.OrdinalIgnoreCase))
                ModsModule.AnalyzeArchive(ctx, target, "Java agent", FileRole.Archive, ct, classPath: true);
            ctx.Advance();
        }

        foreach (var (name, value) in inst.JavaEnvironment)
        {
            ctx.Custody.Record("read-process-environment", $"{procRef}: {name}");
            if (!AgentArg().IsMatch(value)) continue;
            ctx.Report(Builtin.JavaOptionsEnv, [procRef, name],
                $"The environment of {procRef} sets {name}, which made the JVM load: {AgentArg().Match(value).Value}",
                "Only JAVA_TOOL_OPTIONS, _JAVA_OPTIONS and JDK_JAVA_OPTIONS are read from the game process's own environment block.",
                "The JVM reads these variables at start-up, so an agent configured here is injected into Minecraft even though it does not appear in the launch arguments.",
                "Developers sometimes configure profilers or monitoring agents globally.",
                [new Evidence { Kind = EvidenceKind.Environment, Source = "Game process environment", Reference = $"{procRef}: {name}", Details = new() { ["value"] = value.Length > 1500 ? value[..1500] : value } }],
                signature: name, location: procRef);
        }
        ctx.Advance();

        ctx.Statistics["javaAgents"] = inst.Agents.Count;
        if (ctx.CurrentCategory is not null)
            ctx.CurrentCategory.Message = $"{inst.Agents.Count} agent argument(s), {inst.JavaEnvironment.Count} JVM option variable(s)";
        ctx.Advance();
        return Task.CompletedTask;
    }

    internal static bool IsLauncherAgent(ScanContext ctx, string path)
    {
        try
        {
            using var fs = ctx.OpenRead(path);
            var jar = JarAnalyzer.Analyze(fs, new JarAnalyzer.Options { ReadContent = false });
            ctx.Custody.Record("read-archive", path);
            return jar.ClassEntries.Count > 0 && LauncherAgentPackages.Any(p => jar.ClassEntries.All(c => c.StartsWith(p, StringComparison.Ordinal)));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return false; }
    }
}
