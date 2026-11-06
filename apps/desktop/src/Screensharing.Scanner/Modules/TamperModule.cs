using System.Diagnostics.Eventing.Reader;
using System.ServiceProcess;
using Microsoft.Win32;
using Screensharing.Scanner.Engine;
using Screensharing.Scanner.Model;

namespace Screensharing.Scanner.Modules;

/// <summary>Anti-forensics indicators: cleared logs, clock changes, disabled artifact-producing services, disabled Prefetch.</summary>
public sealed class TamperModule : IScanModule
{
    public string Key => "tamper";
    public string Name => "Anti-forensics & tampering";
    public string Activity => "Checking for anti-forensic activity…";
    public string? SkipReason(ScanContext ctx) => ctx.Options.IncludeSystemArtifacts ? null : "System artifacts excluded by scan options";
    public int Plan(ScanContext ctx) => 5;

    private static readonly (string Name, string Purpose)[] Services =
    [
        ("SysMain", "maintains Prefetch execution records"),
        ("EventLog", "records Windows event logs"),
        ("bam", "records program execution (BAM)"),
        ("PcaSvc", "Program Compatibility Assistant execution records"),
        ("DPS", "Diagnostic Policy Service (SRUM resource usage records)"),
    ];

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        var notes = new List<string>();
        Query(ctx, "System", "*[System[Provider[@Name='Microsoft-Windows-Eventlog'] and EventID=104 and TimeCreated[timediff(@SystemTime) <= 604800000]]]", notes, (rec) =>
            Cleared(ctx, rec, "System", "Event 104: an event log was cleared"));
        ctx.Advance();
        if (ctx.Elevated)
            Query(ctx, "Security", "*[System[EventID=1102 and TimeCreated[timediff(@SystemTime) <= 604800000]]]", notes, (rec) =>
                Cleared(ctx, rec, "Security", "Event 1102: the Security audit log was cleared"));
        else notes.Add("Security log requires administrator rights");
        ctx.Advance();

        Query(ctx, "System", "*[System[Provider[@Name='Microsoft-Windows-Kernel-General'] and EventID=1 and TimeCreated[timediff(@SystemTime) <= 604800000]]]", notes, (rec) =>
        {
            var xml = rec.ToXml();
            var newT = Extract(xml, "NewTime");
            var oldT = Extract(xml, "OldTime");
            if (!DateTime.TryParse(newT, null, System.Globalization.DateTimeStyles.AdjustToUniversal, out var n) || !DateTime.TryParse(oldT, null, System.Globalization.DateTimeStyles.AdjustToUniversal, out var o)) return;
            var delta = n - o;
            if (Math.Abs(delta.TotalMinutes) < 5) return;
            ctx.Report(Builtin.TimeChanged, [rec.RecordId?.ToString() ?? xml.GetHashCode().ToString()],
                $"The system clock was changed by {delta.TotalMinutes:+0;-0} minutes at {rec.TimeCreated?.ToUniversalTime():u} (from {o:u} to {n:u}).",
                "Query of System log Kernel-General event 1 (system time change) for the last 7 days; changes under 5 minutes are ignored.",
                "Moving the clock makes file and execution timestamps misleading, which is used to confuse timeline analysis.",
                "Time-zone corrections, dual-boot systems, and a failing CMOS battery cause large adjustments.",
                [new Evidence { Kind = EvidenceKind.EventLog, Source = "Windows System event log", Reference = $"System/Kernel-General/1 record {rec.RecordId}", ModifiedTime = rec.TimeCreated, Details = new() { ["oldTime"] = o.ToString("u"), ["newTime"] = n.ToString("u"), ["deltaMinutes"] = delta.TotalMinutes.ToString("0") } }]);
        });
        ctx.Advance();

        foreach (var (svc, purpose) in Services)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{svc}");
                if (key is null) continue;
                ctx.Custody.Record("read-registry", $@"HKLM\SYSTEM\CurrentControlSet\Services\{svc}\Start");
                var start = key.GetValue("Start") is int s ? s : -1;
                string? status = null;
                try { using var sc = new ServiceController(svc); status = sc.Status.ToString(); } catch (InvalidOperationException) { }
                var disabled = start == 4;
                var stopped = svc is not "bam" && status == "Stopped" && start is 2 or 3 && svc is "SysMain" or "EventLog";
                if (!disabled && !stopped) continue;
                ctx.Report(Builtin.ServiceDisabled, [svc],
                    $"The {svc} service ({purpose}) is {(disabled ? "disabled" : "stopped")}" + (status is null ? "." : $" (current state: {status})."),
                    "Read of the service's Start value in the registry and its current state from the Service Control Manager.",
                    $"With {svc} {(disabled ? "disabled" : "stopped")}, Windows stops producing artifacts that a screenshare relies on.",
                    "Performance-tuning guides commonly disable SysMain; some privacy tools disable diagnostic services.",
                    [new Evidence { Kind = EvidenceKind.Service, Source = "Service configuration", Reference = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svc}", Details = new() { ["Start"] = start.ToString(), ["status"] = status ?? "unknown" } }]);
            }
            catch (Exception e) when (e is System.Security.SecurityException or UnauthorizedAccessException or IOException) { }
        }
        ctx.Advance();

        try
        {
            const string pp = @"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters";
            using var k = Registry.LocalMachine.OpenSubKey(pp);
            ctx.Custody.Record("read-registry", @"HKLM\" + pp);
            if (k?.GetValue("EnablePrefetcher") is int v && v == 0)
                ctx.Report(Builtin.PrefetchDisabled, ["EnablePrefetcher"],
                    "EnablePrefetcher is 0: Windows does not record program execution in Prefetch.",
                    "Read of the PrefetchParameters registry key.",
                    "Disabling Prefetch removes one of the main records of which programs were run.",
                    "Some SSD optimisation guides recommend disabling Prefetch.",
                    [new Evidence { Kind = EvidenceKind.Registry, Source = "Registry", Reference = @"HKLM\" + pp + @"\EnablePrefetcher", Details = new() { ["value"] = "0" } }]);
        }
        catch (Exception e) when (e is System.Security.SecurityException or UnauthorizedAccessException or IOException) { }
        ctx.Advance();

        if (ctx.CurrentCategory is not null && notes.Count > 0) ctx.CurrentCategory.Message = string.Join("; ", notes);
        return Task.CompletedTask;
    }

    private static void Cleared(ScanContext ctx, EventRecord rec, string log, string what)
    {
        var xml = rec.ToXml();
        var channel = Extract(xml, "Channel") ?? log;
        ctx.Report(Builtin.EventLogCleared, [log, rec.RecordId?.ToString() ?? "?"],
            $"{what} at {rec.TimeCreated?.ToUniversalTime():u}{(Extract(xml, "SubjectUserName") is { } u ? $" by {u}" : "")}.",
            $"Query of the {log} event log for log-clear events in the last 7 days.",
            "Clearing event logs shortly before a screenshare removes records of program execution, service changes and time changes.",
            "Administrators, cleanup utilities and some game optimisers clear logs routinely.",
            [new Evidence { Kind = EvidenceKind.EventLog, Source = $"Windows {log} event log", Reference = $"{log}/{rec.Id} record {rec.RecordId}", ModifiedTime = rec.TimeCreated, Details = new() { ["eventId"] = rec.Id.ToString(), ["clearedChannel"] = channel } }]);
    }

    private static void Query(ScanContext ctx, string log, string xpath, List<string> notes, Action<EventRecord> onRecord)
    {
        try
        {
            ctx.Custody.Record("query-event-log", $"{log}: {xpath}");
            using var reader = new EventLogReader(new EventLogQuery(log, PathType.LogName, xpath));
            var n = 0;
            for (var rec = reader.ReadEvent(); rec is not null && n < 500; rec = reader.ReadEvent(), n++)
                using (rec) onRecord(rec);
        }
        catch (Exception e) when (e is UnauthorizedAccessException or EventLogException)
        {
            notes.Add($"{log} log unavailable ({e.GetType().Name})");
        }
    }

    private static string? Extract(string xml, string name)
    {
        var tag = $"Name='{name}'>";
        var i = xml.IndexOf(tag, StringComparison.Ordinal);
        if (i < 0) { tag = $"Name=\"{name}\">"; i = xml.IndexOf(tag, StringComparison.Ordinal); }
        if (i >= 0)
        {
            var s = i + tag.Length;
            var e = xml.IndexOf('<', s);
            return e > s ? xml[s..e] : null;
        }
        var open = $"<{name}>";
        i = xml.IndexOf(open, StringComparison.Ordinal);
        if (i < 0) return null;
        var start = i + open.Length;
        var end = xml.IndexOf('<', start);
        return end > start ? xml[start..end] : null;
    }
}
