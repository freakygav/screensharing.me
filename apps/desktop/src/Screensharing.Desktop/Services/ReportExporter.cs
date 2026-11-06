using System.Globalization;
using System.Text;
using System.Text.Json;
using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;

namespace Screensharing.Desktop.Services;

/// <summary>Exports a report to JSON, CSV (formula-injection safe) or PDF.</summary>
public static class ReportExporter
{
    static ReportExporter()
    {
        QuestPDF.Settings.License = LicenseType.Community;
        // Use Windows fonts (Segoe UI, Consolas) so the single-file executable needs no bundled font files.
        QuestPDF.Settings.UseSystemFonts = true;
    }

    public static void Json(ReportModel r, string path)
    {
        var doc = new
        {
            format = "screensharing.me/report",
            formatVersion = 2,
            generatedAt = DateTimeOffset.UtcNow,
            source = r.Source,
            investigation = new { id = r.InvestigationId, reference = r.Reference, subject = r.Subject, server = r.Server, requestedBy = r.RequestedBy },
            scan = new { r.StartedAt, r.CompletedAt, r.EngineVersion, r.RulesetVersion, r.Elevated, r.ManifestSha256, r.ManifestVerified },
            verdict = new { title = r.Verdict().Title, explanation = r.Verdict().Explanation },
            counts = new { total = r.Findings.Count, critical = r.Count("CRITICAL"), high = r.Count("HIGH"), medium = r.Count("MEDIUM"), low = r.Count("LOW"), info = r.Count("INFO") },
            instance = r.Instance,
            inspection = new { examined = r.FilesExamined, analyzed = r.FilesAnalyzed, skipped = r.FilesSkipped, unableToInspect = r.FilesUnableToInspect, signatures = r.Signatures, uninspected = r.Uninspected, excluded = r.Excluded },
            findings = r.Findings.Select(f => new { f.Id, f.RuleId, f.Name, suspectedClient = f.Family, f.Category, f.Location, f.Signature, status = f.OutcomeLabel, requiresManualReview = f.NeedsReview, f.Severity, f.Tier, f.Confidence, f.Description, f.Method, f.WhyItMatters, f.Limitations, f.FalsePositiveNotes, f.AlternativeExplanations, f.DetectedAt, f.Evidence }),
            coverage = r.Coverage,
            installations = r.Installations,
            mods = r.Mods,
            chainOfCustody = r.Custody.Select(c => new { at = c.At, action = c.Action, target = c.Target }),
        };
        File.WriteAllText(path, JsonSerializer.Serialize(doc, new JsonSerializerOptions(ApiClient.Json) { WriteIndented = true }), new UTF8Encoding(false));
    }

    private static string Cell(object? v)
    {
        var s = v switch { null => "", DateTimeOffset d => d.UtcDateTime.ToString("u", CultureInfo.InvariantCulture), _ => Convert.ToString(v, CultureInfo.InvariantCulture) ?? "" };
        if (s.Length > 0 && "=+-@\t\r".Contains(s[0])) s = "'" + s;
        return s.IndexOfAny([',', '"', '\n', '\r']) >= 0 ? $"\"{s.Replace("\"", "\"\"")}\"" : s;
    }

    public static void Csv(ReportModel r, string path)
    {
        var sb = new StringBuilder();
        sb.AppendLine(string.Join(",", "investigation_reference", "investigation_id", "subject", "finding_id", "rule_id", "name", "suspected_client", "category", "location", "signature", "status", "requires_manual_review", "severity", "evidence_tier", "confidence", "detected_at", "evidence_kind", "evidence_source", "evidence_reference", "sha256", "size_bytes", "file_created", "file_modified", "observed_at", "method", "why_it_matters", "limitations"));
        foreach (var f in r.Findings)
            foreach (var e in f.Evidence)
                sb.AppendLine(string.Join(",", new object?[] { r.Reference, r.InvestigationId, r.Subject, f.Id, f.RuleId, f.Name, f.Family, f.Category, f.Location, f.Signature, f.OutcomeLabel, f.NeedsReview ? "yes" : "no", f.Severity, f.Tier, f.Confidence, f.DetectedAt, e.Kind, e.Source, e.Reference, e.Sha256, e.SizeBytes, e.CreatedTime, e.ModifiedTime, e.ObservedAt, f.Method, f.WhyItMatters, f.Limitations }.Select(Cell)));
        File.WriteAllText(path, sb.ToString(), new UTF8Encoding(true));
    }

    public static void Pdf(ReportModel r, string path)
    {
        var accent = "#3F64D4";
        string SevColor(string s) => s switch { "CRITICAL" => "#DB2645", "HIGH" => "#E86A33", "MEDIUM" => "#C99A0F", "LOW" => "#2F86D9", _ => "#6B7280" };
        var (title, explanation, _) = r.Verdict();
        Document.Create(c => c.Page(page =>
        {
            page.Size(PageSizes.A4);
            page.Margin(40);
            page.DefaultTextStyle(t => t.FontFamily("Segoe UI").FontSize(9).FontColor("#111827"));
            page.Header().Column(h =>
            {
                h.Item().Text("screensharing.me").FontColor(accent).Bold().FontSize(11);
                h.Item().Text("Minecraft Forensic Investigation Report").Bold().FontSize(18);
                h.Item().PaddingTop(4).LineHorizontal(0.6f).LineColor("#D1D5DB");
            });
            page.Footer().AlignCenter().Text(t =>
            {
                t.Span($"{r.Reference} · generated {DateTime.UtcNow:u} · page ").FontSize(7).FontColor("#6B7280");
                t.CurrentPageNumber().FontSize(7).FontColor("#6B7280");
            });
            page.Content().PaddingTop(10).Column(col =>
            {
                col.Spacing(4);
                void Kv(string k, string? v) { if (!string.IsNullOrEmpty(v)) col.Item().Text(t => { t.Span(k + ": ").SemiBold(); t.Span(v); }); }
                Kv("Investigation", $"{r.Reference} ({r.InvestigationId})");
                Kv("Subject (player)", r.Subject);
                Kv("Server", r.Server);
                Kv("Requested by", r.RequestedBy);
                Kv("Scan started", r.StartedAt?.UtcDateTime.ToString("u"));
                Kv("Scan completed", r.CompletedAt?.UtcDateTime.ToString("u"));
                Kv("Scanner / ruleset", $"{r.EngineVersion} / {r.RulesetVersion}");
                Kv("Administrator rights", r.Elevated ? "yes" : "no");
                Kv("Examined instance", r.InstanceName == "-" ? null : $"{r.InstanceName} ({r.InstanceLauncher})");
                Kv("Game directory", r.InstancePath);
                Kv("Files", r.FilesExamined == 0 ? null : $"{r.FilesExamined} examined, {r.FilesAnalyzed} analysed, {r.FilesSkipped} skipped, {r.FilesUnableToInspect} could not be inspected; {r.Signatures} signatures applied");
                if (r.InstancePath.Length > 0) col.Item().Text("Only this instance was examined. Other instances, documents, browsers and Windows records were not read.").FontSize(8).FontColor("#6B7280");
                Kv("Evidence manifest SHA-256", r.ManifestSha256 is null ? null : $"{r.ManifestSha256} ({(r.ManifestVerified == true ? "verified by server" : r.ManifestVerified == false ? "MISMATCH" : "not verified")})");

                col.Item().PaddingTop(10).Text("Verdict").Bold().FontSize(13);
                col.Item().Text(title).Bold().FontColor(accent).FontSize(11);
                col.Item().Text(explanation);
                col.Item().Text($"Findings: {r.Findings.Count} · Critical {r.Count("CRITICAL")} · High {r.Count("HIGH")} · Medium {r.Count("MEDIUM")} · Low {r.Count("LOW")} · Info {r.Count("INFO")}").SemiBold();
                col.Item().Text("A finding describes what an artifact shows. No single filename, unknown mod or isolated artifact establishes that a person cheated.").FontSize(8).FontColor("#6B7280");

                col.Item().PaddingTop(10).Text("Scan coverage").Bold().FontSize(13);
                foreach (var cv in r.Coverage) col.Item().Text($"{cv.Status,-10} {cv.Name}{(cv.Note is null ? "" : " — " + cv.Note)}").FontFamily("Consolas").FontSize(8);

                col.Item().PaddingTop(10).Text("Findings").Bold().FontSize(13);
                if (r.Findings.Count == 0) col.Item().Text("No findings were recorded.").FontColor("#6B7280");
                var i = 0;
                foreach (var f in r.Findings)
                {
                    i++;
                    col.Item().PaddingTop(8).BorderLeft(3).BorderColor(SevColor(f.Severity)).PaddingLeft(8).Column(fc =>
                    {
                        fc.Spacing(2);
                        fc.Item().Text($"{i}. {f.Name}").Bold().FontSize(10.5f);
                        fc.Item().Text($"{f.OutcomeLabel}{(f.NeedsReview ? " (manual review)" : "")} · {f.Severity} · {f.TierLabel} · confidence {f.Confidence}% · {f.Category} · rule {f.RuleId}").FontSize(7.5f).FontColor("#6B7280");
                        if (f.Family is not null || f.Location is not null || f.Signature is not null)
                            fc.Item().Text(string.Join("  |  ", new[] { f.Family is null ? null : "Suspected: " + f.Family, f.Location is null ? null : "Location: " + f.Location, f.Signature is null ? null : "Signature: " + f.Signature }.Where(x => x is not null))).FontFamily("Consolas").FontSize(7.5f);
                        fc.Item().Text(f.Description);
                        fc.Item().Text(t => { t.Span("Why this matters: ").SemiBold(); t.Span(f.WhyItMatters); });
                        fc.Item().Text(t => { t.Span("Method: ").SemiBold(); t.Span(f.Method); });
                        fc.Item().Text(t => { t.Span("Limitations: ").SemiBold(); t.Span(f.Limitations); });
                        fc.Item().Text(t => { t.Span("Alternative explanations: ").SemiBold(); t.Span(f.AlternativeExplanations); });
                        foreach (var e in f.Evidence)
                        {
                            fc.Item().PaddingTop(2).Background("#F3F4F6").Padding(4).Column(ec =>
                            {
                                ec.Item().Text($"[{e.Kind}] {e.Reference}").FontFamily("Consolas").FontSize(7.5f);
                                var meta = string.Join("  |  ", new[] { e.Source, e.Sha256 is null ? null : "sha256 " + e.Sha256, e.SizeBytes is null ? null : $"{e.SizeBytes} bytes", e.ModifiedTime is null ? null : $"modified {e.ModifiedTime.Value.UtcDateTime:u}", $"observed {e.ObservedAt.UtcDateTime:u}" }.Where(x => x is not null));
                                ec.Item().Text(meta).FontFamily("Consolas").FontSize(6.5f).FontColor("#4B5563");
                                foreach (var (k, v) in e.Details.Take(12)) ec.Item().Text($"{k}: {v}").FontFamily("Consolas").FontSize(6.5f).FontColor("#4B5563");
                            });
                        }
                    });
                }
                if (r.Uninspected.Count > 0)
                {
                    col.Item().PaddingTop(12).Text("Files that could not be inspected").Bold().FontSize(13);
                    foreach (var u in r.Uninspected.Take(300)) col.Item().Text($"{u.Location} — {u.Reason ?? u.Status}").FontFamily("Consolas").FontSize(7f);
                }
                if (r.Custody.Count > 0)
                {
                    col.Item().PaddingTop(12).Text("Chain of custody (read-only collection log)").Bold().FontSize(13);
                    foreach (var (at, action, target) in r.Custody.Take(300))
                        col.Item().Text($"{at.UtcDateTime:u}  {action}  {target}").FontFamily("Consolas").FontSize(6.5f);
                    if (r.Custody.Count > 300) col.Item().Text($"… {r.Custody.Count - 300} more entries in the JSON export.").FontSize(7).FontColor("#6B7280");
                }
            });
        })).GeneratePdf(path);
    }
}
