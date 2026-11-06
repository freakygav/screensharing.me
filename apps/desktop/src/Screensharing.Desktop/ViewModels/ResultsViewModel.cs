using System.Collections.ObjectModel;
using System.Diagnostics;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using Screensharing.Desktop.Services;

namespace Screensharing.Desktop.ViewModels;

/// <summary>Scan report: verdict, instance, outcome counts, a findings table with a detail pane, files not inspected, coverage and export.</summary>
public sealed partial class ResultsViewModel : ObservableObject
{
    private readonly MainViewModel _main;
    public ReportModel Report { get; }
    public string? UploadError { get; }
    public ObservableCollection<FindingItem> Visible { get; } = [];
    public List<string> Outcomes { get; } = ["All statuses", "Confirmed", "High confidence", "Low confidence", "Not inspected", "Informational"];
    public List<string> Severities { get; } = ["All severities", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

    [ObservableProperty] private string _search = "";
    [ObservableProperty] private string _outcome = "All statuses";
    [ObservableProperty] private string _severity = "All severities";
    [ObservableProperty] private string _tab = "findings";
    [ObservableProperty] private FindingItem? _selected;
    [ObservableProperty] private string? _exportMessage;

    public string VerdictTitle => Report.Verdict().Title;
    public string VerdictText => Report.Verdict().Explanation;
    public string VerdictLevel => Report.Verdict().Level;
    public int Confirmed => Report.CountOutcome("CONFIRMED");
    public int HighConfidence => Report.CountOutcome("HIGH_CONFIDENCE");
    public int LowConfidence => Report.CountOutcome("LOW_CONFIDENCE");
    public int NotInspected => Report.CountOutcome("UNABLE_TO_INSPECT");
    public int Informational => Report.CountOutcome("INFORMATIONAL");
    public string Integrity => Report.ManifestVerified switch { true => "Verified", false => "Mismatch", null => Report.Source == "local" ? "Not uploaded" : "Unverified" };
    public string SubTitle => $"{Report.Reference} · {Report.Subject}{(Report.Server is null ? "" : " · " + Report.Server)}{(Report.CompletedAt is null ? "" : $" · completed {Report.CompletedAt.Value.ToLocalTime():g}")}";
    public string InstanceLine => string.Join(" · ", new[] { Report.InstanceLauncher, Report.Instance.GetValueOrDefault("versions")?.ToString() is { Length: > 0 } v && v != "—" ? $"Minecraft {v}" : null, Report.Instance.GetValueOrDefault("loader")?.ToString() }.Where(x => !string.IsNullOrEmpty(x)));
    public string Duration => Report.DurationSeconds > 0 ? TimeSpan.FromSeconds(Report.DurationSeconds).ToString(Report.DurationSeconds >= 3600 ? @"h\:mm\:ss" : @"m\:ss") : "—";
    public bool FromServer => Report.Source == "server";
    public string FindingsTabText => $"Findings ({Report.Findings.Count})";
    public string UninspectedTabText => $"Not inspected ({Report.Uninspected.Count})";

    public ResultsViewModel(MainViewModel main, ReportModel report, string? uploadError = null)
    {
        _main = main;
        Report = report;
        UploadError = uploadError;
        Apply();
        Selected = Visible.FirstOrDefault(f => f.Outcome != "INFORMATIONAL") ?? Visible.FirstOrDefault();
    }

    partial void OnSearchChanged(string value) => Apply();
    partial void OnOutcomeChanged(string value) => Apply();
    partial void OnSeverityChanged(string value) => Apply();

    private void Apply()
    {
        var q = Search.Trim();
        var list = Report.Findings
            .Where(f => Outcome == "All statuses" || f.OutcomeLabel == Outcome)
            .Where(f => Severity == "All severities" || f.Severity == Severity)
            .Where(f => q.Length == 0 || new[] { f.Name, f.Description, f.RuleId, f.Category, f.Family ?? "", f.Signature ?? "", f.Location ?? "" }
                .Concat(f.Evidence.Select(e => e.Reference)).Concat(f.Evidence.Select(e => e.Sha256 ?? ""))
                .Any(t => t.Contains(q, StringComparison.OrdinalIgnoreCase)))
            .OrderBy(f => f.OutcomeRank).ThenBy(f => f.SeverityRank).ThenByDescending(f => f.Confidence);
        Visible.Clear();
        foreach (var f in list) Visible.Add(f);
        if (Selected is not null && !Visible.Contains(Selected)) Selected = Visible.FirstOrDefault();
    }

    [RelayCommand] private void ShowTab(string tab) => Tab = tab;
    [RelayCommand] private void OpenEvidence(FindingItem item) => _main.Navigate(new EvidenceViewModel(_main, Report, item));

    [RelayCommand]
    private void Export(string format)
    {
        var dlg = new SaveFileDialog
        {
            FileName = $"screensharing-{Report.Reference}.{format}",
            Filter = format switch { "pdf" => "PDF report|*.pdf", "csv" => "CSV|*.csv", _ => "JSON|*.json" },
            InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
        };
        if (dlg.ShowDialog() != true) return;
        try
        {
            switch (format)
            {
                case "pdf": ReportExporter.Pdf(Report, dlg.FileName); break;
                case "csv": ReportExporter.Csv(Report, dlg.FileName); break;
                default: ReportExporter.Json(Report, dlg.FileName); break;
            }
            ExportMessage = $"Saved {Path.GetFileName(dlg.FileName)}";
            Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{dlg.FileName}\"") { UseShellExecute = true });
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            ExportMessage = $"Export failed: {e.Message}";
        }
    }

    [RelayCommand] private void Done() => _main.Navigate(new ConnectViewModel(_main), clearHistory: true);
}
