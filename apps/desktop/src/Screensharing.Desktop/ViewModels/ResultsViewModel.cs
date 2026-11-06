using System.Collections.ObjectModel;
using System.Diagnostics;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using Screensharing.Desktop.Services;

namespace Screensharing.Desktop.ViewModels;

public sealed partial class FindingRow : ObservableObject
{
    public required FindingItem Item { get; init; }
    [ObservableProperty] private bool _expanded;
}

/// <summary>Detection results with search, severity/category filters, sorting, expandable evidence and export.</summary>
public sealed partial class ResultsViewModel : ObservableObject
{
    private readonly MainViewModel _main;
    public ReportModel Report { get; }
    public string? UploadError { get; }
    public ObservableCollection<FindingRow> Visible { get; } = [];
    public List<string> Severities { get; } = ["All severities", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
    public List<string> Categories { get; }
    public List<string> Sorts { get; } = ["Sort: severity", "Sort: confidence", "Sort: detection time"];

    [ObservableProperty] private string _search = "";
    [ObservableProperty] private string _severity = "All severities";
    [ObservableProperty] private string _category = "All categories";
    [ObservableProperty] private string _sort = "Sort: severity";
    [ObservableProperty] private string? _exportMessage;

    public string VerdictTitle => Report.Verdict().Title;
    public string VerdictText => Report.Verdict().Explanation;
    public string VerdictLevel => Report.Verdict().Level;
    public int Total => Report.Findings.Count;
    public int Critical => Report.Count("CRITICAL");
    public int High => Report.Count("HIGH");
    public int Medium => Report.Count("MEDIUM");
    public int Low => Report.Count("LOW");
    public int Inconclusive => Report.CountTier("INCONCLUSIVE");
    public string Integrity => Report.ManifestVerified switch { true => "Verified", false => "Mismatch", null => Report.Source == "local" ? "Not uploaded" : "Unverified" };
    public string SubTitle => $"{Report.Reference} · {Report.Subject}{(Report.Server is null ? "" : " · " + Report.Server)}{(Report.CompletedAt is null ? "" : $" · completed {Report.CompletedAt.Value.ToLocalTime():g}")}";
    public bool FromServer => Report.Source == "server";

    public ResultsViewModel(MainViewModel main, ReportModel report, string? uploadError = null)
    {
        _main = main;
        Report = report;
        UploadError = uploadError;
        Categories = ["All categories", .. report.Findings.Select(f => f.Category).Distinct().Order()];
        Apply();
    }

    partial void OnSearchChanged(string value) => Apply();
    partial void OnSeverityChanged(string value) => Apply();
    partial void OnCategoryChanged(string value) => Apply();
    partial void OnSortChanged(string value) => Apply();

    private void Apply()
    {
        var q = Search.Trim();
        IEnumerable<FindingItem> list = Report.Findings
            .Where(f => Severity == "All severities" || f.Severity == Severity)
            .Where(f => Category == "All categories" || f.Category == Category)
            .Where(f => q.Length == 0 || new[] { f.Name, f.Description, f.RuleId, f.Category }.Concat(f.Evidence.Select(e => e.Reference)).Concat(f.Evidence.Select(e => e.Sha256 ?? ""))
                .Any(t => t.Contains(q, StringComparison.OrdinalIgnoreCase)));
        list = Sort switch
        {
            "Sort: confidence" => list.OrderByDescending(f => f.Confidence),
            "Sort: detection time" => list.OrderBy(f => f.DetectedAt),
            _ => list.OrderBy(f => f.SeverityRank).ThenByDescending(f => f.Confidence),
        };
        Visible.Clear();
        foreach (var f in list) Visible.Add(new FindingRow { Item = f });
    }

    [RelayCommand] private void Toggle(FindingRow row) => row.Expanded = !row.Expanded;
    [RelayCommand] private void OpenEvidence(FindingRow row) => _main.Navigate(new EvidenceViewModel(_main, Report, row.Item));
    [RelayCommand] private void ExpandAll() { var to = !Visible.All(v => v.Expanded); foreach (var v in Visible) v.Expanded = to; }

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
