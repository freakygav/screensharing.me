using System.Collections.ObjectModel;
using System.Net.Http;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Screensharing.Desktop.Services;
using Screensharing.Scanner.Engine;
using Screensharing.Scanner.Model;

namespace Screensharing.Desktop.ViewModels;

public sealed partial class CategoryRow : ObservableObject
{
    public required string Key { get; init; }
    public required string Name { get; init; }
    [ObservableProperty] private string _status = "PENDING";
    [ObservableProperty] private string _detail = "Pending";
}

/// <summary>Scan progress screen. Percentages come from the engine's real work-unit counts.</summary>
public sealed partial class ScanViewModel : ObservableObject
{
    private readonly MainViewModel _main;
    private readonly InvestigationInfo _inv;
    private readonly CancellationTokenSource _cts = new();
    private InvestigationSession? _session;

    [ObservableProperty] private int _percent;
    [ObservableProperty] private string _activity = "Preparing investigation…";
    [ObservableProperty] private string _units = "";
    [ObservableProperty] private int _findings;
    [ObservableProperty] private int _critical;
    [ObservableProperty] private int _high;
    [ObservableProperty] private string _linkText = "Live connection to the investigator";
    [ObservableProperty] private string _linkState = "Connected";
    [ObservableProperty] private bool _running = true;
    [ObservableProperty] private string? _error;
    public ObservableCollection<CategoryRow> Categories { get; } = [];
    public InvestigationInfo Investigation => _inv;

    public ScanViewModel(MainViewModel main, InvestigationInfo inv)
    {
        _main = main;
        _inv = inv;
    }

    private static void Ui(Action a) => Application.Current.Dispatcher.BeginInvoke(a);

    public async Task StartAsync()
    {
        _session = new InvestigationSession(_main.Api, _inv);
        _session.Progress += p => Ui(() => Apply(p));
        _session.FindingAdded += f => Ui(() =>
        {
            Findings++;
            if (f.Severity == Severity.Critical) Critical++;
            if (f.Severity == Severity.High) High++;
        });
        _session.Link += (s, msg) => Ui(() =>
        {
            LinkState = s.ToString();
            LinkText = s switch
            {
                Services.LinkState.Connected => "Live connection to the investigator",
                Services.LinkState.Reconnecting => "Connection lost — reconnecting. Results are queued and will be sent automatically.",
                _ => $"Upload stopped: {msg}",
            };
        });
        try
        {
            Activity = "Downloading the detection catalog…";
            var rules = await _session.LoadRulesAsync(_cts.Token);
            var http = new HttpClient { Timeout = TimeSpan.FromSeconds(20) };
            http.DefaultRequestHeaders.UserAgent.ParseAdd($"screensharing.me/{AppInfo.Version} (forensic scanner; +https://www.screensharing.me)");
            var options = new ScanOptions
            {
                Rules = rules,
                ModrinthLookup = _main.Store.GetBool("modrinthLookup", true),
                MemoryScan = _main.Store.GetBool("memoryScan", true),
                MemoryScanCapBytes = (long)(double.TryParse(_main.Store.Get("memoryCapGb"), out var gb) ? gb : 3) * 1024 * 1024 * 1024,
                Http = http,
            };
            foreach (var (key, name) in new ScanEngine(options).Categories) Categories.Add(new CategoryRow { Key = key, Name = name });

            var result = await _session.RunAsync(options, _cts.Token);
            Running = false;
            var report = ReportModel.FromLocal(result, _inv, _session.ManifestVerified);
            var folder = Path.Combine(AppInfo.DataDirectory, "reports");
            Directory.CreateDirectory(folder);
            var json = Path.Combine(folder, $"{_inv.Reference}-{DateTime.UtcNow:yyyyMMddHHmmss}.json");
            ReportExporter.Json(report, json);
            _main.Store.AddHistory(_inv.Reference, _inv.SubjectName, report.Findings.Count, json, result.ManifestSha256);
            if (_session.UploadError is null) _main.Store.ClearSession();
            _main.Navigate(new ResultsViewModel(_main, report, uploadError: _session.UploadError), clearHistory: true);
        }
        catch (OperationCanceledException)
        {
            Running = false;
            Activity = "Scan cancelled.";
        }
        catch (Exception e)
        {
            Running = false;
            Error = $"The scan stopped: {e.Message}";
        }
    }

    private void Apply(ScanProgress p)
    {
        Percent = p.Percent;
        Activity = p.Activity ?? Activity;
        Units = p.UnitsTotal > 0 ? $"{p.UnitsDone:N0} of {p.UnitsTotal:N0} work items" : "";
        foreach (var c in p.Categories)
        {
            var row = Categories.FirstOrDefault(r => r.Key == c.Key);
            if (row is null) continue;
            row.Status = Payloads.Status(c.Status);
            row.Detail = c.Status switch
            {
                CategoryStatus.Pending => "Pending",
                CategoryStatus.Running => $"{c.ItemsExamined:N0} examined",
                CategoryStatus.Skipped or CategoryStatus.Failed => c.Message ?? "",
                _ => $"{c.ItemsExamined:N0} examined · {c.FindingsCount} findings",
            };
        }
    }

    [RelayCommand]
    private void Cancel()
    {
        if (MessageBox.Show("Stop the investigation? The investigator will see that the scan was cancelled.", "screensharing.me", MessageBoxButton.YesNo, MessageBoxImage.Warning) == MessageBoxResult.Yes)
            _cts.Cancel();
    }

    [RelayCommand] private void Close() => _main.Navigate(new ConnectViewModel(_main), clearHistory: true);
}
