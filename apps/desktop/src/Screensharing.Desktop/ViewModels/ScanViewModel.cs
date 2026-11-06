using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Net.Http;
using System.Windows;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Screensharing.Desktop.Services;
using Screensharing.Scanner.Engine;
using Screensharing.Scanner.Instance;
using Screensharing.Scanner.Model;

namespace Screensharing.Desktop.ViewModels;

public sealed partial class CategoryRow : ObservableObject
{
    public required string Key { get; init; }
    public required string Name { get; init; }
    [ObservableProperty] private string _status = "PENDING";
    [ObservableProperty] private string _detail = "Pending";
}

/// <summary>Scan progress screen. Every number comes from the engine: real work units, real file counts, real findings.</summary>
public sealed partial class ScanViewModel : ObservableObject
{
    private readonly MainViewModel _main;
    private readonly InvestigationInfo _inv;
    private readonly CancellationTokenSource _cts = new();
    private readonly Stopwatch _clock = new();
    private readonly DispatcherTimer? _timer;
    private InvestigationSession? _session;

    public GameInstance Instance { get; }
    public InvestigationInfo Investigation => _inv;
    public string InstanceDetail => string.Join(" · ", new[] { Instance.Launcher, Instance.MinecraftVersion is null ? null : $"Minecraft {Instance.MinecraftVersion}", Instance.Loader, Instance.ProcessId is null ? null : $"PID {Instance.ProcessId}" }.Where(x => x is not null));

    [ObservableProperty] private int _percent;
    [ObservableProperty] private string _stage = "Preparing";
    [ObservableProperty] private string _activity = "Preparing the investigation…";
    [ObservableProperty] private int _filesExamined;
    [ObservableProperty] private int _filesAnalyzed;
    [ObservableProperty] private int _filesSkipped;
    [ObservableProperty] private int _unableToInspect;
    [ObservableProperty] private int _findings;
    [ObservableProperty] private int _confirmed;
    [ObservableProperty] private int _highConfidence;
    [ObservableProperty] private string _elapsed = "0:00";
    [ObservableProperty] private string _linkText = "Live connection to the investigator";
    [ObservableProperty] private string _linkState = "Connected";
    [ObservableProperty] private bool _running = true;
    [ObservableProperty] private bool _cancelling;
    [ObservableProperty] private string? _error;
    [ObservableProperty] private string? _notice;
    public ObservableCollection<CategoryRow> Categories { get; } = [];

    public ScanViewModel(MainViewModel main, InvestigationInfo inv, GameInstance instance)
    {
        _main = main;
        _inv = inv;
        Instance = instance;
        if (Application.Current is not null)
        {
            _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
            _timer.Tick += (_, _) => Elapsed = Format(_clock.Elapsed);
        }
    }

    private static string Format(TimeSpan t) => t.TotalHours >= 1 ? t.ToString(@"h\:mm\:ss") : t.ToString(@"m\:ss");

    private static void Ui(Action a)
    {
        if (Application.Current?.Dispatcher is { } d) d.BeginInvoke(a); else a();
    }

    public async Task StartAsync()
    {
        _session = new InvestigationSession(_main.Api, _inv);
        _session.Progress += p => Ui(() => Apply(p));
        _session.FindingAdded += f => Ui(() =>
        {
            Findings++;
            if (f.Outcome == FindingOutcome.Confirmed) Confirmed++;
            if (f.Outcome == FindingOutcome.HighConfidence) HighConfidence++;
        });
        _session.Link += (s, msg) => Ui(() =>
        {
            LinkState = s.ToString();
            LinkText = s switch
            {
                Services.LinkState.Connected => "Live connection to the investigator",
                Services.LinkState.Reconnecting => "Connection lost — reconnecting. Results are queued and sent automatically.",
                _ => $"Upload stopped: {msg}",
            };
        });
        _clock.Start();
        _timer?.Start();
        try
        {
            Activity = "Downloading the signature database…";
            var rules = await _session.LoadRulesAsync(_cts.Token);
            var http = new HttpClient { Timeout = TimeSpan.FromSeconds(20) };
            http.DefaultRequestHeaders.UserAgent.ParseAdd($"screensharing.me/{AppInfo.Version} (forensic scanner; +https://www.screensharing.me)");
            var options = new ScanOptions
            {
                Rules = rules,
                Target = Instance,
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
            Stage = "Cancelled";
            Activity = "Scan cancelled.";
            Notice = "The scan was stopped. Nothing on this computer was changed, and the investigator has been told the scan was cancelled.";
        }
        catch (InstanceNotResolvedException e)
        {
            Running = false;
            Error = "The scan did not start: " + e.Message;
        }
        catch (Exception e)
        {
            Running = false;
            Error = $"The scan stopped: {e.Message}";
        }
        finally
        {
            _clock.Stop();
            _timer?.Stop();
            Elapsed = Format(_clock.Elapsed);
        }
    }

    internal void Apply(ScanProgress p)
    {
        Percent = p.Percent;
        Activity = p.Activity ?? Activity;
        if (p.Stage.Length > 0) Stage = p.Stage;
        FilesExamined = p.FilesExamined;
        FilesAnalyzed = p.FilesAnalyzed;
        FilesSkipped = p.FilesSkipped;
        UnableToInspect = p.UnableToInspect;
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
                _ => c.Message ?? $"{c.ItemsExamined:N0} examined · {c.FindingsCount} findings",
            };
        }
    }

    [RelayCommand]
    private void Cancel()
    {
        if (!Running || Cancelling) return;
        if (MessageBox.Show("Stop the scan? Nothing is changed on this computer. The investigator will see that the scan was cancelled.", "screensharing.me", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        Cancelling = true;
        Activity = "Cancelling…";
        _cts.Cancel();
    }

    [RelayCommand] private void Close() => _main.Navigate(new ConnectViewModel(_main), clearHistory: true);
}
