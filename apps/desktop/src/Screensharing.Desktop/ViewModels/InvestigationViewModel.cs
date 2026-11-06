using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Screensharing.Desktop.Services;

namespace Screensharing.Desktop.ViewModels;

/// <summary>Investigation dashboard: who requested the scan, what will be examined, explicit consent, elevation.</summary>
public sealed partial class InvestigationViewModel : ObservableObject
{
    private readonly MainViewModel _main;
    public InvestigationInfo Investigation { get; }
    public ConsentInfo Consent { get; }
    public bool Elevated => _main.Elevated;

    [ObservableProperty][NotifyCanExecuteChangedFor(nameof(BeginCommand))] private bool _accepted;
    [ObservableProperty][NotifyCanExecuteChangedFor(nameof(BeginCommand))] private bool _busy;
    [ObservableProperty] private string? _error;
    private readonly bool _alreadyConsented;

    public InvestigationViewModel(MainViewModel main, InvestigationInfo inv, ConsentInfo consent, bool alreadyConsented)
    {
        _main = main;
        Investigation = inv;
        Consent = consent;
        _alreadyConsented = alreadyConsented;
        Accepted = alreadyConsented;
    }

    public string[] Sources { get; } =
    [
        "Minecraft and launcher folders: mods, versions, libraries, logs, resource packs, launcher profiles",
        "Java installations and the launch options of running Java game processes",
        "Loaded modules and bounded memory of running Minecraft processes",
        "Windows Prefetch and BAM execution records (administrator only)",
        "Your Recycle Bin index and NTFS change-journal entries for .jar/.exe/.dll files (journal: administrator only)",
        "Selected event-log records (log clears, clock changes) and service settings",
    ];

    public string[] NeverCollected { get; } =
    [
        "Browser history, cookies or saved passwords",
        "Launcher account tokens (launcher_accounts.json) or session tokens — command-line tokens are redacted",
        "Documents, photos, messages or any file outside the listed sources",
    ];

    private bool CanBegin => Accepted && !Busy;

    [RelayCommand(CanExecute = nameof(CanBegin))]
    private async Task BeginAsync()
    {
        Busy = true;
        Error = null;
        try
        {
            if (!_alreadyConsented) await _main.Api.ConsentAsync(Consent.Version);
            var scan = new ScanViewModel(_main, Investigation);
            _main.Navigate(scan, clearHistory: true);
            await scan.StartAsync();
        }
        catch (ApiException e) { Error = e.Message; }
        finally { Busy = false; }
    }

    [RelayCommand]
    private void RestartAsAdmin()
    {
        if (!MainViewModel.RestartElevated()) Error = "Administrator rights were not granted. You can continue without them; some checks will be skipped.";
    }
}
