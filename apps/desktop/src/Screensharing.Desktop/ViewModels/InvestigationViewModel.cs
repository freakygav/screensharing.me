using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Screensharing.Desktop.Services;
using Screensharing.Scanner.Instance;

namespace Screensharing.Desktop.ViewModels;

/// <summary>A running Minecraft instance as offered for selection.</summary>
public sealed class InstanceOption
{
    public required GameInstance Instance { get; init; }
    public string Name => Instance.Resolved ? Instance.Name : Instance.ProcessName is null ? Instance.Name : $"{Instance.ProcessName} (PID {Instance.ProcessId})";
    public string Launcher => Instance.Launcher;
    public string Path => Instance.Resolved ? Instance.GameDirectory : Instance.Problem ?? "";
    public bool Resolved => Instance.Resolved;
    public string Detail => string.Join(" · ", new[]
    {
        Instance.MinecraftVersion is null ? null : $"Minecraft {Instance.MinecraftVersion}",
        Instance.Loader,
        Instance.ProcessId is null ? null : $"PID {Instance.ProcessId}",
        Instance.ProcessStartedAt is null ? null : $"started {Instance.ProcessStartedAt.Value.ToLocalTime():t}",
    }.Where(x => x is not null));
    public string Source => Instance.Resolved ? $"Identified from the {Instance.GameDirectorySource}" : "Cannot be scanned";
}

/// <summary>
/// Investigation screen: who requested the scan, which running Minecraft instance will be examined (the player confirms
/// it, choosing one when several are running), explicit consent, and start.
/// </summary>
public sealed partial class InvestigationViewModel : ObservableObject
{
    private readonly MainViewModel _main;
    public InvestigationInfo Investigation { get; }
    public ConsentInfo Consent { get; }
    public bool Elevated => _main.Elevated;
    public ObservableCollection<InstanceOption> Instances { get; } = [];

    [ObservableProperty][NotifyCanExecuteChangedFor(nameof(BeginCommand))] private bool _accepted;
    [ObservableProperty][NotifyCanExecuteChangedFor(nameof(BeginCommand))] private bool _busy;
    [ObservableProperty][NotifyCanExecuteChangedFor(nameof(BeginCommand))] private InstanceOption? _selected;
    [ObservableProperty] private bool _detecting;
    [ObservableProperty] private string? _instanceMessage;
    [ObservableProperty] private string? _error;
    private readonly bool _alreadyConsented;

    /// <summary>Instance detection; replaceable for UI tests.</summary>
    internal Func<IReadOnlyList<GameInstance>> Detect { get; init; } = InstanceResolver.Detect;

    public InvestigationViewModel(MainViewModel main, InvestigationInfo inv, ConsentInfo consent, bool alreadyConsented, bool detectNow = true)
    {
        _main = main;
        Investigation = inv;
        Consent = consent;
        _alreadyConsented = alreadyConsented;
        Accepted = alreadyConsented;
        if (detectNow) _ = RefreshAsync();
    }

    public string[] Sources { get; } =
    [
        "The Minecraft instance you select below: mods, configuration, resource and shader packs, logs and crash reports",
        "The game files that instance loads (client jar and libraries), verified against the launcher's hashes",
        "The running game process: launch arguments, loaded modules and a bounded read of its memory",
    ];

    public string[] NeverCollected { get; } =
    [
        "Other Minecraft instances and anything else on this computer",
        "Documents, browser data, Discord, passwords, account or session tokens",
        "Windows records (Prefetch, registry, event logs). No file is changed.",
    ];

    private bool CanBegin => Accepted && !Busy && Selected is { Resolved: true };

    [RelayCommand]
    public async Task RefreshAsync()
    {
        Detecting = true;
        InstanceMessage = null;
        try
        {
            var previous = Selected?.Instance.ProcessId;
            var found = await Task.Run(Detect);
            Instances.Clear();
            foreach (var i in found.OrderByDescending(i => i.Resolved).ThenByDescending(i => i.ProcessStartedAt))
                Instances.Add(new InstanceOption { Instance = i });
            var resolved = Instances.Where(i => i.Resolved).ToList();
            Selected = resolved.FirstOrDefault(i => i.Instance.ProcessId == previous) ?? (resolved.Count == 1 ? resolved[0] : null);
            InstanceMessage = Instances.Count == 0
                ? "No running Minecraft instance was found. Start the instance you play on, wait until the main menu appears, then select Refresh."
                : resolved.Count == 0 ? "Minecraft is running, but its instance could not be identified (see the reason above). The scan cannot start until it is."
                : resolved.Count > 1 && Selected is null ? "Several instances are running. Select the one you play on."
                : null;
        }
        catch (Exception e) when (e is InvalidOperationException or UnauthorizedAccessException or System.ComponentModel.Win32Exception)
        {
            InstanceMessage = "Running processes could not be listed: " + e.Message;
        }
        finally { Detecting = false; }
    }

    [RelayCommand(CanExecute = nameof(CanBegin))]
    private async Task BeginAsync()
    {
        Busy = true;
        Error = null;
        try
        {
            // Re-identify the selected process right before starting, so a closed or restarted game is never scanned by mistake.
            var chosen = Selected!.Instance;
            var current = await Task.Run(() => chosen.ProcessId is { } pid && ProcessInspector.Get(pid) is { } p ? InstanceResolver.Resolve(p) : null);
            if (current is null || !current.Resolved || !string.Equals(current.GameDirectory, chosen.GameDirectory, StringComparison.OrdinalIgnoreCase))
            {
                Error = "The selected Minecraft instance is no longer running (or changed). Refresh and select it again.";
                await RefreshAsync();
                return;
            }
            if (!_alreadyConsented) await _main.Api.ConsentAsync(Consent.Version);
            var scan = new ScanViewModel(_main, Investigation, current);
            _main.Navigate(scan, clearHistory: true);
            await scan.StartAsync();
        }
        catch (ApiException e) { Error = e.Message; }
        finally { Busy = false; }
    }

    [RelayCommand]
    private void RestartAsAdmin()
    {
        if (!MainViewModel.RestartElevated()) Error = "Administrator rights were not granted.";
    }
}
