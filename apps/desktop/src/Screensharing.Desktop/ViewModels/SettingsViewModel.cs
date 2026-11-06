using System.Collections.ObjectModel;
using System.Diagnostics;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Screensharing.Desktop.Services;

namespace Screensharing.Desktop.ViewModels;

public sealed partial class SettingsViewModel : ObservableObject
{
    private readonly MainViewModel _main;
    [ObservableProperty] private string _serverUrl;
    [ObservableProperty] private bool _modrinthLookup;
    [ObservableProperty] private bool _memoryScan;
    [ObservableProperty] private string _memoryCapGb;
    [ObservableProperty] private string? _message;
    [ObservableProperty] private bool _messageIsError;
    public ObservableCollection<HistoryEntry> History { get; } = [];
    public string DataFolder => AppInfo.DataDirectory;

    public SettingsViewModel(MainViewModel main)
    {
        _main = main;
        _serverUrl = main.ServerUrl;
        _modrinthLookup = main.Store.GetBool("modrinthLookup", true);
        _memoryScan = main.Store.GetBool("memoryScan", true);
        _memoryCapGb = main.Store.Get("memoryCapGb") ?? "3";
        foreach (var h in main.Store.History()) History.Add(h);
    }

    [RelayCommand]
    private void Save()
    {
        try
        {
            if (!double.TryParse(MemoryCapGb, out var gb) || gb < 0.25 || gb > 32) throw new ArgumentException("Memory cap must be between 0.25 and 32 GB.");
            _main.ServerUrl = ServerUrl;
            _main.Store.SetBool("modrinthLookup", ModrinthLookup);
            _main.Store.SetBool("memoryScan", MemoryScan);
            _main.Store.Set("memoryCapGb", gb.ToString(System.Globalization.CultureInfo.InvariantCulture));
            MessageIsError = false;
            Message = "Settings saved.";
        }
        catch (ArgumentException e) { MessageIsError = true; Message = e.Message; }
    }

    [RelayCommand] private void ResetServer() => ServerUrl = AppInfo.DefaultServerUrl;
    [RelayCommand] private void OpenDataFolder() => Process.Start(new ProcessStartInfo("explorer.exe", $"\"{DataFolder}\"") { UseShellExecute = true });
    [RelayCommand] private void OpenReport(HistoryEntry h) { if (File.Exists(h.ReportPath)) Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{h.ReportPath}\"") { UseShellExecute = true }); }
    [RelayCommand] private void ClearHistory() { _main.Store.ClearHistory(); History.Clear(); }
}
