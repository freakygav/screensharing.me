using System.Diagnostics;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Screensharing.Desktop.Services;
using Screensharing.Scanner.Engine;

namespace Screensharing.Desktop.ViewModels;

/// <summary>Shell: owns navigation, the API client and app-wide state.</summary>
public sealed partial class MainViewModel : ObservableObject
{
    public LocalStore Store { get; } = new();
    public ApiClient Api { get; private set; }
    public bool Elevated { get; } = ScanEngine.IsElevated();
    public string Version => AppInfo.Version;

    [ObservableProperty] private ObservableObject? _current;
    [ObservableProperty] private string _serverHost = "";
    [ObservableProperty] private bool _canGoBack;
    private readonly Stack<ObservableObject> _history = new();

    public MainViewModel()
    {
        Api = CreateApi();
        ServerHost = Api.BaseUri.Authority;
        Navigate(new ConnectViewModel(this), clearHistory: true);
    }

    public string ServerUrl
    {
        get => Store.Get("serverUrl") ?? AppInfo.DefaultServerUrl;
        set
        {
            ApiClient.ValidateBaseUrl(value);
            Store.Set("serverUrl", value.Trim().TrimEnd('/'));
            Api = CreateApi();
            ServerHost = Api.BaseUri.Authority;
        }
    }

    private ApiClient CreateApi()
    {
        try { return new ApiClient(Store.Get("serverUrl") ?? AppInfo.DefaultServerUrl); }
        catch (ArgumentException) { return new ApiClient(AppInfo.DefaultServerUrl); }
    }

    public void Navigate(ObservableObject vm, bool clearHistory = false)
    {
        if (clearHistory) _history.Clear();
        else if (Current is not null && Current is not ScanViewModel) _history.Push(Current);
        Current = vm;
        CanGoBack = _history.Count > 0 && vm is not ScanViewModel;
    }

    [RelayCommand]
    private void Back()
    {
        if (_history.Count == 0) return;
        Current = _history.Pop();
        CanGoBack = _history.Count > 0;
    }

    [RelayCommand] private void OpenSettings() { if (Current is not SettingsViewModel && Current is not ScanViewModel) Navigate(new SettingsViewModel(this)); }
    [RelayCommand] private void OpenAbout() { if (Current is not AboutViewModel && Current is not ScanViewModel) Navigate(new AboutViewModel(this)); }
    [RelayCommand] private void OpenAdmin() { if (Current is not ScanViewModel) Navigate(new StaffLoginViewModel(this, adminOnly: true)); }
    [RelayCommand] private void Home() { if (Current is not ScanViewModel) Navigate(new ConnectViewModel(this), clearHistory: true); }

    /// <summary>Restarts the app elevated. The investigation token is kept (DPAPI-encrypted) so the session resumes.</summary>
    public static bool RestartElevated()
    {
        try
        {
            var exe = Environment.ProcessPath!;
            Process.Start(new ProcessStartInfo(exe, "--resume") { UseShellExecute = true, Verb = "runas" });
            Application.Current.Shutdown();
            return true;
        }
        catch (System.ComponentModel.Win32Exception) { return false; } // user declined the UAC prompt
    }
}
