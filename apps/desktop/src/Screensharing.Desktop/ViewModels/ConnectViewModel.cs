using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Screensharing.Desktop.Services;
using System.Text.Json;

namespace Screensharing.Desktop.ViewModels;

/// <summary>Login / authentication screen: verifies the server and client version, offers PIN entry or staff sign-in, resumes sessions.</summary>
public sealed partial class ConnectViewModel : ObservableObject
{
    private readonly MainViewModel _main;
    [ObservableProperty] private bool _checking = true;
    [ObservableProperty] private bool _online;
    [ObservableProperty] private string _status = "Connecting to screensharing.me…";
    [ObservableProperty] private string? _updateNotice;
    [ObservableProperty] private bool _blocked;
    [ObservableProperty] private string? _resumeReference;

    public ConnectViewModel(MainViewModel main)
    {
        _main = main;
        _ = CheckAsync();
    }

    public string Host => _main.ServerHost;
    public bool Elevated => _main.Elevated;

    [RelayCommand]
    private async Task CheckAsync()
    {
        Checking = true;
        Status = $"Connecting to {_main.ServerHost}…";
        try
        {
            var v = await _main.Api.GetVersionAsync();
            Online = true;
            Blocked = !v.Supported;
            Status = Blocked ? $"This version ({AppInfo.Version}) is no longer supported. Version {v.MinimumSupported} or newer is required." : $"Connected securely to {_main.ServerHost}";
            UpdateNotice = v.UpdateAvailable && v.Latest is not null ? $"Version {v.Latest.Version} is available." : null;
            var saved = _main.Store.LoadSession();
            if (saved is not null && DateTimeOffset.UtcNow - saved.SavedAt < TimeSpan.FromHours(12))
            {
                try { ResumeReference = JsonDocument.Parse(saved.InvestigationJson).RootElement.GetProperty("Reference").GetString(); }
                catch (Exception) { ResumeReference = null; }
                if (Environment.GetCommandLineArgs().Contains("--resume") && ResumeReference is not null) await ResumeAsync();
            }
        }
        catch (ApiException e)
        {
            Online = false;
            Status = e.Message;
        }
        finally { Checking = false; }
    }

    [RelayCommand]
    private void EnterPin() => _main.Navigate(new PinViewModel(_main));

    [RelayCommand]
    private void StaffSignIn() => _main.Navigate(new StaffLoginViewModel(_main, adminOnly: false));

    [RelayCommand]
    private async Task ResumeAsync()
    {
        var saved = _main.Store.LoadSession();
        if (saved is null) { ResumeReference = null; return; }
        _main.Api.DeviceToken = saved.DeviceToken;
        try
        {
            var s = await _main.Api.GetSessionAsync();
            if (s.Investigation.Status is "COMPLETED" or "CANCELLED" or "FAILED" or "EXPIRED")
            {
                _main.Store.ClearSession();
                ResumeReference = null;
                Status = $"Investigation {s.Investigation.Reference} is {s.Investigation.Status.ToLowerInvariant()}.";
                return;
            }
            var inv = new InvestigationInfo(s.Investigation.Id, s.Investigation.Reference, s.Investigation.SubjectName, s.Investigation.ServerName, s.Investigation.RequestedBy, s.Investigation.CreatedAt);
            var consent = JsonDocument.Parse(saved.InvestigationJson).RootElement;
            var consentInfo = new ConsentInfo(consent.GetProperty("ConsentVersion").GetString()!, consent.GetProperty("ConsentText").GetString()!);
            _main.Navigate(new InvestigationViewModel(_main, inv, consentInfo, alreadyConsented: s.Investigation.ConsentedAt is not null));
        }
        catch (ApiException e)
        {
            _main.Store.ClearSession();
            _main.Api.DeviceToken = null;
            ResumeReference = null;
            Status = $"The previous session cannot be resumed: {e.Message}";
        }
    }
}
