using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Screensharing.Desktop.Services;

namespace Screensharing.Desktop.ViewModels;

public sealed partial class PinViewModel : ObservableObject
{
    private readonly MainViewModel _main;
    [ObservableProperty][NotifyCanExecuteChangedFor(nameof(StartCommand))] private string _pin = "";
    [ObservableProperty] private string? _error;
    [ObservableProperty][NotifyCanExecuteChangedFor(nameof(StartCommand))] private bool _busy;

    public PinViewModel(MainViewModel main) => _main = main;

    private bool CanStart => !Busy && Pin.Count(char.IsDigit) == 6;

    [RelayCommand(CanExecute = nameof(CanStart))]
    private async Task StartAsync()
    {
        Busy = true;
        Error = null;
        try
        {
            var r = await _main.Api.ClaimPinAsync(new string(Pin.Where(char.IsDigit).ToArray()), _main.Elevated);
            _main.Api.DeviceToken = r.DeviceToken;
            _main.Store.SaveSession(r.DeviceToken, new
            {
                r.Investigation.Id, r.Investigation.Reference, r.Investigation.SubjectName,
                ConsentVersion = r.Consent.Version, ConsentText = r.Consent.Text,
            });
            _main.Navigate(new InvestigationViewModel(_main, r.Investigation, r.Consent, alreadyConsented: false), clearHistory: true);
        }
        catch (ApiException e)
        {
            Error = e.Code == "rate_limited" ? "Too many attempts. Wait a few minutes and try again." : e.Message;
        }
        finally { Busy = false; }
    }
}
