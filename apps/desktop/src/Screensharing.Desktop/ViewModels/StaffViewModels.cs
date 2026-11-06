using System.Collections.ObjectModel;
using System.Windows.Controls;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Screensharing.Desktop.Services;

namespace Screensharing.Desktop.ViewModels;

/// <summary>Staff / administrator sign-in on the desktop (backend-authenticated; no credentials stored locally).</summary>
public sealed partial class StaffLoginViewModel(MainViewModel main, bool adminOnly) : ObservableObject
{
    public bool AdminOnly { get; } = adminOnly;
    public string Title => AdminOnly ? "Administrator sign in" : "Staff sign in";
    public string Subtitle => AdminOnly ? "Restricted. Every sign-in attempt is recorded in the audit log." : "Review the investigations you created on screensharing.me.";
    [ObservableProperty] private string _identifier = "";
    [ObservableProperty] private string? _error;
    [ObservableProperty] private bool _busy;

    [RelayCommand]
    private async Task SignInAsync(PasswordBox box)
    {
        Busy = true;
        Error = null;
        try
        {
            var r = await main.Api.StaffLoginAsync(Identifier.Trim(), box.Password, AdminOnly);
            box.Clear();
            main.Navigate(new StaffDashboardViewModel(main, r.User), clearHistory: true);
        }
        catch (ApiException e) { Error = e.Message; }
        finally { Busy = false; }
    }
}

public sealed partial class StaffDashboardViewModel : ObservableObject
{
    private readonly MainViewModel _main;
    public StaffUser User { get; }
    public bool IsAdmin => User.Role == "ADMIN";
    public ObservableCollection<StaffInvestigation> Investigations { get; } = [];
    [ObservableProperty] private string? _error;
    [ObservableProperty] private bool _busy;
    [ObservableProperty] private string _filter = "";
    private List<StaffInvestigation> _all = [];

    public int Total => _all.Count;
    public int Active => _all.Count(i => i.Status is "WAITING" or "CONNECTED" or "SCANNING");
    public int Completed => _all.Count(i => i.Status == "COMPLETED");
    public int FindingsTotal => _all.Sum(i => i.Findings);

    public StaffDashboardViewModel(MainViewModel main, StaffUser user)
    {
        _main = main;
        User = user;
        _ = RefreshAsync();
    }

    partial void OnFilterChanged(string value) => ApplyFilter();

    private void ApplyFilter()
    {
        Investigations.Clear();
        foreach (var i in _all.Where(i => Filter.Length == 0 || $"{i.Reference} {i.SubjectName} {i.Owner} {i.ServerName}".Contains(Filter, StringComparison.OrdinalIgnoreCase)))
            Investigations.Add(i);
    }

    [RelayCommand]
    private async Task RefreshAsync()
    {
        Busy = true;
        Error = null;
        try
        {
            _all = await _main.Api.StaffInvestigationsAsync();
            ApplyFilter();
            OnPropertyChanged(nameof(Total)); OnPropertyChanged(nameof(Active)); OnPropertyChanged(nameof(Completed)); OnPropertyChanged(nameof(FindingsTotal));
        }
        catch (ApiException e) { Error = e.Message; }
        finally { Busy = false; }
    }

    [RelayCommand]
    private async Task OpenAsync(StaffInvestigation inv)
    {
        try
        {
            using var doc = await _main.Api.StaffReportAsync(inv.Id);
            _main.Navigate(new ResultsViewModel(_main, ReportModel.FromServer(doc.RootElement)));
        }
        catch (ApiException e) { Error = e.Message; }
    }

    [RelayCommand]
    private async Task SignOutAsync()
    {
        await _main.Api.StaffLogoutAsync();
        _main.Navigate(new ConnectViewModel(_main), clearHistory: true);
    }
}
