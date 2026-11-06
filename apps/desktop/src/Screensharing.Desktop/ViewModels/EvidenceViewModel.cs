using System.Diagnostics;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Screensharing.Desktop.Services;

namespace Screensharing.Desktop.ViewModels;

/// <summary>Detailed evidence viewer for one finding.</summary>
public sealed partial class EvidenceViewModel(MainViewModel main, ReportModel report, FindingItem finding) : ObservableObject
{
    public FindingItem Finding { get; } = finding;
    public ReportModel Report { get; } = report;
    public bool Local => Report.Source == "local";

    [RelayCommand] private void Copy(string text) { if (!string.IsNullOrEmpty(text)) Clipboard.SetText(text); }

    /// <summary>Opens Explorer with the file selected. Read-only: nothing is opened or executed.</summary>
    [RelayCommand]
    private void Reveal(string path)
    {
        var p = path.Split("!/")[0];
        if (File.Exists(p)) Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{p}\"") { UseShellExecute = true });
        else if (Directory.Exists(p)) Process.Start(new ProcessStartInfo("explorer.exe", $"\"{p}\"") { UseShellExecute = true });
    }

    [RelayCommand] private void Back() => main.BackCommand.Execute(null);
}
