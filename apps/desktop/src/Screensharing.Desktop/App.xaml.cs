using System.Windows;
using System.Windows.Threading;

namespace Screensharing.Desktop;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        DispatcherUnhandledException += OnUnhandled;
        base.OnStartup(e);
    }

    private static void OnUnhandled(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        var log = Path.Combine(Services.AppInfo.DataDirectory, "error.log");
        File.AppendAllText(log, $"[{DateTime.UtcNow:u}] {e.Exception}\n\n");
        MessageBox.Show($"An unexpected error occurred:\n\n{e.Exception.Message}\n\nDetails were written to {log}.", "screensharing.me", MessageBoxButton.OK, MessageBoxImage.Error);
        e.Handled = true;
    }
}
