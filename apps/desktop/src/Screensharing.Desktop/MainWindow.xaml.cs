using System.Windows;

namespace Screensharing.Desktop;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        StateChanged += (_, _) => Root.BorderThickness = WindowState == WindowState.Maximized ? new Thickness(7) : new Thickness(1);
    }

    private void Minimize_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;
    private void Maximize_Click(object sender, RoutedEventArgs e) => WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;

    private void Close_Click(object sender, RoutedEventArgs e)
    {
        if (DataContext is ViewModels.MainViewModel { Current: ViewModels.ScanViewModel { Running: true } } &&
            MessageBox.Show("A scan is in progress. Closing will stop the investigation. Close anyway?", "screensharing.me", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes)
            return;
        Close();
    }
}
