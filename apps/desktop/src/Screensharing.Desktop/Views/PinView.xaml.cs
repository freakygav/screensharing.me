using System.Windows;
using System.Windows.Controls;

namespace Screensharing.Desktop.Views;

public partial class PinView : UserControl
{
    public PinView() => InitializeComponent();

    private void Pin_Submit(object sender, RoutedEventArgs e)
    {
        if (DataContext is ViewModels.PinViewModel vm && vm.StartCommand.CanExecute(null)) vm.StartCommand.Execute(null);
    }
}
