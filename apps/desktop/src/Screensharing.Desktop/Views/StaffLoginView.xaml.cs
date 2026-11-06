using System.Windows.Controls;
using System.Windows.Input;

namespace Screensharing.Desktop.Views;

public partial class StaffLoginView : UserControl
{
    public StaffLoginView()
    {
        InitializeComponent();
        Loaded += (_, _) => Id.Focus();
    }

    private void Pw_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter && DataContext is ViewModels.StaffLoginViewModel vm) vm.SignInCommand.Execute(Pw);
    }
}
