using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace Screensharing.Desktop.Controls;

/// <summary>Six-digit PIN entry with auto-advance, backspace navigation and paste support ("483-921").</summary>
public partial class PinBox : UserControl
{
    public static readonly DependencyProperty PinProperty = DependencyProperty.Register(nameof(Pin), typeof(string), typeof(PinBox),
        new FrameworkPropertyMetadata("", FrameworkPropertyMetadataOptions.BindsTwoWayByDefault));

    public static readonly RoutedEvent SubmitEvent = EventManager.RegisterRoutedEvent(nameof(Submit), RoutingStrategy.Bubble, typeof(RoutedEventHandler), typeof(PinBox));

    public string Pin { get => (string)GetValue(PinProperty); set => SetValue(PinProperty, value); }
    public event RoutedEventHandler Submit { add => AddHandler(SubmitEvent, value); remove => RemoveHandler(SubmitEvent, value); }

    private readonly TextBox[] _boxes;

    public PinBox()
    {
        InitializeComponent();
        _boxes = [D0, D1, D2, D3, D4, D5];
        for (var i = 0; i < _boxes.Length; i++)
        {
            var idx = i;
            var b = _boxes[i];
            b.PreviewTextInput += (_, e) => { e.Handled = !e.Text.All(char.IsDigit); };
            b.TextChanged += (_, _) =>
            {
                Pin = string.Concat(_boxes.Select(x => x.Text));
                if (b.Text.Length == 1 && idx < 5) _boxes[idx + 1].Focus();
            };
            b.PreviewKeyDown += (_, e) =>
            {
                if (e.Key == Key.Back && b.Text.Length == 0 && idx > 0) { _boxes[idx - 1].Clear(); _boxes[idx - 1].Focus(); e.Handled = true; }
                else if (e.Key == Key.Left && idx > 0) { _boxes[idx - 1].Focus(); e.Handled = true; }
                else if (e.Key == Key.Right && idx < 5) { _boxes[idx + 1].Focus(); e.Handled = true; }
                else if (e.Key == Key.Enter) RaiseEvent(new RoutedEventArgs(SubmitEvent));
            };
            b.GotKeyboardFocus += (_, _) => b.SelectAll();
            DataObject.AddPastingHandler(b, OnPaste);
        }
        Loaded += (_, _) => D0.Focus();
    }

    private void OnPaste(object sender, DataObjectPastingEventArgs e)
    {
        e.CancelCommand();
        if (e.DataObject.GetData(typeof(string)) is not string text) return;
        var digits = text.Where(char.IsDigit).Take(6).ToArray();
        for (var i = 0; i < _boxes.Length; i++) _boxes[i].Text = i < digits.Length ? digits[i].ToString() : "";
        _boxes[Math.Min(digits.Length, 5)].Focus();
    }
}
