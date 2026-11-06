using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;

namespace Screensharing.Desktop;

public sealed class BoolToVis : IValueConverter
{
    public bool Invert { get; set; }
    public object Convert(object? v, Type t, object? p, CultureInfo c) => (v is true) ^ Invert ? Visibility.Visible : Visibility.Collapsed;
    public object ConvertBack(object? v, Type t, object? p, CultureInfo c) => throw new NotSupportedException();
}

public sealed class NullToVis : IValueConverter
{
    public bool Invert { get; set; }
    public object Convert(object? v, Type t, object? p, CultureInfo c) => (v is null || v is string { Length: 0 }) ^ Invert ? Visibility.Collapsed : Visibility.Visible;
    public object ConvertBack(object? v, Type t, object? p, CultureInfo c) => throw new NotSupportedException();
}

/// <summary>Visible when the bound value's string form equals the parameter (supports "A|B" alternatives).</summary>
public sealed class EqualsToVis : IValueConverter
{
    public bool Invert { get; set; }
    public object Convert(object? v, Type t, object? p, CultureInfo c)
    {
        var match = p is string s && s.Split('|').Contains(v?.ToString());
        return match ^ Invert ? Visibility.Visible : Visibility.Collapsed;
    }
    public object ConvertBack(object? v, Type t, object? p, CultureInfo c) => throw new NotSupportedException();
}

public sealed class ZeroToVis : IValueConverter
{
    public object Convert(object? v, Type t, object? p, CultureInfo c) => v is int i && i == 0 ? Visibility.Collapsed : Visibility.Visible;
    public object ConvertBack(object? v, Type t, object? p, CultureInfo c) => throw new NotSupportedException();
}

/// <summary>Maps severity / status / verdict keywords to theme colours. Parameter "soft" returns a translucent fill.</summary>
public sealed class ToneBrush : IValueConverter
{
    private static Color Hex(string h) => (Color)ColorConverter.ConvertFromString(h);
    private static readonly Dictionary<string, Color> Map = new(StringComparer.OrdinalIgnoreCase)
    {
        ["CRITICAL"] = Hex("#FF4D6A"), ["confirmed"] = Hex("#FF4D6A"), ["FAILED"] = Hex("#FF4D6A"), ["Disconnected"] = Hex("#FF4D6A"), ["Mismatch"] = Hex("#FF4D6A"),
        ["HIGH"] = Hex("#FF8A4C"), ["strong"] = Hex("#FF8A4C"),
        ["MEDIUM"] = Hex("#F5C451"), ["suspicious"] = Hex("#F5C451"), ["Reconnecting"] = Hex("#F5C451"), ["SKIPPED"] = Hex("#F5C451"), ["WAITING"] = Hex("#F5C451"),
        ["LOW"] = Hex("#4DB8FF"), ["CONNECTED"] = Hex("#4DB8FF"),
        ["COMPLETED"] = Hex("#3DDC97"), ["clear"] = Hex("#3DDC97"), ["Connected"] = Hex("#3DDC97"), ["Verified"] = Hex("#3DDC97"),
        ["RUNNING"] = Hex("#8A6DFF"), ["SCANNING"] = Hex("#8A6DFF"),
        ["CONFIRMED_ARTIFACT"] = Hex("#A48BFF"), ["STRONG_INDICATOR"] = Hex("#A48BFF"),
    };
    public object Convert(object? v, Type t, object? p, CultureInfo c)
    {
        var color = v is not null && Map.TryGetValue(v.ToString()!, out var col) ? col : Hex("#8B93A8");
        if (p is "soft") color.A = 0x22;
        else if (p is "border") color.A = 0x66;
        var b = new SolidColorBrush(color);
        b.Freeze();
        return b;
    }
    public object ConvertBack(object? v, Type t, object? p, CultureInfo c) => throw new NotSupportedException();
}

public sealed class StatusGlyph : IValueConverter
{
    public object Convert(object? v, Type t, object? p, CultureInfo c) => v?.ToString() switch
    {
        "COMPLETED" => "", "FAILED" => "", "SKIPPED" => "", "RUNNING" => "", _ => "",
    };
    public object ConvertBack(object? v, Type t, object? p, CultureInfo c) => throw new NotSupportedException();
}

public sealed class LocalTime : IValueConverter
{
    public object Convert(object? v, Type t, object? p, CultureInfo c) => v switch
    {
        DateTimeOffset d when d != DateTimeOffset.MinValue => d.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss"),
        _ => "—",
    };
    public object ConvertBack(object? v, Type t, object? p, CultureInfo c) => throw new NotSupportedException();
}

public sealed class Bytes : IValueConverter
{
    public object Convert(object? v, Type t, object? p, CultureInfo c)
    {
        if (v is not long n) return "—";
        string[] u = ["B", "KB", "MB", "GB"];
        double d = n; var i = 0;
        while (d >= 1024 && i < u.Length - 1) { d /= 1024; i++; }
        return $"{d:0.#} {u[i]} ({n:N0} bytes)";
    }
    public object ConvertBack(object? v, Type t, object? p, CultureInfo c) => throw new NotSupportedException();
}

public sealed class InverseBool : IValueConverter
{
    public static readonly InverseBool Instance = new();
    public object Convert(object? v, Type t, object? p, CultureInfo c) => v is not true;
    public object ConvertBack(object? v, Type t, object? p, CultureInfo c) => v is not true;
}
