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
        ["CRITICAL"] = Hex("#E5484D"), ["confirmed"] = Hex("#E5484D"), ["CONFIRMED"] = Hex("#E5484D"), ["FAILED"] = Hex("#E5484D"), ["Disconnected"] = Hex("#E5484D"), ["Mismatch"] = Hex("#E5484D"),
        ["HIGH"] = Hex("#EF7A45"), ["strong"] = Hex("#EF7A45"), ["HIGH_CONFIDENCE"] = Hex("#EF7A45"),
        ["MEDIUM"] = Hex("#D9A53A"), ["suspicious"] = Hex("#D9A53A"), ["review"] = Hex("#D9A53A"), ["LOW_CONFIDENCE"] = Hex("#D9A53A"), ["Reconnecting"] = Hex("#D9A53A"), ["SKIPPED"] = Hex("#D9A53A"), ["WAITING"] = Hex("#D9A53A"),
        ["LOW"] = Hex("#7D8FB0"), ["CONNECTED"] = Hex("#7D8FB0"), ["UNABLE_TO_INSPECT"] = Hex("#B6B8BE"),
        ["COMPLETED"] = Hex("#3FA878"), ["clear"] = Hex("#3FA878"), ["Connected"] = Hex("#3FA878"), ["Verified"] = Hex("#3FA878"),
        ["RUNNING"] = Hex("#4C74E8"), ["SCANNING"] = Hex("#4C74E8"),
        ["CONFIRMED_ARTIFACT"] = Hex("#8FA9F5"), ["STRONG_INDICATOR"] = Hex("#8FA9F5"),
    };
    public object Convert(object? v, Type t, object? p, CultureInfo c)
    {
        var color = v is not null && Map.TryGetValue(v.ToString()!, out var col) ? col : Hex("#8C8F97");
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
