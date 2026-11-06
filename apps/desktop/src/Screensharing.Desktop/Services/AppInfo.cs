using System.Reflection;

namespace Screensharing.Desktop.Services;

public static class AppInfo
{
    public static string Version
    {
        get
        {
            var v = Assembly.GetExecutingAssembly().GetName().Version ?? new Version(1, 0, 0);
            return $"{v.Major}.{v.Minor}.{v.Build}";
        }
    }

    /// <summary>Default server compiled in via the DefaultServerUrl MSBuild property (no secrets are embedded).</summary>
    public static string DefaultServerUrl =>
        Assembly.GetExecutingAssembly().GetCustomAttributes<AssemblyMetadataAttribute>().FirstOrDefault(a => a.Key == "DefaultServerUrl")?.Value
        ?? "https://www.screensharing.me";

    public static string DataDirectory
    {
        get
        {
            var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "screensharing.me");
            Directory.CreateDirectory(dir);
            return dir;
        }
    }
}
