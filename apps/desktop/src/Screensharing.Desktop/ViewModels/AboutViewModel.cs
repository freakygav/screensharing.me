using CommunityToolkit.Mvvm.ComponentModel;
using Screensharing.Desktop.Services;
using Screensharing.Scanner.Engine;
using Screensharing.Scanner.Model;

namespace Screensharing.Desktop.ViewModels;

public sealed class AboutViewModel(MainViewModel main) : ObservableObject
{
    public string AppVersion => AppInfo.Version;
    public string EngineVersion => ScanEngine.EngineVersion;
    public string EmbeddedRuleset { get; } = RuleSet.LoadEmbedded().Version;
    public int EmbeddedRuleCount { get; } = RuleSet.LoadEmbedded().Rules.Count;
    public string Server => main.ServerUrl;
    public string Runtime => $".NET {Environment.Version} · {ScanEngine.OsDescription()}";
    public string Elevation => main.Elevated ? "Running as administrator" : "Running without administrator rights";
}
