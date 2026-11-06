using System.Reflection;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using Screensharing.Desktop.Services;
using Screensharing.Desktop.ViewModels;
using Screensharing.Scanner.Engine;
using Screensharing.Scanner.Model;
using Screensharing.Scanner.Tests.Fixtures;

namespace Screensharing.Desktop.Tests;

/// <summary>
/// Renders every desktop screen offscreen to PNG (documentation/screenshots/desktop) for visual review.
/// Results/evidence screens use a real scan of a synthetic fixture. Opt-in: SSME_UI_SNAPSHOTS=1.
/// Also asserts that every screen's XAML loads and lays out without binding/template exceptions.
/// </summary>
public class UiSnapshotTests
{
    private static readonly string OutDir = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "..", "..", "documentation", "screenshots", "desktop"));

    [Fact]
    public void Render_all_screens()
    {
        Exception? failure = null;
        var t = new Thread(() =>
        {
            try { RenderAll(); }
            catch (Exception e) { failure = e; }
        });
        t.SetApartmentState(ApartmentState.STA);
        t.Start();
        t.Join();
        if (failure is not null) throw new Exception("UI rendering failed", failure);
    }

    private static void Pump(int ms = 150)
    {
        var until = DateTime.UtcNow.AddMilliseconds(ms);
        while (DateTime.UtcNow < until)
        {
            Dispatcher.CurrentDispatcher.Invoke(DispatcherPriority.Background, new Action(() => { }));
            Thread.Sleep(15);
        }
    }

    private static void RenderAll()
    {
        var save = Environment.GetEnvironmentVariable("SSME_UI_SNAPSHOTS") == "1";
        var app = Application.Current as App ?? new App();
        app.InitializeComponent();
        app.ShutdownMode = ShutdownMode.OnExplicitShutdown;

        var win = new MainWindow { WindowStartupLocation = WindowStartupLocation.Manual, Left = -20000, Top = -20000, Width = 1180, Height = 780, ShowActivated = false, ShowInTaskbar = false };
        win.Show();
        var main = (MainViewModel)win.DataContext;
        Pump(1500); // connect screen performs its server check

        // Real data for results/evidence/scan screens.
        using var fx = new FixtureBuilder();
        fx.AddVersion("1.21.1");
        fx.AddMod("sodium-fabric-0.6.0.jar", new FixtureBuilder.JarSpec { FabricId = "sodium", Classes = ["net/caffeinemc/mods/sodium/client/SodiumClientMod"] });
        fx.AddMod("meteor-client-0.5.8.jar", new FixtureBuilder.JarSpec { FabricId = "meteor-client", FabricName = "Meteor Client", Classes = ["meteordevelopment/meteorclient/MeteorClient", "meteordevelopment/meteorclient/systems/modules/combat/KillAura"] });
        fx.AddMod("qol-tools.jar", new FixtureBuilder.JarSpec { FabricId = "qol-tools", Classes = ["x/client/module/combat/AimAssist", "x/client/module/combat/TriggerBot", "x/client/module/movement/Scaffold", "x/client/module/movement/Speed"] });
        fx.AddFabricLog([("sodium", "0.6.0"), ("meteor-client", "0.5.8"), ("qol-tools", "1.0"), ("old-helper", "2.1")]);
        Directory.CreateDirectory(Path.Combine(fx.GameDir, "meteor-client"));
        var engine = new ScanEngine(new ScanOptions { Rules = RuleSet.LoadEmbedded(), Target = fx.Target(), ModrinthLookup = false, MemoryScan = false });
        ScanProgress? mid = null;
        engine.Progress += p => { if (p.Percent is > 35 and < 70 && mid is null) mid = p; };
        var result = engine.RunAsync().GetAwaiter().GetResult();

        var inv = new InvestigationInfo("cl_demo", "INV-7KQ2-M9XD", "Notch_", "play.example.net", "ModeratorAlex", DateTimeOffset.UtcNow.AddMinutes(-4));
        var consent = new ConsentInfo("2026-11b", "The investigator has asked you to run a forensic scan of the Minecraft instance you are playing. Before the scan starts you choose which running instance is examined. With your consent, screensharing.me reads only that instance: its folder (mods, configuration, resource and shader packs, logs and crash reports), the game files it loads, and the running game process (its launch arguments, loaded modules and a bounded read of its memory). Nothing outside the instance is read. No file is changed.");
        var report = ReportModel.FromLocal(result, inv, manifestVerified: true);

        var target = fx.Target();
        var scan = new ScanViewModel(main, inv, target);
        foreach (var (key, name) in engine.Categories) scan.Categories.Add(new CategoryRow { Key = key, Name = name });
        typeof(ScanViewModel).GetMethod("Apply", BindingFlags.NonPublic | BindingFlags.Instance)!.Invoke(scan, [mid ?? new ScanProgress(50, "Examining installed modifications…", [], 50, 100)]);
        scan.Findings = result.Findings.Count(f => f.DetectedAt <= DateTimeOffset.UtcNow);
        scan.Elapsed = "0:07";

        var results = new ResultsViewModel(main, report);
        var investigation = new InvestigationViewModel(main, inv, consent, alreadyConsented: false, detectNow: false);
        investigation.Instances.Add(new InstanceOption { Instance = target });
        investigation.Instances.Add(new InstanceOption { Instance = new Screensharing.Scanner.Instance.GameInstance
        {
            ProcessId = 18232, ProcessName = "javaw.exe", Launcher = "Unknown", Name = "javaw.exe (PID 18232)", GameDirectory = "", InstanceRoot = "", GameDirectorySource = "unknown",
            Resolved = false, Problem = "The game was started without a --gameDir argument and its working directory could not be read: the game process could not be opened for reading (Windows error 5). If the game runs as administrator, run the scanner as administrator too.",
        } });
        investigation.Selected = investigation.Instances[0];

        var pin = new PinViewModel(main) { Pin = "483921" };
        var screens = new (string Name, CommunityToolkit.Mvvm.ComponentModel.ObservableObject Vm)[]
        {
            ("01-connect", main.Current!),
            ("02-pin-entry", pin),
            ("03-instance-and-consent", investigation),
            ("04-scan-progress", scan),
            ("05-detection-results", results),
            ("06-evidence-viewer", new EvidenceViewModel(main, report, report.Findings[0])),
            ("07-admin-login", new StaffLoginViewModel(main, adminOnly: true)),
            ("08-settings", new SettingsViewModel(main)),
            ("09-about", new AboutViewModel(main)),
        };

        if (save) Directory.CreateDirectory(OutDir);
        foreach (var (name, vm) in screens)
        {
            main.Navigate(vm);
            Pump(400);
            var root = (FrameworkElement)win.Content;
            root.UpdateLayout();
            Assert.True(root.ActualWidth > 0 && root.ActualHeight > 0, $"{name} laid out");
            if (!save) continue;
            var dpi = VisualTreeHelper.GetDpi(root);
            var bmp = new RenderTargetBitmap((int)(root.ActualWidth * dpi.DpiScaleX), (int)(root.ActualHeight * dpi.DpiScaleY), dpi.PixelsPerInchX, dpi.PixelsPerInchY, PixelFormats.Pbgra32);
            bmp.Render(root);
            var enc = new PngBitmapEncoder();
            enc.Frames.Add(BitmapFrame.Create(bmp));
            using var fs = File.Create(Path.Combine(OutDir, name + ".png"));
            enc.Save(fs);
        }
        win.Close();
    }
}
