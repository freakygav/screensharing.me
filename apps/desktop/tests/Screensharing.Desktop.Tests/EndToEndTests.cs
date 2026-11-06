using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Text.Json;
using Screensharing.Desktop.Services;
using Screensharing.Scanner.Engine;
using Screensharing.Scanner.Model;
using Screensharing.Scanner.Tests.Fixtures;
using Xunit.Abstractions;

namespace Screensharing.Desktop.Tests;

/// <summary>Runs only when the website/API is reachable (SSME_BASE_URL, default http://localhost:3000).</summary>
public sealed class E2EFactAttribute : FactAttribute
{
    public static readonly string BaseUrl = Environment.GetEnvironmentVariable("SSME_BASE_URL") ?? "http://localhost:3000";

    public E2EFactAttribute()
    {
        var u = new Uri(BaseUrl);
        try
        {
            using var c = new TcpClient();
            if (!c.ConnectAsync(u.Host, u.Port).Wait(1500)) Skip = $"Server {BaseUrl} not reachable";
        }
        catch (Exception) { Skip = $"Server {BaseUrl} not reachable"; }
    }
}

/// <summary>Opt-in full system scan of the machine running the tests (SSME_E2E_FULL=1).</summary>
public sealed class FullScanFactAttribute : FactAttribute
{
    public FullScanFactAttribute()
    {
        if (Environment.GetEnvironmentVariable("SSME_E2E_FULL") != "1") Skip = "Opt-in: set SSME_E2E_FULL=1 to scan this machine and upload to the local server";
        else if (new E2EFactAttribute().Skip is { } s) Skip = s;
    }
}

/// <summary>Investigator side of the workflow, using the website's HTTP API like a browser would.</summary>
internal sealed class Investigator
{
    private readonly HttpClient _http;
    public string Username { get; }
    public string Password { get; } = "e2e-password-" + Guid.NewGuid().ToString("N")[..8] + "1";

    public Investigator()
    {
        _http = new HttpClient(new HttpClientHandler { CookieContainer = new CookieContainer(), UseCookies = true }) { BaseAddress = new Uri(E2EFactAttribute.BaseUrl) };
        _http.DefaultRequestHeaders.Add("Origin", E2EFactAttribute.BaseUrl.TrimEnd('/'));
        Username = "e2e_" + Guid.NewGuid().ToString("N")[..10];
    }

    public async Task RegisterAsync()
    {
        var r = await _http.PostAsJsonAsync("/api/auth/register", new { username = Username, password = Password });
        Assert.True(r.IsSuccessStatusCode, await r.Content.ReadAsStringAsync());
    }

    public async Task<(string Id, string Pin)> CreateInvestigationAsync(string subject)
    {
        var r = await _http.PostAsJsonAsync("/api/investigations", new { subjectName = subject, serverName = "e2e.test" });
        var body = await r.Content.ReadAsStringAsync();
        Assert.True(r.IsSuccessStatusCode, body);
        using var doc = JsonDocument.Parse(body);
        return (doc.RootElement.GetProperty("id").GetString()!, doc.RootElement.GetProperty("pin").GetString()!);
    }

    public async Task<JsonDocument> SnapshotAsync(string id) => JsonDocument.Parse(await _http.GetStringAsync($"/api/investigations/{id}"));
}

/// <summary>Fails a configurable window of requests to simulate a dropped connection mid-scan.</summary>
internal sealed class FlakyHandler(int failFrom, int failCount) : DelegatingHandler(new SocketsHttpHandler())
{
    private int _n;
    public int Failed { get; private set; }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        var n = Interlocked.Increment(ref _n);
        if (n >= failFrom && n < failFrom + failCount)
        {
            Failed++;
            throw new HttpRequestException("Simulated network interruption");
        }
        return base.SendAsync(request, ct);
    }
}

public class EndToEndTests(ITestOutputHelper output)
{
    private static FixtureBuilder Fixture()
    {
        var fx = new FixtureBuilder();
        fx.AddVersion("1.21.1");
        fx.AddMod("sodium.jar", new FixtureBuilder.JarSpec { FabricId = "sodium", Classes = ["net/caffeinemc/mods/sodium/client/SodiumClientMod"] });
        fx.AddMod("meteor-client-0.5.8.jar", new FixtureBuilder.JarSpec
        {
            FabricId = "meteor-client", FabricName = "Meteor Client",
            Classes = ["meteordevelopment/meteorclient/MeteorClient", "meteordevelopment/meteorclient/systems/modules/combat/KillAura"],
        });
        fx.AddMod("helper.jar", new FixtureBuilder.JarSpec { FabricId = "helper", Classes = ["x/module/combat/AimAssist", "x/module/combat/TriggerBot", "x/module/movement/Scaffold"] });
        fx.AddFabricLog([("sodium", "0.6.0"), ("meteor-client", "0.5.8"), ("helper", "1.0"), ("removed-mod", "2.0")]);
        return fx;
    }

    private static ScanOptions Options(FixtureBuilder fx, RuleSet rules) => new()
    {
        Rules = rules, Target = fx.Target(), ModrinthLookup = false, MemoryScan = false,
    };

    [E2EFact]
    public async Task Pin_connect_scan_upload_and_report_roundtrip()
    {
        var investigator = new Investigator();
        await investigator.RegisterAsync();
        var (id, pin) = await investigator.CreateInvestigationAsync("E2EPlayer");

        var api = new ApiClient(E2EFactAttribute.BaseUrl);
        var version = await api.GetVersionAsync();
        Assert.True(version.Supported);

        var claim = await api.ClaimPinAsync(pin, elevated: false);
        api.DeviceToken = claim.DeviceToken;
        Assert.Equal("E2EPlayer", claim.Investigation.SubjectName);
        Assert.Equal(investigator.Username, claim.Investigation.RequestedBy);

        using (var s1 = await investigator.SnapshotAsync(id))
            Assert.Equal("CONNECTED", s1.RootElement.GetProperty("status").GetString());

        await api.ConsentAsync(claim.Consent.Version);
        var session = new InvestigationSession(api, claim.Investigation);
        var rules = await session.LoadRulesAsync(CancellationToken.None);
        Assert.True(rules.Rules.Count > 50, "live catalog downloaded from server");

        using var fx = Fixture();
        var progressSeen = new List<int>();
        session.Progress += p => progressSeen.Add(p.Percent);
        var result = await session.RunAsync(Options(fx, rules), CancellationToken.None);

        Assert.Null(session.UploadError);
        Assert.True(session.ManifestVerified, "server recomputed the same evidence manifest");
        Assert.Contains(result.Findings, f => f.Family == "Meteor Client" && f.Tier == EvidenceTier.ConfirmedArtifact);
        Assert.Contains(result.Findings, f => f.RuleId == Builtin.ModuleClasses);
        Assert.Contains(result.Findings, f => f.RuleId == Builtin.LoggedModMissing);

        using var snap = await investigator.SnapshotAsync(id);
        var root = snap.RootElement;
        Assert.Equal("COMPLETED", root.GetProperty("status").GetString());
        Assert.Equal(result.Findings.Count, root.GetProperty("counts").GetProperty("total").GetInt32());
        Assert.True(root.GetProperty("scan").GetProperty("manifestVerified").GetBoolean());
        Assert.Equal(100, root.GetProperty("scan").GetProperty("progress").GetInt32());
        Assert.Equal("confirmed", root.GetProperty("verdict").GetProperty("level").GetString());
        var categories = root.GetProperty("scan").GetProperty("categories").EnumerateArray().ToList();
        Assert.Equal(8, categories.Count);
        Assert.Contains(categories, c => c.GetProperty("key").GetString() == "process" && c.GetProperty("status").GetString() == "SKIPPED");
        var summary = root.GetProperty("scan").GetProperty("summary");
        Assert.Equal("Selected PvP", summary.GetProperty("instance").GetProperty("name").GetString());
        Assert.True(summary.GetProperty("inspection").GetProperty("analyzed").GetInt32() > 0);
        var meteorRow = root.GetProperty("detections").EnumerateArray().First(d => d.GetProperty("family").GetString() == "Meteor Client");
        Assert.Equal("CONFIRMED", meteorRow.GetProperty("outcome").GetString());
        Assert.Equal("mods/meteor-client-0.5.8.jar", meteorRow.GetProperty("location").GetString());
        Assert.Contains("meteor-client", meteorRow.GetProperty("signature").GetString());
        var meteor = root.GetProperty("detections").EnumerateArray().First(d => d.GetProperty("name").GetString()!.StartsWith("Meteor Client"));
        Assert.Matches("^[0-9a-f]{64}$", meteor.GetProperty("evidence")[0].GetProperty("sha256").GetString()!);

        // Staff view on the desktop: sign in as the investigator and load the server report.
        var staff = new ApiClient(E2EFactAttribute.BaseUrl);
        await staff.StaffLoginAsync(investigator.Username, investigator.Password, adminOnly: false);
        var list = await staff.StaffInvestigationsAsync();
        Assert.Contains(list, i => i.Id == id && i.Status == "COMPLETED");
        await Assert.ThrowsAsync<ApiException>(() => new ApiClient(E2EFactAttribute.BaseUrl).StaffLoginAsync(investigator.Username, investigator.Password, adminOnly: true));
        using var reportDoc = await staff.StaffReportAsync(id);
        var report = ReportModel.FromServer(reportDoc.RootElement);
        Assert.Equal(result.Findings.Count, report.Findings.Count);
        Assert.Equal(8, report.Coverage.Count);
        Assert.Equal("Selected PvP", report.InstanceName);
        Assert.Contains(report.Findings, f => f.Family == "Meteor Client" && f.Location == "mods/meteor-client-0.5.8.jar" && f.Outcome == "CONFIRMED");

        // Exports from the desktop
        var dir = Directory.CreateTempSubdirectory("ssme-export").FullName;
        ReportExporter.Pdf(report, Path.Combine(dir, "r.pdf"));
        ReportExporter.Json(report, Path.Combine(dir, "r.json"));
        ReportExporter.Csv(report, Path.Combine(dir, "r.csv"));
        Assert.Equal("%PDF-", System.Text.Encoding.ASCII.GetString(File.ReadAllBytes(Path.Combine(dir, "r.pdf"))[..5]));
        Assert.Contains("meteor-client", File.ReadAllText(Path.Combine(dir, "r.csv")));
        using (var j = JsonDocument.Parse(File.ReadAllText(Path.Combine(dir, "r.json")))) Assert.Equal(report.Findings.Count, j.RootElement.GetProperty("findings").GetArrayLength());
        var local = ReportModel.FromLocal(result, claim.Investigation, session.ManifestVerified);
        ReportExporter.Pdf(local, Path.Combine(dir, "local.pdf"));
        output.WriteLine($"Investigation {claim.Investigation.Reference}: {result.Findings.Count} findings uploaded, manifest verified; exports in {dir}");
    }

    [E2EFact]
    public async Task Upload_survives_a_network_interruption_mid_scan()
    {
        var investigator = new Investigator();
        await investigator.RegisterAsync();
        var (id, pin) = await investigator.CreateInvestigationAsync("FlakyPlayer");

        // Requests 4..10 fail (after claim, consent, rules, scan/start) — i.e. during progress/finding uploads.
        var flaky = new FlakyHandler(failFrom: 5, failCount: 6);
        var api = new ApiClient(E2EFactAttribute.BaseUrl, flaky);
        var claim = await api.ClaimPinAsync(pin, elevated: false);
        api.DeviceToken = claim.DeviceToken;
        await api.ConsentAsync(claim.Consent.Version);
        var session = new InvestigationSession(api, claim.Investigation);
        var states = new List<LinkState>();
        session.Link += (s, _) => states.Add(s);
        var rules = await session.LoadRulesAsync(CancellationToken.None);
        using var fx = Fixture();
        var result = await session.RunAsync(Options(fx, rules), CancellationToken.None);

        Assert.True(flaky.Failed >= 1, "interruption was injected");
        Assert.Contains(LinkState.Reconnecting, states);
        Assert.Null(session.UploadError);
        Assert.True(session.ManifestVerified);
        using var snap = await investigator.SnapshotAsync(id);
        Assert.Equal("COMPLETED", snap.RootElement.GetProperty("status").GetString());
        Assert.Equal(result.Findings.Count, snap.RootElement.GetProperty("counts").GetProperty("total").GetInt32());
        output.WriteLine($"{flaky.Failed} requests failed; states: {string.Join(",", states)}");
    }

    /// <summary>Scan of the Minecraft instance running on this machine, uploaded to the server (opt-in: SSME_E2E_FULL=1).</summary>
    [FullScanFact]
    public async Task Running_instance_scan_uploads_and_validates()
    {
        var investigator = new Investigator();
        await investigator.RegisterAsync();
        var (id, pin) = await investigator.CreateInvestigationAsync("LocalMachine");
        var api = new ApiClient(E2EFactAttribute.BaseUrl);
        var claim = await api.ClaimPinAsync(pin, ScanEngine.IsElevated());
        api.DeviceToken = claim.DeviceToken;
        await api.ConsentAsync(claim.Consent.Version);
        var session = new InvestigationSession(api, claim.Investigation);
        var rules = await session.LoadRulesAsync(CancellationToken.None);
        var http = new HttpClient();
        http.DefaultRequestHeaders.UserAgent.ParseAdd("screensharing.me-tests/1.0");
        var target = Screensharing.Scanner.Instance.InstanceResolver.Detect().FirstOrDefault(i => i.Resolved);
        Assert.NotNull(target); // start Minecraft before running this test
        var result = await session.RunAsync(new ScanOptions { Rules = rules, Target = target, Http = http, MemoryScanCapBytes = 1L << 30 }, CancellationToken.None);
        Assert.Empty(result.ScopeViolations);
        Assert.Null(session.UploadError);
        Assert.True(session.ManifestVerified);
        using var snap = await investigator.SnapshotAsync(id);
        Assert.Equal(result.Findings.Count, snap.RootElement.GetProperty("counts").GetProperty("total").GetInt32());
        output.WriteLine($"Instance scan {claim.Investigation.Reference} ({id}) of {target.Name} ({target.Launcher}): {result.Findings.Count} findings, {result.Mods.Count} archives, {result.Inspection["examined"]} files examined, {result.Statistics["durationSeconds"]}s");
    }
}
