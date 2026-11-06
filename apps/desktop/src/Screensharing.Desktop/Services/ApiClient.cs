using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Screensharing.Desktop.Services;

public sealed class ApiException(HttpStatusCode status, string code, string message) : Exception(message)
{
    public HttpStatusCode Status { get; } = status;
    public string Code { get; } = code;
    public bool IsNetwork => Status == 0;
}

public sealed record InvestigationInfo(string Id, string Reference, string SubjectName, string? ServerName, string RequestedBy, DateTimeOffset CreatedAt);
public sealed record ConsentInfo(string Version, string Text);
public sealed record ClaimResult(string DeviceToken, DateTimeOffset TokenExpiresAt, InvestigationInfo Investigation, string RulesetVersion, ConsentInfo Consent);
public sealed record VersionInfo(VersionLatest? Latest, string? MinimumSupported, bool UpdateAvailable, bool Supported);
public sealed record VersionLatest(string Version, string? DownloadUrl, string? Sha256, string? Notes);
public sealed record SessionScan(string Id, string Status, int Progress, int FindingsReceived);
public sealed record SessionInvestigation(string Id, string Reference, string SubjectName, string? ServerName, string RequestedBy, DateTimeOffset CreatedAt, string Status, DateTimeOffset? ConsentedAt);
public sealed record SessionInfo(DateTimeOffset TokenExpiresAt, SessionInvestigation Investigation, SessionScan? Scan);
public sealed record StaffUser(string Id, string Username, string DisplayName, string? Email, string Role);
public sealed record StaffLogin(string Token, DateTimeOffset ExpiresAt, StaffUser User);
public sealed record StaffInvestigation(string Id, string Reference, string SubjectName, string? ServerName, string Status, string Owner, DateTimeOffset CreatedAt, DateTimeOffset? CompletedAt, int Progress, int Findings);
public sealed record CompleteResult(bool Ok, bool ManifestVerified, string ServerManifestSha256);

/// <summary>
/// HTTP client for the screensharing.me backend. HTTPS is mandatory except for loopback development servers.
/// Only short-lived, investigation-scoped (or 8-hour staff) bearer tokens are used — no permanent secrets exist in the executable.
/// </summary>
public sealed class ApiClient
{
    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
        Converters = { new UtcIsoConverter(), new NullableUtcIsoConverter() },
    };

    private readonly HttpClient _http;
    public Uri BaseUri { get; }
    public string? DeviceToken { get; set; }
    public string? StaffToken { get; set; }

    /// <param name="handler">Optional transport (tests inject a faulty handler to exercise reconnect handling).</param>
    public ApiClient(string baseUrl, HttpMessageHandler? handler = null)
    {
        BaseUri = ValidateBaseUrl(baseUrl);
        _http = new HttpClient(handler ?? new SocketsHttpHandler { PooledConnectionLifetime = TimeSpan.FromMinutes(5), ConnectTimeout = TimeSpan.FromSeconds(10) })
        {
            BaseAddress = BaseUri,
            Timeout = TimeSpan.FromSeconds(60),
        };
        _http.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("screensharing.me", AppInfo.Version));
    }

    public static Uri ValidateBaseUrl(string url)
    {
        if (!Uri.TryCreate(url.Trim().TrimEnd('/') + "/", UriKind.Absolute, out var u)) throw new ArgumentException("The server address is not a valid URL.");
        var loopback = u.IsLoopback || u.Host.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase);
        if (u.Scheme != Uri.UriSchemeHttps && !(u.Scheme == Uri.UriSchemeHttp && loopback))
            throw new ArgumentException("The server must use HTTPS (plain HTTP is only allowed for a local development server).");
        return u;
    }

    private async Task<T> Send<T>(HttpMethod method, string path, object? body, string? bearer, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(method, path.TrimStart('/'));
        if (bearer is not null) req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        if (body is not null) req.Content = JsonContent.Create(body, body.GetType(), options: Json);
        HttpResponseMessage res;
        try { res = await _http.SendAsync(req, ct).ConfigureAwait(false); }
        catch (HttpRequestException e) { throw new ApiException(0, "network", $"Cannot reach {BaseUri.Host}: {e.Message}"); }
        catch (TaskCanceledException) when (!ct.IsCancellationRequested) { throw new ApiException(0, "timeout", $"{BaseUri.Host} did not respond in time."); }
        using (res)
        {
            var text = await res.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            if (!res.IsSuccessStatusCode)
            {
                string code = "error", message = $"Server returned {(int)res.StatusCode}.";
                try
                {
                    using var doc = JsonDocument.Parse(text);
                    if (doc.RootElement.TryGetProperty("error", out var e))
                    {
                        code = e.TryGetProperty("code", out var c) ? c.GetString() ?? code : code;
                        message = e.TryGetProperty("message", out var m) ? m.GetString() ?? message : message;
                        if (e.TryGetProperty("issues", out var issues) && issues.GetArrayLength() > 0)
                            message += " " + string.Join("; ", issues.EnumerateArray().Take(3).Select(i => $"{i.GetProperty("path").GetString()}: {i.GetProperty("message").GetString()}"));
                    }
                }
                catch (JsonException) { }
                throw new ApiException(res.StatusCode, code, message);
            }
            if (typeof(T) == typeof(JsonDocument)) return (T)(object)JsonDocument.Parse(text);
            return JsonSerializer.Deserialize<T>(text, Json)!;
        }
    }

    // ------------------------------------------------------------- public
    public Task<VersionInfo> GetVersionAsync(CancellationToken ct = default) =>
        Send<VersionInfo>(HttpMethod.Get, $"api/desktop/version?current={Uri.EscapeDataString(AppInfo.Version)}", null, null, ct);

    public Task<ClaimResult> ClaimPinAsync(string pin, bool elevated, CancellationToken ct = default) =>
        Send<ClaimResult>(HttpMethod.Post, "api/desktop/pin/claim", new { pin, appVersion = AppInfo.Version, osVersion = Scanner.Engine.ScanEngine.OsDescription(), elevated }, null, ct);

    // ------------------------------------------------------------- device
    private string Dev => DeviceToken ?? throw new ApiException(HttpStatusCode.Unauthorized, "no_token", "Not connected to an investigation.");

    public Task<SessionInfo> GetSessionAsync(CancellationToken ct = default) => Send<SessionInfo>(HttpMethod.Get, "api/desktop/session", null, Dev, ct);
    public Task<JsonDocument> GetRulesJsonAsync(CancellationToken ct = default) => Send<JsonDocument>(HttpMethod.Get, "api/desktop/rules", null, Dev, ct);
    public Task<JsonDocument> ConsentAsync(string version, CancellationToken ct = default) => Send<JsonDocument>(HttpMethod.Post, "api/desktop/consent", new { accepted = true, consentVersion = version }, Dev, ct);
    public Task<JsonDocument> HeartbeatAsync(CancellationToken ct = default) => Send<JsonDocument>(HttpMethod.Post, "api/desktop/heartbeat", new { }, Dev, ct);
    public Task<JsonDocument> StartScanAsync(object body, CancellationToken ct = default) => Send<JsonDocument>(HttpMethod.Post, "api/desktop/scan/start", body, Dev, ct);
    public Task<JsonDocument> ProgressAsync(object body, CancellationToken ct = default) => Send<JsonDocument>(HttpMethod.Post, "api/desktop/scan/progress", body, Dev, ct);
    public Task<JsonDocument> FindingsAsync(object body, CancellationToken ct = default) => Send<JsonDocument>(HttpMethod.Post, "api/desktop/scan/findings", body, Dev, ct);
    public Task<CompleteResult> CompleteAsync(object body, CancellationToken ct = default) => Send<CompleteResult>(HttpMethod.Post, "api/desktop/scan/complete", body, Dev, ct);
    public Task<JsonDocument> FailAsync(string reason, CancellationToken ct = default) => Send<JsonDocument>(HttpMethod.Post, "api/desktop/scan/fail", new { reason }, Dev, ct);

    // -------------------------------------------------------------- staff
    public async Task<StaffLogin> StaffLoginAsync(string identifier, string password, bool adminOnly, CancellationToken ct = default)
    {
        var r = await Send<StaffLogin>(HttpMethod.Post, "api/desktop/auth/login", new { identifier, password, appVersion = AppInfo.Version, adminOnly }, null, ct).ConfigureAwait(false);
        StaffToken = r.Token;
        return r;
    }

    public async Task StaffLogoutAsync()
    {
        if (StaffToken is null) return;
        try { await Send<JsonDocument>(HttpMethod.Post, "api/desktop/auth/logout", new { }, StaffToken, default).ConfigureAwait(false); }
        catch (ApiException) { }
        StaffToken = null;
    }

    private string Staff => StaffToken ?? throw new ApiException(HttpStatusCode.Unauthorized, "no_token", "Sign in first.");

    public async Task<List<StaffInvestigation>> StaffInvestigationsAsync(CancellationToken ct = default)
    {
        using var doc = await Send<JsonDocument>(HttpMethod.Get, "api/desktop/staff/investigations", null, Staff, ct).ConfigureAwait(false);
        return doc.RootElement.GetProperty("investigations").Deserialize<List<StaffInvestigation>>(Json)!;
    }

    public Task<JsonDocument> StaffReportAsync(string id, CancellationToken ct = default) =>
        Send<JsonDocument>(HttpMethod.Get, $"api/desktop/staff/investigations/{Uri.EscapeDataString(id)}", null, Staff, ct);
}

/// <summary>Serialises timestamps as UTC ISO-8601 with millisecond precision (matches the backend validator).</summary>
public sealed class UtcIsoConverter : JsonConverter<DateTimeOffset>
{
    public override DateTimeOffset Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) => DateTimeOffset.Parse(reader.GetString()!);
    public override void Write(Utf8JsonWriter writer, DateTimeOffset value, JsonSerializerOptions options) => writer.WriteStringValue(value.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'"));
}

public sealed class NullableUtcIsoConverter : JsonConverter<DateTimeOffset?>
{
    public override DateTimeOffset? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) =>
        reader.TokenType == JsonTokenType.Null ? null : DateTimeOffset.Parse(reader.GetString()!);
    public override void Write(Utf8JsonWriter writer, DateTimeOffset? value, JsonSerializerOptions options)
    {
        if (value is null) writer.WriteNullValue();
        else writer.WriteStringValue(value.Value.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'"));
    }
}
