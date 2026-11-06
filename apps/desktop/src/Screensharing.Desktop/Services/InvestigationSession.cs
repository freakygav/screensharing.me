using System.Collections.Concurrent;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using Screensharing.Scanner.Engine;
using Screensharing.Scanner.Model;

namespace Screensharing.Desktop.Services;

public enum LinkState { Connected, Reconnecting, Disconnected }

/// <summary>
/// Runs the local scan and streams progress/findings to the backend.
/// The scan itself never depends on the network: uploads are queued and retried with backoff,
/// and every upload is idempotent so a reconnect can safely resend.
/// </summary>
public sealed class InvestigationSession
{
    private readonly ApiClient _api;
    private readonly ConcurrentDictionary<string, Finding> _pending = new();
    private readonly ConcurrentDictionary<string, Finding> _all = new();
    private ScanProgress? _latestProgress;
    private int _sentProgress = -1;
    private string? _sentActivity;
    private int _sentExamined = -1;
    private DateTime _lastProgressPost = DateTime.MinValue;
    private DateTime _lastHeartbeat = DateTime.MinValue;

    public InvestigationInfo Investigation { get; }
    public event Action<ScanProgress>? Progress;
    public event Action<Finding>? FindingAdded;
    public event Action<LinkState, string?>? Link;
    public LinkState State { get; private set; } = LinkState.Connected;
    public int PendingUploads => _pending.Count;
    public ScanResult? Result { get; private set; }
    public bool? ManifestVerified { get; private set; }
    public string? UploadError { get; private set; }

    public InvestigationSession(ApiClient api, InvestigationInfo investigation)
    {
        _api = api;
        Investigation = investigation;
    }

    private void SetLink(LinkState s, string? msg = null)
    {
        State = s;
        Link?.Invoke(s, msg);
    }

    /// <summary>Downloads the live catalog; falls back to the ruleset compiled into this build.</summary>
    public async Task<RuleSet> LoadRulesAsync(CancellationToken ct)
    {
        try
        {
            using var doc = await _api.GetRulesJsonAsync(ct);
            return RuleSet.Parse(doc.RootElement.GetRawText());
        }
        catch (ApiException) { return RuleSet.LoadEmbedded(); }
    }

    public async Task<ScanResult> RunAsync(ScanOptions options, CancellationToken ct)
    {
        var engine = new ScanEngine(options);
        await Retry(() => _api.StartScanAsync(new
        {
            engineVersion = ScanEngine.EngineVersion,
            rulesetVersion = options.Rules.Version.Length > 40 ? options.Rules.Version[..40] : options.Rules.Version,
            elevated = ScanEngine.IsElevated(),
            categories = engine.Categories.Select(c => new { key = c.Key, name = c.Name }).ToList(),
            instance = Payloads.Instance(options.Target),
        }, ct), ct, attempts: 5);

        engine.Progress += p => { _latestProgress = p; Progress?.Invoke(p); };
        engine.FindingReported += f => { _pending[f.ClientFindingId] = f; _all[f.ClientFindingId] = f; FindingAdded?.Invoke(f); };

        using var uploaderCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var uploader = Task.Run(() => UploadLoop(uploaderCts.Token), CancellationToken.None);

        ScanResult result;
        try
        {
            result = await Task.Run(() => engine.RunAsync(ct), ct);
        }
        catch (OperationCanceledException)
        {
            uploaderCts.Cancel();
            try { await _api.FailAsync("Scan cancelled on the desktop", CancellationToken.None); } catch (ApiException) { }
            throw;
        }
        catch (Exception e)
        {
            uploaderCts.Cancel();
            try { await _api.FailAsync($"Scanner error: {e.GetType().Name}: {e.Message}"[..Math.Min(480, $"Scanner error: {e.GetType().Name}: {e.Message}".Length)], CancellationToken.None); } catch (ApiException) { }
            throw;
        }
        Result = result;
        uploaderCts.Cancel();
        try { await uploader; } catch (OperationCanceledException) { }

        await FinishUploadAsync(result, ct);
        return result;
    }

    /// <summary>Flushes everything and completes the scan on the server, retrying through outages.</summary>
    public async Task FinishUploadAsync(ScanResult result, CancellationToken ct)
    {
        var delay = TimeSpan.FromSeconds(1);
        for (var attempt = 0; ; attempt++)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                await FlushFindings(ct);
                await PostProgress(force: true, ct);
                var complete = await _api.CompleteAsync(Payloads.Complete(result), ct);
                ManifestVerified = complete.ManifestVerified;
                UploadError = null;
                SetLink(LinkState.Connected);
                return;
            }
            catch (ApiException e) when (e.Status == HttpStatusCode.Conflict && e.Message.Contains("findings"))
            {
                // Server is missing findings (e.g. a batch was lost): re-send everything; uploads are idempotent.
                foreach (var f in result.Findings) _pending[f.ClientFindingId] = f;
            }
            catch (ApiException e) when (e.IsNetwork || (int)e.Status >= 500)
            {
                SetLink(LinkState.Reconnecting, e.Message);
            }
            catch (ApiException e)
            {
                UploadError = e.Message;
                SetLink(LinkState.Disconnected, e.Message);
                return; // 401/410/422: cannot be fixed by retrying; results remain available locally.
            }
            if (attempt > 40) { UploadError = "Gave up after repeated failures."; SetLink(LinkState.Disconnected, UploadError); return; }
            await Task.Delay(delay, ct);
            delay = TimeSpan.FromSeconds(Math.Min(30, delay.TotalSeconds * 2));
        }
    }

    private async Task UploadLoop(CancellationToken ct)
    {
        var delay = TimeSpan.FromMilliseconds(750);
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await FlushFindings(ct);
                await PostProgress(force: false, ct);
                if (DateTime.UtcNow - _lastHeartbeat > TimeSpan.FromSeconds(15))
                {
                    await _api.HeartbeatAsync(ct);
                    _lastHeartbeat = DateTime.UtcNow;
                }
                if (State != LinkState.Connected) SetLink(LinkState.Connected);
                delay = TimeSpan.FromMilliseconds(750);
            }
            catch (OperationCanceledException) { return; }
            catch (ApiException e) when (e.IsNetwork || (int)e.Status >= 500 || e.Status == HttpStatusCode.TooManyRequests)
            {
                SetLink(LinkState.Reconnecting, e.Message);
                delay = TimeSpan.FromSeconds(Math.Min(20, Math.Max(2, delay.TotalSeconds * 2)));
            }
            catch (ApiException e)
            {
                SetLink(LinkState.Disconnected, e.Message);
                UploadError = e.Message;
                delay = TimeSpan.FromSeconds(10);
            }
            try { await Task.Delay(delay, ct); } catch (OperationCanceledException) { return; }
        }
    }

    private async Task FlushFindings(CancellationToken ct)
    {
        while (!_pending.IsEmpty)
        {
            var batch = _pending.Values.Take(50).ToList();
            await _api.FindingsAsync(new { findings = batch.Select(Payloads.Finding).ToList() }, ct);
            foreach (var f in batch) _pending.TryRemove(f.ClientFindingId, out _);
        }
    }

    private async Task PostProgress(bool force, CancellationToken ct)
    {
        var p = _latestProgress;
        if (p is null) return;
        var changed = p.Percent != _sentProgress || p.Activity != _sentActivity || p.FilesExamined != _sentExamined;
        if (!force && (!changed || DateTime.UtcNow - _lastProgressPost < TimeSpan.FromSeconds(1))) return;
        await _api.ProgressAsync(Payloads.Progress(p), ct);
        _sentProgress = p.Percent;
        _sentActivity = p.Activity;
        _sentExamined = p.FilesExamined;
        _lastProgressPost = DateTime.UtcNow;
        _lastHeartbeat = DateTime.UtcNow;
    }

    private static async Task Retry(Func<Task> action, CancellationToken ct, int attempts)
    {
        for (var i = 1; ; i++)
        {
            try { await action(); return; }
            catch (ApiException e) when ((e.IsNetwork || (int)e.Status >= 500) && i < attempts)
            {
                await Task.Delay(TimeSpan.FromSeconds(i * 2), ct);
            }
        }
    }
}
