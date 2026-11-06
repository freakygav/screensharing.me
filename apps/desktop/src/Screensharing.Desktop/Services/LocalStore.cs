using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace Screensharing.Desktop.Services;

public sealed record SavedSession(string DeviceToken, string InvestigationJson, DateTimeOffset SavedAt);
public sealed record HistoryEntry(long Id, string Reference, string Subject, DateTimeOffset CompletedAt, int Findings, string ReportPath, string Manifest);

/// <summary>
/// Local SQLite store (%LOCALAPPDATA%\screensharing.me\app.db): settings, scan history and the
/// resumable investigation session. Device tokens are encrypted with Windows DPAPI (current user).
/// </summary>
public sealed class LocalStore
{
    private readonly string _cs;

    public LocalStore(string? path = null)
    {
        _cs = new SqliteConnectionStringBuilder { DataSource = path ?? Path.Combine(AppInfo.DataDirectory, "app.db") }.ToString();
        using var c = Open();
        Exec(c, """
            CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS session (id INTEGER PRIMARY KEY CHECK (id = 1), token BLOB NOT NULL, investigation TEXT NOT NULL, saved_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS history (id INTEGER PRIMARY KEY AUTOINCREMENT, reference TEXT NOT NULL, subject TEXT NOT NULL, completed_at TEXT NOT NULL, findings INTEGER NOT NULL, report_path TEXT NOT NULL, manifest TEXT NOT NULL);
            """);
    }

    private SqliteConnection Open()
    {
        var c = new SqliteConnection(_cs);
        c.Open();
        return c;
    }

    private static void Exec(SqliteConnection c, string sql, params (string, object?)[] p)
    {
        using var cmd = c.CreateCommand();
        cmd.CommandText = sql;
        foreach (var (k, v) in p) cmd.Parameters.AddWithValue(k, v ?? DBNull.Value);
        cmd.ExecuteNonQuery();
    }

    public string? Get(string key)
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT value FROM settings WHERE key = $k";
        cmd.Parameters.AddWithValue("$k", key);
        return cmd.ExecuteScalar() as string;
    }

    public void Set(string key, string value)
    {
        using var c = Open();
        Exec(c, "INSERT INTO settings(key, value) VALUES($k, $v) ON CONFLICT(key) DO UPDATE SET value = excluded.value", ("$k", key), ("$v", value));
    }

    public bool GetBool(string key, bool fallback) => Get(key) is { } v ? v == "1" : fallback;
    public void SetBool(string key, bool value) => Set(key, value ? "1" : "0");

    public void SaveSession(string token, object investigation)
    {
        var enc = ProtectedData.Protect(Encoding.UTF8.GetBytes(token), Encoding.UTF8.GetBytes("ssme-device-token"), DataProtectionScope.CurrentUser);
        using var c = Open();
        Exec(c, "INSERT INTO session(id, token, investigation, saved_at) VALUES(1, $t, $i, $s) ON CONFLICT(id) DO UPDATE SET token = excluded.token, investigation = excluded.investigation, saved_at = excluded.saved_at",
            ("$t", enc), ("$i", JsonSerializer.Serialize(investigation)), ("$s", DateTimeOffset.UtcNow.ToString("o")));
    }

    public SavedSession? LoadSession()
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT token, investigation, saved_at FROM session WHERE id = 1";
        using var r = cmd.ExecuteReader();
        if (!r.Read()) return null;
        try
        {
            var token = Encoding.UTF8.GetString(ProtectedData.Unprotect((byte[])r[0], Encoding.UTF8.GetBytes("ssme-device-token"), DataProtectionScope.CurrentUser));
            return new SavedSession(token, r.GetString(1), DateTimeOffset.Parse(r.GetString(2)));
        }
        catch (CryptographicException) { return null; }
    }

    public void ClearSession()
    {
        using var c = Open();
        Exec(c, "DELETE FROM session");
    }

    public void AddHistory(string reference, string subject, int findings, string reportPath, string manifest)
    {
        using var c = Open();
        Exec(c, "INSERT INTO history(reference, subject, completed_at, findings, report_path, manifest) VALUES($r, $s, $c, $f, $p, $m)",
            ("$r", reference), ("$s", subject), ("$c", DateTimeOffset.UtcNow.ToString("o")), ("$f", findings), ("$p", reportPath), ("$m", manifest));
    }

    public List<HistoryEntry> History()
    {
        var list = new List<HistoryEntry>();
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT id, reference, subject, completed_at, findings, report_path, manifest FROM history ORDER BY id DESC LIMIT 100";
        using var r = cmd.ExecuteReader();
        while (r.Read()) list.Add(new HistoryEntry(r.GetInt64(0), r.GetString(1), r.GetString(2), DateTimeOffset.Parse(r.GetString(3)), r.GetInt32(4), r.GetString(5), r.GetString(6)));
        return list;
    }

    public void ClearHistory()
    {
        using var c = Open();
        Exec(c, "DELETE FROM history");
    }
}
