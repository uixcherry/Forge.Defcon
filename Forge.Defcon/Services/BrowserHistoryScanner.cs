using System.IO;
using Microsoft.Data.Sqlite;
using Forge.Defcon.Models;

namespace Forge.Defcon.Services;

public sealed class BrowserHistoryScanner : IScannerModule
{
    public string Name => "Browser History";

    private static readonly string[] CheatDomains =
    [
        "dreamcheat", "unknowncheats", "mpgh", "ownedcore",
        "cheatengine", "cheat-engine", "wemod", "plitch",
        "aimbot", "wallhack", "esp-cheat", "triggerbot",
        "elite pvpers", "elitepvpers", "guidedhacking",
        "unknowncheats.me", "mpgh.net", "ownedcore.com",
        "dreamcheats.com", "cheatengine.org", "wemod.com",
        "elite-pvpers", "guided-hacking",
    ];

    private static readonly string[] CheatKeywords =
    [
        "dreamcheat", "unknowncheats", "cheat engine",
        "aimbot", "wallhack", "esp hack", "triggerbot",
        "speedhack", "noclip", "godmode", "trainer",
        "spoofer", "hwid bypass", "dma cheat",
        "bypass anticheat", "game cheat", "multiplayer cheat",
        "cheat download", "hack for game", "free cheat",
        "inject dll", "memory hack",
    ];

    private static readonly (string Name, string Path)[] ChromiumBrowsers =
    [
        ("Chrome", @"Google\Chrome\User Data\Default\History"),
        ("Edge", @"Microsoft\Edge\User Data\Default\History"),
        ("Brave", @"BraveSoftware\Brave-Browser\User Data\Default\History"),
        ("Opera", @"Opera Software\Opera Stable\History"),
        ("Opera GX", @"Opera Software\Opera GX Stable\History"),
        ("Yandex", @"Yandex\YandexBrowser\User Data\Default\History"),
    ];

    public async Task<List<ThreatInfo>> ScanAsync(Action<LogEntry> log, CancellationToken ct)
    {
        var threats = new List<ThreatInfo>();
        log(new LogEntry { Level = LogLevel.Info, Message = "Scanning browser history for cheat-related activity...", Source = Name });

        await Task.Run(() =>
        {
            ScanChromiumBrowsers(threats, log, ct);
            ct.ThrowIfCancellationRequested();
            ScanFirefox(threats, log, ct);
        }, ct);

        log(new LogEntry
        {
            Level = threats.Count > 0 ? LogLevel.Warning : LogLevel.Success,
            Message = $"Browser history scan complete: {threats.Count} cheat-related entries found",
            Source = Name
        });

        return threats;
    }

    private void ScanChromiumBrowsers(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        foreach (var (browserName, relativePath) in ChromiumBrowsers)
        {
            ct.ThrowIfCancellationRequested();

            string basePath = relativePath.StartsWith("Opera") ? appData : localAppData;
            string historyPath = Path.Combine(basePath, relativePath);

            if (!File.Exists(historyPath))
                continue;

            try
            {
                string tempCopy = Path.Combine(Path.GetTempPath(), $"fd_history_{Guid.NewGuid():N}.db");
                File.Copy(historyPath, tempCopy, overwrite: true);

                try
                {
                    using var conn = new SqliteConnection($"Data Source={tempCopy};Mode=ReadOnly");
                    conn.Open();

                    using var cmd = conn.CreateCommand();
                    cmd.CommandText = @"
                        SELECT url, title, last_visit_time
                        FROM urls
                        WHERE url IS NOT NULL OR title IS NOT NULL";

                    using var reader = cmd.ExecuteReader();
                    var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                    while (reader.Read())
                    {
                        ct.ThrowIfCancellationRequested();
                        string? url = reader.IsDBNull(0) ? null : reader.GetString(0);
                        string? title = reader.IsDBNull(1) ? null : reader.GetString(1);
                        long lastVisit = reader.IsDBNull(2) ? 0 : reader.GetInt64(2);

                        string combined = $"{url ?? ""} {title ?? ""}".ToLowerInvariant();
                        if (string.IsNullOrWhiteSpace(combined))
                            continue;

                        if (!MatchesCheatPattern(combined, out string? match))
                            continue;

                        string key = $"{browserName}|{match}|{url ?? title}";
                        if (seen.Contains(key))
                            continue;
                        seen.Add(key);

                        DateTime visitTime = ChromeTimeToDateTime(lastVisit);
                        var sev = match != null && IsKnownCheatSite(match) ? ThreatSeverity.High : ThreatSeverity.Medium;

                        threats.Add(new ThreatInfo
                        {
                            Name = $"{browserName}: cheat-related visit",
                            Description = $"Visited or searched: {match}",
                            Severity = sev,
                            Category = ThreatCategory.BrowserHistory,
                            Details = $"URL: {Truncate(url, 80)}\nTitle: {Truncate(title, 60)}\nTime: {visitTime:g}\nBrowser: {browserName}"
                        });
                        log(new LogEntry
                        {
                            Level = sev == ThreatSeverity.High ? LogLevel.Error : LogLevel.Warning,
                            Message = $"[{browserName}] {match}: {Truncate(url ?? title ?? "", 70)}",
                            Source = Name
                        });
                    }
                }
                finally
                {
                    try { File.Delete(tempCopy); } catch { }
                }
            }
            catch (Exception ex)
            {
                log(new LogEntry { Level = LogLevel.Debug, Message = $"Could not read {browserName} history: {ex.Message}", Source = Name });
            }
        }
    }

    private void ScanFirefox(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        string profilesPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            @"Mozilla\Firefox\Profiles");

        if (!Directory.Exists(profilesPath))
            return;

        foreach (var profileDir in Directory.GetDirectories(profilesPath))
        {
            ct.ThrowIfCancellationRequested();
            string placesPath = Path.Combine(profileDir, "places.sqlite");
            if (!File.Exists(placesPath))
                continue;

            try
            {
                string tempCopy = Path.Combine(Path.GetTempPath(), $"fd_firefox_{Guid.NewGuid():N}.db");
                File.Copy(placesPath, tempCopy, overwrite: true);

                try
                {
                    using var conn = new SqliteConnection($"Data Source={tempCopy};Mode=ReadOnly");
                    conn.Open();

                    using var cmd = conn.CreateCommand();
                    cmd.CommandText = @"
                        SELECT url, title, last_visit_date
                        FROM moz_places
                        WHERE (url IS NOT NULL OR title IS NOT NULL) AND last_visit_date IS NOT NULL";

                    using var reader = cmd.ExecuteReader();
                    var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                    while (reader.Read())
                    {
                        ct.ThrowIfCancellationRequested();
                        string? url = reader.IsDBNull(0) ? null : reader.GetString(0);
                        string? title = reader.IsDBNull(1) ? null : reader.GetString(1);
                        long lastVisit = reader.IsDBNull(2) ? 0 : reader.GetInt64(2);

                        string combined = $"{url ?? ""} {title ?? ""}".ToLowerInvariant();
                        if (string.IsNullOrWhiteSpace(combined))
                            continue;

                        if (!MatchesCheatPattern(combined, out string? match))
                            continue;

                        string key = $"Firefox|{match}|{url ?? title}";
                        if (seen.Contains(key))
                            continue;
                        seen.Add(key);

                        DateTime visitTime = FirefoxTimeToDateTime(lastVisit);
                        var sev = match != null && IsKnownCheatSite(match) ? ThreatSeverity.High : ThreatSeverity.Medium;

                        threats.Add(new ThreatInfo
                        {
                            Name = "Firefox: cheat-related visit",
                            Description = $"Visited or searched: {match}",
                            Severity = sev,
                            Category = ThreatCategory.BrowserHistory,
                            Details = $"URL: {Truncate(url, 80)}\nTitle: {Truncate(title, 60)}\nTime: {visitTime:g}\nBrowser: Firefox"
                        });
                        log(new LogEntry
                        {
                            Level = sev == ThreatSeverity.High ? LogLevel.Error : LogLevel.Warning,
                            Message = $"[Firefox] {match}: {Truncate(url ?? title ?? "", 70)}",
                            Source = Name
                        });
                    }
                }
                finally
                {
                    try { File.Delete(tempCopy); } catch { }
                }
            }
            catch (Exception ex)
            {
                log(new LogEntry { Level = LogLevel.Debug, Message = $"Could not read Firefox history: {ex.Message}", Source = Name });
            }
        }
    }

    private static bool MatchesCheatPattern(string combined, out string? match)
    {
        foreach (var domain in CheatDomains)
        {
            if (combined.Contains(domain, StringComparison.OrdinalIgnoreCase))
            {
                match = domain;
                return true;
            }
        }

        foreach (var keyword in CheatKeywords)
        {
            if (combined.Contains(keyword, StringComparison.OrdinalIgnoreCase))
            {
                match = keyword;
                return true;
            }
        }

        match = null;
        return false;
    }

    private static bool IsKnownCheatSite(string match)
    {
        string m = match.ToLowerInvariant();
        return m.Contains("dreamcheat") || m.Contains("unknowncheats") || m.Contains("mpgh") ||
               m.Contains("ownedcore") || m.Contains("cheatengine") || m.Contains("elitepvpers") ||
               m.Contains("guidedhacking") || m.Contains("aimbot") || m.Contains("wallhack");
    }

    private static DateTime ChromeTimeToDateTime(long microsecondsSince1601)
    {
        if (microsecondsSince1601 <= 0) return DateTime.MinValue;
        var epoch = new DateTime(1601, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        return epoch.AddMilliseconds(microsecondsSince1601 / 1000.0).ToLocalTime();
    }

    private static DateTime FirefoxTimeToDateTime(long microsecondsSince1970)
    {
        if (microsecondsSince1970 <= 0) return DateTime.MinValue;
        var epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        return epoch.AddMilliseconds(microsecondsSince1970 / 1000.0).ToLocalTime();
    }

    private static string Truncate(string? s, int maxLen)
    {
        if (string.IsNullOrEmpty(s)) return "";
        return s.Length <= maxLen ? s : s[..maxLen] + "...";
    }
}
