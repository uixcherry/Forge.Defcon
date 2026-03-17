using System.IO;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using Forge.Defcon.Models;

namespace Forge.Defcon.Services;

public sealed class SteamAccountScanner : IScannerModule
{
    public string Name => "Steam Account Scanner";

    public async Task<List<ThreatInfo>> ScanAsync(Action<LogEntry> log, CancellationToken ct)
    {
        var threats = new List<ThreatInfo>();

        log(new LogEntry { Level = LogLevel.Info, Message = "Scanning for Steam accounts...", Source = Name });

        var accounts = new List<SteamAccountInfo>();

        await Task.Run(() =>
        {
            string? steamPath = FindSteamPath();
            if (steamPath == null)
            {
                log(new LogEntry { Level = LogLevel.Warning, Message = "Steam installation not found", Source = Name });
                return;
            }

            log(new LogEntry { Level = LogLevel.Info, Message = $"Steam path: {steamPath}", Source = Name });

            ParseLoginUsersVdf(steamPath, accounts, log);
            ct.ThrowIfCancellationRequested();
            EnumerateUserData(steamPath, accounts, log);
            ct.ThrowIfCancellationRequested();
            CheckRegistryAccounts(accounts, log);
        }, ct);

        log(new LogEntry { Level = LogLevel.Info, Message = "═══ Steam Accounts Found ═══", Source = Name });

        if (accounts.Count == 0)
        {
            log(new LogEntry { Level = LogLevel.Info, Message = "No Steam accounts found on this PC", Source = Name });
        }
        else
        {
            var uniqueAccounts = accounts
                .GroupBy(a => a.SteamId)
                .Select(g => g.First())
                .ToList();

            foreach (var acc in uniqueAccounts)
            {
                string info = $"SteamID: {acc.SteamId} | Name: {acc.AccountName} | Persona: {acc.PersonaName}";
                if (acc.MostRecent) info += " [CURRENT]";

                log(new LogEntry { Level = LogLevel.Info, Message = $"  → {info}", Source = Name });

                threats.Add(new ThreatInfo
                {
                    Name = string.IsNullOrEmpty(acc.PersonaName) ? acc.AccountName : acc.PersonaName,
                    Description = $"Steam account: {acc.AccountName} (SteamID: {acc.SteamId})",
                    Severity = ThreatSeverity.Info,
                    Category = ThreatCategory.SteamAccount,
                    Details = info
                });
            }

            log(new LogEntry
            {
                Level = LogLevel.Info,
                Message = $"Total unique accounts: {uniqueAccounts.Count}",
                Source = Name
            });

            if (uniqueAccounts.Count > 3)
            {
                threats.Add(new ThreatInfo
                {
                    Name = "Multiple Steam Accounts",
                    Description = $"{uniqueAccounts.Count} different Steam accounts found — possible account sharing",
                    Severity = ThreatSeverity.Medium,
                    Category = ThreatCategory.SteamAccount,
                    Details = $"Account count: {uniqueAccounts.Count}"
                });
                log(new LogEntry { Level = LogLevel.Warning, Message = $"High account count: {uniqueAccounts.Count} accounts", Source = Name });
            }
        }

        log(new LogEntry
        {
            Level = LogLevel.Success,
            Message = $"Steam scan complete: {accounts.Count} accounts found",
            Source = Name
        });

        return threats;
    }

    private static string? FindSteamPath()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Valve\Steam");
            string? path = key?.GetValue("SteamPath")?.ToString();
            if (!string.IsNullOrEmpty(path) && Directory.Exists(path))
                return path;
        }
        catch { }

        string[] commonPaths =
        [
            @"C:\Program Files (x86)\Steam",
            @"C:\Program Files\Steam",
            @"D:\Steam",
            @"D:\Program Files (x86)\Steam",
        ];

        return commonPaths.FirstOrDefault(Directory.Exists);
    }

    private static void ParseLoginUsersVdf(string steamPath, List<SteamAccountInfo> accounts, Action<LogEntry> log)
    {
        string vdfPath = Path.Combine(steamPath, "config", "loginusers.vdf");
        if (!File.Exists(vdfPath))
        {
            log(new LogEntry { Level = LogLevel.Debug, Message = "loginusers.vdf not found", Source = "Steam" });
            return;
        }

        try
        {
            string content = File.ReadAllText(vdfPath);
            var steamIdPattern = new Regex(@"""(\d{17})""", RegexOptions.Compiled);
            var kvPattern = new Regex(@"""(\w+)""\s+""([^""]*?)""", RegexOptions.Compiled);

            string? currentId = null;
            string accountName = "", personaName = "", timestamp = "";
            bool rememberPw = false, mostRecent = false;

            foreach (var line in content.Split('\n'))
            {
                string trimmed = line.Trim();

                var idMatch = steamIdPattern.Match(trimmed);
                if (idMatch.Success && !trimmed.Contains("\"AccountName\""))
                {
                    if (currentId != null)
                    {
                        accounts.Add(new SteamAccountInfo
                        {
                            SteamId = currentId, AccountName = accountName,
                            PersonaName = personaName, RememberPassword = rememberPw,
                            MostRecent = mostRecent, Timestamp = timestamp
                        });
                    }

                    currentId = idMatch.Groups[1].Value;
                    accountName = ""; personaName = ""; timestamp = "";
                    rememberPw = false; mostRecent = false;
                    continue;
                }

                var kvMatch = kvPattern.Match(trimmed);
                if (kvMatch.Success && currentId != null)
                {
                    string key = kvMatch.Groups[1].Value;
                    string val = kvMatch.Groups[2].Value;

                    switch (key)
                    {
                        case "AccountName": accountName = val; break;
                        case "PersonaName": personaName = val; break;
                        case "RememberPassword": rememberPw = val == "1"; break;
                        case "MostRecent": mostRecent = val == "1"; break;
                        case "Timestamp": timestamp = val; break;
                    }
                }
            }

            if (currentId != null)
            {
                accounts.Add(new SteamAccountInfo
                {
                    SteamId = currentId, AccountName = accountName,
                    PersonaName = personaName, RememberPassword = rememberPw,
                    MostRecent = mostRecent, Timestamp = timestamp
                });
            }

            log(new LogEntry { Level = LogLevel.Info, Message = $"Parsed {accounts.Count} accounts from loginusers.vdf", Source = "Steam" });
        }
        catch (Exception ex)
        {
            log(new LogEntry { Level = LogLevel.Warning, Message = $"Failed to parse loginusers.vdf: {ex.Message}", Source = "Steam" });
        }
    }

    private static void EnumerateUserData(string steamPath, List<SteamAccountInfo> accounts, Action<LogEntry> log)
    {
        string userDataDir = Path.Combine(steamPath, "userdata");
        if (!Directory.Exists(userDataDir)) return;

        try
        {
            foreach (var dir in Directory.GetDirectories(userDataDir))
            {
                string folderName = Path.GetFileName(dir);
                if (int.TryParse(folderName, out int steam3Id))
                {
                    long steamId64 = 76561197960265728L + steam3Id;
                    string steamIdStr = steamId64.ToString();

                    if (!accounts.Any(a => a.SteamId == steamIdStr))
                    {
                        accounts.Add(new SteamAccountInfo
                        {
                            SteamId = steamIdStr,
                            AccountName = $"[userdata/{folderName}]",
                            PersonaName = ""
                        });
                    }
                }
            }
        }
        catch { }
    }

    private static void CheckRegistryAccounts(List<SteamAccountInfo> accounts, Action<LogEntry> log)
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Valve\Steam");
            if (key == null) return;

            string? lastUser = key.GetValue("LastGameNameUsed")?.ToString();
            string? autoLoginUser = key.GetValue("AutoLoginUser")?.ToString();

            if (!string.IsNullOrEmpty(autoLoginUser))
            {
                log(new LogEntry { Level = LogLevel.Info, Message = $"Auto-login user: {autoLoginUser}", Source = "Steam" });
            }
        }
        catch { }
    }
}
