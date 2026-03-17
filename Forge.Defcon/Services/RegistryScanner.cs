using System.IO;
using Microsoft.Win32;
using Forge.Defcon.Models;

namespace Forge.Defcon.Services;

public sealed class RegistryScanner : IScannerModule
{
    public string Name => "Registry Scanner";

    private static readonly string[] SuspiciousUninstallNames =
    [
        "cheat engine", "cheatengine",
        "extreme injector", "extremeinjector",
        "x64dbg", "x32dbg", "ollydbg",
        "process hacker", "processhacker", "system informer",
        "ida pro", "ida free",
        "ghidra", "binary ninja",
        "wemod", "plitch", "cosmos",
        "wireshark", "fiddler",
        "http debugger", "httpdebugger",
        "dnspy", "dotpeek", "ilspy",
        "hxd", "010 editor",
        "reclass", "scylla",
        "rweverything",
        "artmoney",
    ];

    private static readonly string[] SuspiciousSoftwareKeys =
    [
        @"Software\Cheat Engine",
        @"Software\WeMod",
        @"Software\x64dbg",
        @"Software\NTCore\CFF Explorer",
    ];

    public async Task<List<ThreatInfo>> ScanAsync(Action<LogEntry> log, CancellationToken ct)
    {
        var threats = new List<ThreatInfo>();

        log(new LogEntry { Level = LogLevel.Info, Message = "Scanning Windows Registry...", Source = Name });

        await Task.Run(() =>
        {
            ScanUninstallKeys(threats, log, ct);
            ct.ThrowIfCancellationRequested();
            ScanSoftwareKeys(threats, log, ct);
            ct.ThrowIfCancellationRequested();
            ScanUserAssist(threats, log, ct);
            ct.ThrowIfCancellationRequested();
            ScanBamEntries(threats, log, ct);
            ct.ThrowIfCancellationRequested();
            ScanSecurityPolicies(threats, log, ct);
            ct.ThrowIfCancellationRequested();
            ScanMountPoints(threats, log, ct);
            ct.ThrowIfCancellationRequested();
            ScanDebuggerKeys(threats, log, ct);
        }, ct);

        log(new LogEntry
        {
            Level = LogLevel.Success,
            Message = $"Registry scan complete: {threats.Count} threats",
            Source = Name
        });

        return threats;
    }

    private void ScanUninstallKeys(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "Checking installed software (Uninstall keys)...", Source = Name });

        string[] uninstallPaths =
        [
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        ];

        foreach (var path in uninstallPaths)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(path);
                if (key == null) continue;

                foreach (var subKeyName in key.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    try
                    {
                        using var subKey = key.OpenSubKey(subKeyName);
                        string? displayName = subKey?.GetValue("DisplayName")?.ToString();
                        if (string.IsNullOrEmpty(displayName)) continue;

                        string lower = displayName.ToLowerInvariant();
                        foreach (var suspicious in SuspiciousUninstallNames)
                        {
                            if (lower.Contains(suspicious))
                            {
                                threats.Add(new ThreatInfo
                                {
                                    Name = displayName,
                                    Description = "Suspicious software found in installed programs",
                                    Severity = ThreatSeverity.High,
                                    Category = ThreatCategory.RegistryAnomaly,
                                    Details = $"Registry: {path}\\{subKeyName}"
                                });
                                log(new LogEntry { Level = LogLevel.Error, Message = $"Installed: \"{displayName}\"", Source = Name });
                                break;
                            }
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }
    }

    private void ScanSoftwareKeys(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "Checking HKCU Software keys...", Source = Name });

        foreach (var keyPath in SuspiciousSoftwareKeys)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(keyPath);
                if (key != null)
                {
                    string keyName = keyPath.Split('\\').Last();
                    threats.Add(new ThreatInfo
                    {
                        Name = keyName,
                        Description = $"Registry key exists: HKCU\\{keyPath}",
                        Severity = ThreatSeverity.Medium,
                        Category = ThreatCategory.RegistryAnomaly,
                        Details = $"HKCU\\{keyPath} — {key.SubKeyCount} subkeys, {key.ValueCount} values"
                    });
                    log(new LogEntry { Level = LogLevel.Warning, Message = $"Registry key: HKCU\\{keyPath}", Source = Name });
                }
            }
            catch { }
        }
    }

    private void ScanUserAssist(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "Checking UserAssist execution history...", Source = Name });

        string[] userAssistGuids =
        [
            @"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count",
            @"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}\Count"
        ];

        foreach (var guidPath in userAssistGuids)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(guidPath);
                if (key == null) continue;

                foreach (var valueName in key.GetValueNames())
                {
                    string decoded = Rot13(valueName).ToLowerInvariant();

                    foreach (var suspicious in SuspiciousUninstallNames)
                    {
                        if (decoded.Contains(suspicious))
                        {
                            threats.Add(new ThreatInfo
                            {
                                Name = "UserAssist: " + suspicious,
                                Description = "Execution history shows suspicious program was run",
                                Severity = ThreatSeverity.High,
                                Category = ThreatCategory.RegistryAnomaly,
                                Details = $"Decoded path: {decoded}"
                            });
                            log(new LogEntry { Level = LogLevel.Error, Message = $"UserAssist hit: {decoded}", Source = Name });
                            break;
                        }
                    }
                }
            }
            catch { }
        }
    }

    private void ScanBamEntries(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "Checking BAM (Background Activity Moderator)...", Source = Name });

        try
        {
            using var bamKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings");
            if (bamKey == null) return;

            foreach (var sidKey in bamKey.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using var userKey = bamKey.OpenSubKey(sidKey);
                    if (userKey == null) continue;

                    foreach (var valueName in userKey.GetValueNames())
                    {
                        string lower = valueName.ToLowerInvariant();
                        foreach (var suspicious in SuspiciousUninstallNames)
                        {
                            if (lower.Contains(suspicious))
                            {
                                threats.Add(new ThreatInfo
                                {
                                    Name = "BAM: " + Path.GetFileName(valueName),
                                    Description = "BAM recorded suspicious program execution",
                                    Severity = ThreatSeverity.High,
                                    Category = ThreatCategory.RegistryAnomaly,
                                    Details = $"BAM entry: {valueName}"
                                });
                                log(new LogEntry { Level = LogLevel.Error, Message = $"BAM entry: {valueName}", Source = Name });
                                break;
                            }
                        }
                    }
                }
                catch { }
            }
        }
        catch { }
    }

    private void ScanSecurityPolicies(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "Checking security policies...", Source = Name });

        try
        {
            using var defenderKey = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Policies\Microsoft\Windows Defender");

            if (defenderKey != null)
            {
                var disableVal = defenderKey.GetValue("DisableAntiSpyware");
                if (disableVal is int val && val == 1)
                {
                    threats.Add(new ThreatInfo
                    {
                        Name = "Windows Defender Disabled",
                        Description = "Windows Defender disabled via Group Policy",
                        Severity = ThreatSeverity.Medium,
                        Category = ThreatCategory.RegistryAnomaly,
                        Details = "DisableAntiSpyware = 1"
                    });
                    log(new LogEntry { Level = LogLevel.Warning, Message = "Defender disabled via policy", Source = Name });
                }
            }
        }
        catch { }

        try
        {
            using var tamperKey = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows Defender\Features");

            if (tamperKey != null)
            {
                var tamperVal = tamperKey.GetValue("TamperProtection");
                if (tamperVal is int tp && tp == 0)
                {
                    threats.Add(new ThreatInfo
                    {
                        Name = "Tamper Protection Disabled",
                        Description = "Windows Defender Tamper Protection is off",
                        Severity = ThreatSeverity.Medium,
                        Category = ThreatCategory.RegistryAnomaly,
                        Details = "TamperProtection = 0"
                    });
                    log(new LogEntry { Level = LogLevel.Warning, Message = "Tamper Protection disabled", Source = Name });
                }
            }
        }
        catch { }
    }

    private void ScanMountPoints(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "Checking MountPoints2 for external device history...", Source = Name });

        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2");

            if (key == null) return;

            var guids = key.GetSubKeyNames().Where(n => n.StartsWith('{')).ToArray();
            log(new LogEntry { Level = LogLevel.Info, Message = $"External volumes mounted: {guids.Length}", Source = Name });

            if (guids.Length > 30)
            {
                threats.Add(new ThreatInfo
                {
                    Name = $"Many External Volumes: {guids.Length}",
                    Description = $"{guids.Length} external volumes have been mounted",
                    Severity = ThreatSeverity.Info,
                    Category = ThreatCategory.SuspiciousDevice,
                    Details = $"MountPoints2 volume entries: {guids.Length}"
                });
            }
        }
        catch { }
    }

    private void ScanDebuggerKeys(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "Checking Image File Execution Options (debugger hooks)...", Source = Name });

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options");

            if (key == null) return;

            foreach (var subName in key.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using var subKey = key.OpenSubKey(subName);
                    string? debugger = subKey?.GetValue("Debugger")?.ToString();

                    if (!string.IsNullOrEmpty(debugger))
                    {
                        string target = subName.ToLowerInvariant();
                        bool isAntiCheat = target.Contains("easyanticheat") || target.Contains("battleye") ||
                                          target.Contains("vanguard") || target.Contains("faceit") ||
                                          target.Contains("esea") || target.Contains("gameguard");

                        if (isAntiCheat)
                        {
                            threats.Add(new ThreatInfo
                            {
                                Name = $"IFEO Debugger: {subName}",
                                Description = $"Anti-cheat process has a debugger attached via IFEO",
                                Severity = ThreatSeverity.Critical,
                                Category = ThreatCategory.RegistryAnomaly,
                                Details = $"Target: {subName} | Debugger: {debugger}"
                            });
                            log(new LogEntry { Level = LogLevel.Error, Message = $"IFEO debugger on AC: {subName} → {debugger}", Source = Name });
                        }
                        else
                        {
                            log(new LogEntry { Level = LogLevel.Debug, Message = $"IFEO debugger: {subName} → {debugger}", Source = Name });
                        }
                    }
                }
                catch { }
            }
        }
        catch { }
    }

    private static string Rot13(string input)
    {
        var result = new char[input.Length];
        for (int i = 0; i < input.Length; i++)
        {
            char c = input[i];
            if (c >= 'a' && c <= 'z') result[i] = (char)('a' + (c - 'a' + 13) % 26);
            else if (c >= 'A' && c <= 'Z') result[i] = (char)('A' + (c - 'A' + 13) % 26);
            else result[i] = c;
        }
        return new string(result);
    }
}
