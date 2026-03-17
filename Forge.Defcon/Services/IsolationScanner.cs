using System.Management;
using System.Net.NetworkInformation;
using Microsoft.Win32;
using Forge.Defcon.Models;

namespace Forge.Defcon.Services;

public sealed class IsolationScanner : IScannerModule
{
    public string Name => "Isolation Scanner";

    public async Task<List<ThreatInfo>> ScanAsync(Action<LogEntry> log, CancellationToken ct)
    {
        var threats = new List<ThreatInfo>();

        log(new LogEntry { Level = LogLevel.Info, Message = "Checking system isolation and security state...", Source = Name });

        await Task.Run(() =>
        {
            CheckFirewall(threats, log, ct);
            ct.ThrowIfCancellationRequested();
            CheckWindowsDefender(threats, log, ct);
            ct.ThrowIfCancellationRequested();
            CheckWindowsUpdate(threats, log, ct);
            ct.ThrowIfCancellationRequested();
            CheckNetworkState(threats, log, ct);
            ct.ThrowIfCancellationRequested();
            CheckSecureBoot(threats, log, ct);
            ct.ThrowIfCancellationRequested();
            CheckUac(threats, log, ct);
            ct.ThrowIfCancellationRequested();
            CheckDriverSignatureEnforcement(threats, log, ct);
        }, ct);

        log(new LogEntry
        {
            Level = LogLevel.Success,
            Message = $"Isolation scan complete: {threats.Count} issues found",
            Source = Name
        });

        return threats;
    }

    private void CheckFirewall(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "Checking Windows Firewall status...", Source = Name });

        string[] profiles = ["DomainProfile", "StandardProfile", "PublicProfile"];
        string basePath = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy";

        foreach (var profile in profiles)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey($@"{basePath}\{profile}");
                if (key != null)
                {
                    var enabled = key.GetValue("EnableFirewall");
                    if (enabled is int val && val == 0)
                    {
                        threats.Add(new ThreatInfo
                        {
                            Name = $"Firewall Disabled: {profile}",
                            Description = $"Windows Firewall is disabled for {profile}",
                            Severity = ThreatSeverity.Medium,
                            Category = ThreatCategory.IsolationIssue,
                            Details = $"Profile: {profile} | EnableFirewall = 0"
                        });
                        log(new LogEntry { Level = LogLevel.Warning, Message = $"Firewall OFF: {profile}", Source = Name });
                    }
                }
            }
            catch { }
        }
    }

    private void CheckWindowsDefender(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "Checking Windows Defender real-time protection...", Source = Name });

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection");

            if (key != null)
            {
                var rtpDisabled = key.GetValue("DisableRealtimeMonitoring");
                if (rtpDisabled is int val && val == 1)
                {
                    threats.Add(new ThreatInfo
                    {
                        Name = "Real-Time Protection Disabled",
                        Description = "Windows Defender real-time protection is turned off",
                        Severity = ThreatSeverity.High,
                        Category = ThreatCategory.IsolationIssue,
                        Details = "DisableRealtimeMonitoring = 1"
                    });
                    log(new LogEntry { Level = LogLevel.Error, Message = "Defender Real-Time Protection is OFF", Source = Name });
                }
            }

            using var exclusionsKey = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths");

            if (exclusionsKey != null)
            {
                var exclusions = exclusionsKey.GetValueNames();
                if (exclusions.Length > 0)
                {
                    threats.Add(new ThreatInfo
                    {
                        Name = "Defender Exclusions",
                        Description = $"{exclusions.Length} path exclusion(s) configured in Windows Defender",
                        Severity = ThreatSeverity.Medium,
                        Category = ThreatCategory.IsolationIssue,
                        Details = $"Exclusions: {string.Join(", ", exclusions.Take(5))}"
                    });
                    log(new LogEntry { Level = LogLevel.Warning, Message = $"Defender exclusions: {exclusions.Length} paths", Source = Name });

                    foreach (var excl in exclusions.Take(10))
                    {
                        log(new LogEntry { Level = LogLevel.Info, Message = $"  Exclusion: {excl}", Source = Name });
                    }
                }
            }
        }
        catch { }
    }

    private void CheckWindowsUpdate(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "Checking Windows Update status...", Source = Name });

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU");

            if (key != null)
            {
                var noAutoUpdate = key.GetValue("NoAutoUpdate");
                if (noAutoUpdate is int val && val == 1)
                {
                    threats.Add(new ThreatInfo
                    {
                        Name = "Windows Update Disabled",
                        Description = "Automatic Windows Update is disabled via policy",
                        Severity = ThreatSeverity.Low,
                        Category = ThreatCategory.IsolationIssue,
                        Details = "NoAutoUpdate = 1"
                    });
                    log(new LogEntry { Level = LogLevel.Warning, Message = "Windows Update disabled via policy", Source = Name });
                }
            }
        }
        catch { }
    }

    private void CheckNetworkState(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "Checking network connectivity...", Source = Name });

        try
        {
            bool hasActiveConnection = false;
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus == OperationalStatus.Up &&
                    nic.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                {
                    hasActiveConnection = true;
                    break;
                }
            }

            if (!hasActiveConnection)
            {
                threats.Add(new ThreatInfo
                {
                    Name = "No Network Connection",
                    Description = "System has no active network connection — may be intentionally isolated",
                    Severity = ThreatSeverity.Medium,
                    Category = ThreatCategory.IsolationIssue,
                    Details = "No active non-loopback interface"
                });
                log(new LogEntry { Level = LogLevel.Warning, Message = "No active network connection", Source = Name });
            }
        }
        catch { }
    }

    private void CheckSecureBoot(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "Checking Secure Boot status...", Source = Name });

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\SecureBoot\State");

            if (key != null)
            {
                var enabled = key.GetValue("UEFISecureBootEnabled");
                if (enabled is int val && val == 0)
                {
                    threats.Add(new ThreatInfo
                    {
                        Name = "Secure Boot Disabled",
                        Description = "UEFI Secure Boot is not enabled — unsigned drivers can load",
                        Severity = ThreatSeverity.High,
                        Category = ThreatCategory.IsolationIssue,
                        Details = "UEFISecureBootEnabled = 0"
                    });
                    log(new LogEntry { Level = LogLevel.Error, Message = "Secure Boot is DISABLED", Source = Name });
                }
                else
                {
                    log(new LogEntry { Level = LogLevel.Info, Message = "Secure Boot is enabled", Source = Name });
                }
            }
        }
        catch { }
    }

    private void CheckUac(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "Checking UAC status...", Source = Name });

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System");

            if (key != null)
            {
                var enableLua = key.GetValue("EnableLUA");
                if (enableLua is int val && val == 0)
                {
                    threats.Add(new ThreatInfo
                    {
                        Name = "UAC Disabled",
                        Description = "User Account Control is disabled",
                        Severity = ThreatSeverity.Medium,
                        Category = ThreatCategory.IsolationIssue,
                        Details = "EnableLUA = 0"
                    });
                    log(new LogEntry { Level = LogLevel.Warning, Message = "UAC is disabled", Source = Name });
                }
            }
        }
        catch { }
    }

    private void CheckDriverSignatureEnforcement(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "Checking driver signature enforcement...", Source = Name });

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\CI\Policy");

            if (key != null)
            {
                log(new LogEntry { Level = LogLevel.Info, Message = "CI Policy key exists — checking values", Source = Name });
            }

            using var bcdeKey = Registry.LocalMachine.OpenSubKey(
                @"BCD00000000\Objects");

            bool testSigningFound = false;
            if (bcdeKey != null)
            {
                log(new LogEntry { Level = LogLevel.Info, Message = "BCD store accessible", Source = Name });
            }

            using var ciKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\CI");

            if (ciKey != null)
            {
                var testMode = ciKey.GetValue("TestSigning");
                if (testMode is int ts && ts != 0)
                {
                    testSigningFound = true;
                }
            }

            if (testSigningFound)
            {
                threats.Add(new ThreatInfo
                {
                    Name = "Test Signing Enabled",
                    Description = "Windows test signing mode is enabled — unsigned drivers can load",
                    Severity = ThreatSeverity.Critical,
                    Category = ThreatCategory.IsolationIssue,
                    Details = "Test signing mode allows loading unsigned kernel drivers"
                });
                log(new LogEntry { Level = LogLevel.Error, Message = "TEST SIGNING MODE is ENABLED", Source = Name });
            }
        }
        catch { }
    }
}
