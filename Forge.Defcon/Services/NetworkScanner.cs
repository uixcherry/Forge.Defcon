using System.IO;
using System.Net.NetworkInformation;
using Microsoft.Win32;
using Forge.Defcon.Models;

namespace Forge.Defcon.Services;

public sealed class NetworkScanner : IScannerModule
{
    public string Name => "Network Scanner";

    private static readonly string[] FilterKeywords =
    [
        "filter", "qos", "mac layer", "light-weight", "lightweight",
        "ndis", "scheduler", "wfp",
    ];

    public async Task<List<ThreatInfo>> ScanAsync(Action<LogEntry> log, CancellationToken ct)
    {
        var threats = new List<ThreatInfo>();

        log(new LogEntry { Level = LogLevel.Info, Message = "Scanning network configuration...", Source = Name });

        await Task.Run(() =>
        {
            CheckHostsFile(threats, log, ct);
            ct.ThrowIfCancellationRequested();
            CheckProxySettings(threats, log, ct);
            ct.ThrowIfCancellationRequested();
            CheckDnsSettings(threats, log, ct);
            ct.ThrowIfCancellationRequested();
            CheckVpnAdapters(threats, log, ct);
        }, ct);

        log(new LogEntry { Level = LogLevel.Success, Message = $"Network scan complete: {threats.Count} findings", Source = Name });
        return threats;
    }

    private void CheckHostsFile(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "Checking hosts file for modifications...", Source = Name });

        string hostsPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "System32", "drivers", "etc", "hosts");

        try
        {
            if (!File.Exists(hostsPath)) return;

            var lines = File.ReadAllLines(hostsPath);
            int customEntries = 0;

            string[] antiCheatDomains = [
                "vanguard", "easyanticheat", "battleye", "faceit",
                "esea", "valve", "steampowered", "epicgames",
            ];

            foreach (var line in lines)
            {
                ct.ThrowIfCancellationRequested();
                string trimmed = line.Trim();
                if (string.IsNullOrEmpty(trimmed) || trimmed.StartsWith('#')) continue;

                customEntries++;
                string lower = trimmed.ToLowerInvariant();

                foreach (var domain in antiCheatDomains)
                {
                    if (lower.Contains(domain))
                    {
                        threats.Add(new ThreatInfo
                        {
                            Name = "Anti-cheat domain blocked",
                            Description = $"Hosts file blocks anti-cheat domain: \"{domain}\"",
                            Severity = ThreatSeverity.Critical,
                            Category = ThreatCategory.ProhibitedSoftware,
                            Details = $"Entry: {trimmed}"
                        });
                        log(new LogEntry { Level = LogLevel.Error, Message = $"Hosts block: {trimmed}", Source = Name });
                        break;
                    }
                }
            }

            if (customEntries > 500)
            {
                threats.Add(new ThreatInfo
                {
                    Name = "Large Hosts File",
                    Description = $"Hosts file has {customEntries} custom entries — may be used for ad/AC blocking",
                    Severity = ThreatSeverity.Info,
                    Category = ThreatCategory.SuspiciousDevice,
                    Details = $"Entries: {customEntries}"
                });
            }

            log(new LogEntry { Level = LogLevel.Info, Message = $"Hosts file: {customEntries} custom entries", Source = Name });
        }
        catch (Exception ex)
        {
            log(new LogEntry { Level = LogLevel.Warning, Message = $"Hosts file check failed: {ex.Message}", Source = Name });
        }
    }

    private void CheckProxySettings(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "Checking proxy settings...", Source = Name });

        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Internet Settings");

            if (key == null) return;

            var proxyEnabled = key.GetValue("ProxyEnable");
            var proxyServer = key.GetValue("ProxyServer")?.ToString();

            if (proxyEnabled is int pe && pe == 1 && !string.IsNullOrEmpty(proxyServer))
            {
                threats.Add(new ThreatInfo
                {
                    Name = "System Proxy Active",
                    Description = $"System proxy is configured: {proxyServer}",
                    Severity = ThreatSeverity.Info,
                    Category = ThreatCategory.SuspiciousDevice,
                    Details = $"ProxyServer: {proxyServer}"
                });
                log(new LogEntry { Level = LogLevel.Info, Message = $"Active proxy: {proxyServer}", Source = Name });
            }
        }
        catch { }
    }

    private void CheckDnsSettings(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "Checking DNS configuration...", Source = Name });

        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                ct.ThrowIfCancellationRequested();
                if (nic.OperationalStatus != OperationalStatus.Up) continue;
                if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;

                var props = nic.GetIPProperties();
                foreach (var dns in props.DnsAddresses)
                    log(new LogEntry { Level = LogLevel.Debug, Message = $"DNS on {nic.Name}: {dns}", Source = Name });
            }
        }
        catch { }
    }

    private void CheckVpnAdapters(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "Checking for active VPN connections...", Source = Name });

        var reportedVpns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                ct.ThrowIfCancellationRequested();
                if (nic.OperationalStatus != OperationalStatus.Up) continue;

                string nameLower = nic.Name.ToLowerInvariant();
                string descLower = nic.Description.ToLowerInvariant();

                if (IsFilterAdapter(nameLower) || IsFilterAdapter(descLower))
                    continue;

                bool isVpn = nameLower.Contains("vpn") || descLower.Contains("vpn") ||
                             nameLower.Contains("wireguard") || descLower.Contains("wireguard") ||
                             nameLower.Contains("openvpn") || descLower.Contains("openvpn") ||
                             nameLower.Contains("nordlynx") || descLower.Contains("nordlynx") ||
                             nic.NetworkInterfaceType == NetworkInterfaceType.Ppp;

                if (isVpn)
                {
                    string baseAdapterName = GetBaseAdapterName(nic.Name);
                    if (!reportedVpns.Add(baseAdapterName))
                        continue;

                    threats.Add(new ThreatInfo
                    {
                        Name = $"VPN: {baseAdapterName}",
                        Description = $"Active VPN connection: {nic.Description}",
                        Severity = ThreatSeverity.Info,
                        Category = ThreatCategory.SuspiciousDevice,
                        Details = $"Adapter: {nic.Name} | Type: {nic.NetworkInterfaceType}"
                    });
                    log(new LogEntry { Level = LogLevel.Info, Message = $"Active VPN: {baseAdapterName}", Source = Name });
                }
            }
        }
        catch { }
    }

    private static bool IsFilterAdapter(string name)
    {
        foreach (var kw in FilterKeywords)
        {
            if (name.Contains(kw))
                return true;
        }
        return false;
    }

    private static string GetBaseAdapterName(string name)
    {
        int dashIdx = name.IndexOf('-');
        return dashIdx > 0 ? name[..dashIdx].Trim() : name;
    }
}
