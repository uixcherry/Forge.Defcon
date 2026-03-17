using System.Linq;
using System.Management;
using Forge.Defcon.Models;

namespace Forge.Defcon.Services;

public sealed class DeviceScanner : IScannerModule
{
    public string Name => "Device Scanner";

    private static readonly HashSet<string> SuspiciousUsbVendorIds = new(StringComparer.OrdinalIgnoreCase)
    {
        "VID_10EE",  // Xilinx FPGA (PCILeech, Screamer)
        "VID_1172",  // Altera / Intel FPGA
        "VID_09FB",  // Altera USB-Blaster
        "VID_0403",  // FTDI (FT601 in Screamer DMA adapter)
        "VID_1D50",  // OpenMoko
        "VID_1234",  // Generic test vendor
    };

    private static readonly (string Vid, string Pid)[] DmaUsbDevices =
    [
        ("0403", "6010"),  // FT601Q — Screamer PCIe Squirrel
        ("0403", "6006"),  // FT600Q
        ("10EE", "7014"),  // Xilinx Platform Cable
    ];

    private static readonly string[] SuspiciousDeviceNamePatterns =
    [
        "pcileech", "screamer", "squirrel",
        "fpga", "artix", "spartan", "kintex", "virtex", "zynq",
        "usb-blaster", "jtag", "platform cable",
        "ft60x", "ft601", "ft600",
        "acorn", "lambda", "enigma",
        "lambdaconcept", "dma adapter",
    ];

    private static readonly string[] KnownLegitimateVpn =
    [
        "radmin vpn", "hamachi", "zerotier", "tailscale",
        "nordvpn", "expressvpn", "surfshark", "protonvpn",
        "openvpn", "wireguard", "cloudflare warp",
    ];

    public async Task<List<ThreatInfo>> ScanAsync(Action<LogEntry> log, CancellationToken ct)
    {
        var threats = new List<ThreatInfo>();

        log(new LogEntry { Level = LogLevel.Info, Message = "Scanning all connected devices...", Source = Name });

        await Task.Run(() =>
        {
            ScanUsbDevices(threats, log, ct);
            ct.ThrowIfCancellationRequested();
            ScanAllPnpDevices(threats, log, ct);
            ct.ThrowIfCancellationRequested();
            ScanNetworkAdapters(threats, log, ct);
        }, ct);

        log(new LogEntry
        {
            Level = LogLevel.Success,
            Message = $"Device scan complete: {threats.Count} suspicious devices found",
            Source = Name
        });

        return threats;
    }

    private void ScanUsbDevices(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "Enumerating USB devices...", Source = Name });

        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT * FROM Win32_PnPEntity WHERE DeviceID LIKE 'USB%'");

            int count = 0;
            foreach (var obj in searcher.Get())
            {
                ct.ThrowIfCancellationRequested();
                count++;

                string deviceId = obj["DeviceID"]?.ToString() ?? "";
                string name = obj["Name"]?.ToString() ?? "";
                string desc = obj["Description"]?.ToString() ?? "";

                // DMA-specific USB (FT601, etc.)
                foreach (var (vid, pid) in DmaUsbDevices)
                {
                    if (deviceId.Contains($"VID_{vid}", StringComparison.OrdinalIgnoreCase) &&
                        deviceId.Contains($"PID_{pid}", StringComparison.OrdinalIgnoreCase))
                    {
                        threats.Add(new ThreatInfo
                        {
                            Name = string.IsNullOrEmpty(name) ? deviceId : name,
                            Description = $"Known DMA adapter USB: {vid}:{pid} (FT601=Screamer, Xilinx=FPGA)",
                            Severity = ThreatSeverity.Critical,
                            Category = ThreatCategory.SuspiciousDevice,
                            Details = $"DeviceID: {deviceId}"
                        });
                        log(new LogEntry { Level = LogLevel.Error, Message = $"DMA USB: {name} ({vid}:{pid})", Source = Name });
                        break;
                    }
                }

                foreach (var vid in SuspiciousUsbVendorIds)
                {
                    if (deviceId.Contains(vid, StringComparison.OrdinalIgnoreCase))
                    {
                        threats.Add(new ThreatInfo
                        {
                            Name = string.IsNullOrEmpty(name) ? deviceId : name,
                            Description = $"USB device with DMA-related vendor ID: {vid}",
                            Severity = ThreatSeverity.High,
                            Category = ThreatCategory.SuspiciousDevice,
                            Details = $"DeviceID: {deviceId}"
                        });
                        log(new LogEntry { Level = LogLevel.Error, Message = $"Suspicious USB: {name} ({vid})", Source = Name });
                        break;
                    }
                }

                string combined = $"{name} {desc}".ToLowerInvariant();
                foreach (var pattern in SuspiciousDeviceNamePatterns)
                {
                    if (combined.Contains(pattern))
                    {
                        threats.Add(new ThreatInfo
                        {
                            Name = name,
                            Description = $"Device name contains suspicious pattern: \"{pattern}\"",
                            Severity = ThreatSeverity.High,
                            Category = ThreatCategory.SuspiciousDevice,
                            Details = $"DeviceID: {deviceId} | Desc: {desc}"
                        });
                        log(new LogEntry { Level = LogLevel.Warning, Message = $"Suspicious device name: {name}", Source = Name });
                        break;
                    }
                }
            }

            log(new LogEntry { Level = LogLevel.Info, Message = $"Found {count} USB devices", Source = Name });
        }
        catch (Exception ex)
        {
            log(new LogEntry { Level = LogLevel.Warning, Message = $"USB scan error: {ex.Message}", Source = Name });
        }
    }

    private void ScanAllPnpDevices(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "Checking all PnP devices...", Source = Name });

        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT * FROM Win32_PnPEntity WHERE ConfigManagerErrorCode = 0");

            int count = 0;
            foreach (var obj in searcher.Get())
            {
                ct.ThrowIfCancellationRequested();
                count++;

                string deviceId = obj["DeviceID"]?.ToString() ?? "";
                string name = obj["Name"]?.ToString() ?? "";

                if (deviceId.Contains("VEN_1234", StringComparison.OrdinalIgnoreCase) ||
                    deviceId.Contains("VEN_DEAD", StringComparison.OrdinalIgnoreCase))
                {
                    threats.Add(new ThreatInfo
                    {
                        Name = name,
                        Description = "Device with test/fake vendor ID detected",
                        Severity = ThreatSeverity.Critical,
                        Category = ThreatCategory.SuspiciousDevice,
                        Details = $"DeviceID: {deviceId}"
                    });
                    log(new LogEntry { Level = LogLevel.Error, Message = $"Fake vendor device: {name}", Source = Name });
                }
            }

            log(new LogEntry { Level = LogLevel.Info, Message = $"Checked {count} PnP devices", Source = Name });
        }
        catch (Exception ex)
        {
            log(new LogEntry { Level = LogLevel.Warning, Message = $"PnP scan error: {ex.Message}", Source = Name });
        }
    }

    private void ScanNetworkAdapters(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "Checking network adapters...", Source = Name });

        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT * FROM Win32_NetworkAdapter WHERE PhysicalAdapter = True");

            foreach (var obj in searcher.Get())
            {
                ct.ThrowIfCancellationRequested();

                string name = obj["Name"]?.ToString() ?? "";
                string mac = obj["MACAddress"]?.ToString() ?? "";
                string nameLower = name.ToLowerInvariant();

                if (nameLower.Contains("tap-") || nameLower.Contains("vpn") ||
                    nameLower.Contains("virtual") || nameLower.Contains("tunngle"))
                {
                    bool isKnownVpn = KnownLegitimateVpn.Any(v => nameLower.Contains(v));
                    if (!isKnownVpn)
                    {
                        threats.Add(new ThreatInfo
                        {
                            Name = name,
                            Description = "Virtual/VPN network adapter detected",
                            Severity = ThreatSeverity.Info,
                            Category = ThreatCategory.SuspiciousDevice,
                            Details = $"MAC: {mac}"
                        });
                    }
                    log(new LogEntry { Level = LogLevel.Info, Message = $"Virtual adapter: {name} ({mac})", Source = Name });
                }
            }
        }
        catch (Exception ex)
        {
            log(new LogEntry { Level = LogLevel.Warning, Message = $"Network scan error: {ex.Message}", Source = Name });
        }
    }
}
