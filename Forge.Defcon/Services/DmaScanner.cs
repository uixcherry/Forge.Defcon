using System.IO;
using System.Management;
using Microsoft.Win32;
using Forge.Defcon.Models;

namespace Forge.Defcon.Services;

public sealed class DmaScanner : IScannerModule
{
    public string Name => "DMA Scanner";

    // ── PCI Vendor IDs: FPGA, DMA boards, fake IDs ──
    private static readonly HashSet<string> SuspiciousPciVendorIds = new(StringComparer.OrdinalIgnoreCase)
    {
        "VEN_10EE",  // Xilinx (Artix-7, Kintex, Spartan, Zynq — PCILeech, Screamer)
        "VEN_1172",  // Altera / Intel FPGA
        "VEN_1D0F",  // Amazon FPGA
        "VEN_1556",  // PLDA PCIe IP
        "VEN_1234",  // QEMU / Test
        "VEN_DEAD",  // Fake VID (custom DMA firmware)
        "VEN_CAFE",  // Fake VID
        "VEN_1337",  // Leet
        "VEN_0001",  // Generic test
        "VEN_10B5",  // PLX (PCIe switches in DMA setups)
        "VEN_12D8",  // Pericom (PCIe bridges)
        "VEN_1B4B",  // Marvell
        "VEN_1FC8",  // Lucid/Hydra (PCIe interposer)
        "VEN_FAFA",  // Custom DMA firmware
        "VEN_0666",  // Custom DMA firmware
        "VEN_0403",  // FTDI (FT601Q USB-PCIe bridge in Screamer, etc.)
        "VEN_11C6",  // PLX 8713 (used in some DMA adapters)
        "VEN_1B21",  // ASMedia (PCIe bridges)
    };

    // ── PCI Device IDs: known DMA/FPGA chips ──
    private static readonly HashSet<string> SuspiciousPciDeviceIds = new(StringComparer.OrdinalIgnoreCase)
    {
        "DEV_6010",  // FT601Q
        "DEV_6006",  // FT600Q
        "DEV_7024",  // Xilinx 7-series PCIe
        "DEV_7028",
        "DEV_7032",
        "DEV_9034",  // Xilinx Artix
        "DEV_9036",
        "DEV_9011",  // Xilinx Kintex
        "DEV_9014",
    };

    // ── Device name patterns (PCILeech, Screamer, Squirrel, etc.) ──
    private static readonly string[] SuspiciousDeviceNamePatterns =
    [
        "pcileech", "screamer", "squirrel",
        "fpga", "artix", "spartan", "kintex", "virtex", "zynq",
        "acorn", "lambda", "enigma",
        "dma", "thunderbolt_dma", "pcie_dma",
        "ft60x", "ft601", "ft600",
        "usb3380", "usb3382",
        "xilinx", "altera", "intel fpga",
        "lambdaconcept", "lambda concept",
    ];

    // ── DMA software / firmware files ──
    private static readonly string[] DmaFilePatterns =
    [
        "pcileech", "pcileech-fpga", "pcileech_dma",
        "screamer", "squirrel", "acorn", "lambda", "enigma",
        "dma_fw", "dma_firmware", "dma_gateware",
        "fpga_dma", "pcie_dma",
    ];

    // ── DMA-related registry keys ──
    private static readonly string[] DmaRegistryPaths =
    [
        @"SOFTWARE\PCILeech",
        @"SOFTWARE\Screamer",
        @"SOFTWARE\LambdaConcept",
        @"SYSTEM\CurrentControlSet\Services\pcileech",
        @"SYSTEM\CurrentControlSet\Services\ftdibus",
    ];

    public async Task<List<ThreatInfo>> ScanAsync(Action<LogEntry> log, CancellationToken ct)
    {
        var threats = new List<ThreatInfo>();

        log(new LogEntry { Level = LogLevel.Info, Message = "Scanning for DMA cheat hardware and software...", Source = Name });

        await Task.Run(() =>
        {
            ScanPciDevices(threats, log, ct);
            ct.ThrowIfCancellationRequested();
            CheckThunderbolt(threats, log, ct);
            ct.ThrowIfCancellationRequested();
            CheckUsbDmaAdapters(threats, log, ct);
            ct.ThrowIfCancellationRequested();
            ScanDmaFiles(threats, log, ct);
            ct.ThrowIfCancellationRequested();
            ScanDmaRegistry(threats, log, ct);
            ct.ThrowIfCancellationRequested();
            CheckIommuStatus(threats, log, ct);
        }, ct);

        log(new LogEntry
        {
            Level = threats.Count > 0 ? LogLevel.Error : LogLevel.Success,
            Message = $"DMA scan complete: {threats.Count} threat(s) found",
            Source = Name
        });

        return threats;
    }

    private void ScanPciDevices(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "Scanning PCIe bus for DMA/FPGA devices...", Source = Name });

        int deviceCount = 0;
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT * FROM Win32_PnPEntity WHERE DeviceID LIKE 'PCI%'");

            foreach (var obj in searcher.Get())
            {
                ct.ThrowIfCancellationRequested();
                deviceCount++;

                string deviceId = obj["DeviceID"]?.ToString() ?? "";
                string name = obj["Name"]?.ToString() ?? "";
                string description = obj["Description"]?.ToString() ?? "";
                string status = obj["Status"]?.ToString() ?? "";

                if (seen.Contains(deviceId)) continue;

                // Check vendor ID
                foreach (var vid in SuspiciousPciVendorIds)
                {
                    if (deviceId.Contains(vid, StringComparison.OrdinalIgnoreCase))
                    {
                        seen.Add(deviceId);
                        threats.Add(new ThreatInfo
                        {
                            Name = string.IsNullOrEmpty(name) ? vid : name,
                            Description = $"PCI device with DMA-related vendor ID: {vid}",
                            Severity = ThreatSeverity.Critical,
                            Category = ThreatCategory.DmaDevice,
                            Details = $"DeviceID: {deviceId}\nStatus: {status}\nVendor IDs like {vid} are used in FPGA/DMA hardware (PCILeech, Screamer, etc.)"
                        });
                        log(new LogEntry { Level = LogLevel.Error, Message = $"DMA HARDWARE: {vid} — {name}", Source = Name });
                        break;
                    }
                }

                // Check device ID (FT601, Xilinx, etc.)
                foreach (var did in SuspiciousPciDeviceIds)
                {
                    if (deviceId.Contains(did, StringComparison.OrdinalIgnoreCase) && !seen.Contains(deviceId))
                    {
                        seen.Add(deviceId);
                        threats.Add(new ThreatInfo
                        {
                            Name = name,
                            Description = $"PCI device with known DMA chip ID: {did}",
                            Severity = ThreatSeverity.Critical,
                            Category = ThreatCategory.DmaDevice,
                            Details = $"DeviceID: {deviceId}\n{did} is used in DMA adapters (FT601=Screamer, Xilinx=FPGA DMA)"
                        });
                        log(new LogEntry { Level = LogLevel.Error, Message = $"DMA CHIP: {did} — {name}", Source = Name });
                        break;
                    }
                }

                // Check name patterns
                string combined = $"{name} {description}".ToLowerInvariant();
                foreach (var pattern in SuspiciousDeviceNamePatterns)
                {
                    if (combined.Contains(pattern) && !seen.Contains(deviceId))
                    {
                        seen.Add(deviceId);
                        threats.Add(new ThreatInfo
                        {
                            Name = name,
                            Description = $"Device name matches DMA pattern: \"{pattern}\"",
                            Severity = ThreatSeverity.Critical,
                            Category = ThreatCategory.DmaDevice,
                            Details = $"DeviceID: {deviceId}\nDesc: {description}"
                        });
                        log(new LogEntry { Level = LogLevel.Error, Message = $"DMA pattern: {name}", Source = Name });
                        break;
                    }
                }
            }

            log(new LogEntry { Level = LogLevel.Info, Message = $"Enumerated {deviceCount} PCI devices", Source = Name });
        }
        catch (Exception ex)
        {
            log(new LogEntry { Level = LogLevel.Warning, Message = $"PCI scan failed: {ex.Message}", Source = Name });
        }
    }

    private void CheckThunderbolt(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "Checking Thunderbolt / USB4 controllers...", Source = Name });

        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT * FROM Win32_PnPEntity WHERE Name LIKE '%Thunderbolt%' OR Name LIKE '%USB4%' OR Name LIKE '%USB 4%'");

            foreach (var obj in searcher.Get())
            {
                ct.ThrowIfCancellationRequested();
                string name = obj["Name"]?.ToString() ?? "";
                string deviceId = obj["DeviceID"]?.ToString() ?? "";

                threats.Add(new ThreatInfo
                {
                    Name = name,
                    Description = "Thunderbolt/USB4 controller — DMA attack vector (no IOMMU isolation)",
                    Severity = ThreatSeverity.High,
                    Category = ThreatCategory.DmaDevice,
                    Details = $"DeviceID: {deviceId}\nThunderbolt allows direct PCIe DMA from external devices"
                });
                log(new LogEntry { Level = LogLevel.Warning, Message = $"Thunderbolt: {name}", Source = Name });
            }
        }
        catch { }
    }

    private void CheckUsbDmaAdapters(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "Checking USB devices for DMA adapters (FT601, FPGA)...", Source = Name });

        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT * FROM Win32_PnPEntity WHERE DeviceID LIKE 'USB%'");

            foreach (var obj in searcher.Get())
            {
                ct.ThrowIfCancellationRequested();
                string deviceId = obj["DeviceID"]?.ToString() ?? "";
                string name = obj["Name"]?.ToString() ?? "";
                string desc = obj["Description"]?.ToString() ?? "";
                string combined = $"{name} {desc}".ToLowerInvariant();

                // FT601/FT600 — used in Screamer PCIe Squirrel (VID 0403, PID 6010/6006)
                if (deviceId.Contains("VID_0403", StringComparison.OrdinalIgnoreCase) &&
                    (deviceId.Contains("PID_6010", StringComparison.OrdinalIgnoreCase) ||
                     deviceId.Contains("PID_6006", StringComparison.OrdinalIgnoreCase) ||
                     deviceId.Contains("6010", StringComparison.OrdinalIgnoreCase) ||
                     deviceId.Contains("6006", StringComparison.OrdinalIgnoreCase)))
                {
                    threats.Add(new ThreatInfo
                    {
                        Name = name,
                        Description = "FT601/FT600 USB-PCIe bridge — used in DMA hardware (Screamer)",
                        Severity = ThreatSeverity.Critical,
                        Category = ThreatCategory.DmaDevice,
                        Details = $"DeviceID: {deviceId}\nFT601 is the USB interface for Screamer PCIe Squirrel DMA adapter"
                    });
                    log(new LogEntry { Level = LogLevel.Error, Message = $"DMA USB: FT601 — {name}", Source = Name });
                }

                // Xilinx/Altera USB (JTAG, etc.)
                if ((deviceId.Contains("VID_10EE", StringComparison.OrdinalIgnoreCase) ||
                     deviceId.Contains("VID_09FB", StringComparison.OrdinalIgnoreCase)) &&
                    combined.Contains("fpga", StringComparison.OrdinalIgnoreCase) == false)
                {
                    threats.Add(new ThreatInfo
                    {
                        Name = name,
                        Description = "FPGA USB device (Xilinx/Altera) — DMA programming interface",
                        Severity = ThreatSeverity.High,
                        Category = ThreatCategory.DmaDevice,
                        Details = $"DeviceID: {deviceId}"
                    });
                    log(new LogEntry { Level = LogLevel.Warning, Message = $"FPGA USB: {name}", Source = Name });
                }
            }
        }
        catch (Exception ex)
        {
            log(new LogEntry { Level = LogLevel.Debug, Message = $"USB DMA check: {ex.Message}", Source = Name });
        }
    }

    private void ScanDmaFiles(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "Scanning for DMA software (PCILeech, etc.)...", Source = Name });

        string[] dirs =
        [
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Desktop"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)),
        ];

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var dir in dirs)
        {
            if (!Directory.Exists(dir)) continue;

            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*.*", new System.IO.EnumerationOptions
                {
                    RecurseSubdirectories = true,
                    MaxRecursionDepth = 4,
                    IgnoreInaccessible = true
                }))
                {
                    ct.ThrowIfCancellationRequested();
                    string name = Path.GetFileNameWithoutExtension(file).ToLowerInvariant();
                    string ext = Path.GetExtension(file).ToLowerInvariant();
                    if (ext is not ".exe" and not ".bit" and not ".bin" and not ".rbf" and not ".py" and not ".zip") continue;

                    foreach (var pattern in DmaFilePatterns)
                    {
                        if (name.Contains(pattern.Replace(" ", "")))
                        {
                            string key = $"{file}|{pattern}";
                            if (seen.Add(key))
                            {
                                threats.Add(new ThreatInfo
                                {
                                    Name = Path.GetFileName(file),
                                    Description = $"DMA-related file: \"{pattern}\"",
                                    Severity = ThreatSeverity.Critical,
                                    Category = ThreatCategory.DmaDevice,
                                    Details = $"Path: {file}\n.bit/.rbf = FPGA bitstream, .py = PCILeech scripts"
                                });
                                log(new LogEntry { Level = LogLevel.Error, Message = $"DMA file: {file}", Source = Name });
                            }
                            break;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                log(new LogEntry { Level = LogLevel.Debug, Message = $"DMA file scan: {ex.Message}", Source = Name });
            }
        }
    }

    private void ScanDmaRegistry(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "Checking registry for DMA software...", Source = Name });

        foreach (var path in DmaRegistryPaths)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(path);
                if (key != null)
                {
                    string keyName = path.Split('\\').Last();
                    threats.Add(new ThreatInfo
                    {
                        Name = $"Registry: {keyName}",
                        Description = "DMA software registry key found",
                        Severity = ThreatSeverity.Critical,
                        Category = ThreatCategory.DmaDevice,
                        Details = $"HKLM\\{path}"
                    });
                    log(new LogEntry { Level = LogLevel.Error, Message = $"DMA registry: HKLM\\{path}", Source = Name });
                }
            }
            catch { }
        }
    }

    private void CheckIommuStatus(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "Checking virtualization (VT-x/AMD-V)...", Source = Name });

        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT * FROM Win32_Processor");

            foreach (var obj in searcher.Get())
            {
                ct.ThrowIfCancellationRequested();
                bool virt = obj["VirtualizationFirmwareEnabled"] is true;
                if (!virt)
                {
                    threats.Add(new ThreatInfo
                    {
                        Name = "Virtualization disabled",
                        Description = "VT-x/AMD-V not enabled — IOMMU/VT-d often disabled too, easing DMA attacks",
                        Severity = ThreatSeverity.Low,
                        Category = ThreatCategory.DmaDevice,
                        Details = "Enable VT-d/IOMMU in BIOS to mitigate DMA attacks"
                    });
                    log(new LogEntry { Level = LogLevel.Info, Message = "Virtualization: disabled", Source = Name });
                }
                break;
            }
        }
        catch (Exception ex)
        {
            log(new LogEntry { Level = LogLevel.Debug, Message = $"VT check: {ex.Message}", Source = Name });
        }
    }
}
