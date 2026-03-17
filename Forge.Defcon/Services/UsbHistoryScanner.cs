using Microsoft.Win32;
using Forge.Defcon.Models;

namespace Forge.Defcon.Services;

public sealed class UsbHistoryScanner : IScannerModule
{
    public string Name => "USB History";

    private static readonly string[] SuspiciousUsbNames =
    [
        "rubber ducky", "rubberducky", "bash bunny",
        "lan turtle", "teensy", "digispark",
        "attiny85", "badusb", "o.mg", "omg cable",
        "flipper", "hak5",
    ];

    public async Task<List<ThreatInfo>> ScanAsync(Action<LogEntry> log, CancellationToken ct)
    {
        var threats = new List<ThreatInfo>();

        log(new LogEntry { Level = LogLevel.Info, Message = "Scanning USB device history...", Source = Name });

        await Task.Run(() =>
        {
            ScanUsbStor(threats, log, ct);
            ct.ThrowIfCancellationRequested();
            ScanMountedDevices(threats, log, ct);
            ct.ThrowIfCancellationRequested();
            ScanRecentUsbDevices(threats, log, ct);
        }, ct);

        log(new LogEntry { Level = LogLevel.Success, Message = $"USB history scan: {threats.Count} findings", Source = Name });
        return threats;
    }

    private void ScanUsbStor(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "Checking USBSTOR registry...", Source = Name });

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\USBSTOR");
            if (key == null) { log(new LogEntry { Level = LogLevel.Info, Message = "No USBSTOR entries", Source = Name }); return; }

            var devices = key.GetSubKeyNames();
            int total = 0;

            foreach (var deviceClass in devices)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using var classKey = key.OpenSubKey(deviceClass);
                    if (classKey == null) continue;

                    foreach (var serial in classKey.GetSubKeyNames())
                    {
                        total++;
                        using var devKey = classKey.OpenSubKey(serial);
                        string? friendlyName = devKey?.GetValue("FriendlyName")?.ToString();
                        string desc = friendlyName ?? deviceClass;
                        string lower = desc.ToLowerInvariant();

                        bool suspicious = false;
                        foreach (var pattern in SuspiciousUsbNames)
                        {
                            if (lower.Contains(pattern))
                            {
                                suspicious = true;
                                threats.Add(new ThreatInfo
                                {
                                    Name = desc,
                                    Description = $"Known attack USB device: \"{pattern}\"",
                                    Severity = ThreatSeverity.Critical,
                                    Category = ThreatCategory.SuspiciousDevice,
                                    Details = $"Device: {deviceClass} | Serial: {serial}"
                                });
                                log(new LogEntry { Level = LogLevel.Error, Message = $"Attack USB: {desc}", Source = Name });
                                break;
                            }
                        }

                        if (!suspicious)
                        {
                            log(new LogEntry { Level = LogLevel.Debug, Message = $"USB: {desc} [{serial[..Math.Min(8, serial.Length)]}]", Source = Name });
                        }
                    }
                }
                catch { }
            }

            log(new LogEntry { Level = LogLevel.Info, Message = $"Total USB storage devices: {total}", Source = Name });

            if (total > 20)
            {
                threats.Add(new ThreatInfo
                {
                    Name = $"High USB Device Count: {total}",
                    Description = $"{total} unique USB storage devices connected historically",
                    Severity = ThreatSeverity.Info,
                    Category = ThreatCategory.SuspiciousDevice,
                    Details = $"USBSTOR entries: {total}"
                });
            }
        }
        catch (Exception ex)
        {
            log(new LogEntry { Level = LogLevel.Warning, Message = $"USBSTOR check failed: {ex.Message}", Source = Name });
        }
    }

    private void ScanMountedDevices(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "Checking mounted device history...", Source = Name });

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\MountedDevices");
            if (key == null) return;

            int mountCount = key.GetValueNames().Count(n => n.StartsWith(@"\DosDevices\"));
            log(new LogEntry { Level = LogLevel.Info, Message = $"Mounted device entries: {mountCount}", Source = Name });
        }
        catch { }
    }

    private void ScanRecentUsbDevices(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "Checking recent USB connection times...", Source = Name });

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\USB");
            if (key == null) return;

            int total = 0;
            foreach (var vidPid in key.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using var vpKey = key.OpenSubKey(vidPid);
                    if (vpKey == null) continue;
                    total += vpKey.SubKeyCount;
                }
                catch { }
            }

            log(new LogEntry { Level = LogLevel.Info, Message = $"Total USB device entries: {total}", Source = Name });
        }
        catch { }
    }
}
