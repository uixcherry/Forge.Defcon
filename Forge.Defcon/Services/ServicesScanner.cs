using System.ServiceProcess;
using System.IO;
using Forge.Defcon.Models;

namespace Forge.Defcon.Services;

public sealed class ServicesScanner : IScannerModule
{
    public string Name => "Suspicious Services";

    private static readonly string[] SuspiciousServicePatterns =
    [
        "cheat", "hack", "inject", "spoofer",
        "hwid", "bypass", "loader", "mapper",
        "kdmapper", "drvmap", "pcileech",
        "dma", "fpga", "external",
    ];

    private static readonly string[] SafeServicePatterns =
    [
        "microsoft", "windows", "wpn", "wdi",
        "defender", "security", "update",
        "nvidia", "amd", "intel",
        "sql", "iis", "w3svc",
    ];

    public async Task<List<ThreatInfo>> ScanAsync(Action<LogEntry> log, CancellationToken ct)
    {
        var threats = new List<ThreatInfo>();

        log(new LogEntry { Level = LogLevel.Info, Message = "Scanning Windows services for cheat-related entries...", Source = Name });

        await Task.Run(() =>
        {
            ScanServices(threats, log, ct);
            ct.ThrowIfCancellationRequested();
            ScanServiceBinaries(threats, log, ct);
        }, ct);

        log(new LogEntry
        {
            Level = threats.Count > 0 ? LogLevel.Warning : LogLevel.Success,
            Message = $"Services scan complete: {threats.Count} findings",
            Source = Name
        });

        return threats;
    }

    private void ScanServices(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "Enumerating Windows services...", Source = Name });

        try
        {
            foreach (var svc in ServiceController.GetServices())
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    string name = svc.ServiceName.ToLowerInvariant();
                    string display = svc.DisplayName.ToLowerInvariant();
                    string combined = $"{name} {display}";

                    if (IsSafeService(combined))
                        continue;

                    foreach (var pattern in SuspiciousServicePatterns)
                    {
                        if (combined.Contains(pattern))
                        {
                            threats.Add(new ThreatInfo
                            {
                                Name = $"Service: {svc.DisplayName}",
                                Description = $"Suspicious service (pattern: {pattern})",
                                Severity = ThreatSeverity.High,
                                Category = ThreatCategory.SuspiciousService,
                                Details = $"Name: {svc.ServiceName}\nDisplay: {svc.DisplayName}\nStatus: {svc.Status}"
                            });
                            log(new LogEntry { Level = LogLevel.Error, Message = $"Suspicious service: {svc.ServiceName} — {svc.DisplayName}", Source = Name });
                            break;
                        }
                    }
                }
                finally { svc.Dispose(); }
            }
        }
        catch (Exception ex)
        {
            log(new LogEntry { Level = LogLevel.Warning, Message = $"Service enumeration error: {ex.Message}", Source = Name });
        }
    }

    private void ScanServiceBinaries(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "Checking service binaries in non-standard locations...", Source = Name });

        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services");
            if (key == null) return;

            foreach (var svcName in key.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using var svcKey = key.OpenSubKey(svcName);
                    string? imagePath = svcKey?.GetValue("ImagePath")?.ToString();
                    if (string.IsNullOrEmpty(imagePath)) continue;

                    imagePath = imagePath.TrimStart('"').Split('"')[0].Trim();
                    if (imagePath.StartsWith("\\??\\")) imagePath = imagePath[4..];
                    if (imagePath.StartsWith("systemroot", StringComparison.OrdinalIgnoreCase))
                        imagePath = Path.Combine(
                            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                            imagePath[11..].TrimStart('\\'));

                    string fullPath = Path.GetFullPath(imagePath);
                    string systemRoot = Environment.GetFolderPath(Environment.SpecialFolder.Windows);

                    if (fullPath.StartsWith(systemRoot, StringComparison.OrdinalIgnoreCase))
                        continue;

                    string dir = Path.GetDirectoryName(fullPath)?.ToLowerInvariant() ?? "";
                    if (dir.Contains("program files") || dir.Contains("windows"))
                        continue;

                    foreach (var pattern in SuspiciousServicePatterns)
                    {
                        if (dir.Contains(pattern) || Path.GetFileName(fullPath).ToLowerInvariant().Contains(pattern))
                        {
                            threats.Add(new ThreatInfo
                            {
                                Name = $"Service from user path: {svcName}",
                                Description = "Service binary in non-standard location",
                                Severity = ThreatSeverity.Critical,
                                Category = ThreatCategory.SuspiciousService,
                                Details = $"Service: {svcName}\nPath: {fullPath}"
                            });
                            log(new LogEntry { Level = LogLevel.Error, Message = $"Service in user path: {svcName} → {fullPath}", Source = Name });
                            break;
                        }
                    }
                }
                catch { }
            }
        }
        catch (Exception ex)
        {
            log(new LogEntry { Level = LogLevel.Debug, Message = $"Binary scan: {ex.Message}", Source = Name });
        }
    }

    private static bool IsSafeService(string combined)
    {
        foreach (var safe in SafeServicePatterns)
        {
            if (combined.Contains(safe))
                return true;
        }
        return false;
    }
}
