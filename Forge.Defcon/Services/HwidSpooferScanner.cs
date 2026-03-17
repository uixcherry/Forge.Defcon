using System.Diagnostics;
using System.IO;
using Microsoft.Win32;
using Forge.Defcon.Models;

namespace Forge.Defcon.Services;

public sealed class HwidSpooferScanner : IScannerModule
{
    public string Name => "HWID Spoofer";

    private static readonly HashSet<string> SpooferProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "antifakhwid", "antifak-hwid", "anti-fak-hwid",
        "hwidspoofer", "hwid spoofer", "hwidchanger",
        "hwid changer", "hwidgen", "hwid gen",
        "spoofer", "hwidkiller", "hwid killer",
        "serialspoofer", "serial spoofer",
        "diskid", "volumeid", "macchanger",
        "smbiosspoofer", "smbios spoofer",
    };

    private static readonly string[] SpooferFilePatterns =
    [
        "antifakhwid", "anti-fak-hwid", "hwidspoofer",
        "hwid spoofer", "hwidchanger", "hwid changer",
        "hwidgen", "serialspoofer", "smbiosspoofer",
        "volumeid", "diskid", "macchanger",
    ];

    private static readonly string[] SpooferRegistryPaths =
    [
        @"SOFTWARE\AntiFakHWID",
        @"SOFTWARE\HWID Spoofer",
        @"SOFTWARE\HWIDSpoofer",
        @"SOFTWARE\HWIDChanger",
        @"SOFTWARE\SerialSpoofer",
        @"SOFTWARE\SMBIOSSpoofer",
        @"SOFTWARE\WOW6432Node\AntiFakHWID",
        @"SOFTWARE\WOW6432Node\HWIDSpoofer",
    ];

    private static readonly string[] SpooferDriverNames =
    [
        "hwidspoof", "hwid_spoof", "serialspoof",
        "smbiosspoof", "diskidspoof", "volumespoof",
    ];

    public async Task<List<ThreatInfo>> ScanAsync(Action<LogEntry> log, CancellationToken ct)
    {
        var threats = new List<ThreatInfo>();

        log(new LogEntry { Level = LogLevel.Info, Message = "Scanning for HWID spoofer tools (AntiFakHWID, etc.)...", Source = Name });

        await Task.Run(() =>
        {
            ScanRunningProcesses(threats, log, ct);
            ct.ThrowIfCancellationRequested();
            ScanFiles(threats, log, ct);
            ct.ThrowIfCancellationRequested();
            ScanRegistry(threats, log, ct);
            ct.ThrowIfCancellationRequested();
            ScanDrivers(threats, log, ct);
        }, ct);

        log(new LogEntry
        {
            Level = threats.Count > 0 ? LogLevel.Error : LogLevel.Success,
            Message = $"HWID Spoofer scan complete: {threats.Count} findings",
            Source = Name
        });

        return threats;
    }

    private void ScanRunningProcesses(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "Checking running processes...", Source = Name });

        try
        {
            foreach (var proc in Process.GetProcesses())
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    string name = proc.ProcessName.ToLowerInvariant();
                    if (SpooferProcessNames.Contains(name))
                    {
                        string path = GetProcessPath(proc);
                        threats.Add(new ThreatInfo
                        {
                            Name = $"HWID Spoofer process: {proc.ProcessName}",
                            Description = "Known HWID spoofer tool is running",
                            Severity = ThreatSeverity.Critical,
                            Category = ThreatCategory.HwidSpoofer,
                            Details = $"PID: {proc.Id} | Path: {path}"
                        });
                        log(new LogEntry { Level = LogLevel.Error, Message = $"Spoofer process running: {proc.ProcessName} (PID {proc.Id})", Source = Name });
                    }
                }
                finally { proc.Dispose(); }
            }
        }
        catch (Exception ex)
        {
            log(new LogEntry { Level = LogLevel.Warning, Message = $"Process scan error: {ex.Message}", Source = Name });
        }
    }

    private void ScanFiles(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "Scanning for spoofer files...", Source = Name });

        string[] dirs =
        [
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)),
        ];

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var dir in dirs)
        {
            if (!Directory.Exists(dir)) continue;

            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*.*", new EnumerationOptions
                {
                    RecurseSubdirectories = true,
                    MaxRecursionDepth = 3,
                    IgnoreInaccessible = true
                }))
                {
                    ct.ThrowIfCancellationRequested();
                    string name = Path.GetFileNameWithoutExtension(file).ToLowerInvariant();
                    string ext = Path.GetExtension(file).ToLowerInvariant();
                    if (ext is not ".exe" and not ".dll" and not ".sys") continue;

                    foreach (var pattern in SpooferFilePatterns)
                    {
                        if (name.Contains(pattern.Replace(" ", "")))
                        {
                            string key = $"{file}|{pattern}";
                            if (seen.Add(key))
                            {
                                threats.Add(new ThreatInfo
                                {
                                    Name = $"Spoofer file: {Path.GetFileName(file)}",
                                    Description = $"HWID spoofer tool file detected (pattern: {pattern})",
                                    Severity = ThreatSeverity.High,
                                    Category = ThreatCategory.HwidSpoofer,
                                    Details = $"Path: {file}"
                                });
                                log(new LogEntry { Level = LogLevel.Error, Message = $"Spoofer file: {file}", Source = Name });
                            }
                            break;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                log(new LogEntry { Level = LogLevel.Debug, Message = $"Cannot scan {dir}: {ex.Message}", Source = Name });
            }
        }
    }

    private void ScanRegistry(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "Checking registry for spoofer keys...", Source = Name });

        foreach (var path in SpooferRegistryPaths)
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
                        Description = "HWID spoofer registry key found",
                        Severity = ThreatSeverity.Critical,
                        Category = ThreatCategory.HwidSpoofer,
                        Details = $"HKLM\\{path}"
                    });
                    log(new LogEntry { Level = LogLevel.Error, Message = $"Spoofer registry: HKLM\\{path}", Source = Name });
                }
            }
            catch { }

            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(path);
                if (key != null)
                {
                    string keyName = path.Split('\\').Last();
                    threats.Add(new ThreatInfo
                    {
                        Name = $"Registry: {keyName}",
                        Description = "HWID spoofer registry key found",
                        Severity = ThreatSeverity.Critical,
                        Category = ThreatCategory.HwidSpoofer,
                        Details = $"HKCU\\{path}"
                    });
                    log(new LogEntry { Level = LogLevel.Error, Message = $"Spoofer registry: HKCU\\{path}", Source = Name });
                }
            }
            catch { }
        }
    }

    private void ScanDrivers(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "Checking for spoofer drivers...", Source = Name });

        try
        {
            string driverPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                "System32", "drivers");

            if (!Directory.Exists(driverPath)) return;

            foreach (var file in Directory.GetFiles(driverPath, "*.sys"))
            {
                ct.ThrowIfCancellationRequested();
                string name = Path.GetFileNameWithoutExtension(file).ToLowerInvariant();
                foreach (var pattern in SpooferDriverNames)
                {
                    if (name.Contains(pattern))
                    {
                        threats.Add(new ThreatInfo
                        {
                            Name = $"Driver: {Path.GetFileName(file)}",
                            Description = "Possible HWID spoofer driver",
                            Severity = ThreatSeverity.Critical,
                            Category = ThreatCategory.HwidSpoofer,
                            Details = $"Path: {file}"
                        });
                        log(new LogEntry { Level = LogLevel.Error, Message = $"Spoofer driver: {file}", Source = Name });
                        break;
                    }
                }
            }
        }
        catch (Exception ex)
        {
            log(new LogEntry { Level = LogLevel.Debug, Message = $"Driver scan error: {ex.Message}", Source = Name });
        }
    }

    private static string GetProcessPath(Process proc)
    {
        try { return proc.MainModule?.FileName ?? ""; }
        catch { return ""; }
    }
}
