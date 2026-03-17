using System.IO;
using Microsoft.Win32;
using Forge.Defcon.Models;

namespace Forge.Defcon.Services;

public sealed class StartupScanner : IScannerModule
{
    public string Name => "Startup Scanner";

    private static readonly string[] SuspiciousPatterns =
    [
        "cheat", "hack", "trainer",
        "spoof", "mapper", "dll_inject",
        "code_inject", "aimbot", "wallhack",
    ];

    private static readonly string[] SafeTaskNames =
    [
        "monitor", "monitoring",
        "calibration", "loader",
        "service", "update", "microsoft",
        "google", "adobe", "nvidia",
        "intel", "realtek", "office",
        "defender", "security",
        "onedrive", "edge", "chrome",
        "firefox", "discord", "steam",
        "familysafety",
    ];

    public async Task<List<ThreatInfo>> ScanAsync(Action<LogEntry> log, CancellationToken ct)
    {
        var threats = new List<ThreatInfo>();

        log(new LogEntry { Level = LogLevel.Info, Message = "Scanning startup entries...", Source = Name });

        await Task.Run(() =>
        {
            ScanRunKeys(threats, log, ct);
            ct.ThrowIfCancellationRequested();
            ScanStartupFolders(threats, log, ct);
            ct.ThrowIfCancellationRequested();
            ScanScheduledTasks(threats, log, ct);
        }, ct);

        log(new LogEntry { Level = LogLevel.Success, Message = $"Startup scan complete: {threats.Count} threats", Source = Name });
        return threats;
    }

    private void ScanRunKeys(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "Checking Run/RunOnce registry keys...", Source = Name });

        (RegistryKey root, string path)[] keys =
        [
            (Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Run"),
            (Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Run"),
            (Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        ];

        int total = 0;
        foreach (var (root, path) in keys)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var key = root.OpenSubKey(path);
                if (key == null) continue;

                foreach (var name in key.GetValueNames())
                {
                    total++;
                    string? value = key.GetValue(name)?.ToString();
                    if (string.IsNullOrEmpty(value)) continue;

                    string lower = $"{name} {value}".ToLowerInvariant();

                    if (IsSafeEntry(lower)) continue;

                    foreach (var pattern in SuspiciousPatterns)
                    {
                        if (lower.Contains(pattern))
                        {
                            threats.Add(new ThreatInfo
                            {
                                Name = name,
                                Description = $"Suspicious startup entry matching \"{pattern}\"",
                                Severity = ThreatSeverity.High,
                                Category = ThreatCategory.RegistryAnomaly,
                                Details = $"Key: {path} | Value: {value}"
                            });
                            log(new LogEntry { Level = LogLevel.Error, Message = $"Suspicious startup: {name} = {value}", Source = Name });
                            break;
                        }
                    }
                }
            }
            catch { }
        }

        log(new LogEntry { Level = LogLevel.Info, Message = $"Found {total} startup entries", Source = Name });
    }

    private void ScanStartupFolders(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "Checking Startup folders...", Source = Name });

        string[] startupDirs =
        [
            Environment.GetFolderPath(Environment.SpecialFolder.Startup),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup),
        ];

        foreach (var dir in startupDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir)) continue;

            try
            {
                foreach (var file in Directory.GetFiles(dir))
                {
                    string fname = Path.GetFileName(file).ToLowerInvariant();

                    foreach (var pattern in SuspiciousPatterns)
                    {
                        if (fname.Contains(pattern))
                        {
                            threats.Add(new ThreatInfo
                            {
                                Name = Path.GetFileName(file),
                                Description = "Suspicious file in Startup folder",
                                Severity = ThreatSeverity.High,
                                Category = ThreatCategory.SuspiciousFile,
                                Details = $"Path: {file}"
                            });
                            log(new LogEntry { Level = LogLevel.Error, Message = $"Suspicious startup file: {file}", Source = Name });
                            break;
                        }
                    }
                }
            }
            catch { }
        }
    }

    private void ScanScheduledTasks(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "Checking scheduled tasks...", Source = Name });

        string tasksDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "System32", "Tasks");

        if (!Directory.Exists(tasksDir)) return;

        try
        {
            int count = 0;
            foreach (var file in Directory.EnumerateFiles(tasksDir, "*", new EnumerationOptions
            {
                RecurseSubdirectories = true,
                IgnoreInaccessible = true,
                MaxRecursionDepth = 3
            }))
            {
                ct.ThrowIfCancellationRequested();
                count++;
                string fname = Path.GetFileName(file).ToLowerInvariant();
                string fullLower = file.ToLowerInvariant();

                bool isMicrosoftTask = fullLower.Contains(@"\microsoft\");
                if (isMicrosoftTask) continue;

                foreach (var pattern in SuspiciousPatterns)
                {
                    if (fname.Contains(pattern))
                    {
                        threats.Add(new ThreatInfo
                        {
                            Name = Path.GetFileName(file),
                            Description = "Suspicious scheduled task",
                            Severity = ThreatSeverity.Medium,
                            Category = ThreatCategory.RegistryAnomaly,
                            Details = $"Path: {file}"
                        });
                        log(new LogEntry { Level = LogLevel.Warning, Message = $"Suspicious task: {file}", Source = Name });
                        break;
                    }
                }
            }

            log(new LogEntry { Level = LogLevel.Info, Message = $"Checked {count} scheduled tasks", Source = Name });
        }
        catch { }
    }

    private static bool IsSafeEntry(string lower)
    {
        foreach (var safe in SafeTaskNames)
        {
            if (lower.Contains(safe))
                return true;
        }
        return false;
    }
}
