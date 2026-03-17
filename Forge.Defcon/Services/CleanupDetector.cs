using System.Diagnostics;
using System.IO;
using Microsoft.Win32;
using Forge.Defcon.Models;

namespace Forge.Defcon.Services;

public sealed class CleanupDetector : IScannerModule
{
    public string Name => "Cleanup Detector";

    public async Task<List<ThreatInfo>> ScanAsync(Action<LogEntry> log, CancellationToken ct)
    {
        var threats = new List<ThreatInfo>();

        log(new LogEntry { Level = LogLevel.Info, Message = "Checking for evidence of pre-scan cleanup...", Source = Name });

        await Task.Run(() =>
        {
            CheckPrefetch(threats, log, ct);
            ct.ThrowIfCancellationRequested();
            CheckEventLogs(threats, log, ct);
            ct.ThrowIfCancellationRequested();
            CheckCleaningToolExecution(threats, log, ct);
            ct.ThrowIfCancellationRequested();
            CheckRecentFiles(threats, log, ct);
            ct.ThrowIfCancellationRequested();
            CheckSystemRestore(threats, log, ct);
        }, ct);

        log(new LogEntry
        {
            Level = LogLevel.Success,
            Message = $"Cleanup detection complete: {threats.Count} indicators",
            Source = Name
        });

        return threats;
    }

    private void CheckPrefetch(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "Checking Prefetch folder...", Source = Name });

        string prefetchDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");

        if (!Directory.Exists(prefetchDir))
        {
            log(new LogEntry { Level = LogLevel.Info, Message = "Prefetch folder not found (may be disabled on SSD)", Source = Name });
            return;
        }

        try
        {
            var files = Directory.GetFiles(prefetchDir, "*.pf");
            log(new LogEntry { Level = LogLevel.Info, Message = $"Prefetch files: {files.Length}", Source = Name });

            var uptime = TimeSpan.FromMilliseconds(Environment.TickCount64);
            bool freshBoot = uptime.TotalHours < 1;

            if (files.Length < 10 && !freshBoot && uptime.TotalDays > 1)
            {
                threats.Add(new ThreatInfo
                {
                    Name = "Prefetch Cleared",
                    Description = $"Only {files.Length} prefetch files (system uptime: {uptime.TotalHours:F0}h) — likely cleared",
                    Severity = ThreatSeverity.Critical,
                    Category = ThreatCategory.CleanupEvidence,
                    Details = $"Count: {files.Length} | Uptime: {uptime}"
                });
                log(new LogEntry { Level = LogLevel.Error, Message = $"Low prefetch count: {files.Length} (uptime {uptime.TotalHours:F0}h)", Source = Name });
            }

            if (files.Length > 5)
            {
                var oldest = files.Min(f => File.GetCreationTime(f));
                var newest = files.Max(f => File.GetCreationTime(f));
                var span = newest - oldest;

                if (span.TotalHours < 1 && !freshBoot)
                {
                    threats.Add(new ThreatInfo
                    {
                        Name = "Prefetch Regenerated",
                        Description = $"All prefetch files created within {span.TotalMinutes:F0} min — cleared and rebuilt",
                        Severity = ThreatSeverity.High,
                        Category = ThreatCategory.CleanupEvidence,
                        Details = $"Oldest: {oldest:g} | Newest: {newest:g}"
                    });
                    log(new LogEntry { Level = LogLevel.Error, Message = $"Prefetch timespan: {span.TotalMinutes:F0} min", Source = Name });
                }
            }

            foreach (var file in files)
            {
                string fname = Path.GetFileName(file).ToUpperInvariant();
                if (fname.Contains("CCLEANER") || fname.Contains("BLEACHBIT") ||
                    fname.Contains("PRIVAZER") || fname.Contains("ERASER"))
                {
                    var lastWrite = File.GetLastWriteTime(file);
                    bool recent = (DateTime.Now - lastWrite).TotalDays < 3;

                    if (recent)
                    {
                        threats.Add(new ThreatInfo
                        {
                            Name = "Recent Cleanup Tool Usage",
                            Description = $"Cleanup tool ran recently: {Path.GetFileName(file)}",
                            Severity = ThreatSeverity.High,
                            Category = ThreatCategory.CleanupEvidence,
                            Details = $"File: {file} | Last run: {lastWrite:g}"
                        });
                        log(new LogEntry { Level = LogLevel.Error, Message = $"Recent cleanup tool: {Path.GetFileName(file)} ({lastWrite:g})", Source = Name });
                    }
                }
            }
        }
        catch (Exception ex)
        {
            log(new LogEntry { Level = LogLevel.Warning, Message = $"Prefetch check failed: {ex.Message}", Source = Name });
        }
    }

    private void CheckEventLogs(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "Checking Windows Event Logs for clear events...", Source = Name });

        try
        {
            var eventLogs = new[] { "System", "Security" };
            foreach (var logName in eventLogs)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using var evtLog = new EventLog(logName);
                    int entryCount = evtLog.Entries.Count;

                    log(new LogEntry { Level = LogLevel.Info, Message = $"{logName} log: {entryCount} entries", Source = Name });

                    if (entryCount > 0)
                    {
                        int startIdx = Math.Max(0, entryCount - 200);
                        for (int i = startIdx; i < entryCount; i++)
                        {
                            try
                            {
                                var entry = evtLog.Entries[i];
                                long id = entry.InstanceId;
                                if ((id == 104 || id == 1102) &&
                                    entry.TimeGenerated > DateTime.Now.AddDays(-7))
                                {
                                    threats.Add(new ThreatInfo
                                    {
                                        Name = "Event Log Cleared",
                                        Description = $"{logName} log was cleared on {entry.TimeGenerated:g}",
                                        Severity = ThreatSeverity.Critical,
                                        Category = ThreatCategory.CleanupEvidence,
                                        Details = $"InstanceID: {id} | Time: {entry.TimeGenerated:g}"
                                    });
                                    log(new LogEntry { Level = LogLevel.Error, Message = $"Log cleared: {logName} at {entry.TimeGenerated:g}", Source = Name });
                                    break;
                                }
                            }
                            catch { }
                        }
                    }
                }
                catch { }
            }
        }
        catch (Exception ex)
        {
            log(new LogEntry { Level = LogLevel.Warning, Message = $"Event log check failed: {ex.Message}", Source = Name });
        }
    }

    private void CheckCleaningToolExecution(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "Checking for recent cleaning tool activity...", Source = Name });

        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Piriform\CCleaner");
            if (key != null)
            {
                log(new LogEntry { Level = LogLevel.Info, Message = "CCleaner is installed (noted)", Source = Name });
            }
        }
        catch { }

        string[] cleanerProcesses = ["ccleaner", "ccleaner64", "bleachbit", "privazer"];
        try
        {
            foreach (var proc in Process.GetProcesses())
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    string name = proc.ProcessName.ToLowerInvariant();
                    foreach (var cleaner in cleanerProcesses)
                    {
                        if (name.Contains(cleaner))
                        {
                            threats.Add(new ThreatInfo
                            {
                                Name = $"Cleaning Tool Running: {proc.ProcessName}",
                                Description = $"Cleanup tool is currently running (PID: {proc.Id})",
                                Severity = ThreatSeverity.Critical,
                                Category = ThreatCategory.CleanupEvidence,
                                Details = $"Process: {proc.ProcessName} | PID: {proc.Id}"
                            });
                            log(new LogEntry { Level = LogLevel.Error, Message = $"Cleaning tool running: {proc.ProcessName}", Source = Name });
                            break;
                        }
                    }
                }
                catch { }
                finally { proc.Dispose(); }
            }
        }
        catch { }
    }

    private void CheckRecentFiles(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "Checking Recent Files folder...", Source = Name });

        string recentDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "Microsoft", "Windows", "Recent");

        if (!Directory.Exists(recentDir)) return;

        try
        {
            var files = Directory.GetFiles(recentDir, "*.lnk");
            log(new LogEntry { Level = LogLevel.Info, Message = $"Recent files count: {files.Length}", Source = Name });

            if (files.Length == 0)
            {
                threats.Add(new ThreatInfo
                {
                    Name = "Recent Files Empty",
                    Description = "Recent Files folder is completely empty — likely cleared",
                    Severity = ThreatSeverity.Medium,
                    Category = ThreatCategory.CleanupEvidence,
                    Details = $"Path: {recentDir}"
                });
                log(new LogEntry { Level = LogLevel.Warning, Message = "Recent files folder is empty", Source = Name });
            }
        }
        catch { }
    }

    private void CheckSystemRestore(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "Checking System Restore...", Source = Name });

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore");

            if (key != null)
            {
                var disabled = key.GetValue("RPSessionInterval");
                if (disabled is int val && val == 0)
                {
                    threats.Add(new ThreatInfo
                    {
                        Name = "System Restore Disabled",
                        Description = "System Restore is disabled",
                        Severity = ThreatSeverity.Low,
                        Category = ThreatCategory.CleanupEvidence,
                        Details = "RPSessionInterval = 0"
                    });
                    log(new LogEntry { Level = LogLevel.Info, Message = "System Restore is disabled", Source = Name });
                }
            }
        }
        catch { }
    }
}
