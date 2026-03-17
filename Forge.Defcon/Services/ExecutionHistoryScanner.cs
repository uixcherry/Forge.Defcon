using System.IO;
using Microsoft.Win32;
using Forge.Defcon.Models;

namespace Forge.Defcon.Services;

public sealed class ExecutionHistoryScanner : IScannerModule
{
    public string Name => "Execution History";

    private static readonly string[] CheatToolNames =
    [
        "cheatengine", "cheat engine",
        "extremeinjector", "extreme injector",
        "xenos", "x64dbg", "x32dbg",
        "processhacker", "process hacker", "systeminformer",
        "ida64", "ida pro", "ghidra",
        "dnspy", "dotpeek", "ilspy",
        "wemod", "plitch", "cosmos",
        "kdmapper", "drvmap",
        "pcileech", "fpga",
        "scylla", "megadumper",
        "reclass",
        "artmoney",
        "rweverything",
        "wireshark", "fiddler",
        "httpdebuggerpro",
        "hxd", "010editor",
        "autohotkey", "autoit",
        "spoofer", "hwid",
        "injector", "trainer",
        "speedhack",
    ];

    public async Task<List<ThreatInfo>> ScanAsync(Action<LogEntry> log, CancellationToken ct)
    {
        var threats = new List<ThreatInfo>();

        log(new LogEntry { Level = LogLevel.Info, Message = "Scanning program execution history...", Source = Name });

        await Task.Run(() =>
        {
            ScanPrefetchHistory(threats, log, ct);
            ct.ThrowIfCancellationRequested();
            ScanAmCache(threats, log, ct);
            ct.ThrowIfCancellationRequested();
            ScanMuiCache(threats, log, ct);
            ct.ThrowIfCancellationRequested();
            ScanRecentApps(threats, log, ct);
        }, ct);

        log(new LogEntry { Level = LogLevel.Success, Message = $"Execution history scan: {threats.Count} findings", Source = Name });
        return threats;
    }

    private void ScanPrefetchHistory(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "Checking Prefetch for cheat tool execution...", Source = Name });

        string prefetchDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");

        if (!Directory.Exists(prefetchDir)) return;

        try
        {
            var pfFiles = Directory.GetFiles(prefetchDir, "*.pf");
            int hits = 0;

            foreach (var pf in pfFiles)
            {
                ct.ThrowIfCancellationRequested();
                string fname = Path.GetFileName(pf).ToLowerInvariant();

                foreach (var tool in CheatToolNames)
                {
                    if (fname.Contains(tool.Replace(" ", "")))
                    {
                        hits++;
                        var lastRun = File.GetLastWriteTime(pf);
                        bool recent = (DateTime.Now - lastRun).TotalDays < 14;

                        threats.Add(new ThreatInfo
                        {
                            Name = $"Prefetch: {Path.GetFileName(pf)}",
                            Description = $"Cheat tool was executed{(recent ? " recently" : "")} (last: {lastRun:d})",
                            Severity = recent ? ThreatSeverity.Critical : ThreatSeverity.High,
                            Category = ThreatCategory.ProhibitedSoftware,
                            Details = $"File: {pf} | Last run: {lastRun:g}"
                        });
                        log(new LogEntry
                        {
                            Level = LogLevel.Error,
                            Message = $"Prefetch evidence: {Path.GetFileName(pf)} (last: {lastRun:g})",
                            Source = Name
                        });
                        break;
                    }
                }
            }

            log(new LogEntry { Level = LogLevel.Info, Message = $"Prefetch: {pfFiles.Length} files, {hits} cheat matches", Source = Name });
        }
        catch (Exception ex)
        {
            log(new LogEntry { Level = LogLevel.Warning, Message = $"Prefetch scan failed: {ex.Message}", Source = Name });
        }
    }

    private void ScanAmCache(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "Checking AmCache for execution evidence...", Source = Name });

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store");

            if (key == null) return;

            var entries = key.GetValueNames();
            int hits = 0;

            foreach (var entry in entries)
            {
                ct.ThrowIfCancellationRequested();
                string lower = entry.ToLowerInvariant();

                foreach (var tool in CheatToolNames)
                {
                    if (lower.Contains(tool.Replace(" ", "")))
                    {
                        hits++;
                        threats.Add(new ThreatInfo
                        {
                            Name = $"AppCompat: {Path.GetFileName(entry)}",
                            Description = "Cheat tool execution recorded in AppCompatFlags",
                            Severity = ThreatSeverity.High,
                            Category = ThreatCategory.ProhibitedSoftware,
                            Details = $"Path: {entry}"
                        });
                        log(new LogEntry { Level = LogLevel.Error, Message = $"AppCompat evidence: {entry}", Source = Name });
                        break;
                    }
                }
            }

            log(new LogEntry { Level = LogLevel.Info, Message = $"AppCompat: {entries.Length} entries, {hits} matches", Source = Name });
        }
        catch { }
    }

    private void ScanMuiCache(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "Checking MuiCache for execution evidence...", Source = Name });

        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(
                @"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache");

            if (key == null) return;

            var entries = key.GetValueNames();
            int hits = 0;

            foreach (var entry in entries)
            {
                ct.ThrowIfCancellationRequested();
                string lower = entry.ToLowerInvariant();

                foreach (var tool in CheatToolNames)
                {
                    if (lower.Contains(tool.Replace(" ", "")))
                    {
                        hits++;
                        string? displayName = key.GetValue(entry)?.ToString();
                        threats.Add(new ThreatInfo
                        {
                            Name = $"MuiCache: {displayName ?? Path.GetFileName(entry)}",
                            Description = "Cheat tool execution recorded in MuiCache",
                            Severity = ThreatSeverity.High,
                            Category = ThreatCategory.ProhibitedSoftware,
                            Details = $"Path: {entry}"
                        });
                        log(new LogEntry { Level = LogLevel.Error, Message = $"MuiCache evidence: {entry}", Source = Name });
                        break;
                    }
                }
            }

            log(new LogEntry { Level = LogLevel.Info, Message = $"MuiCache: {entries.Length} entries, {hits} matches", Source = Name });
        }
        catch { }
    }

    private void ScanRecentApps(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "Checking RecentApps registry...", Source = Name });

        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Search\RecentApps");

            if (key == null) return;

            foreach (var guid in key.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using var appKey = key.OpenSubKey(guid);
                    string? appPath = appKey?.GetValue("AppPath")?.ToString();
                    if (string.IsNullOrEmpty(appPath)) continue;

                    string lower = appPath.ToLowerInvariant();
                    foreach (var tool in CheatToolNames)
                    {
                        if (lower.Contains(tool.Replace(" ", "")))
                        {
                            threats.Add(new ThreatInfo
                            {
                                Name = $"RecentApp: {Path.GetFileName(appPath)}",
                                Description = "Cheat tool found in Windows recent apps",
                                Severity = ThreatSeverity.High,
                                Category = ThreatCategory.ProhibitedSoftware,
                                Details = $"Path: {appPath}"
                            });
                            log(new LogEntry { Level = LogLevel.Error, Message = $"RecentApp evidence: {appPath}", Source = Name });
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
