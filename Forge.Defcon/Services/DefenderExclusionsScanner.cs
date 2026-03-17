using Microsoft.Win32;
using Forge.Defcon.Models;

namespace Forge.Defcon.Services;

public sealed class DefenderExclusionsScanner : IScannerModule
{
    public string Name => "Defender Exclusions";

    private static readonly string[] CheatRelatedPaths =
    [
        "cheat", "hack", "inject", "trainer", "wemod",
        "spoof", "bypass", "loader", "mapper", "dma",
        "aimbot", "wallhack", "esp", "bhop", "plitch",
    ];

    public async Task<List<ThreatInfo>> ScanAsync(Action<LogEntry> log, CancellationToken ct)
    {
        var threats = new List<ThreatInfo>();

        log(new LogEntry { Level = LogLevel.Info, Message = "Scanning Windows Defender exclusions...", Source = Name });

        await Task.Run(() =>
        {
            ScanPathExclusions(threats, log, ct);
            ct.ThrowIfCancellationRequested();
            ScanProcessExclusions(threats, log, ct);
            ct.ThrowIfCancellationRequested();
            ScanExtensionExclusions(threats, log, ct);
            ct.ThrowIfCancellationRequested();
            ScanPolicyExclusions(threats, log, ct);
        }, ct);

        log(new LogEntry { Level = LogLevel.Success, Message = $"Defender exclusions scan: {threats.Count} findings", Source = Name });
        return threats;
    }

    private void ScanPathExclusions(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "Checking path exclusions...", Source = Name });

        string[] regPaths =
        [
            @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths",
            @"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths",
        ];

        foreach (var regPath in regPaths)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(regPath);
                if (key == null) continue;

                var paths = key.GetValueNames();
                log(new LogEntry { Level = LogLevel.Info, Message = $"Path exclusions: {paths.Length}", Source = Name });

                foreach (var path in paths)
                {
                    if (string.IsNullOrWhiteSpace(path)) continue;
                    string lower = path.ToLowerInvariant();

                    var sev = ThreatSeverity.Info;
                    string reason = "User-configured exclusion";

                    bool isSuspicious = false;
                    foreach (var cheatWord in CheatRelatedPaths)
                    {
                        if (lower.Contains(cheatWord))
                        {
                            sev = ThreatSeverity.Critical;
                            reason = $"Exclusion contains cheat-related keyword: \"{cheatWord}\"";
                            isSuspicious = true;
                            break;
                        }
                    }

                    if (!isSuspicious)
                    {
                        bool isWholeDrive = path.Length <= 3 && path.Contains(':');
                        bool isUserRoot = lower.Contains(@"\users\") && path.Split('\\').Length <= 3;
                        bool isTemp = lower.Contains(@"\temp") || lower.Contains(@"\tmp");
                        bool isDesktop = lower.Contains(@"\desktop");
                        bool isDownloads = lower.Contains(@"\downloads");

                        if (isWholeDrive) { sev = ThreatSeverity.Critical; reason = "Entire drive excluded"; }
                        else if (isUserRoot) { sev = ThreatSeverity.High; reason = "Broad user directory excluded"; }
                        else if (isTemp || isDesktop || isDownloads) { sev = ThreatSeverity.High; reason = "Suspicious user directory excluded"; }
                        else { sev = ThreatSeverity.Medium; }
                    }

                    threats.Add(new ThreatInfo
                    {
                        Name = $"Exclusion: {TruncatePath(path)}",
                        Description = reason,
                        Severity = sev,
                        Category = ThreatCategory.IsolationIssue,
                        Details = $"Path: {path}"
                    });
                    log(new LogEntry
                    {
                        Level = sev >= ThreatSeverity.High ? LogLevel.Error : LogLevel.Info,
                        Message = $"  Path exclusion: {path}",
                        Source = Name
                    });
                }
            }
            catch { }
        }
    }

    private void ScanProcessExclusions(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "Checking process exclusions...", Source = Name });

        string[] regPaths =
        [
            @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes",
            @"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Processes",
        ];

        foreach (var regPath in regPaths)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(regPath);
                if (key == null) continue;

                var procs = key.GetValueNames();
                log(new LogEntry { Level = LogLevel.Info, Message = $"Process exclusions: {procs.Length}", Source = Name });

                foreach (var proc in procs)
                {
                    if (string.IsNullOrWhiteSpace(proc)) continue;
                    string lower = proc.ToLowerInvariant();

                    var sev = ThreatSeverity.Medium;
                    foreach (var cheatWord in CheatRelatedPaths)
                    {
                        if (lower.Contains(cheatWord)) { sev = ThreatSeverity.Critical; break; }
                    }

                    threats.Add(new ThreatInfo
                    {
                        Name = $"Process Exclusion: {proc}",
                        Description = $"Process \"{proc}\" is excluded from Defender scanning",
                        Severity = sev,
                        Category = ThreatCategory.IsolationIssue,
                        Details = $"Process: {proc}"
                    });
                    log(new LogEntry
                    {
                        Level = sev >= ThreatSeverity.High ? LogLevel.Error : LogLevel.Warning,
                        Message = $"  Process exclusion: {proc}",
                        Source = Name
                    });
                }
            }
            catch { }
        }
    }

    private void ScanExtensionExclusions(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "Checking extension exclusions...", Source = Name });

        string[] dangerousExts = [".exe", ".dll", ".sys", ".com", ".bat", ".cmd", ".ps1", ".vbs"];

        string[] regPaths =
        [
            @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions",
            @"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Extensions",
        ];

        foreach (var regPath in regPaths)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(regPath);
                if (key == null) continue;

                var exts = key.GetValueNames();

                foreach (var ext in exts)
                {
                    if (string.IsNullOrWhiteSpace(ext)) continue;
                    string lower = ext.ToLowerInvariant();
                    string dotExt = lower.StartsWith('.') ? lower : "." + lower;

                    bool isDangerous = false;
                    foreach (var de in dangerousExts)
                    {
                        if (dotExt == de) { isDangerous = true; break; }
                    }

                    threats.Add(new ThreatInfo
                    {
                        Name = $"Extension Exclusion: {ext}",
                        Description = $"File extension \"{ext}\" is excluded from scanning",
                        Severity = isDangerous ? ThreatSeverity.Critical : ThreatSeverity.Medium,
                        Category = ThreatCategory.IsolationIssue,
                        Details = $"Extension: {ext}"
                    });
                    log(new LogEntry
                    {
                        Level = isDangerous ? LogLevel.Error : LogLevel.Warning,
                        Message = $"  Extension exclusion: {ext}",
                        Source = Name
                    });
                }
            }
            catch { }
        }
    }

    private void ScanPolicyExclusions(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "Checking Defender policy overrides...", Source = Name });

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Policies\Microsoft\Windows Defender");
            if (key == null) return;

            var disable = key.GetValue("DisableAntiSpyware");
            if (disable is int d && d == 1)
            {
                threats.Add(new ThreatInfo
                {
                    Name = "Defender Disabled by Policy",
                    Description = "Windows Defender completely disabled via Group Policy",
                    Severity = ThreatSeverity.Critical,
                    Category = ThreatCategory.IsolationIssue,
                    Details = "DisableAntiSpyware = 1"
                });
                log(new LogEntry { Level = LogLevel.Error, Message = "Defender DISABLED by GPO", Source = Name });
            }
        }
        catch { }
    }

    private static string TruncatePath(string path) =>
        path.Length > 60 ? "..." + path[^55..] : path;
}
