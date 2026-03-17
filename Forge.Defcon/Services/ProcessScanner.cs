using System.Diagnostics;
using Forge.Defcon.Models;

namespace Forge.Defcon.Services;

public sealed class ProcessScanner : IScannerModule
{
    public string Name => "Process Scanner";

    private static readonly HashSet<string> KnownCheatProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "cheatengine", "cheatengine-x86_64", "ce-x64", "ce-x86",
        "cheatengine-i386", "ceclient",
        "artmoney", "artmoney_pro", "artmoneypro",
        "tsearch", "gamecih", "squalr", "memoryeditor",

        "x64dbg", "x32dbg", "ollydbg", "ollydbg2",
        "windbg", "windbgx", "dbgview", "dbgview64",
        "ida", "ida64", "idaq", "idaq64", "idaw", "idaw64",
        "ghidra", "ghidrarun",
        "binaryninja", "binja",
        "cutter", "iaito",
        "radare2", "r2", "r2agent",

        "dnspy", "dnspy-x86",
        "dotpeek", "dotpeek64",
        "ilspy",
        "de4dot", "de4dot-x64",
        "justdecompile",
        "reclass", "reclass.net", "reclasskern",
        "pestudio", "pe-bear", "peview",
        "cff explorer",
        "die", "detectiteasy",
        "exeinfope",

        "extremeinjector", "extreme injector",
        "xenos", "xenos64",
        "ghoztinjector", "ghozinjector",
        "shade_injector", "shadeinjector",
        "remoteinjector", "remotedll",
        "dll_injector", "dllinjector", "injector",
        "manualmap", "manual_mapper",
        "syringe",

        "processhacker", "processhacker2", "systeminformer",
        "procexp", "procexp64",
        "apimonitor", "apimonitor-x64", "apimonitor-x86",

        "megadumper", "megadumper64",
        "scylla", "scylla_x64", "scylla_x86",
        "pe-sieve", "pesieve",
        "hollowshunter",

        "wemod", "wemodapp",
        "plitch", "cosmos", "cosmosapp",
        "cheatsmith",
        "fling_trainer", "flingtrainer",
        "mrantifun", "gameguardian",

        "wireshark", "tshark", "dumpcap",
        "fiddler", "fiddlereverywhere",
        "charles", "charlesproxy",
        "httpdebuggerpro", "httpdebugger",
        "mitmproxy", "mitmdump",
        "burpsuite", "burp",

        "hxd", "hxd64", "hxd32",
        "010editor", "winhex", "winhex64",

        "hwid_spoofer", "spoofer", "hwidspoofer",
        "antifakhwid", "anti-fak-hwid",
        "macchanger", "volumeid",

        "rweverything", "rweverything64",
        "pcileech", "fpga_loader",
        "kdmapper", "drvmap",
        "speedhack",
    };

    private static readonly string[] SuspiciousWindowPatterns =
    [
        "cheat engine", "dll injector", "process hacker",
        "extreme injector", "game guardian",
        "memory editor", "hack tool", "trainer",
        "speed hack", "aimbot", "wallhack",
        "esp overlay", "triggerbot",
        "system informer", "hwid spoof",
    ];

    private static readonly string[] SuspiciousPathSegments =
    [
        @"\temp\", @"\tmp\",
        @"\desktop\", @"\downloads\",
    ];

    private static readonly HashSet<string> SafeProcessesInTempDirs = new(StringComparer.OrdinalIgnoreCase)
    {
        "setup", "installer", "update", "updater",
        "chrome", "firefox", "edge", "opera",
        "discord", "steam", "epicgames",
        "dotnet", "msbuild", "nuget",
    };

    public async Task<List<ThreatInfo>> ScanAsync(Action<LogEntry> log, CancellationToken ct)
    {
        var threats = new List<ThreatInfo>();

        log(new LogEntry { Level = LogLevel.Info, Message = "Enumerating running processes...", Source = Name });

        var processes = await Task.Run(() => Process.GetProcesses(), ct);
        log(new LogEntry { Level = LogLevel.Info, Message = $"Found {processes.Length} running processes", Source = Name });

        int scanned = 0;
        foreach (var proc in processes)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                string procName = proc.ProcessName;
                string procLower = procName.ToLowerInvariant();

                if (KnownCheatProcesses.Contains(procLower))
                {
                    threats.Add(new ThreatInfo
                    {
                        Name = procName,
                        Description = $"Known cheat/hack tool running (PID: {proc.Id})",
                        Severity = ThreatSeverity.Critical,
                        Category = ThreatCategory.CheatProcess,
                        Details = $"PID: {proc.Id} | Session: {proc.SessionId}"
                    });
                    log(new LogEntry { Level = LogLevel.Error, Message = $"THREAT: {procName} (PID: {proc.Id})", Source = Name });
                }

                try
                {
                    string title = proc.MainWindowTitle;
                    if (!string.IsNullOrEmpty(title))
                    {
                        string titleLower = title.ToLowerInvariant();
                        foreach (var pattern in SuspiciousWindowPatterns)
                        {
                            if (titleLower.Contains(pattern))
                            {
                                threats.Add(new ThreatInfo
                                {
                                    Name = procName,
                                    Description = $"Suspicious window title: \"{title}\"",
                                    Severity = ThreatSeverity.High,
                                    Category = ThreatCategory.CheatProcess,
                                    Details = $"PID: {proc.Id} | Window: {title}"
                                });
                                log(new LogEntry { Level = LogLevel.Warning, Message = $"Suspicious window: \"{title}\"", Source = Name });
                                break;
                            }
                        }
                    }
                }
                catch { }

                try
                {
                    string? exePath = proc.MainModule?.FileName;
                    if (!string.IsNullOrEmpty(exePath))
                    {
                        string pathLower = exePath.ToLowerInvariant();

                        bool isSafe = false;
                        foreach (var safe in SafeProcessesInTempDirs)
                        {
                            if (procLower.Contains(safe)) { isSafe = true; break; }
                        }

                        if (!isSafe)
                        {
                            foreach (var seg in SuspiciousPathSegments)
                            {
                                if (pathLower.Contains(seg))
                                {
                                    threats.Add(new ThreatInfo
                                    {
                                        Name = procName,
                                        Description = $"Process running from suspicious location",
                                        Severity = ThreatSeverity.Medium,
                                        Category = ThreatCategory.CheatProcess,
                                        Details = $"Path: {exePath} | PID: {proc.Id}"
                                    });
                                    log(new LogEntry { Level = LogLevel.Warning, Message = $"Suspicious path: {procName} @ {exePath}", Source = Name });
                                    break;
                                }
                            }
                        }
                    }
                }
                catch { }

                scanned++;
            }
            catch { }
            finally { proc.Dispose(); }
        }

        log(new LogEntry
        {
            Level = LogLevel.Success,
            Message = $"Process scan complete: {scanned} scanned, {threats.Count} threats",
            Source = Name
        });

        return threats;
    }
}
