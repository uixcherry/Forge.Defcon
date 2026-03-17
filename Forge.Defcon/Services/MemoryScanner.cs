using System.Diagnostics;
using Forge.Defcon.Models;

namespace Forge.Defcon.Services;

public sealed class MemoryScanner : IScannerModule
{
    public string Name => "Memory Scanner";

    private static readonly HashSet<string> KnownCheatDlls = new(StringComparer.OrdinalIgnoreCase)
    {
        "cheatengine-x86_64.dll", "speedhack-x86_64.dll",
        "speedhack-i386.dll", "vehhook.dll",
        "d3dhook.dll", "d3dhook64.dll",
    };

    private static readonly string[] SuspiciousDllPatterns =
    [
        "cheatengine", "ce_hook", "ce_inject",
        "speedhack",
        "aimbot", "wallhack",
        "d3d9_proxy", "d3d11_proxy", "dxgi_proxy",
        "opengl_proxy",
        "frida-agent",
        "sbiedll",
        "hwidspoof", "serialspoof",
        "antifakhwid",
    ];

    private static readonly string[] SafeDllPatterns =
    [
        "dependencyinjection",
        "microsoft.extensions",
        "assistedinject",
        "jakarta.inject",
        "component_reference",
        "widget_core_interface",
        "minhook",
    ];

    private static readonly string[] SuspiciousLoadPaths =
    [
        @"\temp\", @"\tmp\", @"\appdata\local\temp\",
        @"\desktop\", @"\downloads\",
    ];

    public async Task<List<ThreatInfo>> ScanAsync(Action<LogEntry> log, CancellationToken ct)
    {
        var threats = new List<ThreatInfo>();
        int processesChecked = 0;
        int modulesChecked = 0;

        log(new LogEntry { Level = LogLevel.Info, Message = "Scanning process memory and loaded modules...", Source = Name });

        var processes = await Task.Run(() => Process.GetProcesses(), ct);

        foreach (var proc in processes)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                ProcessModuleCollection? modules = null;
                try { modules = proc.Modules; } catch { continue; }

                processesChecked++;

                foreach (ProcessModule module in modules)
                {
                    modulesChecked++;
                    try
                    {
                        string modName = module.ModuleName.ToLowerInvariant();
                        string modPath = module.FileName?.ToLowerInvariant() ?? "";

                        if (IsSafeDll(modName)) continue;

                        if (KnownCheatDlls.Contains(module.ModuleName))
                        {
                            threats.Add(new ThreatInfo
                            {
                                Name = module.ModuleName,
                                Description = $"Known cheat DLL loaded in {proc.ProcessName} (PID: {proc.Id})",
                                Severity = ThreatSeverity.Critical,
                                Category = ThreatCategory.MemoryAnomaly,
                                Details = $"Module: {module.FileName} | Process: {proc.ProcessName} PID:{proc.Id}"
                            });
                            log(new LogEntry { Level = LogLevel.Error, Message = $"Cheat DLL: {module.ModuleName} in {proc.ProcessName}", Source = Name });
                            continue;
                        }

                        foreach (var pattern in SuspiciousDllPatterns)
                        {
                            if (modName.Contains(pattern))
                            {
                                threats.Add(new ThreatInfo
                                {
                                    Name = module.ModuleName,
                                    Description = $"Suspicious DLL pattern \"{pattern}\" in {proc.ProcessName}",
                                    Severity = ThreatSeverity.High,
                                    Category = ThreatCategory.MemoryAnomaly,
                                    Details = $"Module: {module.FileName} | Process: {proc.ProcessName} PID:{proc.Id}"
                                });
                                log(new LogEntry { Level = LogLevel.Warning, Message = $"Suspicious module: {module.ModuleName} in {proc.ProcessName}", Source = Name });
                                break;
                            }
                        }

                        foreach (var suspPath in SuspiciousLoadPaths)
                        {
                            if (modPath.Contains(suspPath) && modName.EndsWith(".dll"))
                            {
                                bool isFramework = modPath.Contains(@"\dotnet\") ||
                                                   modPath.Contains(@"\microsoft.net\") ||
                                                   modPath.Contains(@"\windowsapps\") ||
                                                   modPath.Contains(@"\program files");

                                if (!isFramework)
                                {
                                    threats.Add(new ThreatInfo
                                    {
                                        Name = module.ModuleName,
                                        Description = $"DLL loaded from suspicious path in {proc.ProcessName}",
                                        Severity = ThreatSeverity.Medium,
                                        Category = ThreatCategory.MemoryAnomaly,
                                        Details = $"Path: {module.FileName} | Process: {proc.ProcessName} PID:{proc.Id}"
                                    });
                                    log(new LogEntry { Level = LogLevel.Warning, Message = $"Suspicious load path: {module.FileName}", Source = Name });
                                    break;
                                }
                            }
                        }
                    }
                    catch { }
                }
            }
            catch { }
            finally { proc.Dispose(); }
        }

        log(new LogEntry
        {
            Level = LogLevel.Success,
            Message = $"Memory scan complete: {processesChecked} processes, {modulesChecked} modules, {threats.Count} threats",
            Source = Name
        });

        return threats;
    }

    private static bool IsSafeDll(string modNameLower)
    {
        foreach (var safe in SafeDllPatterns)
        {
            if (modNameLower.Contains(safe))
                return true;
        }
        return false;
    }
}
