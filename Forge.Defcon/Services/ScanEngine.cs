using Forge.Defcon.Models;

namespace Forge.Defcon.Services;

public sealed class ScanEngine
{
    private readonly List<IScannerModule> _modules =
    [
        new ProcessScanner(),
        new DriverScanner(),
        new DmaScanner(),
        new FileScanner(),
        new RegistryScanner(),
        new MemoryScanner(),
        new DeviceScanner(),
        new VirtualizationScanner(),
        new SteamAccountScanner(),
        new CleanupDetector(),
        new IsolationScanner(),
        new StartupScanner(),
        new NetworkScanner(),
        new DefenderExclusionsScanner(),
        new UsbHistoryScanner(),
        new ExecutionHistoryScanner(),
        new BrowserHistoryScanner(),
        new HwidSpooferScanner(),
        new KernelDebugScanner(),
        new GameCheatScanner(),
        new ServicesScanner(),
    ];

    public IReadOnlyList<IScannerModule> Modules => _modules;

    public async Task<ScanResult> RunFullScanAsync(
        Action<LogEntry> log,
        Action<int> progressCallback,
        Action<int, ModuleState, int>? moduleStatusCallback,
        CancellationToken ct)
    {
        var allThreats = new List<ThreatInfo>();
        var sw = System.Diagnostics.Stopwatch.StartNew();
        int total = _modules.Count;

        log(new LogEntry { Level = LogLevel.Info, Message = "═══════════════════════════════════════════════════", Source = "Engine" });
        log(new LogEntry { Level = LogLevel.Info, Message = "    FORGE DEFCON — Full System Scan", Source = "Engine" });
        log(new LogEntry { Level = LogLevel.Info, Message = $"    Modules: {total} | Started: {DateTime.Now:HH:mm:ss}", Source = "Engine" });
        log(new LogEntry { Level = LogLevel.Info, Message = "═══════════════════════════════════════════════════", Source = "Engine" });

        for (int i = 0; i < total; i++)
        {
            ct.ThrowIfCancellationRequested();
            var threats = await RunModuleInternal(i, log, moduleStatusCallback, ct);
            allThreats.AddRange(threats);
            progressCallback((int)((i + 1) / (double)total * 100));
        }

        sw.Stop();
        LogSummary(log, allThreats, sw.Elapsed);

        return new ScanResult
        {
            Threats = allThreats,
            Duration = sw.Elapsed,
            TotalModulesRun = total
        };
    }

    public async Task<List<ThreatInfo>> RunSingleModuleAsync(
        int moduleIndex,
        Action<LogEntry> log,
        Action<int, ModuleState, int>? moduleStatusCallback,
        CancellationToken ct)
    {
        if (moduleIndex < 0 || moduleIndex >= _modules.Count)
            return [];

        var module = _modules[moduleIndex];
        log(new LogEntry { Level = LogLevel.Info, Message = $"──── Running: {module.Name} ────", Source = "Engine" });

        return await RunModuleInternal(moduleIndex, log, moduleStatusCallback, ct);
    }

    private async Task<List<ThreatInfo>> RunModuleInternal(
        int index,
        Action<LogEntry> log,
        Action<int, ModuleState, int>? statusCb,
        CancellationToken ct)
    {
        var module = _modules[index];
        statusCb?.Invoke(index, ModuleState.Scanning, 0);

        log(new LogEntry { Level = LogLevel.Info, Message = $"──── [{index + 1}/{_modules.Count}] {module.Name} ────", Source = "Engine" });

        try
        {
            var threats = await module.ScanAsync(log, ct);
            foreach (var t in threats) t.ModuleName = module.Name;

            statusCb?.Invoke(index,
                threats.Count > 0 ? ModuleState.ThreatFound : ModuleState.Clean,
                threats.Count);

            return threats;
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            log(new LogEntry { Level = LogLevel.Error, Message = $"Module failed: {ex.Message}", Source = module.Name });
            statusCb?.Invoke(index, ModuleState.Error, 0);
            return [];
        }
    }

    private static void LogSummary(Action<LogEntry> log, List<ThreatInfo> threats, TimeSpan elapsed)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "═══════════════════════════════════════════════════", Source = "Engine" });

        if (threats.Count == 0)
        {
            log(new LogEntry { Level = LogLevel.Success, Message = $"  SCAN COMPLETE — System CLEAN ({elapsed.TotalSeconds:F1}s)", Source = "Engine" });
        }
        else
        {
            int c = threats.Count(t => t.Severity == ThreatSeverity.Critical);
            int h = threats.Count(t => t.Severity == ThreatSeverity.High);
            int m = threats.Count(t => t.Severity == ThreatSeverity.Medium);
            log(new LogEntry { Level = LogLevel.Error, Message = $"  SCAN COMPLETE — {threats.Count} THREAT(S) ({elapsed.TotalSeconds:F1}s)", Source = "Engine" });
            log(new LogEntry { Level = LogLevel.Error, Message = $"  Critical: {c} | High: {h} | Medium: {m}", Source = "Engine" });
        }

        log(new LogEntry { Level = LogLevel.Info, Message = "═══════════════════════════════════════════════════", Source = "Engine" });
    }
}
