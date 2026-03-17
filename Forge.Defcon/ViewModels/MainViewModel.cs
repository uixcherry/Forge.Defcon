using System.Collections.ObjectModel;
using System.IO;
using System.Management;
using System.Text;
using System.Windows;
using System.Windows.Input;
using Forge.Defcon.Models;
using Forge.Defcon.Services;
using Microsoft.Win32;

namespace Forge.Defcon.ViewModels;

public sealed class MainViewModel : BaseViewModel
{
    private readonly ScanEngine _engine = new();
    private CancellationTokenSource? _cts;
    private readonly List<ThreatInfo> _allThreats = [];

    private bool _isScanning;
    private int _progress;
    private string _statusText = "Ready";
    private string _scanButtonText = "START SCAN";
    private int _threatCount;
    private int _criticalCount;
    private int _highCount;
    private int _mediumCount;
    private string _lastScanTime = "--";
    private string _elapsedText = "00:00";
    private string _statusBarText = "Idle";
    private int _selectedModuleFilter = -1;
    private string _filterLabel = "ALL";
    private int _activeTab;
    private string _systemInfo = "";
    private System.Timers.Timer? _elapsedTimer;
    private DateTime _scanStartTime;

    public MainViewModel()
    {
        StartScanCommand = new RelayCommand(_ => StartFullScan(), _ => !IsScanning);
        StopScanCommand = new RelayCommand(_ => _cts?.Cancel(), _ => IsScanning);
        ClearConsoleCommand = new RelayCommand(_ => LogEntries.Clear());
        CopyLogsCommand = new RelayCommand(_ => CopyLogs());
        SelectModuleCommand = new RelayCommand(p => SelectModuleFilter(p));
        ShowAllThreatsCommand = new RelayCommand(_ => SelectModuleFilter(null));
        RunSingleModuleCommand = new RelayCommand(p => RunSingleModule(p), _ => !IsScanning);
        SwitchTabCommand = new RelayCommand(p => { if (p is int tab) ActiveTab = tab; });
        ExportReportCommand = new RelayCommand(_ => ExportReport(), _ => _allThreats.Count > 0);
        CopyThreatsCommand = new RelayCommand(_ => CopyThreats(), _ => _allThreats.Count > 0);

        for (int i = 0; i < _engine.Modules.Count; i++)
            ModuleStatuses.Add(new ModuleStatus { Name = _engine.Modules[i].Name, Index = i });

        Log(LogLevel.Info, "Forge Defcon v1.0 initialized", "System");
        Log(LogLevel.Info, $"Loaded {_engine.Modules.Count} scanner modules", "System");

        Task.Run(CollectSystemInfo);
    }

    public ObservableCollection<LogEntry> LogEntries { get; } = [];
    public ObservableCollection<ThreatInfo> FilteredThreats { get; } = [];
    public ObservableCollection<ModuleStatus> ModuleStatuses { get; } = [];

    public ICommand StartScanCommand { get; }
    public ICommand StopScanCommand { get; }
    public ICommand ClearConsoleCommand { get; }
    public ICommand CopyLogsCommand { get; }
    public ICommand SelectModuleCommand { get; }
    public ICommand ShowAllThreatsCommand { get; }
    public ICommand RunSingleModuleCommand { get; }
    public ICommand SwitchTabCommand { get; }
    public ICommand ExportReportCommand { get; }
    public ICommand CopyThreatsCommand { get; }

    public bool IsScanning
    {
        get => _isScanning;
        set { if (SetProperty(ref _isScanning, value)) { ScanButtonText = value ? "SCANNING..." : "START SCAN"; OnPropertyChanged(nameof(IsNotScanning)); } }
    }
    public bool IsNotScanning => !IsScanning;
    public int Progress { get => _progress; set => SetProperty(ref _progress, value); }
    public string StatusText { get => _statusText; set => SetProperty(ref _statusText, value); }
    public string ScanButtonText { get => _scanButtonText; set => SetProperty(ref _scanButtonText, value); }
    public int ThreatCount { get => _threatCount; set => SetProperty(ref _threatCount, value); }
    public int CriticalCount { get => _criticalCount; set => SetProperty(ref _criticalCount, value); }
    public int HighCount { get => _highCount; set => SetProperty(ref _highCount, value); }
    public int MediumCount { get => _mediumCount; set => SetProperty(ref _mediumCount, value); }
    public string LastScanTime { get => _lastScanTime; set => SetProperty(ref _lastScanTime, value); }
    public string ElapsedText { get => _elapsedText; set => SetProperty(ref _elapsedText, value); }
    public string StatusBarText { get => _statusBarText; set => SetProperty(ref _statusBarText, value); }
    public string FilterLabel { get => _filterLabel; set => SetProperty(ref _filterLabel, value); }
    public string SystemInfo { get => _systemInfo; set => SetProperty(ref _systemInfo, value); }
    public int ActiveTab
    {
        get => _activeTab;
        set { if (SetProperty(ref _activeTab, value)) { OnPropertyChanged(nameof(IsScanTab)); OnPropertyChanged(nameof(IsToolsTab)); } }
    }
    public bool IsScanTab => ActiveTab == 0;
    public bool IsToolsTab => ActiveTab == 1;
    public int SelectedModuleFilter
    {
        get => _selectedModuleFilter;
        set { if (SetProperty(ref _selectedModuleFilter, value)) RebuildFiltered(); }
    }

    private async void StartFullScan()
    {
        ActiveTab = 0;
        IsScanning = true;
        Progress = 0;
        _allThreats.Clear();
        FilteredThreats.Clear();
        ResetCounters();
        StatusText = "Initializing...";
        StatusBarText = "Scanning...";
        SelectedModuleFilter = -1;

        foreach (var ms in ModuleStatuses) { ms.State = ModuleState.Pending; ms.ThreatCount = 0; }

        _scanStartTime = DateTime.Now;
        StartElapsedTimer();
        _cts = new CancellationTokenSource();

        try
        {
            var result = await _engine.RunFullScanAsync(
                entry => Dispatch(() => AddLog(entry)),
                progress => Dispatch(() => { Progress = progress; StatusText = $"Scanning... {progress}%"; }),
                (idx, state, count) => Dispatch(() =>
                {
                    if (idx < ModuleStatuses.Count) { ModuleStatuses[idx].State = state; ModuleStatuses[idx].ThreatCount = count; }
                    StatusBarText = $"Module {idx + 1}/{ModuleStatuses.Count} | Threats: {_allThreats.Count}";
                }),
                _cts.Token);

            Dispatch(() => FinishScan(result));
        }
        catch (OperationCanceledException) { StatusText = "Cancelled"; StatusBarText = "Scan cancelled"; Log(LogLevel.Warning, "Scan cancelled", "Engine"); }
        catch (Exception ex) { StatusText = "Error"; StatusBarText = $"Failed: {ex.Message}"; Log(LogLevel.Error, $"Scan failed: {ex.Message}", "Engine"); }
        finally { IsScanning = false; Progress = 100; StopElapsedTimer(); _cts?.Dispose(); _cts = null; }
    }

    private async void RunSingleModule(object? param)
    {
        if (param is not int index || index < 0 || index >= ModuleStatuses.Count) return;

        ActiveTab = 0;
        IsScanning = true;
        var ms = ModuleStatuses[index];
        ms.State = ModuleState.Pending;
        ms.ThreatCount = 0;
        StatusText = $"Running {ms.Name}...";
        StatusBarText = $"Running {ms.Name}...";

        _allThreats.RemoveAll(t => t.ModuleName == ms.Name);

        _scanStartTime = DateTime.Now;
        StartElapsedTimer();
        _cts = new CancellationTokenSource();

        try
        {
            var threats = await _engine.RunSingleModuleAsync(index,
                entry => Dispatch(() => AddLog(entry)),
                (idx, state, count) => Dispatch(() =>
                {
                    if (idx < ModuleStatuses.Count) { ModuleStatuses[idx].State = state; ModuleStatuses[idx].ThreatCount = count; }
                }),
                _cts.Token);

            Dispatch(() =>
            {
                _allThreats.AddRange(threats);
                UpdateCounters();
                RebuildFiltered();
                StatusText = threats.Count == 0 ? $"{ms.Name}: Clean" : $"{ms.Name}: {threats.Count} threat(s)";
                StatusBarText = $"{ms.Name} complete — {threats.Count} findings";
            });
        }
        catch (OperationCanceledException) { StatusText = "Cancelled"; Log(LogLevel.Warning, "Cancelled", "Engine"); }
        catch (Exception ex) { StatusText = "Error"; Log(LogLevel.Error, $"Failed: {ex.Message}", "Engine"); }
        finally { IsScanning = false; StopElapsedTimer(); _cts?.Dispose(); _cts = null; }
    }

    private void SelectModuleFilter(object? param)
    {
        if (param is int index)
        {
            SelectedModuleFilter = index;
            foreach (var ms in ModuleStatuses) ms.IsSelected = ms.Index == index;
            FilterLabel = ModuleStatuses[index].Name;
        }
        else
        {
            SelectedModuleFilter = -1;
            foreach (var ms in ModuleStatuses) ms.IsSelected = false;
            FilterLabel = "ALL";
        }
    }

    private void RebuildFiltered()
    {
        FilteredThreats.Clear();
        IEnumerable<ThreatInfo> source = _allThreats.OrderByDescending(t => t.Severity);
        if (_selectedModuleFilter >= 0 && _selectedModuleFilter < ModuleStatuses.Count)
        {
            string name = ModuleStatuses[_selectedModuleFilter].Name;
            source = source.Where(t => t.ModuleName == name);
        }
        foreach (var t in source) FilteredThreats.Add(t);
    }

    private void FinishScan(ScanResult result)
    {
        _allThreats.AddRange(result.Threats);
        UpdateCounters();
        RebuildFiltered();
        LastScanTime = $"{result.Duration.TotalSeconds:F1}s";
        StatusText = result.IsClean ? "CLEAN" : $"{result.Threats.Count} THREAT(S)";
        StatusBarText = result.IsClean
            ? $"Scan complete — CLEAN ({result.Duration.TotalSeconds:F1}s)"
            : $"Scan complete — {result.Threats.Count} threat(s) ({result.Duration.TotalSeconds:F1}s)";
    }

    private void CopyLogs()
    {
        var sb = new StringBuilder();
        foreach (var e in LogEntries) sb.AppendLine($"{e.FormattedTime} {e.Prefix} {e.Message}");
        if (sb.Length > 0) { Clipboard.SetText(sb.ToString()); Log(LogLevel.Success, $"Copied {LogEntries.Count} log entries", "System"); }
    }

    private void CopyThreats()
    {
        var sb = new StringBuilder();
        sb.AppendLine($"FORGE DEFCON — Scan Report ({DateTime.Now:g})");
        sb.AppendLine(new string('═', 60));
        foreach (var t in _allThreats.OrderByDescending(t => t.Severity))
            sb.AppendLine($"[{t.SeverityLabel}] {t.Name}\n  {t.Description}\n  {t.Details}\n");
        Clipboard.SetText(sb.ToString());
        Log(LogLevel.Success, $"Copied {_allThreats.Count} threats to clipboard", "System");
    }

    private void ExportReport()
    {
        var dlg = new SaveFileDialog
        {
            FileName = $"ForgeDefcon_Report_{DateTime.Now:yyyyMMdd_HHmmss}.txt",
            Filter = "Text files|*.txt|All files|*.*",
            DefaultExt = ".txt"
        };

        if (dlg.ShowDialog() != true) return;

        var sb = new StringBuilder();
        sb.AppendLine("╔══════════════════════════════════════════════════╗");
        sb.AppendLine("║         FORGE DEFCON — SCAN REPORT              ║");
        sb.AppendLine($"║  Date: {DateTime.Now:g,-41}║");
        sb.AppendLine($"║  Threats: {_allThreats.Count,-38}║");
        sb.AppendLine("╚══════════════════════════════════════════════════╝");
        sb.AppendLine();

        var grouped = _allThreats.GroupBy(t => t.ModuleName);
        foreach (var group in grouped)
        {
            sb.AppendLine($"── {group.Key} ({group.Count()}) ──");
            foreach (var t in group.OrderByDescending(t => t.Severity))
            {
                sb.AppendLine($"  [{t.SeverityLabel,-8}] {t.Name}");
                sb.AppendLine($"            {t.Description}");
                if (!string.IsNullOrEmpty(t.Details))
                    sb.AppendLine($"            {t.Details}");
                sb.AppendLine();
            }
        }

        sb.AppendLine("── Console Log ──");
        foreach (var e in LogEntries)
            sb.AppendLine($"  {e.FormattedTime} {e.Prefix} {e.Message}");

        File.WriteAllText(dlg.FileName, sb.ToString());
        Log(LogLevel.Success, $"Report exported to {dlg.FileName}", "System");
        StatusBarText = $"Report saved: {dlg.FileName}";
    }

    private void CollectSystemInfo()
    {
        var sb = new StringBuilder();
        try
        {
            sb.AppendLine($"OS: {Environment.OSVersion}");
            sb.AppendLine($"Machine: {Environment.MachineName}");
            sb.AppendLine($"User: {Environment.UserName}");
            sb.AppendLine($"Processors: {Environment.ProcessorCount}");
            sb.AppendLine($"64-bit OS: {Environment.Is64BitOperatingSystem}");

            var uptime = TimeSpan.FromMilliseconds(Environment.TickCount64);
            sb.AppendLine($"Uptime: {uptime.Days}d {uptime.Hours}h {uptime.Minutes}m");

            try
            {
                using var cpu = new ManagementObjectSearcher("SELECT Name FROM Win32_Processor");
                foreach (var obj in cpu.Get())
                    sb.AppendLine($"CPU: {obj["Name"]}");
            }
            catch { }

            try
            {
                using var mem = new ManagementObjectSearcher("SELECT TotalPhysicalMemory FROM Win32_ComputerSystem");
                foreach (var obj in mem.Get())
                {
                    if (obj["TotalPhysicalMemory"] is ulong bytes)
                        sb.AppendLine($"RAM: {bytes / 1024 / 1024 / 1024} GB");
                }
            }
            catch { }

            try
            {
                using var gpu = new ManagementObjectSearcher("SELECT Name FROM Win32_VideoController");
                foreach (var obj in gpu.Get())
                    sb.AppendLine($"GPU: {obj["Name"]}");
            }
            catch { }

            try
            {
                foreach (var drive in DriveInfo.GetDrives())
                {
                    if (drive.IsReady && drive.DriveType == DriveType.Fixed)
                        sb.AppendLine($"Disk {drive.Name}: {drive.TotalSize / 1024 / 1024 / 1024} GB ({drive.AvailableFreeSpace / 1024 / 1024 / 1024} GB free)");
                }
            }
            catch { }
        }
        catch { sb.AppendLine("Failed to collect system info"); }

        Dispatch(() => SystemInfo = sb.ToString());
    }

    private void ResetCounters() { ThreatCount = 0; CriticalCount = 0; HighCount = 0; MediumCount = 0; }

    private void UpdateCounters()
    {
        ThreatCount = _allThreats.Count;
        CriticalCount = _allThreats.Count(t => t.Severity == ThreatSeverity.Critical);
        HighCount = _allThreats.Count(t => t.Severity == ThreatSeverity.High);
        MediumCount = _allThreats.Count(t => t.Severity is ThreatSeverity.Medium or ThreatSeverity.Low or ThreatSeverity.Info);
    }

    private void Log(LogLevel level, string message, string source)
        => AddLog(new LogEntry { Level = level, Message = message, Source = source });

    private void AddLog(LogEntry entry)
    {
        LogEntries.Add(entry);
        while (LogEntries.Count > 10000) LogEntries.RemoveAt(0);
    }

    private static void Dispatch(Action action) => Application.Current.Dispatcher.Invoke(action);

    private void StartElapsedTimer()
    {
        _elapsedTimer = new System.Timers.Timer(1000);
        _elapsedTimer.Elapsed += (_, _) =>
        {
            var e = DateTime.Now - _scanStartTime;
            Dispatch(() => ElapsedText = $"{e.Minutes:D2}:{e.Seconds:D2}");
        };
        _elapsedTimer.Start();
    }

    private void StopElapsedTimer() { _elapsedTimer?.Stop(); _elapsedTimer?.Dispose(); _elapsedTimer = null; }
}
