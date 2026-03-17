namespace Forge.Defcon.Models;

public enum ThreatSeverity
{
    Info,
    Low,
    Medium,
    High,
    Critical
}

public enum ThreatCategory
{
    CheatProcess,
    SuspiciousDriver,
    DmaDevice,
    ProhibitedSoftware,
    SuspiciousFile,
    MemoryAnomaly,
    RegistryAnomaly,
    SuspiciousDevice,
    VirtualEnvironment,
    CleanupEvidence,
        IsolationIssue,
    SteamAccount,
    BrowserHistory,
    HwidSpoofer,
    KernelDebug,
    GameCheat,
    SuspiciousService
}

public sealed class ThreatInfo
{
    public string Name { get; init; } = string.Empty;
    public string Description { get; init; } = string.Empty;
    public ThreatSeverity Severity { get; init; }
    public ThreatCategory Category { get; init; }
    public string Details { get; init; } = string.Empty;
    public string ModuleName { get; set; } = string.Empty;
    public DateTime DetectedAt { get; init; } = DateTime.Now;

    public bool HasDetails => !string.IsNullOrWhiteSpace(Details);

    public string SeverityLabel => Severity switch
    {
        ThreatSeverity.Info     => "INFO",
        ThreatSeverity.Low      => "LOW",
        ThreatSeverity.Medium   => "MEDIUM",
        ThreatSeverity.High     => "HIGH",
        ThreatSeverity.Critical => "CRITICAL",
        _ => "UNKNOWN"
    };

    public string CategoryLabel => Category switch
    {
        ThreatCategory.CheatProcess       => "Cheat Process",
        ThreatCategory.SuspiciousDriver   => "Suspicious Driver",
        ThreatCategory.DmaDevice          => "DMA Device",
        ThreatCategory.ProhibitedSoftware => "Prohibited Software",
        ThreatCategory.SuspiciousFile     => "Suspicious File",
        ThreatCategory.MemoryAnomaly      => "Memory Anomaly",
        ThreatCategory.RegistryAnomaly    => "Registry Anomaly",
        ThreatCategory.SuspiciousDevice   => "Suspicious Device",
        ThreatCategory.VirtualEnvironment => "Virtual Environment",
        ThreatCategory.CleanupEvidence    => "Cleanup Evidence",
        ThreatCategory.IsolationIssue     => "Isolation Issue",
        ThreatCategory.SteamAccount       => "Steam Account",
        ThreatCategory.BrowserHistory     => "Browser History",
        ThreatCategory.HwidSpoofer        => "HWID Spoofer",
        ThreatCategory.KernelDebug       => "Kernel Debug",
        ThreatCategory.GameCheat         => "Game Cheat",
        ThreatCategory.SuspiciousService => "Suspicious Service",
        _ => "Unknown"
    };
}

public sealed class ScanResult
{
    public bool IsClean => Threats.Count == 0;
    public List<ThreatInfo> Threats { get; init; } = [];
    public TimeSpan Duration { get; init; }
    public int TotalModulesRun { get; set; }
}

public sealed class SteamAccountInfo
{
    public string SteamId { get; init; } = string.Empty;
    public string AccountName { get; init; } = string.Empty;
    public string PersonaName { get; init; } = string.Empty;
    public bool RememberPassword { get; init; }
    public bool MostRecent { get; init; }
    public string Timestamp { get; init; } = string.Empty;
}
