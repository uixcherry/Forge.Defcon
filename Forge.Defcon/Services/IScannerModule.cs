using Forge.Defcon.Models;

namespace Forge.Defcon.Services;

public interface IScannerModule
{
    string Name { get; }
    Task<List<ThreatInfo>> ScanAsync(Action<LogEntry> log, CancellationToken ct);
}
