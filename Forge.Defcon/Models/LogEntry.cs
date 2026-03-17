namespace Forge.Defcon.Models;

public enum LogLevel
{
    Info,
    Success,
    Warning,
    Error,
    Debug
}

public sealed class LogEntry
{
    public DateTime Timestamp { get; init; } = DateTime.Now;
    public LogLevel Level { get; init; } = LogLevel.Info;
    public string Message { get; init; } = string.Empty;
    public string Source { get; init; } = string.Empty;

    public string FormattedTime => Timestamp.ToString("HH:mm:ss.fff");

    public string Prefix => Level switch
    {
        LogLevel.Info    => "[INFO]",
        LogLevel.Success => "[ OK ]",
        LogLevel.Warning => "[WARN]",
        LogLevel.Error   => "[FAIL]",
        LogLevel.Debug   => "[DBG ]",
        _ => "[----]"
    };
}
