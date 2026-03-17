using System.Diagnostics;
using System.IO;
using Microsoft.Win32;
using Forge.Defcon.Models;

namespace Forge.Defcon.Services;

public sealed class KernelDebugScanner : IScannerModule
{
    public string Name => "Kernel Debug";

    public async Task<List<ThreatInfo>> ScanAsync(Action<LogEntry> log, CancellationToken ct)
    {
        var threats = new List<ThreatInfo>();

        log(new LogEntry { Level = LogLevel.Info, Message = "Checking kernel debugging and boot configuration...", Source = Name });

        await Task.Run(() =>
        {
            CheckTestSigning(threats, log, ct);
            ct.ThrowIfCancellationRequested();
            CheckDebugMode(threats, log, ct);
            ct.ThrowIfCancellationRequested();
            CheckBcdSettings(threats, log, ct);
        }, ct);

        log(new LogEntry
        {
            Level = threats.Count > 0 ? LogLevel.Warning : LogLevel.Success,
            Message = $"Kernel Debug scan complete: {threats.Count} findings",
            Source = Name
        });

        return threats;
    }

    private void CheckTestSigning(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "Checking driver signature enforcement...", Source = Name });

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\CI\Policy");
            if (key == null) return;

            var upPolicy = key.GetValue("UpgradedSystem");
            var policy = key.GetValue("Policy");
            int val = upPolicy is int u ? u : (policy is int p ? p : -1);

            if (val == 0 || val == 8) // 0 = disabled, 8 = test signing
            {
                threats.Add(new ThreatInfo
                {
                    Name = "Test signing or signature enforcement disabled",
                    Description = "Allows unsigned drivers — used by cheat loaders",
                    Severity = ThreatSeverity.High,
                    Category = ThreatCategory.KernelDebug,
                    Details = $"Policy value: {val} (0=off, 8=test signing)"
                });
                log(new LogEntry { Level = LogLevel.Error, Message = $"Driver signature policy: {val}", Source = Name });
            }
        }
        catch (Exception ex)
        {
            log(new LogEntry { Level = LogLevel.Debug, Message = $"Policy check: {ex.Message}", Source = Name });
        }
    }

    private void CheckDebugMode(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "Checking kernel debugger...", Source = Name });

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Session Manager\Debug Print Filter");
            // Alternative: check for debugger in BCD

            var si = new ProcessStartInfo
            {
                FileName = "bcdedit",
                Arguments = "/enum",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                CreateNoWindow = true
            };

            using var proc = Process.Start(si);
            if (proc == null) return;

            string output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(5000);

            if (output.Contains("debug", StringComparison.OrdinalIgnoreCase) &&
                output.Contains("Yes", StringComparison.OrdinalIgnoreCase))
            {
                threats.Add(new ThreatInfo
                {
                    Name = "Kernel debugger enabled",
                    Description = "Kernel debugging is enabled — used by some cheat tools",
                    Severity = ThreatSeverity.High,
                    Category = ThreatCategory.KernelDebug,
                    Details = "BCD indicates debug mode"
                });
                log(new LogEntry { Level = LogLevel.Error, Message = "Kernel debugger enabled in BCD", Source = Name });
            }

            if (output.Contains("testsigning", StringComparison.OrdinalIgnoreCase) &&
                output.Contains("Yes", StringComparison.OrdinalIgnoreCase))
            {
                threats.Add(new ThreatInfo
                {
                    Name = "Test signing mode",
                    Description = "Test signing is enabled — allows unsigned drivers",
                    Severity = ThreatSeverity.High,
                    Category = ThreatCategory.KernelDebug,
                    Details = "BCD testsigning = Yes"
                });
                log(new LogEntry { Level = LogLevel.Error, Message = "Test signing enabled in BCD", Source = Name });
            }
        }
        catch (Exception ex)
        {
            log(new LogEntry { Level = LogLevel.Debug, Message = $"BCD check: {ex.Message}", Source = Name });
        }
    }

    private void CheckBcdSettings(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "Checking boot configuration...", Source = Name });

        try
        {
            string bcdPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                "config", "BCD");
            if (!File.Exists(bcdPath)) return;

            // BCD is binary; we rely on bcdedit output from CheckDebugMode
            // Additional: check for nointegritychecks
            var si = new ProcessStartInfo
            {
                FileName = "bcdedit",
                Arguments = "/enum {current}",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                CreateNoWindow = true
            };

            using var proc = Process.Start(si);
            if (proc == null) return;

            string output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(5000);

            if (output.Contains("nointegritychecks", StringComparison.OrdinalIgnoreCase) &&
                output.Contains("Yes", StringComparison.OrdinalIgnoreCase))
            {
                threats.Add(new ThreatInfo
                {
                    Name = "No integrity checks",
                    Description = "Boot integrity checks disabled",
                    Severity = ThreatSeverity.Critical,
                    Category = ThreatCategory.KernelDebug,
                    Details = "BCD nointegritychecks = Yes"
                });
                log(new LogEntry { Level = LogLevel.Error, Message = "No integrity checks in BCD", Source = Name });
            }
        }
        catch (Exception ex)
        {
            log(new LogEntry { Level = LogLevel.Debug, Message = $"BCD settings: {ex.Message}", Source = Name });
        }
    }
}
