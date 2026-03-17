using System.IO;
using Microsoft.Win32;
using Forge.Defcon.Models;

namespace Forge.Defcon.Services;

public sealed class DriverScanner : IScannerModule
{
    public string Name => "Driver Scanner";

    private static readonly HashSet<string> SuspiciousDrivers = new(StringComparer.OrdinalIgnoreCase)
    {
        "dbk64.sys", "dbk32.sys",
        "kdmapper.sys", "drvmap.sys",

        "capcom.sys",
        "iqvw64e.sys",
        "asusgio2.sys", "asusgio3.sys",
        "gdrv.sys",
        "atillk64.sys",
        "amdryzenmaster.sys",
        "winio64.sys", "winio32.sys",
        "winring0x64.sys", "winring0.sys",
        "physmem.sys", "phymemx64.sys",
        "inpoutx64.sys", "inpout32.sys",
        "rwdrv.sys",
        "cpuz141.sys", "cpuz_x64.sys",
        "ene.sys",
        "msio64.sys", "msio32.sys",
        "glckio2.sys",
        "amifldrv64.sys",
        "rtcore64.sys",
        "directio64.sys", "directio32.sys",
        "gmer64.sys", "gmer.sys",
        "speedfan.sys",
        "mhyprot.sys", "mhyprot2.sys", "mhyprot3.sys",
        "echo_driver.sys",
        "nicm.sys",
        "hw64.sys", "hw32.sys",
        "pchunter.sys",
        "dbutil_2_3.sys",
        "kprocesshacker.sys",
        "nodefender.sys",
        "disable_dse.sys",
        "disablesigning.sys",
        "testsigning.sys",
        "procexp152.sys",
        "hwidspoof.sys", "serialspoof.sys",
        "smbiosspoof.sys", "volumespoof.sys",
        "pcileech.sys", "screamer.sys", "ft601.sys",
        "pcileech-fpga.sys", "pcileech-squirrel.sys",
    };

    public async Task<List<ThreatInfo>> ScanAsync(Action<LogEntry> log, CancellationToken ct)
    {
        var threats = new List<ThreatInfo>();

        log(new LogEntry { Level = LogLevel.Info, Message = "Scanning kernel drivers...", Source = Name });

        var drivers = await Task.Run(() => EnumerateDriverFiles(), ct);
        log(new LogEntry { Level = LogLevel.Info, Message = $"Found {drivers.Count} driver files", Source = Name });

        foreach (var driverPath in drivers)
        {
            ct.ThrowIfCancellationRequested();
            string fileName = Path.GetFileName(driverPath);

            if (SuspiciousDrivers.Contains(fileName))
            {
                threats.Add(new ThreatInfo
                {
                    Name = fileName,
                    Description = $"Suspicious/exploit driver: {fileName}",
                    Severity = ThreatSeverity.Critical,
                    Category = ThreatCategory.SuspiciousDriver,
                    Details = $"Path: {driverPath} | Modified: {File.GetLastWriteTime(driverPath):g}"
                });
                log(new LogEntry { Level = LogLevel.Error, Message = $"THREAT: {fileName}", Source = Name });
            }
        }

        CheckNonStandardDriverLocations(threats, log, ct);
        ct.ThrowIfCancellationRequested();
        CheckRecentlyInstalledDrivers(threats, log, ct);
        ct.ThrowIfCancellationRequested();
        CheckDriverStore(threats, log, ct);

        log(new LogEntry
        {
            Level = LogLevel.Success,
            Message = $"Driver scan complete: {drivers.Count} checked, {threats.Count} threats",
            Source = Name
        });

        return threats;
    }

    private void CheckNonStandardDriverLocations(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "Checking for drivers in non-standard locations...", Source = Name });

        string[] suspiciousDirs =
        [
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        ];

        foreach (var dir in suspiciousDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir)) continue;

            try
            {
                var sysFiles = Directory.GetFiles(dir, "*.sys", new EnumerationOptions
                {
                    RecurseSubdirectories = true,
                    MaxRecursionDepth = 3,
                    IgnoreInaccessible = true
                });

                foreach (var file in sysFiles)
                {
                    threats.Add(new ThreatInfo
                    {
                        Name = Path.GetFileName(file),
                        Description = "Driver file found in user directory",
                        Severity = ThreatSeverity.High,
                        Category = ThreatCategory.SuspiciousDriver,
                        Details = $"Path: {file}"
                    });
                    log(new LogEntry { Level = LogLevel.Warning, Message = $"Driver in unusual path: {file}", Source = Name });
                }
            }
            catch { }
        }
    }

    private void CheckRecentlyInstalledDrivers(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "Checking recently installed drivers...", Source = Name });

        string driversDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "System32", "drivers");

        if (!Directory.Exists(driversDir)) return;

        try
        {
            var recentDrivers = Directory.GetFiles(driversDir, "*.sys")
                .Select(f => new { Path = f, Modified = File.GetLastWriteTime(f) })
                .Where(f => (DateTime.Now - f.Modified).TotalDays < 7)
                .OrderByDescending(f => f.Modified)
                .ToList();

            if (recentDrivers.Count > 0)
            {
                log(new LogEntry { Level = LogLevel.Info, Message = $"Drivers modified in last 7 days: {recentDrivers.Count}", Source = Name });

                foreach (var drv in recentDrivers.Take(10))
                {
                    string name = Path.GetFileName(drv.Path);
                    if (SuspiciousDrivers.Contains(name))
                        continue;

                    log(new LogEntry { Level = LogLevel.Info, Message = $"  Recent: {name} ({drv.Modified:g})", Source = Name });
                }
            }
        }
        catch { }
    }

    private void CheckDriverStore(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "Checking DriverStore for staged suspicious drivers...", Source = Name });

        string driverStore = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "System32", "DriverStore", "FileRepository");

        if (!Directory.Exists(driverStore)) return;

        try
        {
            var sysFiles = Directory.EnumerateFiles(driverStore, "*.sys", new EnumerationOptions
            {
                RecurseSubdirectories = true,
                MaxRecursionDepth = 2,
                IgnoreInaccessible = true
            });

            foreach (var file in sysFiles)
            {
                ct.ThrowIfCancellationRequested();
                string name = Path.GetFileName(file);

                if (SuspiciousDrivers.Contains(name))
                {
                    threats.Add(new ThreatInfo
                    {
                        Name = $"DriverStore: {name}",
                        Description = "Suspicious driver staged in DriverStore",
                        Severity = ThreatSeverity.High,
                        Category = ThreatCategory.SuspiciousDriver,
                        Details = $"Path: {file}"
                    });
                    log(new LogEntry { Level = LogLevel.Warning, Message = $"DriverStore threat: {name}", Source = Name });
                }
            }
        }
        catch { }
    }

    private static List<string> EnumerateDriverFiles()
    {
        var result = new List<string>();
        try
        {
            string driversDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                "System32", "drivers");

            if (Directory.Exists(driversDir))
                result.AddRange(Directory.GetFiles(driversDir, "*.sys"));
        }
        catch { }
        return result;
    }
}
