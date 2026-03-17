using System.IO;
using Forge.Defcon.Models;

namespace Forge.Defcon.Services;

public sealed class GameCheatScanner : IScannerModule
{
    public string Name => "Game Cheats";

    private static readonly (string Game, string[] Paths)[] GamePaths =
    [
        ("Valorant", ["Riot Games\\VALORANT", "Riot Games\\Riot Client"]),
        ("CS2", ["Steam\\steamapps\\common\\Counter-Strike Global Offensive", "Steam\\steamapps\\common\\Counter-Strike 2"]),
        ("Fortnite", ["Epic Games\\Fortnite"]),
        ("PUBG", ["Steam\\steamapps\\common\\PUBG", "PUBG"]),
        ("Apex Legends", ["Origin Games\\Apex Legends", "Steam\\steamapps\\common\\Apex Legends", "EA\\Apex Legends"]),
        ("Rainbow Six", ["Steam\\steamapps\\common\\Tom Clancy's Rainbow Six Siege", "Ubisoft Game Launcher\\games\\Tom Clancy's Rainbow Six Siege"]),
        ("Escape from Tarkov", ["Steam\\steamapps\\common\\Escape From Tarkov", "Battlestate Games\\Escape From Tarkov"]),
        ("Rust", ["Steam\\steamapps\\common\\Rust"]),
        ("GTA V", ["Steam\\steamapps\\common\\Grand Theft Auto V", "Epic Games\\GTAV"]),
        ("Call of Duty", ["Call of Duty", "Battle.net", "Steam\\steamapps\\common\\Call of Duty Modern Warfare II", "Steam\\steamapps\\common\\Call of Duty Modern Warfare III"]),
    ];

    private static readonly string[] CheatFolderNames =
    [
        "cheat", "hack", "aimbot", "esp", "triggerbot",
        "inject", "loader", "bypass", "spoofer",
        "external", "internal", "dll", "trainer",
    ];

    private static readonly string[] CheatFilePatterns =
    [
        ".ct", ".cetrainer", "cheat", "hack", "aimbot",
        "esp", "loader", "inject", "bypass", "spoofer",
    ];

    public async Task<List<ThreatInfo>> ScanAsync(Action<LogEntry> log, CancellationToken ct)
    {
        var threats = new List<ThreatInfo>();

        log(new LogEntry { Level = LogLevel.Info, Message = "Scanning game directories for cheat files...", Source = Name });

        await Task.Run(() =>
        {
            string programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            string programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
            string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

            foreach (var (game, paths) in GamePaths)
            {
                ct.ThrowIfCancellationRequested();

                foreach (var relPath in paths)
                {
                    string[] bases = [programFiles, programFilesX86, localAppData, appData];
                    foreach (var baseDir in bases)
                    {
                        string fullPath = Path.Combine(baseDir, relPath);
                        if (Directory.Exists(fullPath))
                        {
                            ScanGameDirectory(threats, log, game, fullPath, ct);
                            break;
                        }
                    }
                }
            }

            ScanCommonCheatLocations(threats, log, ct);
        }, ct);

        log(new LogEntry
        {
            Level = threats.Count > 0 ? LogLevel.Warning : LogLevel.Success,
            Message = $"Game Cheats scan complete: {threats.Count} findings",
            Source = Name
        });

        return threats;
    }

    private void ScanGameDirectory(List<ThreatInfo> threats, Action<LogEntry> log, string game, string basePath, CancellationToken ct)
    {
        try
        {
            foreach (var dir in Directory.GetDirectories(basePath))
            {
                ct.ThrowIfCancellationRequested();
                string dirName = Path.GetFileName(dir).ToLowerInvariant();
                foreach (var cheat in CheatFolderNames)
                {
                    if (dirName.Contains(cheat))
                    {
                        threats.Add(new ThreatInfo
                        {
                            Name = $"{game}: suspicious folder",
                            Description = $"Cheat-related folder in game directory: {Path.GetFileName(dir)}",
                            Severity = ThreatSeverity.High,
                            Category = ThreatCategory.GameCheat,
                            Details = $"Path: {dir}\nGame: {game}"
                        });
                        log(new LogEntry { Level = LogLevel.Error, Message = $"[{game}] Suspicious folder: {dir}", Source = Name });
                        break;
                    }
                }
            }

            foreach (var file in Directory.EnumerateFiles(basePath, "*.*", new EnumerationOptions
            {
                RecurseSubdirectories = true,
                MaxRecursionDepth = 4,
                IgnoreInaccessible = true
            }))
            {
                ct.ThrowIfCancellationRequested();
                string name = Path.GetFileName(file).ToLowerInvariant();
                string ext = Path.GetExtension(file).ToLowerInvariant();

                if (ext is ".ct" or ".cetrainer" or ".sgr")
                {
                    threats.Add(new ThreatInfo
                    {
                        Name = $"{game}: cheat file",
                        Description = $"Cheat table/trainer file: {Path.GetFileName(file)}",
                        Severity = ThreatSeverity.High,
                        Category = ThreatCategory.GameCheat,
                        Details = $"Path: {file}"
                    });
                    log(new LogEntry { Level = LogLevel.Error, Message = $"[{game}] Cheat file: {file}", Source = Name });
                    continue;
                }

                foreach (var pattern in CheatFilePatterns)
                {
                    if (name.Contains(pattern) && (ext is ".exe" or ".dll" or ".ini" or ".cfg"))
                    {
                        threats.Add(new ThreatInfo
                        {
                            Name = $"{game}: suspicious file",
                            Description = $"Possible cheat file: {Path.GetFileName(file)}",
                            Severity = ThreatSeverity.Medium,
                            Category = ThreatCategory.GameCheat,
                            Details = $"Path: {file}"
                        });
                        log(new LogEntry { Level = LogLevel.Warning, Message = $"[{game}] Suspicious file: {file}", Source = Name });
                        break;
                    }
                }
            }
        }
        catch (Exception ex)
        {
            log(new LogEntry { Level = LogLevel.Debug, Message = $"Cannot scan {basePath}: {ex.Message}", Source = Name });
        }
    }

    private void ScanCommonCheatLocations(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        string[] dirs =
        [
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop)),
        ];

        foreach (var dir in dirs)
        {
            if (!Directory.Exists(dir)) continue;

            try
            {
                foreach (var folder in Directory.GetDirectories(dir))
                {
                    ct.ThrowIfCancellationRequested();
                    string name = Path.GetFileName(folder).ToLowerInvariant();
                    if (name.Contains("valorant") || name.Contains("cs2") || name.Contains("csgo") ||
                        name.Contains("fortnite") || name.Contains("tarkov") || name.Contains("rust"))
                    {
                        foreach (var cheat in CheatFolderNames)
                        {
                            if (name.Contains(cheat))
                            {
                                threats.Add(new ThreatInfo
                                {
                                    Name = $"Suspicious game folder: {Path.GetFileName(folder)}",
                                    Description = "Possible cheat folder for game",
                                    Severity = ThreatSeverity.Medium,
                                    Category = ThreatCategory.GameCheat,
                                    Details = $"Path: {folder}"
                                });
                                log(new LogEntry { Level = LogLevel.Warning, Message = $"Suspicious game folder: {folder}", Source = Name });
                                break;
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                log(new LogEntry { Level = LogLevel.Debug, Message = $"Scan error: {ex.Message}", Source = Name });
            }
        }
    }
}
