using System.IO;
using Forge.Defcon.Models;

namespace Forge.Defcon.Services;

public sealed class FileScanner : IScannerModule
{
    public string Name => "File Scanner";

    private static readonly HashSet<string> SuspiciousFileNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "cheatengine.exe", "cheatengine-x86_64.exe",
        "extremeinjector.exe", "extreme injector.exe",
        "xenos.exe", "xenos64.exe",
        "kdmapper.exe", "drvmap.exe",
        "processhacker.exe",
        "x64dbg.exe", "x32dbg.exe",
        "ida.exe", "ida64.exe",
        "ghidra.exe", "ghidrarun.bat",
        "dnspy.exe", "dotpeek.exe", "ilspy.exe",
        "wemod.exe", "plitch.exe",
        "scylla.exe", "scylla_x64.exe",
        "megadumper.exe",
        "reclass.exe", "reclass.net.exe",
        "hxd.exe", "hxd64.exe",
        "wireshark.exe", "fiddler.exe",
        "httpdebuggerpro.exe",
        "artmoney.exe", "artmoneypro.exe",
        "rweverything.exe", "rweverything64.exe",
        "pcileech.exe", "pcileech-fpga.exe", "pcileech-squirrel.exe",
        "screamer.exe", "screamer-fpga.exe",
        "squalr.exe",
        "inject.exe", "injector.exe",
        "trainer.exe",
        "spoofer.exe", "hwid_spoofer.exe",
        "antifakhwid.exe", "anti-fak-hwid.exe",
        "macchanger.exe", "volumeid.exe",
        "cosmos.exe",
        "apimonitor.exe",
        "de4dot.exe",
    };

    private static readonly HashSet<string> CheatFileExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".ct",
        ".cetrainer",
        ".sgr",
    };

    private static readonly HashSet<string> SuspiciousExecutableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".com",
        ".scr",
        ".pif",
        ".hta",
        ".vbs",
        ".vbe",
        ".wsf",
        ".wsh",
    };

    private static readonly HashSet<string> AllExecutableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".com", ".scr", ".pif", ".bat", ".cmd",
        ".hta", ".vbs", ".vbe", ".wsf", ".wsh", ".ps1",
        ".msi", ".dll", ".sys",
    };

    private static readonly string[] SuspiciousNamePatterns =
    [
        "aimbot", "wallhack", "esp_", "triggerbot",
        "speedhack", "noclip", "godmode",
        "unban", "dma_cheat", "dma_fw", "dma_", "_dma",
        "pcileech", "screamer", "squirrel", "fpga_dma",
        "radar_hack", "no_recoil", "silent_aim",
        "bhop", "skinchanger", "extermal",
        "driver_mapper", "manual_map",
        "dll_inject", "code_inject",
        "hwid_spoof", "hwid_chang", "hwid_ban",
        "spoofer_", "_spoofer",
    ];

    private static readonly string[] SafePathSegments =
    [
        @"\microsoft office\",
        @"\windowsapps\",
        @"\dotnet\",
        @"\nuget\",
        @"\visual studio\",
        @"\wsl\",
        @"\common files\microsoft",
        @"\adobe\",
        @"\microsoft.net\",
        @"\program files\windows",
        @"\program files (x86)\windows",
        @"\windows defender\",
        @"\java\",
        @"\maven\",
        @"\gradle\",
        @"\node_modules\",
        @"\python\",
        @"\.tlauncher\",
        @"\.minecraft\",
        @"\city car driving\",
        @"\tor browser\",
        @"\assetripper",
        @"\assetstudio",
        @"\die_win64",
        @"\detect it easy\",
        @"\cloudflare warp\",
        @"\telegram desktop\",
        @"\chatgpt",
        @"\openaic.chatgpt",
        @"\desktopappinstaller",
        @"\microsoft.desktopappinstaller",
        @"\adobe after effects\",
        @"\formathandlers\",
        @"\microsoft.ceres\",
        @"\configurationremoting\",
        @"\winget\",
        @"\windows store\",
        @"\microsoft.windowsstore",
        @"\appinstaller",
        @"\cegui",
        @"\smartsteam",
        @"\accessiblemarshal",
        @"\libglesv2",
        @"\humanizer",
        @"\windowsbase",
        @"\modelcontextprotocol",
        @"\wingetmcpserver",
        @"\storedesktopextension",
        @"\startuptask",
        @"\webview2loader",
        @"\updater.exe",
        @"\cheat engine\autorun\",
        @"\program files\cheat engine\autorun\",
    ];

    private static readonly string[] SafePathForEntropy =
    [
        @"\program files\",
        @"\program files (x86)\",
        @"\windowsapps\",
        @"\microsoft.",
        @"\adobe\",
        @"\tor browser\",
        @"\city car driving\",
        @"\assetripper",
        @"\assetstudio",
        @"\die_win64",
        @"\cloudflare warp\",
        @"\telegram",
        @"\chatgpt",
        @"\openaic.chatgpt",
        @"\desktopappinstaller",
        @"\formathandlers\",
        @"\microsoft.ceres\",
        @"\cegui",
        @"\smartsteam",
        @"\accessiblemarshal",
        @"\libglesv2",
        @"\webview2loader",
        @"\updater.exe",
        @"\humanizer",
        @"\windowsbase",
        @"\modelcontextprotocol",
        @"\wingetmcpserver",
        @"\storedesktopextension",
        @"\startuptask",
        @"\storage\",
        @"\app`s\",
        @"\modengine\",
    ];

    private static readonly string[] UserDirNames =
    [
        "desktop", "downloads", "documents",
        @"\temp\", @"\tmp\",
    ];

    private static IEnumerable<string> GetScanDirectories()
    {
        var dirs = new List<string>();

        void TryAdd(string path)
        {
            if (Directory.Exists(path)) dirs.Add(path);
        }

        string appdata = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string localAppdata = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        string programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        string temp = Path.GetTempPath();

        TryAdd(Path.Combine(userProfile, "Desktop"));
        TryAdd(Path.Combine(userProfile, "Downloads"));
        TryAdd(Path.Combine(userProfile, "Documents"));
        TryAdd(temp);
        TryAdd(appdata);
        TryAdd(localAppdata);
        TryAdd(programFiles);
        TryAdd(programFilesX86);

        TryAdd(Path.Combine(appdata, "Cheat Engine"));
        TryAdd(Path.Combine(localAppdata, "Cheat Engine"));
        TryAdd(Path.Combine(localAppdata, "WeMod"));
        TryAdd(Path.Combine(localAppdata, "CrackSoft"));

        return dirs;
    }

    private static bool IsInSafePath(string filePath)
    {
        string lower = filePath.ToLowerInvariant();
        foreach (var safe in SafePathSegments)
        {
            if (lower.Contains(safe))
                return true;
        }
        return false;
    }

    private static bool IsInSafePathForEntropy(string filePath)
    {
        string lower = filePath.ToLowerInvariant();
        foreach (var safe in SafePathForEntropy)
        {
            if (lower.Contains(safe))
                return true;
        }
        return false;
    }

    private static bool IsInSafePathForDoubleExt(string filePath)
    {
        string lower = filePath.ToLowerInvariant();
        return lower.Contains(@"\program files\") || lower.Contains(@"\windowsapps\") ||
               lower.Contains(@"\windows defender") || lower.Contains(@"\formathandlers\") ||
               lower.Contains(@"\microsoft.ceres\");
    }

    private static bool IsInSafePathForSuspiciousExt(string filePath, string ext)
    {
        string lower = filePath.ToLowerInvariant();
        if (ext.Equals(".com", StringComparison.OrdinalIgnoreCase))
            return lower.Contains(@"\adobe\") && lower.Contains("afterfx");
        if (ext.Equals(".vbs", StringComparison.OrdinalIgnoreCase))
            return lower.Contains(@"\microsoft office\") && lower.Contains("ospp");
        return false;
    }

    private static bool IsInUserDir(string filePath)
    {
        string lower = filePath.ToLowerInvariant();
        foreach (var dir in UserDirNames)
        {
            if (lower.Contains(dir))
                return true;
        }
        return false;
    }

    private static double CalculateEntropy(string s)
    {
        if (string.IsNullOrEmpty(s) || s.Length < 3) return 0;
        var freq = new Dictionary<char, int>();
        foreach (var c in s)
            freq[c] = freq.GetValueOrDefault(c) + 1;
        double len = s.Length;
        double entropy = 0;
        foreach (var count in freq.Values)
        {
            double p = count / len;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }

    private static bool HasDoubleExtension(string fileName)
    {
        int lastDot = fileName.LastIndexOf('.');
        if (lastDot <= 0) return false;
        string withoutLast = fileName[..lastDot];
        int prevDot = withoutLast.LastIndexOf('.');
        if (prevDot <= 0) return false;

        string innerExt = withoutLast[(prevDot)..].ToLowerInvariant();
        string[] docExtensions = [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".png", ".txt", ".zip", ".rar"];
        foreach (var de in docExtensions)
        {
            if (innerExt == de) return true;
        }
        return false;
    }

    public async Task<List<ThreatInfo>> ScanAsync(Action<LogEntry> log, CancellationToken ct)
    {
        var threats = new List<ThreatInfo>();
        int totalScanned = 0;

        log(new LogEntry { Level = LogLevel.Info, Message = "Scanning file system for suspicious files...", Source = Name });

        var dirs = GetScanDirectories().ToList();
        log(new LogEntry { Level = LogLevel.Info, Message = $"Scanning {dirs.Count} directories...", Source = Name });

        foreach (var dir in dirs)
        {
            ct.ThrowIfCancellationRequested();

            try
            {
                var files = await Task.Run(() =>
                {
                    try
                    {
                        return Directory.EnumerateFiles(dir, "*.*", new EnumerationOptions
                        {
                            RecurseSubdirectories = true,
                            MaxRecursionDepth = 3,
                            IgnoreInaccessible = true,
                            AttributesToSkip = FileAttributes.System
                        }).ToList();
                    }
                    catch { return new List<string>(); }
                }, ct);

                foreach (var filePath in files)
                {
                    ct.ThrowIfCancellationRequested();
                    totalScanned++;

                    string fileName = Path.GetFileName(filePath);
                    string ext = Path.GetExtension(filePath);
                    string nameLower = fileName.ToLowerInvariant();
                    string baseName = Path.GetFileNameWithoutExtension(filePath);

                    // 1. Known cheat tools by exact name
                    if (SuspiciousFileNames.Contains(fileName))
                    {
                        threats.Add(new ThreatInfo
                        {
                            Name = fileName,
                            Description = "Known cheat/hack tool found on disk",
                            Severity = ThreatSeverity.High,
                            Category = ThreatCategory.SuspiciousFile,
                            Details = $"Path: {filePath}"
                        });
                        log(new LogEntry { Level = LogLevel.Error, Message = $"Suspicious file: {filePath}", Source = Name });
                        continue;
                    }

                    // 2. Cheat-specific extensions (.ct, .cetrainer, .sgr)
                    if (CheatFileExtensions.Contains(ext))
                    {
                        threats.Add(new ThreatInfo
                        {
                            Name = fileName,
                            Description = $"Cheat file type: {ext}",
                            Severity = ThreatSeverity.High,
                            Category = ThreatCategory.SuspiciousFile,
                            Details = $"Path: {filePath}"
                        });
                        log(new LogEntry { Level = LogLevel.Warning, Message = $"Cheat file {ext}: {filePath}", Source = Name });
                        continue;
                    }

                    // 3. Rare executable extensions (.com, .scr, .pif, .hta, .vbs, etc.)
                    if (SuspiciousExecutableExtensions.Contains(ext) && !IsInSafePathForSuspiciousExt(filePath, ext))
                    {
                        var sev = IsInUserDir(filePath) ? ThreatSeverity.High : ThreatSeverity.Medium;
                        threats.Add(new ThreatInfo
                        {
                            Name = fileName,
                            Description = $"Suspicious executable type {ext} — rarely used by legitimate software",
                            Severity = sev,
                            Category = ThreatCategory.SuspiciousFile,
                            Details = $"Path: {filePath}"
                        });
                        log(new LogEntry { Level = LogLevel.Warning, Message = $"Suspicious executable {ext}: {filePath}", Source = Name });
                        continue;
                    }

                    // 4. Double extensions (e.g., document.pdf.exe, photo.jpg.com) — skip Microsoft format handlers
                    if (AllExecutableExtensions.Contains(ext) && HasDoubleExtension(fileName) && !IsInSafePathForDoubleExt(filePath))
                    {
                        threats.Add(new ThreatInfo
                        {
                            Name = fileName,
                            Description = "Double extension — likely disguised executable",
                            Severity = ThreatSeverity.Critical,
                            Category = ThreatCategory.SuspiciousFile,
                            Details = $"Path: {filePath}"
                        });
                        log(new LogEntry { Level = LogLevel.Error, Message = $"Double extension: {filePath}", Source = Name });
                        continue;
                    }

                    // 5. Random-looking filename with executable extension — only in high-risk user dirs, skip known safe paths
                    if (AllExecutableExtensions.Contains(ext) && IsInUserDir(filePath) && !IsInSafePathForEntropy(filePath) && baseName.Length >= 5)
                    {
                        double entropy = CalculateEntropy(baseName);
                        bool hasMixedCase = baseName.Any(char.IsUpper) && baseName.Any(char.IsLower);
                        bool noSpacesOrSeparators = !baseName.Any(c => c is ' ' or '_' or '-' or '.');
                        bool looksRandom = entropy >= 2.8 && hasMixedCase && noSpacesOrSeparators;

                        if (looksRandom)
                        {
                            threats.Add(new ThreatInfo
                            {
                                Name = fileName,
                                Description = $"Randomly named executable in user directory (entropy: {entropy:F2})",
                                Severity = ThreatSeverity.High,
                                Category = ThreatCategory.SuspiciousFile,
                                Details = $"Path: {filePath} | Entropy: {entropy:F2}"
                            });
                            log(new LogEntry { Level = LogLevel.Error, Message = $"Random-name executable: {filePath} (entropy {entropy:F2})", Source = Name });
                            continue;
                        }
                    }

                    // 6. Pattern matching (skip safe paths)
                    if (!IsInSafePath(filePath))
                    {
                        foreach (var pattern in SuspiciousNamePatterns)
                        {
                            if (nameLower.Contains(pattern))
                            {
                                threats.Add(new ThreatInfo
                                {
                                    Name = fileName,
                                    Description = $"File name matches suspicious pattern: \"{pattern}\"",
                                    Severity = ThreatSeverity.Medium,
                                    Category = ThreatCategory.SuspiciousFile,
                                    Details = $"Path: {filePath}"
                                });
                                log(new LogEntry { Level = LogLevel.Warning, Message = $"Pattern match \"{pattern}\": {filePath}", Source = Name });
                                break;
                            }
                        }
                    }
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                log(new LogEntry { Level = LogLevel.Debug, Message = $"Cannot scan {dir}: {ex.Message}", Source = Name });
            }
        }

        log(new LogEntry
        {
            Level = LogLevel.Success,
            Message = $"File scan complete: {totalScanned} files checked, {threats.Count} threats",
            Source = Name
        });

        return threats;
    }
}
