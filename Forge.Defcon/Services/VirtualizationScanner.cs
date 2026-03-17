using System.Diagnostics;
using System.Management;
using System.Net.NetworkInformation;
using Forge.Defcon.Models;

namespace Forge.Defcon.Services;

public sealed class VirtualizationScanner : IScannerModule
{
    public string Name => "VM / Sandbox Scanner";

    private static readonly (string Prefix, string VmName)[] VmMacPrefixes =
    [
        ("00:0C:29", "VMware"), ("00:50:56", "VMware"), ("00:05:69", "VMware"),
        ("08:00:27", "VirtualBox"), ("0A:00:27", "VirtualBox"),
        ("00:15:5D", "Hyper-V"),
        ("52:54:00", "QEMU/KVM"),
        ("00:16:3E", "Xen"),
    ];

    private static readonly (string ProcessName, string VmName)[] VmProcesses =
    [
        ("vmtoolsd", "VMware"), ("vmwaretray", "VMware"), ("vmwareuser", "VMware"),
        ("vmacthlp", "VMware"), ("vmware-vmx", "VMware"),
        ("VBoxService", "VirtualBox"), ("VBoxTray", "VirtualBox"),
        ("VBoxClient", "VirtualBox"),
        ("qemu-ga", "QEMU"), ("qemu-system", "QEMU"),
        ("xenservice", "Xen"),
        ("prl_tools", "Parallels"), ("prl_cc", "Parallels"),
        ("SandboxieRpcSs", "Sandboxie"), ("SbieSvc", "Sandboxie"),
        ("vmsrvc", "Virtual PC"), ("vmusrvc", "Virtual PC"),
        ("joeboxserver", "Joe Sandbox"), ("joeboxcontrol", "Joe Sandbox"),
    ];

    private static readonly (string DriverName, string VmName)[] VmDrivers =
    [
        ("vmhgfs", "VMware"), ("vmci", "VMware"), ("vmmouse", "VMware"),
        ("vmxnet", "VMware"), ("vmx_svga", "VMware"), ("vm3dmp", "VMware"),
        ("VBoxGuest", "VirtualBox"), ("VBoxMouse", "VirtualBox"),
        ("VBoxSF", "VirtualBox"), ("VBoxVideo", "VirtualBox"),
        ("vioscsi", "QEMU"), ("viostor", "QEMU"), ("balloon", "QEMU"),
    ];

    public async Task<List<ThreatInfo>> ScanAsync(Action<LogEntry> log, CancellationToken ct)
    {
        var threats = new List<ThreatInfo>();

        log(new LogEntry { Level = LogLevel.Info, Message = "Scanning for virtual machines and sandboxes...", Source = Name });

        await Task.Run(() =>
        {
            CheckWmiFingerprint(threats, log, ct);
            ct.ThrowIfCancellationRequested();
            CheckVmProcesses(threats, log, ct);
            ct.ThrowIfCancellationRequested();
            CheckVmDrivers(threats, log, ct);
            ct.ThrowIfCancellationRequested();
            CheckMacAddresses(threats, log, ct);
            ct.ThrowIfCancellationRequested();
            CheckBiosStrings(threats, log, ct);
        }, ct);

        log(new LogEntry
        {
            Level = LogLevel.Success,
            Message = $"VM/Sandbox scan complete: {threats.Count} indicators found",
            Source = Name
        });

        return threats;
    }

    private void CheckWmiFingerprint(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "Checking WMI hardware fingerprint...", Source = Name });

        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_ComputerSystem");
            foreach (var obj in searcher.Get())
            {
                string manufacturer = obj["Manufacturer"]?.ToString() ?? "";
                string model = obj["Model"]?.ToString() ?? "";

                string combined = $"{manufacturer} {model}".ToLowerInvariant();

                (string pattern, string vmName)[] vmIndicators =
                [
                    ("vmware", "VMware"), ("virtual machine", "Hyper-V/Generic VM"),
                    ("virtualbox", "VirtualBox"), ("vbox", "VirtualBox"),
                    ("qemu", "QEMU"), ("kvm", "KVM"),
                    ("xen", "Xen"), ("parallels", "Parallels"),
                    ("bochs", "Bochs"), ("innotek", "VirtualBox"),
                ];

                foreach (var (pattern, vmName) in vmIndicators)
                {
                    if (combined.Contains(pattern))
                    {
                        threats.Add(new ThreatInfo
                        {
                            Name = $"Virtual Machine: {vmName}",
                            Description = $"System appears to be running in {vmName}",
                            Severity = ThreatSeverity.Critical,
                            Category = ThreatCategory.VirtualEnvironment,
                            Details = $"Manufacturer: {manufacturer} | Model: {model}"
                        });
                        log(new LogEntry { Level = LogLevel.Error, Message = $"VM detected: {vmName} ({manufacturer} {model})", Source = Name });
                        return;
                    }
                }

                log(new LogEntry { Level = LogLevel.Info, Message = $"Hardware: {manufacturer} {model}", Source = Name });
            }
        }
        catch (Exception ex)
        {
            log(new LogEntry { Level = LogLevel.Warning, Message = $"WMI query failed: {ex.Message}", Source = Name });
        }
    }

    private void CheckVmProcesses(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "Checking for VM guest processes...", Source = Name });

        try
        {
            var processes = Process.GetProcesses();
            foreach (var proc in processes)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    string name = proc.ProcessName;
                    foreach (var (procName, vmName) in VmProcesses)
                    {
                        if (name.Equals(procName, StringComparison.OrdinalIgnoreCase))
                        {
                            threats.Add(new ThreatInfo
                            {
                                Name = $"VM Process: {name}",
                                Description = $"{vmName} guest tool process detected",
                                Severity = ThreatSeverity.High,
                                Category = ThreatCategory.VirtualEnvironment,
                                Details = $"Process: {name} (PID: {proc.Id})"
                            });
                            log(new LogEntry { Level = LogLevel.Error, Message = $"VM process: {name} ({vmName})", Source = Name });
                            break;
                        }
                    }
                }
                catch { }
                finally { proc.Dispose(); }
            }
        }
        catch { }
    }

    private void CheckVmDrivers(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "Checking for VM drivers/services...", Source = Name });

        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_SystemDriver");
            foreach (var obj in searcher.Get())
            {
                ct.ThrowIfCancellationRequested();
                string driverName = obj["Name"]?.ToString() ?? "";

                foreach (var (knownDriver, vmName) in VmDrivers)
                {
                    if (driverName.Equals(knownDriver, StringComparison.OrdinalIgnoreCase))
                    {
                        threats.Add(new ThreatInfo
                        {
                            Name = $"VM Driver: {driverName}",
                            Description = $"{vmName} virtual driver detected",
                            Severity = ThreatSeverity.High,
                            Category = ThreatCategory.VirtualEnvironment,
                            Details = $"Driver: {driverName} | State: {obj["State"]}"
                        });
                        log(new LogEntry { Level = LogLevel.Error, Message = $"VM driver: {driverName} ({vmName})", Source = Name });
                        break;
                    }
                }
            }
        }
        catch (Exception ex)
        {
            log(new LogEntry { Level = LogLevel.Warning, Message = $"Driver check failed: {ex.Message}", Source = Name });
        }
    }

    private void CheckMacAddresses(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "Checking network MAC addresses for VM patterns...", Source = Name });

        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                ct.ThrowIfCancellationRequested();

                if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;

                string mac = nic.GetPhysicalAddress().ToString();
                if (string.IsNullOrEmpty(mac) || mac.Length < 6) continue;

                string macFormatted = string.Join(":", Enumerable.Range(0, mac.Length / 2)
                    .Select(i => mac.Substring(i * 2, 2)));

                foreach (var (prefix, vmName) in VmMacPrefixes)
                {
                    string normalizedPrefix = prefix.Replace(":", "");
                    if (mac.StartsWith(normalizedPrefix, StringComparison.OrdinalIgnoreCase))
                    {
                        threats.Add(new ThreatInfo
                        {
                            Name = $"VM MAC: {nic.Name}",
                            Description = $"Network adapter MAC matches {vmName} pattern",
                            Severity = ThreatSeverity.High,
                            Category = ThreatCategory.VirtualEnvironment,
                            Details = $"Adapter: {nic.Name} | MAC: {macFormatted} | Type: {nic.NetworkInterfaceType}"
                        });
                        log(new LogEntry { Level = LogLevel.Error, Message = $"VM MAC detected: {macFormatted} ({vmName})", Source = Name });
                        break;
                    }
                }
            }
        }
        catch (Exception ex)
        {
            log(new LogEntry { Level = LogLevel.Warning, Message = $"MAC check failed: {ex.Message}", Source = Name });
        }
    }

    private void CheckBiosStrings(List<ThreatInfo> threats, Action<LogEntry> log, CancellationToken ct)
    {
        log(new LogEntry { Level = LogLevel.Info, Message = "Checking BIOS/firmware strings...", Source = Name });

        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_BIOS");
            foreach (var obj in searcher.Get())
            {
                string version = obj["Version"]?.ToString() ?? "";
                string manufacturer = obj["Manufacturer"]?.ToString() ?? "";
                string serial = obj["SerialNumber"]?.ToString() ?? "";

                string combined = $"{version} {manufacturer} {serial}".ToLowerInvariant();

                string[] vmBios = ["vmware", "virtualbox", "vbox", "qemu", "bochs", "xen", "parallels", "hyper-v", "innotek"];

                foreach (var pattern in vmBios)
                {
                    if (combined.Contains(pattern))
                    {
                        threats.Add(new ThreatInfo
                        {
                            Name = $"VM BIOS: {pattern.ToUpper()}",
                            Description = $"BIOS strings indicate virtual machine",
                            Severity = ThreatSeverity.High,
                            Category = ThreatCategory.VirtualEnvironment,
                            Details = $"Version: {version} | Manufacturer: {manufacturer} | Serial: {serial}"
                        });
                        log(new LogEntry { Level = LogLevel.Error, Message = $"VM BIOS: {manufacturer} {version}", Source = Name });
                        break;
                    }
                }
            }
        }
        catch (Exception ex)
        {
            log(new LogEntry { Level = LogLevel.Warning, Message = $"BIOS check failed: {ex.Message}", Source = Name });
        }
    }
}
