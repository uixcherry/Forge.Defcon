using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace Forge.Defcon.Models;

public enum ModuleState
{
    Pending,
    Scanning,
    Clean,
    ThreatFound,
    Error
}

public sealed class ModuleStatus : INotifyPropertyChanged
{
    private ModuleState _state = ModuleState.Pending;
    private int _threatCount;
    private bool _isSelected;

    public string Name { get; init; } = string.Empty;
    public int Index { get; init; }

    public ModuleState State
    {
        get => _state;
        set { _state = value; Notify(); Notify(nameof(StateSymbol)); Notify(nameof(IsActive)); }
    }

    public int ThreatCount
    {
        get => _threatCount;
        set { _threatCount = value; Notify(); }
    }

    public bool IsSelected
    {
        get => _isSelected;
        set { _isSelected = value; Notify(); }
    }

    public bool IsActive => _state == ModuleState.Scanning;

    public string StateSymbol => _state switch
    {
        ModuleState.Pending     => "○",
        ModuleState.Scanning    => "◉",
        ModuleState.Clean       => "✓",
        ModuleState.ThreatFound => "✗",
        ModuleState.Error       => "!",
        _ => "○"
    };

    public event PropertyChangedEventHandler? PropertyChanged;
    private void Notify([CallerMemberName] string? n = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(n));
}
