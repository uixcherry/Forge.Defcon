using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;
using Forge.Defcon.Models;

namespace Forge.Defcon.Converters;

public sealed class ModuleStateToBrushConverter : IValueConverter
{
    private static readonly SolidColorBrush PendingBrush = new(Color.FromRgb(0x48, 0x4F, 0x58));
    private static readonly SolidColorBrush ScanningBrush = new(Color.FromRgb(0x00, 0xD4, 0xFF));
    private static readonly SolidColorBrush CleanBrush = new(Color.FromRgb(0x2E, 0xD5, 0x73));
    private static readonly SolidColorBrush ThreatBrush = new(Color.FromRgb(0xFF, 0x47, 0x57));
    private static readonly SolidColorBrush ErrorBrush = new(Color.FromRgb(0xFF, 0xA5, 0x02));

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        return value is ModuleState state ? state switch
        {
            ModuleState.Scanning    => ScanningBrush,
            ModuleState.Clean       => CleanBrush,
            ModuleState.ThreatFound => ThreatBrush,
            ModuleState.Error       => ErrorBrush,
            _ => PendingBrush
        } : PendingBrush;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
