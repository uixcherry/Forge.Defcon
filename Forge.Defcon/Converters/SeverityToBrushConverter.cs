using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;
using Forge.Defcon.Models;

namespace Forge.Defcon.Converters;

public sealed class SeverityToBrushConverter : IValueConverter
{
    private static readonly SolidColorBrush LowBrush      = new(Color.FromRgb(0x94, 0xA3, 0xB8));
    private static readonly SolidColorBrush MediumBrush   = new(Color.FromRgb(0xEA, 0xB3, 0x08));
    private static readonly SolidColorBrush HighBrush     = new(Color.FromRgb(0xF9, 0x73, 0x16));
    private static readonly SolidColorBrush CriticalBrush = new(Color.FromRgb(0xEF, 0x44, 0x44));

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        return value is ThreatSeverity severity ? severity switch
        {
            ThreatSeverity.Medium   => MediumBrush,
            ThreatSeverity.High     => HighBrush,
            ThreatSeverity.Critical => CriticalBrush,
            _                       => LowBrush
        } : LowBrush;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
