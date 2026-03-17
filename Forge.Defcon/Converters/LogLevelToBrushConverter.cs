using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;
using Forge.Defcon.Models;

namespace Forge.Defcon.Converters;

public sealed class LogLevelToBrushConverter : IValueConverter
{
    private static readonly SolidColorBrush InfoBrush    = new(Color.FromRgb(0x8B, 0x94, 0x9E));
    private static readonly SolidColorBrush SuccessBrush = new(Color.FromRgb(0x2E, 0xD5, 0x73));
    private static readonly SolidColorBrush WarningBrush = new(Color.FromRgb(0xFF, 0xA5, 0x02));
    private static readonly SolidColorBrush ErrorBrush   = new(Color.FromRgb(0xFF, 0x47, 0x57));
    private static readonly SolidColorBrush DebugBrush   = new(Color.FromRgb(0x48, 0x4F, 0x58));

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        return value is LogLevel level ? level switch
        {
            LogLevel.Success => SuccessBrush,
            LogLevel.Warning => WarningBrush,
            LogLevel.Error   => ErrorBrush,
            LogLevel.Debug   => DebugBrush,
            _                => InfoBrush
        } : InfoBrush;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
