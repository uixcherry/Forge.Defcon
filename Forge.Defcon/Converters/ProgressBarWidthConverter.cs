using System.Globalization;
using System.Windows.Data;

namespace Forge.Defcon.Converters;

public sealed class ProgressBarWidthConverter : IMultiValueConverter
{
    public object Convert(object[] values, Type targetType, object parameter, CultureInfo culture)
    {
        if (values.Length < 4) return 0.0;
        double val = values[0] is double v ? v : 0;
        double min = values[1] is double mn ? mn : 0;
        double max = values[2] is double mx ? mx : 100;
        double width = values[3] is double w ? w : 0;
        if (max <= min || width <= 0) return 0.0;
        double pct = Math.Clamp((val - min) / (max - min), 0, 1);
        return pct * width;
    }

    public object[] ConvertBack(object value, Type[] targetTypes, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
