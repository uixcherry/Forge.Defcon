using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace Forge.Defcon.Converters;

public sealed class TabToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is int active && parameter is string expected && int.TryParse(expected, out int tab))
            return active == tab ? Visibility.Visible : Visibility.Collapsed;
        return Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
