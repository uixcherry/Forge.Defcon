using System.Collections.Specialized;
using System.IO;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Microsoft.Win32;

namespace Forge.Defcon;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();

        if (DataContext is ViewModels.MainViewModel vm)
            vm.LogEntries.CollectionChanged += LogEntries_CollectionChanged;
    }

    private void LogEntries_CollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        if (e.Action == NotifyCollectionChangedAction.Add && ConsoleListBox.Items.Count > 0)
            ConsoleListBox.ScrollIntoView(ConsoleListBox.Items[^1]);
    }

    private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ClickCount == 2) Maximize_Click(sender, e);
        else DragMove();
    }

    private void Minimize_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;

    private void Maximize_Click(object sender, RoutedEventArgs e)
        => WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;

    private void Close_Click(object sender, RoutedEventArgs e) => Close();

    private void Screenshot_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var dpi = VisualTreeHelper.GetDpi(this);
            var bounds = new Rect(new Size(ActualWidth, ActualHeight));
            var rtb = new RenderTargetBitmap(
                (int)(bounds.Width * dpi.DpiScaleX),
                (int)(bounds.Height * dpi.DpiScaleY),
                dpi.PixelsPerInchX,
                dpi.PixelsPerInchY,
                PixelFormats.Pbgra32);

            rtb.Render(this);

            var dlg = new SaveFileDialog
            {
                FileName = $"ForgeDefcon_{DateTime.Now:yyyyMMdd_HHmmss}.png",
                Filter = "PNG Image|*.png",
                DefaultExt = ".png"
            };

            if (dlg.ShowDialog() != true) return;

            var encoder = new PngBitmapEncoder();
            encoder.Frames.Add(BitmapFrame.Create(rtb));
            using var stream = File.Create(dlg.FileName);
            encoder.Save(stream);

            if (DataContext is ViewModels.MainViewModel vm)
            {
                vm.LogEntries.Add(new Models.LogEntry
                {
                    Level = Models.LogLevel.Success,
                    Message = $"Screenshot saved to {dlg.FileName}",
                    Source = "System"
                });
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Screenshot failed: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }
}
