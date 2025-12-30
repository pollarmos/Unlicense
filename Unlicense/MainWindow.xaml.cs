using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using Unlicense.Core;

namespace Unlicense
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
            this.Loaded += MainWindow_Loaded;
        }

        private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            string path = @"d:\ragnarok\ragexe.exe";

            try
            {
                // [핵심] UI 스레드를 잡고 있지 않도록 Task.Run으로 감싸서 백그라운드로 보냅니다.
                // 이렇게 하면 내부에서 .GetResult()를 써도 UI가 멈추지 않습니다.
                await Task.Run(() =>
                {
                    Unlicense.Core.Application.RunUnlicense(path, false, false, false, null, null, 10);
                });

                // 작업이 끝나면 여기서 알림 창을 띄우거나 UI 갱신 가능
                MessageBox.Show("Frida 작업이 완료되었습니다!");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"오류 발생: {ex.Message}");
            }
            
            
        }
    }
}