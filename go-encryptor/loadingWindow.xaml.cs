using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;

namespace go_encryptor
{
    /// <summary>
    /// Interaction logic for LoadingWindow.xaml
    /// </summary>
    public partial class LoadingWindow : Window
    {
        private DispatcherTimer dispatcherTimer;

        public bool ShouldClose
        {
            get;
            set;
        }

        public string ContentText
        {
            get
            {
                return lblContent.Content.ToString();
            }
            set
            {
                lblContent.Content = value;
            }
        }

        public LoadingWindow()
        {
            InitializeComponent();

            dispatcherTimer = new DispatcherTimer();
            dispatcherTimer.Interval = TimeSpan.FromSeconds(1);
            dispatcherTimer.Tick += DispatcherTimer_Tick;
            dispatcherTimer.Start();
        }

        private void DispatcherTimer_Tick(object sender, EventArgs e)
        {
            if (ShouldClose)
            {
                Close();
            }
        }

        private void melLoading_MediaEnded(object sender, RoutedEventArgs e)
        {
            melLoading.Position = new TimeSpan(0, 0, 1);
            melLoading.Play();
        }
    }
}
