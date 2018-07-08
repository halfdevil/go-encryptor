using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;

namespace go_encryptor
{
    /// <summary>
    /// Interaction logic for PasswordWindow.xaml
    /// </summary>    
    public partial class PasswordWindow : Window
    {
        public string Password
        {
            get
            {
                return lblPassword.Password;
            }
        }

        public PasswordWindow()
        {
            InitializeComponent();
        }

        private void Ok_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = true;
        }
    }
}
