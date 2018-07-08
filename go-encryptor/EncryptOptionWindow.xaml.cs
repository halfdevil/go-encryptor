using System;
using System.Windows;

namespace go_encryptor
{
    /// <summary>
    /// Interaction logic for EncryptOptionWindow.xaml
    /// </summary>
    public partial class EncryptOptionWindow : Window
    {
        public bool AuthorizedUsers
        {
            get
            {
                return rdbAuthorizedUsers.IsChecked == true;
            }
        }

        public string Password
        {
            get
            {
                return pboxPassword.Password;
            }
        }

        public EncryptOptionWindow()
        {
            InitializeComponent();
        }

        private void Ok_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = true;
        }

        private void Users_Checked(object sender, RoutedEventArgs e)
        {
            if (rdbExternalUsers != null)
            {
                if (rdbExternalUsers.IsChecked == true)
                {
                    lblPassword.IsEnabled = true;
                    pboxPassword.IsEnabled = true;
                }
                else
                {
                    lblPassword.IsEnabled = false;
                    pboxPassword.IsEnabled = false;
                }
            }
        }
    }
}
