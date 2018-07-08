using System;
using System.Text;
using System.Runtime.InteropServices;
using System.Windows;
using System.Threading;
using System.IO;
using Microsoft.Win32;

namespace go_encryptor
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private const int ErrorBufferSize = 1024;
        private const int KeyId = 999;

        private bool success;
        private StringBuilder error;        

        public MainWindow()
        {            
            InitializeComponent();

            error = new StringBuilder(ErrorBufferSize);
            if (EncryptionSdkWrapper.load_sdk() == 0)
            {
                MessageBox.Show(this, "Unable to load encryption sdk",
                    "GO Encryptor",
                    MessageBoxButton.OK, MessageBoxImage.Error);

                Application.Current.Shutdown();
                return;
            }

            EncryptionSdkWrapper.register_key(KeyId, "EncryptionKey");            
        }

        private void Encrypt_Click(object sender, RoutedEventArgs e)
        {
            var fileDialog = new OpenFileDialog();
            fileDialog.Multiselect = false;

            if (fileDialog.ShowDialog() == true)
            {
                var inputFile = fileDialog.FileName;
                var outputFile = inputFile + ".genc";

                if (Path.GetExtension(inputFile) == ".genc")
                {
                    MessageBox.Show(this, "File has a .genc extension",
                        "GO Encryptor",
                        MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                var optionsWindow = new EncryptOptionWindow();
                optionsWindow.Owner = this;

                optionsWindow.ShowDialog();
                if (optionsWindow.DialogResult.Value == true)
                {
                    string password = optionsWindow.AuthorizedUsers ? null :
                        optionsWindow.Password;

                    var loadingWindow = new LoadingWindow();
                    loadingWindow.Owner = this;
                    loadingWindow.ShouldClose = false;
                    loadingWindow.ContentText = "Encrypting File...";

                    Thread thread = new Thread(() => EncryptFile(loadingWindow, inputFile, outputFile, password));
                    thread.Start();

                    if (!loadingWindow.ShouldClose)
                        loadingWindow.ShowDialog();

                    thread.Join();

                    if (success)
                    {
                        MessageBox.Show(this, "Successfully encrypted file: " + inputFile,
                            "GO Encryptor",
                            MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                    else
                    {
                        MessageBox.Show(this, "Unable to encrypt file: " + error.ToString(),
                            "GO Encryptor",
                            MessageBoxButton.OK, MessageBoxImage.Error);
                    }
                }
            }
        }

        private void Decrypt_Click(object sender, RoutedEventArgs e)
        {
            var fileDialog = new OpenFileDialog();
            fileDialog.Multiselect = false;
            fileDialog.Filter = "GO encrypted files (*.genc)| *.genc";

            if (fileDialog.ShowDialog() == true)
            {
                var inputFile = fileDialog.FileName;
                var outputFile = "";

                if (Path.GetExtension(inputFile) != ".genc")
                {
                    MessageBox.Show(this, "Invalid GO encrypted file extension",
                        "GO Encryptor",
                        MessageBoxButton.OK, MessageBoxImage.Error);

                    return;
                }
                else
                {
                    outputFile = Path.Combine(Path.GetDirectoryName(inputFile), 
                        Path.GetFileNameWithoutExtension(inputFile));
                }

                string password = null;

                if (EncryptionSdkWrapper.is_file_encrypted_with_password(inputFile) == 1)
                {
                    var passwordWindow = new PasswordWindow();
                    passwordWindow.Owner = this;

                    passwordWindow.ShowDialog();
                    if (passwordWindow.DialogResult.Value)
                    {
                        password = passwordWindow.Password;
                    }
                    else
                    {
                        return;
                    }
                }
                else if (EncryptionSdkWrapper.is_file_encrypted(inputFile) == 0)
                {
                    MessageBox.Show(this, "Not a valid GO encrypted file",
                        "GO Encryptor",
                        MessageBoxButton.OK, MessageBoxImage.Error);

                    return;
                }
                
                var loadingWindow = new LoadingWindow();
                loadingWindow.Owner = this;
                loadingWindow.ShouldClose = false;
                loadingWindow.ContentText = "Decrypting File...";

                Thread thread = new Thread(() => DecryptFile(loadingWindow, inputFile, outputFile, password));
                thread.Start();

                if (!loadingWindow.ShouldClose)
                    loadingWindow.ShowDialog();

                thread.Join();                

                if (success)
                {
                    MessageBox.Show(this, "Successfully decrypted file: " + inputFile,
                        "GO Encryptor",
                        MessageBoxButton.OK, MessageBoxImage.Information);
                }
                else
                {
                    MessageBox.Show(this, "Unable to decrypt file: " + error.ToString(),
                        "GO Encryptor",
                        MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void EncryptFile(LoadingWindow loadingWindow, string inputFile, string outputFile, string password = null)
        {
            if (password == null)
            {
                if (EncryptionSdkWrapper.encrypt_file(KeyId, inputFile,
                    outputFile, error) != 0)
                {
                    success = false;
                }
                else
                {
                    success = true;
                }
            }
            else
            {
                if (EncryptionSdkWrapper.encrypt_file_with_password(KeyId,
                            password, inputFile, outputFile, error) != 0)
                {
                    success = false;
                }
                else
                {
                    success = true;
                }
            }

            loadingWindow.ShouldClose = true;
        }

        private void DecryptFile(LoadingWindow loadingWindow, string inputFile, string outputFile, string password = null)
        {
            if (password == null)
            {
                if (EncryptionSdkWrapper.decrypt_file(KeyId, inputFile,
                    outputFile, error) != 0)
                {
                    success = false;
                }
                else
                {
                    success = true;
                }
            }
            else
            {
                if (EncryptionSdkWrapper.decrypt_file_with_password(password, 
                    inputFile, outputFile, error) != 0)
                {
                    success = false;
                }
                else
                {
                    success = true;
                }
            }

            loadingWindow.ShouldClose = true;
        }

        private void wndMain_Drop(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                string[] files = (string[])e.Data.GetData(DataFormats.FileDrop);
                if (files.Length > 1)
                {
                    MessageBox.Show(this, "Only single file is supported",
                        "GO Encryptor",
                        MessageBoxButton.OK, MessageBoxImage.Error);
                }
                else
                {
                    if (Path.GetExtension(files[0]) == ".genc")
                    {
                        var inputFile = files[0];
                        var outputFile = Path.Combine(Path.GetDirectoryName(inputFile),
                            Path.GetFileNameWithoutExtension(inputFile));

                        string password = null;

                        if (EncryptionSdkWrapper.is_file_encrypted_with_password(inputFile) == 1)
                        {
                            var passwordWindow = new PasswordWindow();
                            passwordWindow.Owner = this;

                            passwordWindow.ShowDialog();
                            if (passwordWindow.DialogResult.Value)
                            {
                                password = passwordWindow.Password;
                            }
                            else
                            {
                                return;
                            }
                        }
                        else if (EncryptionSdkWrapper.is_file_encrypted(inputFile) == 0)
                        {
                            MessageBox.Show(this, "Not a valid GO encrypted file",
                                "GO Encryptor",
                                MessageBoxButton.OK, MessageBoxImage.Error);

                            return;
                        }

                        var loadingWindow = new LoadingWindow();
                        loadingWindow.Owner = this;
                        loadingWindow.ShouldClose = false;
                        loadingWindow.ContentText = "Decrypting File...";

                        Thread thread = new Thread(() => DecryptFile(loadingWindow, inputFile, outputFile, password));
                        thread.Start();

                        if (!loadingWindow.ShouldClose)
                            loadingWindow.ShowDialog();

                        thread.Join();

                        if (success)
                        {
                            MessageBox.Show(this, "Successfully decrypted file: " + inputFile,
                                "GO Encryptor",
                                MessageBoxButton.OK, MessageBoxImage.Information);
                        }
                        else
                        {
                            MessageBox.Show(this, "Unable to decrypt file: " + error.ToString(),
                                "GO Encryptor",
                                MessageBoxButton.OK, MessageBoxImage.Error);
                        }
                    }
                    else
                    {
                        var inputFile = files[0];
                        var outputFile = inputFile + ".genc";

                        var optionsWindow = new EncryptOptionWindow();
                        optionsWindow.Owner = this;

                        optionsWindow.ShowDialog();
                        if (optionsWindow.DialogResult.Value == true)
                        {
                            string password = optionsWindow.AuthorizedUsers ? null :
                                optionsWindow.Password;

                            var loadingWindow = new LoadingWindow();
                            loadingWindow.Owner = this;
                            loadingWindow.ShouldClose = false;
                            loadingWindow.ContentText = "Encrypting File...";

                            Thread thread = new Thread(() => EncryptFile(loadingWindow, inputFile, outputFile, password));
                            thread.Start();

                            if (!loadingWindow.ShouldClose)
                                loadingWindow.ShowDialog();

                            thread.Join();

                            if (success)
                            {
                                MessageBox.Show(this, "Successfully encrypted file: " + inputFile,
                                    "GO Encryptor",
                                    MessageBoxButton.OK, MessageBoxImage.Information);
                            }
                            else
                            {
                                MessageBox.Show(this, "Unable to encrypt file: " + error.ToString(),
                                    "GO Encryptor",
                                    MessageBoxButton.OK, MessageBoxImage.Error);
                            }
                        }
                    }
                }
            }
        }

        private void miAboutGo_Click(object sender, RoutedEventArgs e)
        {
            var aboutWindow = new AboutWindow();
            aboutWindow.Owner = this;

            aboutWindow.ShowDialog();
        }
    }
}
