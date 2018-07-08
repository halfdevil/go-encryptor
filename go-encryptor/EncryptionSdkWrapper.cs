using System;
using System.Text;
using System.Runtime.InteropServices;

namespace go_encryptor
{
    public class EncryptionSdkWrapper
    {
        [DllImport("encryption-sdk.dll", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern int load_sdk();

        [DllImport("encryption-sdk.dll", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern void unload_sdk();

        [DllImport("encryption-sdk.dll", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern int is_sdk_loaded();

        [DllImport("encryption-sdk.dll", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern void register_key(int key_id, [MarshalAs(UnmanagedType.LPStr)] string key);

        [DllImport("encryption-sdk.dll", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern int encrypt_file(int key_id, [MarshalAs(UnmanagedType.LPStr)] string input_file, [MarshalAs(UnmanagedType.LPStr)] string output_file, StringBuilder error);

        [DllImport("encryption-sdk.dll", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern int encrypt_file_with_password(int key_id, [MarshalAs(UnmanagedType.LPStr)] string password, [MarshalAs(UnmanagedType.LPStr)] string input_file, [MarshalAs(UnmanagedType.LPStr)] string output_file, StringBuilder error);

        [DllImport("encryption-sdk.dll", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern int decrypt_file(int key_id, [MarshalAs(UnmanagedType.LPStr)] string input_file, [MarshalAs(UnmanagedType.LPStr)] string output_file, StringBuilder error);

        [DllImport("encryption-sdk.dll", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern int decrypt_file_with_password([MarshalAs(UnmanagedType.LPStr)] string password, [MarshalAs(UnmanagedType.LPStr)] string input_file, [MarshalAs(UnmanagedType.LPStr)] string output_file, StringBuilder error);

        [DllImport("encryption-sdk.dll", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern int is_file_encrypted([MarshalAs(UnmanagedType.LPStr)] string file);

        [DllImport("encryption-sdk.dll", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern int is_file_encrypted_with_password([MarshalAs(UnmanagedType.LPStr)] string file);
    }
}
