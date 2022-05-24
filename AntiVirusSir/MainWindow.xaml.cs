using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows;
using System.Windows.Forms;

namespace AntiVirusSir
{
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }
        public void BrowseFolder(object c, RoutedEventArgs a)
        {
            List<string> fileNames = new List<string>();
            FolderBrowserDialog folderBrowser = new FolderBrowserDialog();

            DialogResult result = folderBrowser.ShowDialog();

            if (!string.IsNullOrWhiteSpace(folderBrowser.SelectedPath))
            {
                try {
                    string[] files = Directory.GetFileSystemEntries(folderBrowser.SelectedPath, "*", SearchOption.AllDirectories);
                    foreach (var file in files)
                    {
                        var ex = System.IO.Path.GetExtension(file);
                        if (!ex.Equals(""))
                        {
                                if (IsPEFile(file))
                                {
                                    fileNames.Add(file);
                                }
                        }
                    }
                    File.AppendAllLines($"{folderBrowser.SelectedPath}_log.txt", fileNames);
                    Process.Start("notepad.exe", $"{folderBrowser.SelectedPath}log.txt");
                }

                catch (Exception e)
                {
                    System.Windows.Forms.MessageBox.Show(e.ToString());
                }
            }
        }

        static PEFile ToFileHeader(byte[] ar)
        {
            GCHandle handle = GCHandle.Alloc(ar, GCHandleType.Pinned);
            PEFile pfh = (PEFile)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(PEFile));
            handle.Free();
            return pfh;
        }

        static bool IsPEFile(string path)
        {
            using (BinaryReader br = new BinaryReader(File.OpenRead(path), Encoding.ASCII))
            {
                
                byte[] ar = br.ReadBytes(64);
                PEFile sig = ToFileHeader(ar);
                br.BaseStream.Seek(sig.PEHeaderAddress, SeekOrigin.Begin);
                string pe = new string(br.ReadChars(2));
                return sig.DosHeader == "MZ" && pe == "PE";
            }
        }

        [StructLayout(LayoutKind.Explicit)]
        struct PEFile
        {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 3)]
            [FieldOffset(0)]
            public string DosHeader;
            [MarshalAs(UnmanagedType.I8)]
            [FieldOffset(0x3C)]
            public long PEHeaderAddress;
        }
    }
}

