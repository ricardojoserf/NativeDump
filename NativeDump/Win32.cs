using System;
using System.Runtime.InteropServices;


namespace NativeDump
{
    internal class Win32
    {
        ///////////////// CONSTANTS /////////////////
        public const int MEM_COMMIT = 0x00001000;
        public const int PAGE_NOACCESS = 0x01;
        public const uint PROCESS_QUERY_INFORMATION = 0x0400;
        public const uint PROCESS_VM_READ = 0x0010;
        public const uint MemoryBasicInformation = 0;
        public const uint TOKEN_ADJUST_PRIVILEGES = 0x00000020;
        public const uint TOKEN_QUERY = 0x00000008;
        public const uint GENERIC_READ = 0x80000000;
        public const uint FILE_SHARE_READ = 0x00000001;
        public const uint OPEN_EXISTING = 3;
        public const uint FILE_ATTRIBUTE_NORMAL = 0x00000080;
        public const uint PAGE_READONLY = 0x02;
        public const uint SEC_IMAGE_NO_EXECUTE = 0x11000000;
        public const uint FILE_MAP_READ = 4;
        public const uint PAGE_EXECUTE_WRITECOPY = 0x80;
        public const uint OBJ_CASE_INSENSITIVE = 0x00000040;
        public const int SECTION_MAP_READ = 0x0004;
        public const uint DEBUG_PROCESS = 0x00000001;
        public const int offset_mappeddll = 4096;


        ///////////////// FUNCTIONS — ntdll.dll /////////////////
        [DllImport("ntdll.dll")]
        public static extern uint NtOpenProcess(ref IntPtr ProcessHandle, uint DesiredAccess, ref OBJECT_ATTRIBUTES ObjectAttributes, ref CLIENT_ID processId);

        [DllImport("ntdll.dll")]
        public static extern uint NtReadVirtualMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("ntdll.dll")]
        public static extern uint NtQueryVirtualMemory(IntPtr hProcess, IntPtr lpAddress, uint MemoryInformationClass, out MEMORY_BASIC_INFORMATION MemoryInformation, uint MemoryInformationLength, out uint ReturnLength);

        [DllImport("ntdll.dll")]
        public static extern uint NtOpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, ref IntPtr TokenHandle);

        [DllImport("ntdll.dll")]
        public static extern uint NtAdjustPrivilegesToken(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

        [DllImport("ntdll.dll")]
        public static extern uint NtClose(IntPtr hObject);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern uint RtlGetVersion(ref OSVERSIONINFOEX lpVersionInformation);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern uint NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, IntPtr pbi, uint processInformationLength, out uint returnLength);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern uint NtOpenSection(ref IntPtr FileHandle, int DesiredAccess, ref OBJECT_ATTRIBUTES_FULL ObjectAttributes);


        ///////////////// FUNCTIONS — kernel32.dll /////////////////
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateFileA(string lpFileName, uint dwDesiredAccess, uint dwShareMode, uint lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, uint hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateFileMappingA(IntPtr hFile, uint lpFileMappingAttributes, uint flProtect, uint dwMaximumSizeHigh, uint dwMaximumSizeLow, string lpName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr MapViewOfFile(IntPtr hFileMappingObject, uint dwDesiredAccess, uint dwFileOffsetHigh, uint dwFileOffsetLow, uint dwNumberOfBytesToMap);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll")]
        public static extern bool DebugActiveProcessStop(int dwProcessId);

        [DllImport("kernel32.dll")]
        public static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out uint lpNumberOfBytesRead);


        ///////////////// STRUCTS /////////////////
        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_PRIVILEGES
        {
            public uint PrivilegeCount;
            public LUID Luid;
            public uint Attributes;
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public int AllocationProtect;
            public IntPtr RegionSize;
            public int State;
            public int Protect;
            public int Type;
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct CLIENT_ID
        {
            public IntPtr UniqueProcess;
            public IntPtr UniqueThread;
        }


        [StructLayout(LayoutKind.Sequential, Pack = 0)]
        public struct OBJECT_ATTRIBUTES
        {
            public int Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct OSVERSIONINFOEX
        {
            public int dwOSVersionInfoSize;
            public int dwMajorVersion;
            public int dwMinorVersion;
            public int dwBuildNumber;
            public int dwPlatformId;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
            public string szCSDVersion;
            public short wServicePackMajor;
            public short wServicePackMinor;
            public short wSuiteMask;
            public byte wProductType;
            public byte wReserved;
        }


        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            [MarshalAs(UnmanagedType.LPWStr)] public string Buffer;
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct OBJECT_ATTRIBUTES_FULL
        {
            public uint Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFO
        {
            public int cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public int dwX;
            public int dwY;
            public int dwXSize;
            public int dwYSize;
            public int dwXCountChars;
            public int dwYCountChars;
            public int dwFillAttribute;
            public int dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }


        ////////////// STRUCTS - Minidump file //////////
        [StructLayout(LayoutKind.Sequential)]
        public struct Memory64Info
        {
            public IntPtr Address;
            public IntPtr Size;
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct MinidumpHeader
        {
            public uint Signature;
            public ushort Version;
            public ushort ImplementationVersion;
            public ushort NumberOfStreams;
            public uint StreamDirectoryRva;
            public uint CheckSum;
            public IntPtr TimeDateStamp;
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct MinidumpStreamDirectoryEntry
        {
            public uint StreamType;
            public uint Size;
            public uint Location;
        }


        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode, Pack = 2)]
        public struct CUSTOM_UNICODE_STRING
        {
            public uint Length;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 31)]
            public string Buffer;
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct SystemInfoStream
        {
            public ushort ProcessorArchitecture;
            public ushort ProcessorLevel;
            public ushort ProcessorRevision;
            public byte NumberOfProcessors;
            public byte ProductType;
            public uint MajorVersion;
            public uint MinorVersion;
            public uint BuildNumber;
            public uint PlatformId;
            public uint UnknownField1;
            public uint UnknownField2;
            public IntPtr ProcessorFeatures;
            public IntPtr ProcessorFeatures2;
            public uint UnknownField3;
            public ushort UnknownField14;
            public byte UnknownField15;
        }


        [StructLayout(LayoutKind.Sequential, Pack = 2)]
        public struct ModuleListStream
        {
            public uint NumberOfModules;
            public IntPtr BaseAddress;
            public uint Size;
            public uint UnknownField1;
            public uint Timestamp;
            public uint PointerName;
            public IntPtr UnknownField2;
            public IntPtr UnknownField3;
            public IntPtr UnknownField4;
            public IntPtr UnknownField5;
            public IntPtr UnknownField6;
            public IntPtr UnknownField7;
            public IntPtr UnknownField8;
            public IntPtr UnknownField9;
            public IntPtr UnknownField10;
            public IntPtr UnknownField11;
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct Memory64ListStream
        {
            public ulong NumberOfEntries;
            public uint MemoryRegionsBaseAddress;
        }


        ///////////////// HELPERS /////////////////
        public static OBJECT_ATTRIBUTES_FULL InitializeObjectAttributes(string dll_name, uint Attributes)
        {
            OBJECT_ATTRIBUTES_FULL oa = new OBJECT_ATTRIBUTES_FULL();
            oa.RootDirectory = IntPtr.Zero;
            UNICODE_STRING objectName = new UNICODE_STRING();
            objectName.Buffer = dll_name;
            objectName.Length = (ushort)(dll_name.Length * 2);
            objectName.MaximumLength = (ushort)(dll_name.Length * 2 + 2);
            oa.ObjectName = Marshal.AllocHGlobal(Marshal.SizeOf(objectName));
            Marshal.StructureToPtr(objectName, oa.ObjectName, false);
            oa.SecurityDescriptor = IntPtr.Zero;
            oa.SecurityQualityOfService = IntPtr.Zero;
            oa.Attributes = Attributes;
            oa.Length = (uint)Marshal.SizeOf(oa);
            return oa;
        }
    }
}
