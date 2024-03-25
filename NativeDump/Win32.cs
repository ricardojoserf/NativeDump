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


        ///////////////// FUNCTIONS /////////////////
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
    }
}