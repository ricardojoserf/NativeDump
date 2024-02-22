using System;
using System.Runtime.InteropServices;


namespace NativeDump
{
    internal class Win32
    {
        ///////////////// CONSTANTS /////////////////
        public const int MEM_COMMIT = 0x00001000;
        public const int PAGE_READWRITE = 0x04;
        public const int PAGE_NOACCESS = 0x01;
        public const uint PROCESS_QUERY_INFORMATION = 0x0400;
        public const uint PROCESS_VM_READ = 0x0010;
        public const int MAXIMUM_ALLOWED = 0x02000000;
        public const uint GENERIC_ALL = 0x10000000;
        public const uint FILE_SHARE_WRITE = 0x00000002;
        public const uint CREATE_ALWAYS = 2;
        public const uint FILE_ATTRIBUTE_NORMAL = 128;
        public const uint MemoryBasicInformation = 0;
        public const uint OBJ_CASE_INSENSITIVE = 0x00000040;
        public const uint FileAccess_FILE_GENERIC_WRITE = 0x120116;
        public const uint FileAttributes_Normal = 128;
        public const uint FileShare_Write = 2;
        public const uint CreationDisposition_FILE_OVERWRITE_IF = 5;
        public const uint CreateOptionFILE_SYNCHRONOUS_IO_NONALERT = 32;
        public const uint TOKEN_ADJUST_PRIVILEGES = 0x00000020;
        public const uint TOKEN_QUERY = 0x00000008;
        public const string SE_DEBUG_NAME = "SeDebugPrivilege";


        ///////////////// FUNCTIONS /////////////////
        [DllImport("ntdll.dll")]
        public static extern uint NtOpenProcess(ref IntPtr ProcessHandle, uint DesiredAccess, ref OBJECT_ATTRIBUTES ObjectAttributes, ref CLIENT_ID processId);

        [DllImport("ntdll.dll")]
        public static extern bool NtReadVirtualMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("ntdll.dll")]
        public static extern uint NtQueryVirtualMemory(IntPtr hProcess, IntPtr lpAddress, uint MemoryInformationClass, out MEMORY_BASIC_INFORMATION MemoryInformation, uint MemoryInformationLength, out uint ReturnLength);
        
        [DllImport("ntdll.dll")]
        public static extern int NtOpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, ref IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, ref LUID lpLuid);
        /*
        [DllImport("ntdll.dll")]
        public static extern int NtLookupPrivilegeValue(IntPtr PolicyHandle, ref UNICODE_STRING pString, ref LUID pLuid);
        */

        [DllImport("ntdll.dll")]
        public static extern int NtAdjustPrivilegesToken(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

        [DllImport("ntdll.dll")]
        public static extern int NtClose(IntPtr hObject);

        [DllImport("psapi.dll")]
        public static extern bool EnumProcessModulesEx(IntPtr hProcess, [Out] IntPtr[] lphModule, int cb, out uint lpcbNeeded, int dwFilterFlag);

        [DllImport("psapi.dll", SetLastError = true)]
        public static extern uint GetModuleBaseName(IntPtr hProcess, IntPtr hModule, [Out] char[] lpBaseName, uint nSize);


        ///////////////// STRUCTS /////////////////
        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_PRIVILEGES
        {
            public uint PrivilegeCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public LUID_AND_ATTRIBUTES[] Privileges;
        }

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

        // Structs Minidump file
        public struct Memory64Info
        {
            public IntPtr Address;
            public IntPtr Size;
        }
    }
}