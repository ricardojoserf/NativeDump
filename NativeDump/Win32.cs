using System;
using System.Runtime.InteropServices;


namespace NativDump
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


        ///////////////// FUNCTIONS /////////////////
        [DllImport("ntdll.dll")]
        public static extern uint NtOpenProcess(
            ref IntPtr ProcessHandle,
            uint DesiredAccess,
            ref OBJECT_ATTRIBUTES ObjectAttributes,
            ref CLIENT_ID processId);

        [DllImport("ntdll.dll")]
        public static extern bool NtReadVirtualMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            [Out] byte[] lpBuffer,
            int dwSize,
            out IntPtr lpNumberOfBytesRead);

        [DllImport("ntdll.dll")]
        public static extern uint NtQueryVirtualMemory(
            IntPtr hProcess,
            IntPtr lpAddress,
            uint MemoryInformationClass,
            out MEMORY_BASIC_INFORMATION MemoryInformation,
            uint MemoryInformationLength,
            out uint ReturnLength);

        [DllImport("ntdll.dll")]
        public static extern void RtlInitUnicodeString(
           out UNICODE_STRING DestinationString,
           [MarshalAs(UnmanagedType.LPWStr)] string SourceString);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern uint NtCreateFile(
          out IntPtr FileHadle,
          uint DesiredAcces,
          ref OBJECT_ATTRIBUTES ObjectAttributes,
          ref IO_STATUS_BLOCK IoStatusBlock,
          ref long AllocationSize,
          uint FileAttributes,
          uint ShareAccess,
          uint CreateDisposition,
          uint CreateOptions,
          IntPtr EaBuffer,
          uint EaLength
        );

        [DllImport("ntdll.dll")]
        public static extern uint NtWriteFile(
            IntPtr FileHandle,
            IntPtr Event,
            IntPtr ApcRoutine,
            IntPtr ApcContext,
            ref IO_STATUS_BLOCK IoStatusBlock,
            byte[] Buffer,
            uint Length,
            IntPtr ByteOffset,
            IntPtr Key
            );

        [DllImport("ntdll.dll")]
        public static extern int NtOpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, ref IntPtr TokenHandle);


        [DllImport("ntdll.dll")]
        public static extern int NtLookupPrivilegeValue(IntPtr PolicyHandle, ref UNICODE_STRING pString, ref LUID pLuid);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, ref LUID lpLuid);

        [DllImport("ntdll.dll")]
        public static extern int NtAdjustPrivilegesToken(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

        [DllImport("ntdll.dll")]
        public static extern int NtClose(IntPtr hObject);

        [DllImport("psapi.dll")]
        public static extern bool EnumProcessModulesEx(IntPtr hProcess, [Out] IntPtr[] lphModule, int cb, out uint lpcbNeeded, int dwFilterFlag);

        [DllImport("psapi.dll", SetLastError = true)]
        public static extern uint GetModuleBaseName(IntPtr hProcess, IntPtr hModule, [Out] char[] lpBaseName, uint nSize);


        public const uint TOKEN_ADJUST_PRIVILEGES = 0x00000020;
        public const uint TOKEN_QUERY = 0x00000008;
        public const string SE_DEBUG_NAME = "SeDebugPrivilege";

        // Estructura LUID para representar un identificador de privilegio
        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        // Estructura LUID_AND_ATTRIBUTES para representar un par de LUID y atributos
        [StructLayout(LayoutKind.Sequential)]
        public struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public uint Attributes;
        }

        // Estructura TOKEN_PRIVILEGES para representar los privilegios de un token
        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_PRIVILEGES
        {
            public uint PrivilegeCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public LUID_AND_ATTRIBUTES[] Privileges;
        }

        /*
        [DllImport("kernel32.dll")]
        static extern void GetSystemInfo(out SYSTEM_INFO lpSystemInfo);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateFileA(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll")]
        public static extern bool WriteFile(
            IntPtr hFile,
            byte[] lpBuffer,
            uint nNumberOfBytesToWrite,
            out uint lpNumberOfBytesWritten,
            IntPtr lpOverlapped);
        */


        ///////////////// STRUCTS /////////////////
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


        [StructLayout(LayoutKind.Sequential, Pack = 0)]
        public struct IO_STATUS_BLOCK
        {
            public uint status;
            public IntPtr information;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 0)]
        public struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        /*
        public struct SYSTEM_INFO
        {
            public ushort processorArchitecture;
            ushort reserved;
            public uint pageSize;
            public IntPtr minimumApplicationAddress;
            public IntPtr maximumApplicationAddress;
            public IntPtr activeProcessorMask;
            public uint numberOfProcessors;
            public uint processorType;
            public uint allocationGranularity;
            public ushort processorLevel;
            public ushort processorRevision;
        }
        */


        /* // Source: https://jhalon.github.io/utilizing-syscalls-in-csharp-2/
        ///////////////// STRUCTS /////////////////

        [Flags]
        public enum FileAccess : uint
        {
            AccessSystemSecurity = 0x1000000,
            MaximumAllowed = 0x2000000,

            Delete = 0x10000,
            ReadControl = 0x20000,
            WriteDAC = 0x40000,
            WriteOwner = 0x80000,
            Synchronize = 0x100000,

            StandardRightsRequired = 0xF0000,
            StandardRightsRead = ReadControl,
            StandardRightsWrite = ReadControl,
            StandardRightsExecute = ReadControl,
            StandardRightsAll = 0x1F0000,
            SpecificRightsAll = 0xFFFF,

            FILE_READ_DATA = 0x0001,
            FILE_LIST_DIRECTORY = 0x0001,
            FILE_WRITE_DATA = 0x0002,
            FILE_ADD_FILE = 0x0002,
            FILE_APPEND_DATA = 0x0004,
            FILE_ADD_SUBDIRECTORY = 0x0004,
            FILE_CREATE_PIPE_INSTANCE = 0x0004,
            FILE_READ_EA = 0x0008,
            FILE_WRITE_EA = 0x0010,
            FILE_EXECUTE = 0x0020,
            FILE_TRAVERSE = 0x0020,
            FILE_DELETE_CHILD = 0x0040,
            FILE_READ_ATTRIBUTES = 0x0080,
            FILE_WRITE_ATTRIBUTES = 0x0100,

            GenericRead = 0x80000000,
            GenericWrite = 0x40000000,
            GenericExecute = 0x20000000,
            GenericAll = 0x10000000,

            SPECIFIC_RIGHTS_ALL = 0x00FFFF,
            FILE_ALL_ACCESS =
            StandardRightsRequired |
            Synchronize |
            0x1FF,

            FILE_GENERIC_READ = StandardRightsRead |
                FILE_READ_DATA |
                FILE_READ_ATTRIBUTES |
                FILE_READ_EA |
                Synchronize,

            FILE_GENERIC_WRITE = StandardRightsWrite |
                FILE_WRITE_DATA |
                FILE_WRITE_ATTRIBUTES |
                FILE_WRITE_EA |
                FILE_APPEND_DATA |
                Synchronize,

            FILE_GENERIC_EXECUTE = StandardRightsExecute |
              FILE_READ_ATTRIBUTES |
              FILE_EXECUTE |
              Synchronize
        }

        [Flags]
        public enum FileShare : uint
        {
            None = 0x00000000,
            Read = 0x00000001,
            Write = 0x00000002,
            Delete = 0x00000004
        }

        [Flags]
        internal enum CreationDisposition : uint
        {
            FILE_SUPERSEDE = 0,
            FILE_OPEN = 1,
            FILE_CREATE = 2,
            FILE_OPEN_IF = 3,
            FILE_OVERWRITE = 4,
            FILE_OVERWRITE_IF = 5
        }

        [Flags]
        public enum CreateOption : uint
        {
            FILE_WRITE_THROUGH = 0x00000002,
            FILE_SEQUENTIAL_ONLY = 0x00000004,
            FILE_NO_INTERMEDIATE_BUFFERING = 0x00000008,
            FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020,
            FILE_RANDOM_ACCESS = 0x00000800
        }

        [Flags]
        public enum FileAttributes : uint
        {
            ReadOnly = 0x00000001,
            Hidden = 0x00000002,
            System = 0x00000004,
            Directory = 0x00000010,
            Archive = 0x00000020,
            Device = 0x00000040,
            Normal = 0x00000080,
            Temporary = 0x00000100,
            SparseFile = 0x00000200,
            ReparsePoint = 0x00000400,
            Compressed = 0x00000800,
            Offline = 0x00001000,
            NotContentIndexed = 0x00002000,
            Encrypted = 0x00004000,
            Write_Through = 0x80000000,
            Overlapped = 0x40000000,
            NoBuffering = 0x20000000,
            RandomAccess = 0x10000000,
            SequentialScan = 0x08000000,
            DeleteOnClose = 0x04000000,
            BackupSemantics = 0x02000000,
            PosixSemantics = 0x01000000,
            OpenReparsePoint = 0x00200000,
            OpenNoRecall = 0x00100000,
            FirstPipeInstance = 0x00080000
        }

        public enum AllocationProtect : uint
        {
            PAGE_EXECUTE = 0x00000010,
            PAGE_EXECUTE_READ = 0x00000020,
            PAGE_EXECUTE_READWRITE = 0x00000040,
            PAGE_EXECUTE_WRITECOPY = 0x00000080,
            PAGE_NOACCESS = 0x00000001,
            PAGE_READONLY = 0x00000002,
            PAGE_READWRITE = 0x00000004,
            PAGE_WRITECOPY = 0x00000008,
            PAGE_GUARD = 0x00000100,
            PAGE_NOCACHE = 0x00000200,
            PAGE_WRITECOMBINE = 0x00000400
        }
        */

        // Enums
        public enum MemProtect
        {
            PAGE_EXECUTE = 0x10,
            PAGE_EXECUTE_READ = 0x20,
            PAGE_EXECUTE_READWRITE = 0x40,
            PAGE_EXECUTE_WRITECOPY = 0x80,
            PAGE_NOACCESS = 0x01,
            PAGE_READONLY = 0x02,
            PAGE_READWRITE = 0x04,
            PAGE_WRITECOPY = 0x08,
            PAGE_TARGETS_INVALID = 0x40000000,
            PAGE_TARGETS_NO_UPDATE = 0x40000000,
            PAGE_GUARD = 0x00000100,
            PAGE_NOCACHE = 0x00000200,
            PAGE_WRITECOMBINE = 0x00000400
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint VirtualProtect(
            IntPtr lpAddress,
            uint dwSize,
            uint flNewProtect,
            out uint lpflOldProtect);

        [DllImport("kernel32.dll")]
        public static extern uint GetLastError();

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            uint nsize,
            out uint lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(
            uint processAccess,
            bool bInheritHandle,
            int processId);
    }

    ///////////////////// MINIDUMP
    public struct Memory64Info
    {
        public IntPtr Address;
        public IntPtr Size;
    }

}