# NativeDump

NativeDump allows to dump the lsass process using only NTAPIs generating a Minidump file with only the streams needed to be parsed by tools like Mimikatz or Pypykatz (SystemInfo, ModuleList and Memory64List Streams).

![esquema](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/nativedump/nativedump_esquema.png)

- NTOpenProcessToken and NtAdjustPrivilegeToken to get the "SeDebugPrivilege" privilege
- RtlGetVersion to get the Operating System version details (Major version, minor version and build number). This is necessary for the SystemInfo Stream
- NtQueryInformationProcess and NtReadVirtualMemory to get the lsasrv.dll address. This is the only module necessary for the ModuleList Stream
- NtOpenProcess to get a handle for the lsass process
- NtQueryVirtualMemory and NtReadVirtualMemory to loop through the memory regions and dump all possible ones. At the same time it populates the Memory64List Stream


<br>

The program has one optional argument for the output file, the default file name is "proc_\<PID\>.dmp":

```
NativeDump.exe [DUMP_FILE]
```

![poc](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/nativedump/Screenshot_1.png)

The tool has been tested against Windows 10 and 11 devices with the most common security solutions (Microsoft Defender for Endpoints, Crowdstrike...) and is for now undetected. However, it does not work if PPL is enabled ~~or PEB structure is not readable~~. **Update**: Now it is possible to execute the programs without reading the PEB, check the [peb-unreadable branch](https://github.com/ricardojoserf/NativeDump/tree/peb-unreadable) :)

Some benefits of this technique are:
- It does not use the well-known dbghelp!MinidumpWriteDump function
- It only uses functions from Ntdll.dll, so it is possible to bypass API hooking by remapping the library
- The Minidump file does not have to be written to disk, you can transfer its bytes (encoded or encrypted) to a remote machine

You can find the project in different flavours (or languages):

- [main](https://github.com/ricardojoserf/NativeDump/tree/main) - **.NET** basic implementation (this branch)
  
- [python-flavour](https://github.com/ricardojoserf/NativeDump/tree/python-flavour) - **Python** implementation with 3 ntdll.dll overwrite methods + Exfiltrate to remote machine 

- [golang-flavour](https://github.com/ricardojoserf/NativeDump/tree/golang-flavour) - **Golang** implementation with 3 ntdll.dll overwrite methods + Exfiltrate to remote machine 

- [c-flavour](https://github.com/ricardojoserf/NativeDump/tree/c-flavour) - **C/C++** implementation with 3 ntdll.dll overwrite methods

- [bof-flavour](https://github.com/ricardojoserf/NativeDump/tree/bof-flavour) - **BOF file** with 3 ntdll.dll overwrite methods

- [rust-flavour](https://github.com/safedv/RustiveDump) - **Rust** implementation by @safedv

- [crystal-flavour](https://github.com/ricardojoserf/NativeDump/tree/crystal-flavour) - **Crystal** implementation with ntdll.dll overwrite capabilities

Other interesting branches using .NET:

- [remote](https://github.com/ricardojoserf/NativeDump/tree/remote) - Exfiltrate to remote machine + 3 ntdll.dll overwrite methods + Dynamic function resolution + String AES encryption + XOR-encoding Minidump content

- [all-modules](https://github.com/ricardojoserf/NativeDump/tree/all-modules) - Get the information for all modules (not only lsasrv.dll)

- [peb-unreadable](https://github.com/ricardojoserf/NativeDump/tree/peb-unreadable) - Implementation without reading lsass' PEB structure + 3 ntdll.dll overwrite methods


<!-- - [ntdlloverwrite](https://github.com/ricardojoserf/NativeDump/tree/ntdlloverwrite) - Overwrite ntdll.dll library using a clean version from a DLL file already on disk -->

<br>

-----------------------------

## Technique in detail: Creating a minimal Minidump file

After reading Minidump undocumented structures, its structure can be summed up to:

- Header: Information like the Signature ("MDMP"), the location of the Stream Directory and the number of streams
- Stream Directory: One entry for each stream, containing the type, total size and location in the file of each one 
- Streams: Every stream contains different information related to the process and has its own format
- Regions: The actual bytes from the process from each memory region which can be read

![estructure](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/nativedump/minidump_structure.png)

I created a parsing tool which can be helpful: [MinidumpParser](https://github.com/ricardojoserf/MinidumpParser). We will focus on creating a valid file with only the necessary values for the header, stream directory and the only 3 streams needed for a Minidump file to be parsed by Mimikatz/Pypykatz: SystemInfo, ModuleList and Memory64List Streams.

---------------------

#### A. Header

The header is a 32-bytes structure which can be defined in C# as:

```
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
```

The required values are:
- Signature: Fixed value 0x504d44d ("MDMP" string) 
- Version: Fixed value 0xa793 (Microsoft constant MINIDUMP_VERSION)
- NumberOfStreams: Fixed value 3, the three Streams required for the file
- StreamDirectoryRVA: Fixed value 0x20 or 32 bytes, the size of the header

---------------------

#### B. Stream Directory

Each entry in the Stream Directory is a 12-bytes structure so having 3 entries the size is 36 bytes. The C# struct definition for an entry is:

```
public struct MinidumpStreamDirectoryEntry
{
    public uint StreamType;
    public uint Size;
    public uint Location;
}
```

The field "StreamType" represents the type of stream as an integer or ID, some of the most relevant are:

| ID | Stream Type |
| :-------- | :------- |
| 0x00 | UnusedStream | 
| 0x01 | ReservedStream0 | 
| 0x02 | ReservedStream1 | 
| 0x03 | ThreadListStream | 
| 0x04 | ModuleListStream | 
| 0x05 | MemoryListStream | 
| 0x06 | ExceptionStream | 
| 0x07 | SystemInfoStream | 
| 0x08 | ThreadExListStream | 
| 0x09 | Memory64ListStream | 
| 0x0A | CommentStreamA | 
| 0x0B | CommentStreamW | 
| 0x0C | HandleDataStream | 
| 0x0D | FunctionTableStream | 
| 0x0E | UnloadedModuleListStream | 
| 0x0F | MiscInfoStream | 
| 0x10 | MemoryInfoListStream | 
| 0x11 | ThreadInfoListStream | 
| 0x12 | HandleOperationListStream | 
| 0x13 | TokenStream | 
| 0x16 | HandleOperationListStream | 

---------------------

#### C. SystemInformation Stream

First stream is a SystemInformation Stream, with ID 7. The size is 56 bytes and will be located at offset 68 (0x44), after the Stream Directory. Its C# definition is:

```
public struct SystemInformationStream
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
```

The required values are:
- ProcessorArchitecture: 9 for 64-bit and 0 for 32-bit Windows systems
- Major version, Minor version and the BuildNumber: Hardcoded or obtained through kernel32!GetVersionEx or ntdll!RtlGetVersion (we will use the latter)

---------------------

#### D. ModuleList Stream

Second stream is a ModuleList stream, with ID 4. It is located at offset 124 (0x7C) after the SystemInformation stream and it will also have a fixed size, of 112 bytes, since it will have the entry of a single module, the only one needed for the parse to be correct: "lsasrv.dll". 

The typical structure for this stream is a 4-byte value containing the number of entries followed by 108-byte entries for each module:

```
public struct ModuleListStream
{
    public uint NumberOfModules;
    public ModuleInfo[] Modules;
}
```

As there is only one, it gets simplified to:

```
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
```

The required values are:
- NumberOfStreams: Fixed value 1
- BaseAddress: Using psapi!GetModuleBaseName or a combination of ntdll!NtQueryInformationProcess and ntdll!NtReadVirtualMemory (we will use the latter)
- Size: Obtained adding all memory region sizes since BaseAddress until one with a size of 4096 bytes (0x1000), the .text section of other library
- PointerToName: Unicode string structure for the "C:\Windows\System32\lsasrv.dll" string, located after the stream itself at offset 236 (0xEC)

---------------------

#### E. Memory64List Stream

Third stream is a Memory64List stream, with ID 9. It is located at offset 298 (0x12A), after the ModuleList stream and the Unicode string, and its size depends on the number of modules.

```
public struct Memory64ListStream
{
    public ulong NumberOfEntries; 
    public uint MemoryRegionsBaseAddress;
    public Memory64Info[] MemoryInfoEntries;
}
```

Each module entry is a 16-bytes structure:

```
public struct Memory64Info
{
    public IntPtr Address;
    public IntPtr Size;
}
```

The required values are:
- NumberOfEntries: Number of memory regions, obtained after looping memory regions
- MemoryRegionsBaseAddress: Location of the start of memory regions bytes, calculated after adding the size of all 16-bytes memory entries
- Address and Size: Obtained for each valid region while looping them

---------------------

#### F. Looping memory regions

There are pre-requisites to loop the memory regions of the lsass.exe process which can be solved using only NTAPIs:

1. Obtain the "SeDebugPrivilege" permission. Instead of the typical Advapi!OpenProcessToken, Advapi!LookupPrivilegeValue and Advapi!AdjustTokenPrivilege, we will use ntdll!NtOpenProcessToken, ntdll!NtAdjustPrivilegesToken and the hardcoded value of 20 for the Luid (which is constant in all latest Windows versions)
2. Obtain the process ID. For example, loop all processes using ntdll!NtGetNextProcess, obtain the PEB address with ntdll!NtQueryInformationProcess and use ntdll!NtReadVirtualMemory to read the ImagePathName field inside ProcessParameters. To avoid overcomplicating the PoC, we will use .NET's Process.GetProcessesByName(<PROCESS_NAME>)
3. Open a process handle. Use ntdll!OpenProcess with permissions PROCESS_QUERY_INFORMATION (0x0400) to retrieve process information and PROCESS_VM_READ (0x0010) to read the memory bytes

With this it is possible to traverse process memory by calling:
- ntdll!NtQueryVirtualMemory: Return a MEMORY_BASIC_INFORMATION structure with the protection type, state, base address and size of each memory region
    - If the memory protection is not PAGE_NOACCESS (0x01) and the memory state is MEM_COMMIT (0x1000), meaning it is accessible and committed, the base address and size populates one entry of the Memory64List stream and bytes can be added to the file
    - If the base address equals lsasrv.dll base address, it is used to calculate the size of lsasrv.dll in memory
- ntdll!NtReadVirtualMemory: Add bytes of that region to the Minidump file after the Memory64List Stream

---------------------

#### G. Creating Minidump file

After previous steps we have all that is necessary to create the Minidump file. We can create a file locally or send the bytes to a remote machine, with the possibility of encoding or encrypting the bytes before. Some of these possibilities are coded in the [delegates branch](https://github.com/ricardojoserf/NativeDump/tree/delegates), where the file created locally can be encoded with XOR, and in the [remote branch](https://github.com/ricardojoserf/NativeDump/tree/remote), where the file can be encoded with XOR before being sent to a remote machine.

<br>


------------------------------------------------------------

## ⭐ Support This Project by Starring the Repository!

If you find this project helpful or interesting, please consider giving it a star 🌟 on GitHub! :)
