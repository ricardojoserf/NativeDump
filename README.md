# NativeDump - "peb-unreadable" branch

This branch implements the same functionality as the main branch but it does not read values from the PEB structure. To get *lsasrv.dll* information, it loads the module with LdrLoadDll in your process and get its address and size with NtQueryVirtualMemory (it will be the same address in the lsass process!). As you don't need to read PEB structure in lsass process, admin privilege is not needed to get this information.

- RtlGetVersion to get the Operating System version details (Major version, minor version and build number). This is necessary for the SystemInfo Stream
- LdrLoadDll and NtQueryInformationProcess to load the lsasrv.dll module and get its address and size. This is the only module necessary for the ModuleList Stream
- NTOpenProcessToken and NtAdjustPrivilegeToken to get the "SeDebugPrivilege" privilege
- NtOpenProcess to get a handle for the lsass process
- NtQueryVirtualMemory and NtReadVirtualMemory to loop through the memory regions and dump all possible ones. At the same time it populates the Memory64List Stream
