# NativeDump

NativeDump allows to dump the lsass process using only NTAPIs generating a Minidump file with only the streams needed to be parsed by tools like Mimikatz or Pypykatz (SystemInfo, ModuleList and Memory64List stream):

- NTOpenProcessToken and NtAdjustPrivilegeToken to get the "SeDebugPrivilege" privilege.
- RtlGetVersion to get the Operating System version details (Major version, minor version and build number). This is necessary for the SystemInfo stream.
- NtQueryInformationProcess and NtReadVirtualMemory to get the lsasrv.dll address. This is the only modules necessary for the ModuleList stream.
- NtOpenProcess to get a handle for the lsass process.
- NtQueryVirtualMemory and NtReadVirtualMemory to loop through the memory regions and dump all possible ones. At the same time it populates the Memory64List stream.


![esquema](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/nativedump/nativedump_esquema.png)


The tool has been tested against Windows 10 and 11 devices with the most common security solutions (Microsoft Defender for Endpoints, Crowdstrike...) and is for now undetected.

As it only uses functions from the Ntdll.dll library, it is possible to bypass all API hooking by EDRs by remapping the Ntdll.dll in the process with a clean version of it. You can test this with the project branches:

- ntdlloverwrite - Overwrite ntdll.dll's ".text" section using a clean version from the DLL file already on disk ("C:\Windows\System32\ntdll.dll"). You can use other techniques from [SharpNtdllOverwrite](https://github.com/ricardojoserf/SharpNtdllOverwrite/)

- delegates - Overwrite ntdll.dll + Dynamic function resolution + String encryption using AES
