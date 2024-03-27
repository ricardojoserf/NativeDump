# NativeDump - "delegates" branch

This branch implements:

- Ntdll.dll remapping by overwriting the process library ".text" section with the clean section from the file "C:\\Windows\\System32\\ntdll.dll"
- Dynamic function resolution using function delegates and custom implementations for GetModuleHandle and GetProcAddress
- AES encryption for all relevant strings in the program ("lsass", "lsasrv.dll", function names...)
- XOR-encoding the Minidump file bytes


## Usage

```
NativeDump.exe [DUMP_FILE] [xor]
```

- DUMP_FILE: Name of file to create. The default file name is "proc_<PID>.dmp".
- "xor": Add the word "xor" after the file name to XOR the Minidump file bytes with the default value 0xCC.

You can update these values in the first lines of the Main function in Program.cs, included the XOR byte 0xCC (if you change it, update the Decoder project as well).

## Example

Using the default values:

![img](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/nativedump/Screenshot_Delegates.png)

Using XOR-encoding:

![img](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/nativedump/Screenshot_Delegates2.png)