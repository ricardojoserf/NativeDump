# NativeDump - "bof-flavour" branch

This branch implements the same functionality as the main branch using BOF files: 

- Minidump file generation using only NTAPIS
- Overwrite the Ntdll.dll library (Optional)

You can execute the files with Cobalt Strike using "bof" or with TrustedSec's [COFFLoader](https://github.com/trustedsec/COFFLoader):

```
bof nativedump_bof.o [disk/knowndlls/debugproc]
```

```
COFFLoader64.exe go nativedump_bof.o [disk/knowndlls/debugproc]
```

![bof1](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/nativedump/Screenshot_BOF.png)


You can use use an argument for overwriting ntdll.dll:
- "disk": Using a DLL already on disk. Use the value "0e0000000a0000006400690073006b000000" with COFFLoader.
- "knowndlls": Using the KnownDlls folder. Use the value "18000000140000006b006e006f0077006e0064006c006c0073000000" with COFFLoader.
- "debugproc": Using a process created in debug mode. Use the value "180000001400000064006500620075006700700072006f0063000000" with COFFLoader.

Example to overwrite the library from the ntdll.dll in disk with COFFLoader:

```
COFFLoader64.exe go nativedump_bof.o 0e0000000a0000006400690073006b000000
```

![ntdlloverwrite](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/nativedump/Screenshot_BOF2.png)