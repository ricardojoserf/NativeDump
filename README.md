# NativeDump - "bof-flavour" branch

This branch implements the same functionality as the main branch using BOF files: 

- Minidump file generation using only NTAPIS
- Overwrite the Ntdll.dll library (Optional)

You can execute the files with Cobalt Strike using "bof" or with TrustedSec's [COFFLoader](https://github.com/trustedsec/COFFLoader):

```
bof nativedump_bof.o <OVERWRITE_TECHNIQUE>
```

```
COFFLoader64.exe go nativedump_bof.o <OVERWRITE_TECHNIQUE>
```

![bof1](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/nativedump/Screenshot_BOF1.png)


You can use use an argument for overwriting ntdll.dll:
- "disk": Using a DLL already on disk. The default path is "C:\Windows\System32\ntdll.dll".
  - Translated to the value "0e0000000a0000006400690073006b000000" for COFFLoader.
    
- "knowndlls": Using the KnownDlls folder.
  - Translated to the value "18000000140000006b006e006f0077006e0064006c006c0073000000" for COFFLoader.

- "debugproc": Using a process created in debug mode. The default process is "c:\windows\system32\calc.exe".
  - Translated to the value "180000001400000064006500620075006700700072006f0063000000" for COFFLoader.

Example to overwrite the library from the ntdll.dll in disk with Cobalt Strike and COFFLoader:

```
bof nativedump_bof.o disk
```

```
COFFLoader64.exe go nativedump_bof.o 0e0000000a0000006400690073006b000000
```

![ntdlloverwrite](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/nativedump/Screenshot_BOF2.png)
