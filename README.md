# NativeDump - "c-flavour" branch

This branch implements the same functionality as the main branch using C/C++: 

- Minidump file generation using only NTAPIS
- Overwrite the Ntdll.dll library (Optional)

```
NativeDump.exe
```

![c1](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/nativedump/Screenshot_C1.png)

You can use use an argument for overwriting the ntdll.dll library:
- "disk": Using a DLL already on disk. The default path is "C:\Windows\System32\ntdll.dll".
- "knowndlls": Using the KnownDlls folder.
- "debugproc": Using a process created in debug mode. The default process is "c:\windows\system32\calc.exe"

![ntdlloverwrite](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/nativedump/Screenshot_C2.png)
