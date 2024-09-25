# NativeDump - "bof-flavour" branch

This branch implements the same functionality as the main branch using BOF files: 

- Minidump file generation using only NTAPIS
- Overwrite the Ntdll.dll library (Optional)

You can execute the files using Cobalt Strike, TrustedSec's [COFFLoader](https://github.com/trustedsec/COFFLoader) or Meterpreter's [bofloader module](https://docs.metasploit.com/docs/using-metasploit/advanced/meterpreter/meterpreter-executebof-command.html).

-----------------------------------------

## Cobalt Strike

You can execute the BOF file after importing the aggressor script "nativedump.cna":

```
nativedump <OVERWRITE_TECHNIQUE>
``` 

You can use use an argument for overwriting ntdll.dll:
- "disk": Using a DLL already on disk. The default path is "C:\Windows\System32\ntdll.dll".    
- "knowndlls": Using the KnownDlls folder.
- "debugproc": Using a process created in debug mode. The default process is "c:\windows\system32\calc.exe".
  
![bof1](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/nativedump/Screenshot_BOF1.png)

-----------------------------------------

## COFFLoader

```
COFFLoader64.exe go nativedump_bof.o <OVERWRITE_TECHNIQUE>
```

![bof2](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/nativedump/Screenshot_BOF2.png)

The argument to overwrite the ntdll library must be generated using COFFLoader's [beacon_generate.py script](https://github.com/trustedsec/COFFLoader/blob/main/beacon_generate.py):
- "disk": Use the value 09000000050000006469736b00
- "knowndlls": Use the value 0e0000000a0000006b6e6f776e646c6c7300
- "debugproc": Use the value 0e0000000a000000646562756770726f6300
  
Example using the option "disk":

```
COFFLoader64.exe go nativedump_bof.o 09000000050000006469736b00
```

![bof3](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/nativedump/Screenshot_BOF3.png)

--------------------------------------

## Meterpreter's bofloader module

You can run the BOF files in your Meterpreter session after loading the execute_bof module and using "--format-string z " to use a ntdll overwrite technique. It is important to interact with the session with a timeout around 60 seconds, so the BOF can finish execution:

```
sessions -i <SESSION-ID> --timeout 60
load bofloader
execute_bof nativedump_bof.o --format-string z <OVERWRITE_TECHNIQUE>
```

![bof4](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/nativedump/Screenshot_BOF4.png)
