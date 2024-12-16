# CrystalDump

CrystalDump is a port of NativeDump, designed to provide fast and efficient memory dumping capabilities.

It supports remapping ntdll.dll, getting a clean version of the library from a process created in debug mode.


## Build

```
crystal build crystaldump.cr
```


## Usage


```
crystaldump.exe [-o OUTPUTFILE ] [-r]
```

- **Output file** (optional): Dump file name

- **Remap ntdll** (flag, optional): Remap the ntdll library


## Examples

By default it creates the "crystal.dmp" file:

```
crystaldump.exe
```

Using the parameter *-r* it remaps the ntdll.dll library:

```
crystaldump.exe -r
```

Using the parameter *-o* changes the output file name:

```
crystaldump.exe -o document.pptx -r
```

