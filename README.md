# CrystalDump

CrystalDump is a port of NativeDump, designed to provide fast and efficient memory dumping capabilities.

It supports remapping ntdll.dll, getting a clean version of the library from a process created in debug mode.


## Build

```
crystal build crystaldump.cr --release
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

![img1](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/refs/heads/master/images/nativedump/crystal_1.png)


Using the parameter *-r* it remaps the ntdll.dll library:

```
crystaldump.exe -r
```

![img2](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/refs/heads/master/images/nativedump/crystal_2.png)


Using the parameter *-o* changes the output file name:

```
crystaldump.exe -r -o document.pptx
```

![img3](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/refs/heads/master/images/nativedump/crystal_3.png)