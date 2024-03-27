# NativeDump - "ntdlloverwrite" branch

This branch implements Ntdll.dll remapping by overwriting the process library ".text" section with the clean section from the file "C:\\Windows\\System32\\ntdll.dll". You can find more remapping options in [SharpNtdllOverwrite](https://github.com/ricardojoserf/SharpNtdllOverwrite).

## Usage

```
NativeDump.exe [DUMP_FILE]
```
- DUMP_FILE: Name of file to create. The default file name is "proc_.dmp".

## Example

![img](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/nativedump/Screenshot_NtdllOverwrite.png)
