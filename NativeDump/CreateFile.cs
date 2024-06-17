using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using static NativeDump.Win32;


namespace NativeDump
{
    internal class CreateFile
    {
        public static byte[] JoinByteArrays(params byte[][] arrays)
        {
            return arrays.SelectMany(array => array).ToArray();
        }


        public static byte[] StructToByteArray<T>(T structInstance) where T : struct
        {
            int structSize = Marshal.SizeOf(structInstance);
            byte[] byteArray = new byte[structSize];
            IntPtr ptr = Marshal.AllocHGlobal(structSize);
            Marshal.StructureToPtr(structInstance, ptr, true);
            Marshal.Copy(ptr, byteArray, 0, structSize);
            Marshal.FreeHGlobal(ptr);
            return byteArray;
        }


        public static OSVERSIONINFOEX getBuildNumber() {
            OSVERSIONINFOEX osVersionInfo = new OSVERSIONINFOEX();
            osVersionInfo.dwOSVersionInfoSize = Marshal.SizeOf(typeof(OSVERSIONINFOEX));
            RtlGetVersion(ref osVersionInfo);
            return osVersionInfo;
        }


        public static void CreateMinidump(List<ModuleInformation> moduleInformationList, List<Memory64Info> mem64info_List, byte[] memoryRegions_byte_arr, string dumpfile)
        {
            // Header
            MinidumpHeader header = new MinidumpHeader();
            header.Signature = 0x504d444d;
            header.Version = 0xa793;
            header.NumberOfStreams = 0x3;
            header.StreamDirectoryRva = 0x20;

            // Calculate ModuleList size
            moduleInformationList.RemoveAll(moduleInfo => string.IsNullOrEmpty(moduleInfo.Name));
            Console.WriteLine("[+] Total number of modules: " + moduleInformationList.Count);
            uint moduleList_size = (uint)(Marshal.SizeOf(typeof(ModuleListStream))); // + ModuleListStream struct
            moduleList_size += (uint)(108 * moduleInformationList.Count); // (uint)(Marshal.SizeOf(typeof(ModuleInfo)) * moduleInformationList.Count); // + All MouleInfo structs
            foreach (ModuleInformation modInfo in moduleInformationList)
            {
                moduleList_size += (((uint)modInfo.FullPath.Length * 2) + 8);
            }            
            // Calculate mem64info offset
            uint mem64info_List_offset = 0x7c + moduleList_size;

            // Stream Directory
            MinidumpStreamDirectoryEntry minidumpStreamDirectoryEntry_1 = new MinidumpStreamDirectoryEntry();
            minidumpStreamDirectoryEntry_1.StreamType = 4;
            minidumpStreamDirectoryEntry_1.Size = moduleList_size; // 112 changes
            minidumpStreamDirectoryEntry_1.Location = 0x7c;
            MinidumpStreamDirectoryEntry minidumpStreamDirectoryEntry_2 = new MinidumpStreamDirectoryEntry();
            minidumpStreamDirectoryEntry_2.StreamType = 7;
            minidumpStreamDirectoryEntry_2.Size = 56;
            minidumpStreamDirectoryEntry_2.Location = 0x44;
            MinidumpStreamDirectoryEntry minidumpStreamDirectoryEntry_3 = new MinidumpStreamDirectoryEntry();
            minidumpStreamDirectoryEntry_3.StreamType = 9;
            minidumpStreamDirectoryEntry_3.Size = (uint)(16 + 16 * mem64info_List.Count);
            minidumpStreamDirectoryEntry_3.Location = mem64info_List_offset; // 0x12A changes

            // SystemInfoStream
            SystemInfoStream systemInfoStream = new SystemInfoStream();
            systemInfoStream.ProcessorArchitecture = 0x9;
            OSVERSIONINFOEX osVersionInfo = getBuildNumber();
            systemInfoStream.MajorVersion = (uint)osVersionInfo.dwMajorVersion;
            systemInfoStream.MinorVersion = (uint)osVersionInfo.dwMinorVersion;
            systemInfoStream.BuildNumber = (uint)osVersionInfo.dwBuildNumber;

            // ModuleList
            ModuleListStream moduleListStream = new ModuleListStream();
            moduleListStream.NumberOfModules = (uint)moduleInformationList.Count;
            uint pointer_index = 0x7c;                                              // Offset to ModuleList
            pointer_index += (uint)(Marshal.SizeOf(typeof(ModuleListStream)));      // + ModuleListStream struct
            pointer_index += (uint)(108 * moduleInformationList.Count); // (uint) (Marshal.SizeOf(typeof(ModuleInfo)) * moduleInformationList.Count); // + All MouleInfo structs
            
            byte[] moduleinfo_byte_arr = { };
            byte[] dll_unicodepaths_byte_arr = { };

            foreach (ModuleInformation modInfo in moduleInformationList)
            {
                ModuleInfoStruct module_info_aux = new ModuleInfoStruct();
                module_info_aux.BaseAddress = modInfo.Address;
                module_info_aux.Size = (uint)modInfo.Size;
                module_info_aux.PointerName = pointer_index;
                pointer_index += (uint) (modInfo.FullPath.Length * 2 + 8);
                byte[] moduleInfo1_byte_arr = StructToByteArray(module_info_aux);
                Array.Resize(ref moduleInfo1_byte_arr, moduleInfo1_byte_arr.Length + 4); // Padding needed
                moduleinfo_byte_arr = JoinByteArrays(moduleinfo_byte_arr, moduleInfo1_byte_arr); // Add to byte array

                string dll_str = modInfo.FullPath;
                uint length = (uint)(dll_str.Length * 2);
                dll_unicodepaths_byte_arr = JoinByteArrays(dll_unicodepaths_byte_arr, StructToByteArray(length));
                byte[] byteArray = Encoding.Unicode.GetBytes(dll_str);
                Array.Resize(ref byteArray, byteArray.Length + 4); // Padding needed
                dll_unicodepaths_byte_arr = JoinByteArrays(dll_unicodepaths_byte_arr, byteArray); // Add to byte array
            }

            // Memory64List
            int number_of_entries = mem64info_List.Count;
            int offset_mem_regions = (int)mem64info_List_offset + 16 + (16 * number_of_entries); // 0x12A + 16 + (16 * number_of_entries); ////// Cambia el 0x12A
            Memory64ListStream memory64ListStream = new Memory64ListStream();
            memory64ListStream.NumberOfEntries = (ulong)number_of_entries;
            memory64ListStream.MemoryRegionsBaseAddress = (uint)offset_mem_regions;
            byte[] memory64ListStream_byte_arr = StructToByteArray(memory64ListStream);
            for (int i = 0; i < mem64info_List.Count; i++)
            {
                Memory64Info memory64Info = mem64info_List[i];
                memory64ListStream_byte_arr = JoinByteArrays(memory64ListStream_byte_arr, StructToByteArray(memory64Info));
            }

            // Create Minidump file complete byte array
            byte[] header_byte_arr = StructToByteArray(header);
            byte[] streamDirectory_byte_arr = JoinByteArrays(StructToByteArray(minidumpStreamDirectoryEntry_1), StructToByteArray(minidumpStreamDirectoryEntry_2), StructToByteArray(minidumpStreamDirectoryEntry_3));
            byte[] systemInfoStream_byte_arr = StructToByteArray(systemInfoStream);
            byte[] moduleListStream_byte_arr = JoinByteArrays(StructToByteArray(moduleListStream), moduleinfo_byte_arr, dll_unicodepaths_byte_arr);
            byte[] minidumpFile = JoinByteArrays(header_byte_arr, streamDirectory_byte_arr, systemInfoStream_byte_arr, moduleListStream_byte_arr, memory64ListStream_byte_arr, memoryRegions_byte_arr);

            // Save to file
            try
            {
                using (FileStream fs = new FileStream(dumpfile, FileMode.Create))
                {
                    fs.Write(minidumpFile, 0, minidumpFile.Length);
                }
                Console.WriteLine("[+] File " + dumpfile + " created.");
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] It was not possible to create the file. Exception message: " + ex.Message);
            }
        }
    }
}