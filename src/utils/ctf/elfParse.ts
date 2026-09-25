// ELF 结构解析器（纯 JS，零依赖）：header / program headers / sections / dynamic / dynsym / symtab，
// 以及 checksec（NX/Canary/PIE/RELRO/RPATH/FORTIFY/Stripped）推导与攻击路径建议。
// 语义对齐 readelf / pwntools checksec；本地解析、不执行、20MB 上限由调用方约束。
// 用途：Pwn 域 checksec 卡 + libc 符号偏移 + 逆向域 ELF 结构面板 + gadget 扫描（配合 capstone）。

export type ElfClass = 32 | 64;
export type ElfEndian = 'little' | 'big';

export interface ElfProgramHeader {
  index: number;
  type: string;
  flags: string;
  vaddr: number;
  offset: number;
  filesz: number;
  memsz: number;
  readable: boolean;
  writable: boolean;
  executable: boolean;
}

export interface ElfSection {
  index: number;
  name: string;
  type: string;
  flags: string;
  addr: number;
  offset: number;
  size: number;
  writable: boolean;
  executable: boolean;
}

export interface ElfSymbol {
  name: string;
  value: number;
  size: number;
  // undefined=导入（SHN_UNDEF），global/weak 定义=导出，local=本地符号。
  bind: 'local' | 'global' | 'weak';
  type: string;
  defined: boolean;
}

export interface ElfDynamicEntry {
  tag: string;
  value: number;
}

export type ChecksecKey = 'arch' | 'relro' | 'canary' | 'nx' | 'pie' | 'rpath' | 'fortify' | 'stripped';

export interface ChecksecItem {
  key: ChecksecKey;
  label: string;
  value: string;
  // ok = 保护开启（对攻击者不利）；warn = 关闭（存在可利用路径）；info = 中性描述。
  severity: 'ok' | 'warn' | 'info';
  advice: string;
}

export interface ElfInfo {
  ok: true;
  byteLength: number;
  eiClass: ElfClass;
  endian: ElfEndian;
  osabi: string;
  eiType: string;
  typeId: number;
  machine: string;
  entry: number;
  programHeaders: ElfProgramHeader[];
  sections: ElfSection[];
  dynamic: ElfDynamicEntry[];
  dynamicSymbols: ElfSymbol[];
  symbolTable: ElfSymbol[];
  needed: string[];
  interp: string | null;
  buildId: string | null;
  checksec: ChecksecItem[];
  isSharedObject: boolean;
}

export type ElfParseResult = ElfInfo | { ok: false; error: string };

const PT_NAMES: Record<number, string> = {
  0: 'NULL', 1: 'LOAD', 2: 'DYNAMIC', 3: 'INTERP', 4: 'NOTE', 5: 'SHLIB', 6: 'PHDR',
  7: 'TLS', 0x6474e550: 'GNU_EH_FRAME', 0x6474e551: 'GNU_STACK', 0x6474e552: 'GNU_RELRO',
  0x6474e553: 'GNU_PROPERTY', 0x6474e554: 'GNU_SFRAME',
};

const SHT_NAMES: Record<number, string> = {
  0: 'NULL', 1: 'PROGBITS', 2: 'SYMTAB', 3: 'STRTAB', 4: 'RELA', 5: 'HASH', 6: 'DYNAMIC',
  7: 'NOTE', 8: 'NOBITS', 9: 'REL', 10: 'SHLIB', 11: 'DYNSYM', 14: 'INIT_ARRAY', 15: 'FINI_ARRAY',
  0x6ffffff5: 'GNU_ATTRIBUTES', 0x6ffffff6: 'GNU_HASH', 0x6ffffffd: 'GNU_verdef', 0x6ffffffe: 'GNU_verneed', 0x6fffffff: 'GNU_versym',
};

const EM_NAMES: Record<number, string> = {
  3: 'x86', 8: 'MIPS', 20: 'PowerPC', 40: 'ARM', 50: 'IA-64', 62: 'x86-64', 183: 'AArch64', 243: 'RISC-V',
};

const ET_NAMES: Record<number, string> = { 1: 'REL（可重定位）', 2: 'EXEC（可执行）', 3: 'DYN（PIE/共享对象）', 4: 'CORE' };

const STT_NAMES: Record<number, string> = { 0: 'NOTYPE', 1: 'OBJECT', 2: 'FUNC', 3: 'SECTION', 4: 'FILE', 5: 'COMMON', 6: 'TLS' };

const OSABI_NAMES: Record<number, string> = {
  0: 'SYSV', 1: 'HPUX', 2: 'NETBSD', 3: 'GNU/Linux', 6: 'SOLARIS', 9: 'FREEBSD', 12: 'OPENBSD',
};

const DT_NAMES: Record<number, string> = {
  2: 'PLTRELSZ', 3: 'PLTGOT', 4: 'HASH', 5: 'STRTAB', 6: 'SYMTAB', 7: 'RELA', 8: 'RELASZ',
  9: 'RELAENT', 10: 'STRSZ', 11: 'SYMENT', 14: 'SONAME', 20: 'PLTREL', 21: 'DEBUG', 23: 'JMPREL',
  0x6ffffef5: 'GNU_HASH', 0x6ffffff0: 'VERSYM', 0x6ffffffe: 'VERNEED', 0x6fffffff: 'VERNEEDNUM',
};

class Cursor {
  offset = 0;
  private readonly bytes: Uint8Array;
  private readonly little: boolean;
  constructor(bytes: Uint8Array, little: boolean) {
    this.bytes = bytes;
    this.little = little;
  }
  seek(offset: number): void { this.offset = offset; }
  u8(): number { return this.bytes[this.offset++]; }
  u16(): number {
    const b = this.bytes;
    const o = this.offset;
    const v = this.little ? b[o] | (b[o + 1] << 8) : (b[o] << 8) | b[o + 1];
    this.offset += 2;
    return v >>> 0;
  }
  u32(): number {
    const b = this.bytes;
    const o = this.offset;
    const v = this.little
      ? b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)
      : (b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3];
    this.offset += 4;
    return v >>> 0;
  }
  // CTF 场景的地址/大小均 < 2^53，u64 直接拼 Number。小端先读低 32 位，大端先读高 32 位。
  u64(): number {
    const first = this.u32();
    const second = this.u32();
    return this.little ? first + second * 0x1_0000_0000 : first * 0x1_0000_0000 + second;
  }
}

const ascii = (bytes: Uint8Array, start: number, end: number): string => {
  let out = '';
  for (let i = start; i < end; i++) out += String.fromCharCode(bytes[i]);
  return out;
};

const hexNum = (value: number): string => `0x${value.toString(16)}`;

// 从 strtab（NUL 结尾字节表）读一个字符串；strOffset=0 返回空串。
const cstringAt = (bytes: Uint8Array, strtabOffset: number, strOffset: number, maxLen = 4096): string => {
  if (strOffset === 0 || strtabOffset + strOffset >= bytes.length) return '';
  const start = strtabOffset + strOffset;
  let end = start;
  const limit = Math.min(bytes.length, start + maxLen);
  while (end < limit && bytes[end] !== 0) end++;
  return ascii(bytes, start, end);
};

const phFlagsText = (value: number): string => {
  let out = '';
  if (value & 4) out += 'R';
  if (value & 2) out += 'W';
  if (value & 1) out += 'E';
  return out || '-';
};

// SHF_WRITE=0x1 SHF_ALLOC=0x2 SHF_EXECINSTR=0x4
const shFlagsText = (value: number): string => {
  let out = '';
  if (value & 0x1) out += 'W';
  if (value & 0x2) out += 'A';
  if (value & 0x4) out += 'X';
  return out || '-';
};

export const parseElf = (bytes: Uint8Array): ElfParseResult => {
  if (bytes.length < 22) return { ok: false, error: '文件过短，不是有效 ELF。' };
  if (!(bytes[0] === 0x7f && bytes[1] === 0x45 && bytes[2] === 0x4c && bytes[3] === 0x46)) {
    return { ok: false, error: '魔数不是 \\x7fELF——非 ELF 文件。' };
  }
  const eiClass: ElfClass = bytes[4] === 2 ? 64 : 32;
  const endian: ElfEndian = bytes[5] === 2 ? 'big' : 'little';
  const osabi = OSABI_NAMES[bytes[7]] ?? `ABI ${bytes[7]}`;
  const cur = new Cursor(bytes, endian === 'little');
  cur.seek(16);
  const typeId = cur.u16();
  const machineId = cur.u16();
  if (cur.u32() !== 1) return { ok: false, error: 'ELF version 字段异常（应为 1）。' };
  const entry = eiClass === 64 ? cur.u64() : cur.u32();
  const phoff = eiClass === 64 ? cur.u64() : cur.u32();
  const shoff = eiClass === 64 ? cur.u64() : cur.u32();
  cur.u32(); // e_flags
  cur.u16(); // e_ehsize
  const phentsize = cur.u16();
  const phnum = cur.u16();
  const shentsize = cur.u16();
  const shnum = cur.u16();
  const shstrndx = cur.u16();

  // ---- program headers ----
  const programHeaders: ElfProgramHeader[] = [];
  for (let i = 0; i < Math.min(phnum, 256); i++) {
    const base = phoff + i * phentsize;
    if (base + phentsize > bytes.length || base < 0) break;
    cur.seek(base);
    if (eiClass === 64) {
      const pType = cur.u32();
      const pFlags = cur.u32();
      const pOffset = cur.u64();
      const pVaddr = cur.u64();
      cur.u64(); // p_paddr
      const pFilesz = cur.u64();
      const pMemsz = cur.u64();
      programHeaders.push({
        index: i, type: PT_NAMES[pType] ?? hexNum(pType), flags: phFlagsText(pFlags),
        vaddr: pVaddr, offset: pOffset, filesz: pFilesz, memsz: pMemsz,
        readable: (pFlags & 4) !== 0, writable: (pFlags & 2) !== 0, executable: (pFlags & 1) !== 0,
      });
    } else {
      const pType = cur.u32();
      const pOffset = cur.u32();
      const pVaddr = cur.u32();
      cur.u32(); // p_paddr
      const pFilesz = cur.u32();
      const pMemsz = cur.u32();
      const pFlags = cur.u32();
      programHeaders.push({
        index: i, type: PT_NAMES[pType] ?? hexNum(pType), flags: phFlagsText(pFlags),
        vaddr: pVaddr, offset: pOffset, filesz: pFilesz, memsz: pMemsz,
        readable: (pFlags & 4) !== 0, writable: (pFlags & 2) !== 0, executable: (pFlags & 1) !== 0,
      });
    }
  }

  // ---- section headers ----
  interface RawSection { nameOff: number; type: number; flags: number; addr: number; offset: number; size: number }
  const rawSections: RawSection[] = [];
  for (let i = 0; i < Math.min(shnum, 1024); i++) {
    const base = shoff + i * shentsize;
    if (base + shentsize > bytes.length || base < 0) break;
    cur.seek(base);
    const nameOff = cur.u32();
    const type = cur.u32();
    const flags = eiClass === 64 ? cur.u64() : cur.u32();
    const addr = eiClass === 64 ? cur.u64() : cur.u32();
    const offset = eiClass === 64 ? cur.u64() : cur.u32();
    const size = eiClass === 64 ? cur.u64() : cur.u32();
    rawSections.push({ nameOff, type, flags, addr, offset, size });
  }
  const shstrRaw = rawSections[shstrndx];
  const shstrBase = shstrRaw && shstrRaw.offset + shstrRaw.size <= bytes.length ? shstrRaw.offset : 0;
  const sections: ElfSection[] = rawSections.map((raw, index) => ({
    index,
    name: shstrBase ? cstringAt(bytes, shstrBase, raw.nameOff, 256) : '',
    type: SHT_NAMES[raw.type] ?? hexNum(raw.type),
    flags: shFlagsText(raw.flags),
    addr: raw.addr,
    offset: raw.offset,
    size: raw.size,
    writable: (raw.flags & 0x1) !== 0,
    executable: (raw.flags & 0x4) !== 0,
  }));

  // ---- 符号表（.dynsym 导入/导出，.symtab 完整符号）----
  const readSymbols = (section: ElfSection | undefined): ElfSymbol[] => {
    if (!section || (section.type !== 'DYNSYM' && section.type !== 'SYMTAB')) return [];
    const strSection = sections[section.index + 1];
    if (!strSection || strSection.type !== 'STRTAB') return [];
    const strtabOffset = strSection.offset;
    const entsize = eiClass === 64 ? 24 : 16;
    const out: ElfSymbol[] = [];
    const count = Math.min(Math.floor(section.size / entsize), 20000);
    for (let i = 0; i < count; i++) {
      const base = section.offset + i * entsize;
      if (base + entsize > bytes.length) break;
      cur.seek(base);
      const nameOff = cur.u32();
      if (eiClass === 64) {
        const info = cur.u8();
        cur.u8(); // st_other
        const shndx = cur.u16();
        const value = cur.u64();
        const size = cur.u64();
        out.push({
          name: cstringAt(bytes, strtabOffset, nameOff),
          value, size,
          bind: (info >> 4) === 2 ? 'weak' : (info >> 4) === 1 ? 'global' : 'local',
          type: STT_NAMES[info & 0xf] ?? String(info & 0xf),
          defined: shndx !== 0,
        });
      } else {
        const value = cur.u32();
        const size = cur.u32();
        const info = cur.u8();
        cur.u8(); // st_other
        const shndx = cur.u16();
        out.push({
          name: cstringAt(bytes, strtabOffset, nameOff),
          value, size,
          bind: (info >> 4) === 2 ? 'weak' : (info >> 4) === 1 ? 'global' : 'local',
          type: STT_NAMES[info & 0xf] ?? String(info & 0xf),
          defined: shndx !== 0,
        });
      }
    }
    return out;
  };
  const dynamicSymbols = readSymbols(sections.find(s => s.name === '.dynsym'));
  const symbolTable = readSymbols(sections.find(s => s.name === '.symtab'));

  // ---- .dynamic（NEEDED / RPATH / RUNPATH / BIND_NOW）----
  const dynamic: ElfDynamicEntry[] = [];
  const needed: string[] = [];
  let rpath = '';
  let runpath = '';
  let bindNow = false;
  let df1Pie = false;
  const dynamicSection = sections.find(s => s.name === '.dynamic');
  if (dynamicSection) {
    const strSec = sections.find(s => s.name === '.dynstr');
    const strBase = strSec ? strSec.offset : 0;
    const entsize = eiClass === 64 ? 16 : 8;
    const count = Math.min(Math.floor(dynamicSection.size / entsize), 512);
    for (let i = 0; i < count; i++) {
      const base = dynamicSection.offset + i * entsize;
      cur.seek(base);
      const tag = eiClass === 64 ? cur.u64() : cur.u32();
      const val = eiClass === 64 ? cur.u64() : cur.u32();
      if (tag === 0) break;
      if (tag === 1 && strBase) { needed.push(cstringAt(bytes, strBase, val)); continue; }
      if (tag === 15 && strBase) { rpath = cstringAt(bytes, strBase, val); continue; }
      if (tag === 29 && strBase) { runpath = cstringAt(bytes, strBase, val); continue; }
      if (tag === 24) { bindNow = true; continue; }
      if (tag === 30) { bindNow = bindNow || (val & 8) !== 0; continue; } // DT_FLAGS: DF_BIND_NOW=0x8
      if (tag === 0x6ffffffb) { // DT_FLAGS_1: DF_BIND_NOW=0x8 / DF_1_PIE=0x08000000
        bindNow = bindNow || (val & 8) !== 0;
        df1Pie = df1Pie || (val & 0x08000000) !== 0;
        continue;
      }
      dynamic.push({ tag: DT_NAMES[tag] ?? hexNum(tag), value: val });
    }
  }

  // ---- INTERP ----
  const interpPh = programHeaders.find(p => p.type === 'INTERP');
  const interp = interpPh && interpPh.offset < bytes.length
    ? (() => {
      const end = bytes.indexOf(0, interpPh.offset);
      return ascii(bytes, interpPh.offset, end < 0 ? Math.min(bytes.length, interpPh.offset + 256) : end);
    })()
    : null;

  // ---- BuildID（PT_NOTE 内 NT_GNU_BUILD_ID = type 3 / "GNU"）----
  let buildId: string | null = null;
  const notePh = programHeaders.find(p => p.type === 'NOTE');
  if (notePh) {
    const end = Math.min(bytes.length, notePh.offset + notePh.filesz);
    let off = notePh.offset;
    while (off + 16 <= end) {
      cur.seek(off);
      const namesz = cur.u32();
      const descsz = cur.u32();
      const ntype = cur.u32();
      const pad4 = (n: number) => n + ((4 - (n % 4)) % 4);
      const nameStart = off + 12;
      const descStart = nameStart + pad4(namesz);
      if (ntype === 3 && namesz >= 4 && ascii(bytes, nameStart, nameStart + 4) === 'GNU\0' && descStart + descsz <= end) {
        let id = '';
        for (let i = 0; i < Math.min(descsz, 64); i++) id += bytes[descStart + i].toString(16).padStart(2, '0');
        buildId = id;
        break;
      }
      off = descStart + pad4(descsz);
    }
  }

  // ---- checksec 推导（语义对齐 pwntools checksec）----
  const machine = EM_NAMES[machineId] ?? `EM_${machineId}`;
  const gnuStack = programHeaders.find(p => p.type === 'GNU_STACK');
  const nx = gnuStack ? !gnuStack.executable : false;
  const canary = dynamicSymbols.some(s => s.name === '__stack_chk_fail');
  // PIE 判定用 DT_FLAGS_1 的 DF_1_PIE（glibc 的 libc.so.6 也带 PT_INTERP 可独立运行，
  // "有无 INTERP" 区分不了 PIE 可执行与共享对象，pwntools 同样以 DF_1_PIE 为准）。
  const pie = typeId === 3 && df1Pie;
  const isSharedObject = typeId === 3 && !df1Pie;
  const relroPh = programHeaders.find(p => p.type === 'GNU_RELRO');
  const relro = !relroPh ? 'No RELRO' : bindNow ? 'Full RELRO' : 'Partial RELRO';
  const FORTIFY_NAMES = ['__printf_chk', '__fprintf_chk', '__sprintf_chk', '__snprintf_chk', '__memcpy_chk', '__strcpy_chk', '__memset_chk', '__longjmp_chk', '__read_chk', '__recv_chk'];
  const fortified = dynamicSymbols.filter(s => s.defined && FORTIFY_NAMES.includes(s.name)).length;
  const stripped = !sections.some(s => s.name === '.symtab');

  const checksec: ChecksecItem[] = [
    {
      key: 'arch', label: '架构', value: `${machine} · ${eiClass} 位 · ${endian === 'little' ? '小端' : '大端'}`, severity: 'info',
      advice: isSharedObject
        ? '共享对象（.so）：作为库被载入，题面通常给泄漏地址求基址。'
        : '32 位下函数参数走栈；64 位前 6 个参数走寄存器（RDI/RSI/RDX/RCX/R8/R9），ROP 用 pop rdi 布参。',
    },
    {
      key: 'relro', label: 'RELRO', value: relro, severity: relro === 'Full RELRO' ? 'ok' : 'warn',
      advice: relro === 'Full RELRO'
        ? 'GOT 只读：ret2dlresolve 与 GOT 改写不可用，走 ret2libc / 栈迁移。'
        : relro === 'Partial RELRO'
          ? '.got.plt 仍可写：可改写 GOT 项（如 free@GOT → system）。'
          : '无 RELRO：整个 GOT 可写，ret2dlresolve / GOT 覆写路径全开。',
    },
    {
      key: 'canary', label: 'Canary', value: canary ? 'Canary found' : 'No canary', severity: canary ? 'ok' : 'warn',
      advice: canary
        ? '栈溢出先泄漏 canary（格式化字符串或逐字节爆破），写回时原样放回低位 \\x00。'
        : '无栈保护：可直接覆盖返回地址，无需处理 canary。',
    },
    {
      key: 'nx', label: 'NX', value: nx ? 'NX enabled' : 'NX disabled', severity: nx ? 'ok' : 'warn',
      advice: nx
        ? '栈/堆不可执行：不能直接弹 shellcode，走 ROP（pop rdi; ret → system("/bin/sh")）。'
        : 'NX 关闭：可写段直接放 shellcode 并跳转执行。',
    },
    {
      key: 'pie', label: 'PIE', value: pie ? 'PIE enabled' : isSharedObject ? 'SO（基址待泄漏）' : 'No PIE', severity: pie ? 'ok' : 'warn',
      advice: pie
        ? '地址随机化：先泄漏基址（puts(puts@got) / 格式化字符串）再构造 ROP。'
        : isSharedObject
          ? '库加载基址由使用方决定，用泄漏值减去符号偏移求基址。'
          : '地址固定：ELF 内地址可直接硬编码进 payload。',
    },
    {
      key: 'rpath', label: 'RPATH', value: runpath || rpath || '—', severity: 'info',
      advice: runpath || rpath ? '指定了运行时库搜索路径——留意同名 so 替换劫持。' : '未设置运行时库搜索路径。',
    },
    {
      key: 'fortify', label: 'FORTIFY', value: fortified > 0 ? `Enabled（${fortified} 处 _chk）` : 'No', severity: 'info',
      advice: fortified > 0 ? '部分危险函数带边界检查，溢出长度受限。' : '危险函数无边界检查加固。',
    },
    {
      key: 'stripped', label: 'Symbols', value: stripped ? 'Stripped' : `${symbolTable.length} 符号`, severity: 'info',
      advice: stripped
        ? '已 strip：.dynsym（导入函数）仍在；main 可由 __libc_start_main 的 RDI 参数定位。'
        : '未 strip：符号表可直接定位函数（IDA/Ghidra 打开即有函数名）。',
    },
  ];

  return {
    ok: true,
    byteLength: bytes.length,
    eiClass,
    endian,
    osabi,
    eiType: ET_NAMES[typeId] ?? String(typeId),
    typeId,
    machine,
    entry,
    programHeaders,
    sections,
    dynamic,
    dynamicSymbols,
    symbolTable,
    needed,
    interp,
    buildId,
    checksec,
    isSharedObject,
  };
};

// gadget 扫描辅助：文件偏移 → 虚拟地址（PIE 下即相对基址偏移；不在任何 LOAD 段内返回 null）。
export const fileOffsetToVaddr = (elf: ElfInfo, offset: number): number | null => {
  const seg = elf.programHeaders.find(p => p.type === 'LOAD' && offset >= p.offset && offset < p.offset + p.filesz);
  return seg ? seg.vaddr + (offset - seg.offset) : null;
};

// vaddr → 文件偏移（反汇编入口定位用）。
export const vaddrToFileOffset = (elf: ElfInfo, vaddr: number): number | null => {
  const seg = elf.programHeaders.find(p => p.type === 'LOAD' && vaddr >= p.vaddr && vaddr < p.vaddr + p.filesz);
  return seg ? seg.offset + (vaddr - seg.vaddr) : null;
};
