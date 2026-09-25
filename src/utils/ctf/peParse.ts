// PE（Windows 可执行）解析器（批次 RV，纯 JS 零依赖）：DOS/NT 头、节区表、导入/导出目录、
// 完整性标志（ASLR/DEP/CFG/Signature）。服务逆向域 PE 题的静态分析第一公里。
// 语义对齐 dumpbin /fileheaders、pefile 库的关键字段。

export interface PeSection {
  name: string;
  virtualAddress: number;
  virtualSize: number;
  rawSize: number;
  characteristics: string;
  readable: boolean;
  writable: boolean;
  executable: boolean;
}

export interface PeImport {
  dll: string;
  functions: string[];
}

export interface PeExport {
  name: string;
  ordinal: number;
  rva: number;
}

export type PeSecurityKey = 'aslr' | 'dep' | 'cfg' | 'signed' | 'seh';

export interface PeSecurityItem {
  key: PeSecurityKey;
  label: string;
  value: string;
  severity: 'ok' | 'warn' | 'info';
  advice: string;
}

export interface PeInfo {
  ok: true;
  machine: string;
  isDll: boolean;
  is64Bit: boolean;
  subsystem: string;
  timeStamp: string;
  entryPoint: number;
  imageBase: number;
  sections: PeSection[];
  imports: PeImport[];
  exports: PeExport[];
  security: PeSecurityItem[];
}

export type PeParseResult = PeInfo | { ok: false; error: string };

const MACHINE_NAMES: Record<number, string> = {
  0x014c: 'i386', 0x8664: 'x86-64', 0x01c0: 'ARM', 0xaa64: 'AArch64',
};

const SUBSYSTEM_NAMES: Record<number, string> = {
  2: 'GUI', 3: 'Console', 1: 'Native', 9: 'Windows CE', 14: 'EFI',
};

const sectionChars = (c: number): string => {
  let out = '';
  if (c & 0x40000000) out += 'R';
  if (c & 0x80000000) out += 'W';
  if (c & 0x20000000) out += 'E';
  if (c & 0x00000020) out += 'C';
  return out || '-';
};

const rvaToOffset = (rva: number, sections: Array<{ virtualAddress: number; virtualSize: number; rawPointer: number; rawSize: number }>): number => {
  for (const s of sections) {
    if (rva >= s.virtualAddress && rva < s.virtualAddress + Math.max(s.virtualSize, s.rawSize)) {
      return s.rawPointer + (rva - s.virtualAddress);
    }
  }
  return -1;
};

const readAscii = (bytes: Uint8Array, offset: number, maxLen = 256): string => {
  let out = '';
  const end = Math.min(bytes.length, offset + maxLen);
  for (let i = offset; i < end; i++) {
    if (bytes[i] === 0) break;
    out += String.fromCharCode(bytes[i]);
  }
  return out;
};

export const parsePe = (bytes: Uint8Array): PeParseResult => {
  if (bytes.length < 64) return { ok: false, error: '文件过短，不是有效 PE。' };
  if (!(bytes[0] === 0x4d && bytes[1] === 0x5a)) return { ok: false, error: '魔数不是 MZ——非 PE 文件。' };
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const peOffset = dv.getUint32(0x3c, true);
  if (peOffset <= 0 || peOffset + 24 > bytes.length) return { ok: false, error: 'e_lfanew 超界——损坏或非 PE 文件。' };
  if (dv.getUint32(peOffset, true) !== 0x00004550) return { ok: false, error: 'PE\\0\\0 签名缺失。' };

  const machineId = dv.getUint16(peOffset + 4, true);
  const numberOfSections = dv.getUint16(peOffset + 6, true);
  const timeStamp = dv.getUint32(peOffset + 8, true);
  const sizeOfOptionalHeader = dv.getUint16(peOffset + 20, true);
  const characteristics = dv.getUint16(peOffset + 22, true);
  const isDll = (characteristics & 0x2000) !== 0;

  const optOffset = peOffset + 24;
  if (optOffset + sizeOfOptionalHeader > bytes.length) return { ok: false, error: 'OptionalHeader 越界。' };
  const magic = dv.getUint16(optOffset, true);
  if (magic !== 0x10b && magic !== 0x20b) return { ok: false, error: `OptionalHeader 魔数异常 0x${magic.toString(16)}。` };
  const is64Bit = magic === 0x20b;
  const entryRva = dv.getUint32(optOffset + 16, true);
  const imageBase = is64Bit ? Number(dv.getBigUint64(optOffset + 24, true)) : dv.getUint32(optOffset + 28, true);
  const subsystemId = dv.getUint16(optOffset + (is64Bit ? 68 : 68), true);
  const dllCharacteristics = dv.getUint16(optOffset + (is64Bit ? 70 : 70), true);

  // DataDirectory：32 位在 opt+96，64 位在 opt+112。
  const dataDirOffset = optOffset + (is64Bit ? 112 : 96);
  const dataDir = (index: number): { rva: number; size: number } => ({
    rva: dv.getUint32(dataDirOffset + index * 8, true),
    size: dv.getUint32(dataDirOffset + index * 8 + 4, true),
  });
  const importDir = dataDir(1);
  const exportDir = dataDir(0);
  const securityDir = dataDir(4);

  // 节区表
  const sectionsStart = optOffset + sizeOfOptionalHeader;
  interface RawSection { name: string; virtualAddress: number; virtualSize: number; rawPointer: number; rawSize: number; chars: number }
  const rawSections: RawSection[] = [];
  for (let i = 0; i < Math.min(numberOfSections, 96); i++) {
    const base = sectionsStart + i * 40;
    if (base + 40 > bytes.length) break;
    const name = readAscii(bytes, base, 8);
    const virtualSize = dv.getUint32(base + 8, true);
    const virtualAddress = dv.getUint32(base + 12, true);
    const rawSize = dv.getUint32(base + 16, true);
    const rawPointer = dv.getUint32(base + 20, true);
    const chars = dv.getUint32(base + 36, true);
    rawSections.push({ name, virtualAddress, virtualSize, rawPointer, rawSize, chars });
  }
  const sections: PeSection[] = rawSections.map(s => ({
    name: s.name,
    virtualAddress: s.virtualAddress,
    virtualSize: s.virtualSize,
    rawSize: s.rawSize,
    characteristics: sectionChars(s.chars),
    readable: (s.chars & 0x40000000) !== 0,
    writable: (s.chars & 0x80000000) !== 0,
    executable: (s.chars & 0x20000000) !== 0,
  }));

  // 导入表
  const imports: PeImport[] = [];
  if (importDir.rva > 0) {
    const importOffset = rvaToOffset(importDir.rva, rawSections);
    for (let i = 0; i < 96; i++) {
      const base = importOffset + i * 20;
      if (base < 0 || base + 20 > bytes.length) break;
      const nameRva = dv.getUint32(base + 12, true);
      if (nameRva === 0) break;
      const dllName = readAscii(bytes, rvaToOffset(nameRva, rawSections));
      const thunkRva = dv.getUint32(base + 16, true) || dv.getUint32(base, true);
      const thunkOffset = rvaToOffset(thunkRva, rawSections);
      const functions: string[] = [];
      if (thunkOffset > 0) {
        const step = is64Bit ? 8 : 4;
        for (let j = 0; j < 4096; j++) {
          const t = thunkOffset + j * step;
          if (t + step > bytes.length) break;
          const ordinalFlag = is64Bit ? Number(dv.getBigUint64(t, true) & (1n << 63n)) : dv.getUint32(t, true) & 0x80000000;
          if (ordinalFlag) break;
          const hintRva = is64Bit ? Number(dv.getBigUint64(t, true) & 0xffffffffn) : dv.getUint32(t, true);
          if (hintRva === 0) break;
          const hintOffset = rvaToOffset(hintRva, rawSections);
          if (hintOffset < 0 || hintOffset + 2 > bytes.length) break;
          functions.push(readAscii(bytes, hintOffset + 2, 128));
          if (functions.length >= 512) break;
        }
      }
      imports.push({ dll: dllName, functions });
      if (imports.length >= 64) break;
    }
  }

  // 导出表
  const exports: PeExport[] = [];
  if (exportDir.rva > 0) {
    const exportOffset = rvaToOffset(exportDir.rva, rawSections);
    if (exportOffset > 0 && exportOffset + 40 <= bytes.length) {
      const numberOfFunctions = dv.getUint32(exportOffset + 20, true);
      const numberOfNames = dv.getUint32(exportOffset + 24, true);
      const namesRva = dv.getUint32(exportOffset + 32, true);
      const namesOffset = rvaToOffset(namesRva, rawSections);
      const functionsRva = dv.getUint32(exportOffset + 28, true);
      for (let i = 0; i < Math.min(numberOfNames, 2000); i++) {
        const namePtrOffset = namesOffset + i * 4;
        if (namePtrOffset + 4 > bytes.length) break;
        const fnRva = dv.getUint32(namePtrOffset, true);
        const fnOffset = rvaToOffset(fnRva, rawSections);
        if (fnOffset < 0) continue;
        const ordinal = dv.getUint16(rvaToOffset(functionsRva, rawSections) + i * 2, true);
        exports.push({ name: readAscii(bytes, fnOffset, 200), ordinal, rva: dv.getUint32(rvaToOffset(functionsRva, rawSections) + i * 2 + 0, true) });
        void ordinal;
        if (exports.length >= 500) break;
      }
      void numberOfFunctions;
    }
  }

  const security: PeSecurityItem[] = [
    {
      key: 'aslr', label: 'ASLR', value: (dllCharacteristics & 0x40) ? 'Enabled (DYNAMIC_BASE)' : 'Disabled',
      severity: (dllCharacteristics & 0x40) ? 'ok' : 'warn',
      advice: (dllCharacteristics & 0x40)
        ? '地址随机化：需要先泄漏模块基址。'
        : '无 ASLR：模块加载地址固定，硬编码地址即可。',
    },
    {
      key: 'dep', label: 'DEP', value: (dllCharacteristics & 0x100) ? 'Enabled (NX_COMPAT)' : 'Disabled',
      severity: (dllCharacteristics & 0x100) ? 'ok' : 'warn',
      advice: (dllCharacteristics & 0x100) ? '栈不可执行：走 ROP。' : '栈可执行：可直接弹 shellcode。',
    },
    {
      key: 'cfg', label: 'CFG', value: (dllCharacteristics & 0x4000) ? 'Enabled (GUARD_CF)' : 'Disabled',
      severity: 'info',
      advice: (dllCharacteristics & 0x4000) ? '控制流防护：间接调用受检查。' : '无控制流防护。',
    },
    {
      key: 'signed', label: 'Signature', value: securityDir.size > 0 ? 'Authenticode 签名存在' : '未签名',
      severity: 'info',
      advice: securityDir.size > 0 ? '证书目录存在，签名校验思路见逆向速查。' : '无数字签名。',
    },
    {
      key: 'seh', label: 'SafeSEH', value: (dllCharacteristics & 0x400) ? 'Enabled' : 'Disabled',
      severity: 'info',
      advice: (dllCharacteristics & 0x400) ? 'SEH 表受校验（32 位相关）。' : 'SEH 劫持路径开放（32 位）。',
    },
  ];

  return {
    ok: true,
    machine: MACHINE_NAMES[machineId] ?? `0x${machineId.toString(16)}`,
    isDll,
    is64Bit,
    subsystem: SUBSYSTEM_NAMES[subsystemId] ?? String(subsystemId),
    timeStamp: new Date(timeStamp * 1000).toISOString().slice(0, 10),
    entryPoint: imageBase + entryRva,
    imageBase,
    sections,
    imports,
    exports,
    security,
  };
};
