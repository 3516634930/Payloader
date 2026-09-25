// ret2libc 工作台逻辑（批次 PW2）：给定 libc 文件（ElfInfo）与泄漏值，完成
// 符号偏移查询 / "/bin/sh" 字符串扫描 / 泄漏地址→基址换算 / 目标地址计算 / 尾码识别。
// 全部纯本地计算；语义对齐 one_gadget / libc-database 的手动推导路径。

import type { ElfInfo } from './elfParse';

export interface LibcKeySymbol {
  name: string;
  offset: number;
}

// ret2libc 常用符号（含别名形态，按出现顺序全收）。
const KEY_SYMBOL_NAMES = [
  'system', 'execve', '__libc_system',
  '__libc_start_main', 'puts', 'printf', 'write', 'read', 'open', 'mprotect', 'setvbuf',
  'str_bin_sh',
] as const;

// 在 .dynsym 定义符号中查指定名字（同名多版本取最小偏移）。
export const findLibcSymbol = (elf: ElfInfo, name: string): LibcKeySymbol | null => {
  const hits = elf.dynamicSymbols.filter(s => s.defined && s.name === name && s.value > 0);
  if (hits.length === 0) return null;
  const best = hits.reduce((min, s) => (s.value < min.value ? s : min));
  return { name, offset: best.value };
};

// 关键符号面板数据：常用符号 + "binsh" 伪符号（.rodata 扫描）。
export interface LibcKeySymbols {
  symbols: LibcKeySymbol[];
  binsh: Array<{ offset: number; preview: string }>;
}

// 扫描可读段里的 "/bin/sh"（NUL 结尾），全部偏移返回（IDA 里 Strings→bin/sh 的手动等价）。
export const scanBinSh = (elf: ElfInfo, bytes: Uint8Array): Array<{ offset: number; preview: string }> => {
  const needle = '/bin/sh\0';
  const results: Array<{ offset: number; preview: string }> = [];
  const readable = elf.programHeaders.filter(p => p.type === 'LOAD' && p.readable);
  const seen = new Set<number>();
  for (const seg of readable) {
    const start = seg.offset;
    const end = Math.min(bytes.length, seg.offset + seg.filesz);
    for (let i = start; i + needle.length <= end; i++) {
      if (bytes[i] !== 0x2f) continue;
      let match = true;
      for (let j = 1; j < needle.length; j++) {
        if (bytes[i + j] !== needle.charCodeAt(j)) { match = false; break; }
      }
      if (!match) continue;
      const vaddr = seg.vaddr + (i - seg.offset);
      if (seen.has(vaddr)) continue;
      seen.add(vaddr);
      let previewEnd = i;
      const limit = Math.min(end, i + 32);
      while (previewEnd < limit && bytes[previewEnd] !== 0) previewEnd++;
      let preview = '';
      for (let j = i; j < previewEnd; j++) preview += String.fromCharCode(bytes[j]);
      results.push({ offset: vaddr, preview });
      i += needle.length - 1;
    }
    if (results.length >= 16) break;
  }
  return results;
};

export const collectLibcKeys = (elf: ElfInfo, bytes: Uint8Array): LibcKeySymbols => {
  const symbols: LibcKeySymbol[] = [];
  for (const name of KEY_SYMBOL_NAMES) {
    if (name === 'str_bin_sh') continue;
    const hit = findLibcSymbol(elf, name);
    if (hit) symbols.push(hit);
  }
  return { symbols, binsh: scanBinSh(elf, bytes) };
};

// ---- 泄漏地址 → 基址 / 目标地址换算 ----

export interface LibcBaseResult {
  base: number;
  hex: string;
}

// leak = base + offset → base = leak - offset（页对齐校验：glibc 基址始终 0x…000 页对齐）。
export const computeLibcBase = (leak: number, symbolOffset: number): LibcBaseResult | { error: string } => {
  if (!Number.isFinite(leak) || leak <= 0) return { error: '泄漏地址无效。' };
  if (!Number.isFinite(symbolOffset) || symbolOffset < 0) return { error: '符号偏移无效。' };
  const base = leak - symbolOffset;
  if (base <= 0) return { error: `泄漏值小于符号偏移（0x${symbolOffset.toString(16)}），基址为负——符号或泄漏值对不上。` };
  return { base, hex: `0x${base.toString(16)}` };
};

// 目标地址 = base + offset。
export const computeLibcAddress = (base: number, offset: number): string =>
  `0x${(base + offset).toString(16)}`;

// 页对齐提示：基址低 12 位应为 0。
export const isPageAligned = (value: number): boolean => (value & 0xfff) === 0;

// ---- 尾码识别（libc-database 的离线降级路径）----
// 泄漏地址低 12 位（页内偏移）不受 ASLR 影响：libc-database 按符号尾码匹配版本。
// 本地无数据库时给出尾码本身 + 常用符号尾码速查引导（不联网）。
export const libcTailCode = (leak: number): string =>
  (leak & 0xfff).toString(16).padStart(3, '0');

// ---- 常用 libc 版本特征速查（静态知识，供选手比对；不代替真实数据库）----
export const LIBC_TAIL_HINTS: ReadonlyArray<{ symbol: string; note: string }> = [
  { symbol: '__libc_start_main', note: '泄露它的返回地址最常见：main 的调用点在 __libc_start_main+0x?? 处，注意题面给的是函数地址还是返回地址。' },
  { symbol: 'puts / write', note: 'ret2libc 第一步泄漏 GOT：puts(puts@got) 拿到 puts 真实地址。' },
  { symbol: 'system', note: '有了基址直接 base+system；无 /bin/sh 时用 sh 或 read 读入。' },
];
