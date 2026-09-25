// capstone 桥接模块（批次 PW3）：懒加载 @alexaltea/capstone-js（BSD-3，Capstone 5 WASM，~3.3MB），
// 统一 Node（测试）与 Vite（浏览器）两种环境的 wasm 定位；只在用户首次反汇编/gadget 扫描时加载。
// 零联网约束：wasm 随应用打包本地加载，运行时不发任何网络请求。

import type { ElfInfo } from './elfParse';

export interface DisasmLine {
  address: number;
  size: number;
  bytes: string;
  mnemonic: string;
  opStr: string;
}

export interface CapstoneArch {
  arch: number;
  mode: number;
}

export const CS_ARCH_X86 = 3;
export const CS_MODE_32 = 4;
export const CS_MODE_64 = 8;
export const CS_ARCH_ARM = 0;
export const CS_MODE_ARM = 0;
export const CS_MODE_THUMB = 1 << 4;
export const CS_ARCH_ARM64 = 1;
export const CS_MODE_LITTLE_ENDIAN = 0;

export const archForElf = (elf: ElfInfo): CapstoneArch | null => {
  if (elf.machine === 'x86-64') return { arch: CS_ARCH_X86, mode: CS_MODE_64 };
  if (elf.machine === 'x86') return { arch: CS_ARCH_X86, mode: CS_MODE_32 };
  if (elf.machine === 'AArch64') return { arch: CS_ARCH_ARM64, mode: CS_MODE_LITTLE_ENDIAN };
  if (elf.machine === 'ARM') return { arch: CS_ARCH_ARM, mode: CS_MODE_ARM };
  return null;
};

type CapstoneInstance = {
  disasm: (code: number[] | Uint8Array, address: number, count?: number) => Array<{ address: number; size: number; mnemonic: string; op_str: string }>;
  close: () => void;
};

interface CapstoneModule {
  Capstone: new (arch: number, mode: number) => CapstoneInstance;
  ARCH_X86: number;
  MODE_32: number;
  MODE_64: number;
  ARCH_ARM: number;
  ARCH_ARM64: number;
  MODE_ARM: number;
  MODE_THUMB: number;
}

let modulePromise: Promise<CapstoneModule> | null = null;

// ESM 环境引用 wasm URL（public/wasm/capstone.wasm 随应用打包，相对 base './' 路径）；
// Node 测试环境走包内默认定位。
let wasmUrlFactory: (() => string) | null = null;
export const setCapstoneWasmUrl = (factory: () => string): void => {
  wasmUrlFactory = factory;
};

const loadCapstoneModule = async (): Promise<CapstoneModule> => {
  // 包导出形态：CJS default（ESM namespace 下为 { default: init, 'module.exports': init }）。
  const imported = (await import('@alexaltea/capstone-js')) as unknown as
    Record<string, unknown>;
  const raw = (imported.default ?? imported['module.exports'] ?? imported) as
    (options?: { locateFile?: (path: string) => string }) => Promise<CapstoneModule>;
  const init = typeof raw === 'function' ? raw : (raw as { default?: unknown }).default as typeof raw;
  const options = wasmUrlFactory ? { locateFile: (path: string) => (path.endsWith('.wasm') ? wasmUrlFactory!() : path) } : undefined;
  return init(options);
};

export const getCapstone = (): Promise<CapstoneModule> => {
  if (!modulePromise) {
    modulePromise = loadCapstoneModule().catch(error => {
      modulePromise = null;
      throw error;
    });
  }
  return modulePromise;
};

export const disassembleBytes = async (
  code: Uint8Array,
  address: number,
  arch: CapstoneArch,
  maxInstructions = 4096,
): Promise<DisasmLine[]> => {
  const cs = await getCapstone();
  const handle = new cs.Capstone(arch.arch, arch.mode);
  try {
    const insns = handle.disasm(code, address, maxInstructions);
    return insns.map(insn => {
      // capstone 5 wasm 返回的 address/size 可能是 BigInt（64 位地址域），统一收敛为 Number。
      const insnAddress = typeof insn.address === 'bigint' ? Number(insn.address) : insn.address;
      const insnSize = typeof insn.size === 'bigint' ? Number(insn.size) : insn.size;
      const codeStart = insnAddress - address;
      return {
        address: insnAddress,
        size: insnSize,
        bytes: Array.from(code.subarray(codeStart, codeStart + insnSize))
          .map(b => b.toString(16).padStart(2, '0'))
          .join(' '),
        mnemonic: insn.mnemonic,
        opStr: insn.op_str,
      };
    });
  } finally {
    handle.close();
  }
};

// ---- gadget 扫描（ROPgadget 同思路：以控制转移指令为锚反向尝试解码）----

export interface GadgetHit {
  address: number;
  offset: number;
  // 从锚点指令起整段指令序列（如 "pop rdi ; ret"）。
  gadgets: string;
  size: number;
}

export interface GadgetScanOptions {
  // 反向回看窗口：锚点前最多尝试的字节数（默认 10，覆盖 4-5 条短指令）。
  lookback?: number;
  // 最多保留条数（按地址升序）。
  limit?: number;
  // 关键词过滤（对 gadget 序列做子串匹配，如 "pop rdi"）。
  filter?: string;
}

const TERMINATORS = new Set(['ret', 'syscall', 'sysenter', 'leave', 'jmp', 'call', 'iretd', 'iretq', 'hlt']);

export const scanGadgets = async (
  segment: Uint8Array,
  vaddrBase: number,
  globalOffset: number,
  arch: CapstoneArch,
  options: GadgetScanOptions = {},
): Promise<GadgetHit[]> => {
  const lookback = Math.max(1, Math.min(options.lookback ?? 10, 24));
  const limit = Math.max(1, Math.min(options.limit ?? 200, 2000));
  const filter = options.filter?.trim().toLowerCase();
  // x86/x64 锚点字节：C3=ret / 0F 05=syscall / C9=leave（栈迁移）。
  const anchorSingles = new Set([0xc3, 0xc9]);
  const hits: GadgetHit[] = [];
  const seen = new Set<number>();
  let scannedAnchors = 0;
  const cs = await getCapstone();
  const handle = new cs.Capstone(arch.arch, arch.mode);
  try {
    // capstone-wasm 对个别截断指令（如 0xc4 前缀）会抛字符串异常（CS_ERR_OK 却 throw），
    // 抛错即视为该窗口无效，不中断扫描。
    const tryDecodeAt = (start: number, anchorEnd: number): { text: string; size: number } | null => {
      const window = segment.subarray(start, anchorEnd);
      let insns: Array<{ mnemonic: string; op_str: string; size: number | bigint }>;
      try {
        insns = handle.disasm(window, vaddrBase + start, 8) as Array<{ mnemonic: string; op_str: string; size: number | bigint }>;
      } catch {
        return null;
      }
      // 解码必须完整覆盖窗口（否则是错位解码，丢弃）；size 可能是 BigInt，统一 Number。
      const consumed = insns.reduce((sum, insn) => sum + Number(insn.size), 0);
      if (consumed !== window.length) return null;
      const mnemonics = insns.map(insn => insn.mnemonic);
      for (let i = 0; i < insns.length - 1; i++) {
        // 中间出现 ret/syscall/jmp 等才算截断；leave 在中间是合法 gadget（mov rsp, rbp 后接 pop 是常见链，如 leave ; ret）。
        if (mnemonics[i] !== 'leave' && TERMINATORS.has(mnemonics[i])) return null;
      }
      if (!TERMINATORS.has(mnemonics[mnemonics.length - 1])) return null;
      const text = insns.map(insn => `${insn.mnemonic}${insn.op_str ? ' ' + insn.op_str : ''}`).join(' ; ');
      return { text, size: consumed };
    };
    for (let i = 0; i < segment.length; i++) {
      // 每 2048 个锚点让出主线程一次：2MB 级 libc 的全段扫描不在同步循环里冻结 UI。
      if ((i & 0x7ff) === 0 && i > 0) await new Promise(resolve => setTimeout(resolve, 0));
      const b = segment[i];
      let anchorEnd = -1;
      if (anchorSingles.has(b)) anchorEnd = i + 1;
      else if (b === 0x0f && segment[i + 1] === 0x05) anchorEnd = i + 2; // syscall
      if (anchorEnd < 0) continue;
      for (let back = lookback; back >= 1; back--) {
        const start = anchorEnd - 1 - back;
        if (start < 0) continue;
        // 长链优先：先试最长的回看窗口，命中即取（ROPgadget 语义：完整指令链）。
        const result = tryDecodeAt(start, anchorEnd);
        if (!result) continue;
        const address = vaddrBase + start;
        if (seen.has(address)) continue;
        if (filter && !result.text.toLowerCase().includes(filter)) continue;
        seen.add(address);
        hits.push({ address, offset: globalOffset + start, gadgets: result.text, size: result.size });
        break;
      }
      if (seen.size >= limit * 4) break; // 粗截断：去重后统一裁剪（带过滤词时按锚点计数防失控）。
      scannedAnchors += 1;
      if (scannedAnchors >= limit * 8) break;
    }
  } finally {
    handle.close();
  }
  const unique = new Map<string, GadgetHit>();
  for (const hit of hits) {
    if (!unique.has(hit.gadgets)) unique.set(hit.gadgets, hit);
  }
  return [...unique.values()].sort((a, b) => a.address - b.address).slice(0, limit);
};

// 只扫可执行段（PT_LOAD X）。
export const scanElfGadgets = async (
  elf: ElfInfo,
  bytes: Uint8Array,
  options: GadgetScanOptions = {},
): Promise<{ hits: GadgetHit[]; arch: CapstoneArch | null; error?: string }> => {
  const arch = archForElf(elf);
  if (!arch) return { hits: [], arch: null, error: `暂不支持 ${elf.machine} 架构的 gadget 扫描（支持 x86 / x86-64 / ARM / AArch64）。` };
  const execSegs = elf.programHeaders.filter(p => p.type === 'LOAD' && p.executable && p.filesz > 0);
  if (execSegs.length === 0) return { hits: [], arch, error: '没有可执行段。' };
  const all: GadgetHit[] = [];
  for (const seg of execSegs) {
    const end = Math.min(bytes.length, seg.offset + seg.filesz);
    const hits = await scanGadgets(bytes.subarray(seg.offset, end), seg.vaddr, seg.offset, arch, options);
    all.push(...hits);
  }
  const filter = options.filter?.trim().toLowerCase();
  const unique = new Map<string, GadgetHit>();
  for (const hit of all) {
    if (!unique.has(hit.gadgets)) unique.set(hit.gadgets, hit);
  }
  const list = [...unique.values()].sort((a, b) => a.address - b.address);
  return { hits: filter ? list.filter(h => h.gadgets.toLowerCase().includes(filter)) : list, arch };
};
