// @alexaltea/capstone-js 无类型声明（BSD-3，Capstone 5 WASM 移植），按实际导出面补充最小声明。
declare module '@alexaltea/capstone-js' {
  export interface CapstoneInsn {
    address: number | bigint;
    size: number | bigint;
    mnemonic: string;
    op_str: string;
  }
  export class Capstone {
    constructor(arch: number, mode: number);
    disasm(code: Uint8Array | number[], address: number, count?: number): CapstoneInsn[];
    close(): void;
  }
  export interface CapstoneNamespace {
    Capstone: typeof Capstone;
    ARCH_ARM: number;
    ARCH_ARM64: number;
    ARCH_MIPS: number;
    ARCH_PPC: number;
    ARCH_SPARC: number;
    ARCH_SYSZ: number;
    ARCH_X86: number;
    ARCH_XCORE: number;
    MODE_32: number;
    MODE_64: number;
    MODE_ARM: number;
    MODE_LITTLE_ENDIAN: number;
    MODE_BIG_ENDIAN: number;
    MODE_THUMB: number;
  }
  export default function initCapstone(options?: { locateFile?: (path: string) => string }): Promise<CapstoneNamespace>;
}
