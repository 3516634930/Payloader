// UPX 壳解析与解压（批次 UX）：特征解析（UPX! magic / l_info / p_info / b_info / 文件尾
// PackHeader）+ NRV2B/NRV2D/NRV2E 解压器（UCL 官方 n2b_d.c/n2d_d.c/n2e_d.c/getbit.h
// 逐行语义移植，存档 output/ucl-*.c；GPL-2 算法语义复刻非逐字翻译）。
// 策略：解析 + 全 b_info 块解压到原始字节（供 strings/flag 搜索），不做可执行重建
//（filter 逆变换与重定位收益低），UI 提供 upx -d 指导。
// 结构锚定 upx/upx src/conf.h L540/L620-633、src/stub/src/include/linux.h L570-593。

export interface UpxBlockInfo {
  offset: number;
  uncompressedSize: number;
  compressedSize: number;
  method: string;
  filterId: number;
  filterCto: number;
}

export interface UpxInfo {
  ok: true;
  upxVersion: number;
  format: string;
  method: string;
  originalSize: number;
  packedSize: number;
  filter: number;
  blocks: UpxBlockInfo[];
}

export type UpxParseResult = UpxInfo | { ok: false; error: string };

const UPX_MAGIC = [0x55, 0x50, 0x58, 0x21]; // "UPX!"（conf.h:540 UPX_MAGIC_LE32）

const METHOD_NAMES: Record<number, string> = {
  2: 'NRV2B_LE32', 3: 'NRV2B_8', 4: 'NRV2B_LE16',
  5: 'NRV2D_LE32', 6: 'NRV2D_8', 7: 'NRV2D_LE16',
  8: 'NRV2E_LE32', 9: 'NRV2E_8', 10: 'NRV2E_LE16',
  14: 'LZMA', 15: 'DEFLATE',
};

const FORMAT_NAMES: Record<number, string> = {
  1: 'DOS COM', 2: 'DOS SYS', 3: 'DOS EXE', 4: 'DJGPP2 COFF', 5: 'Watcom/LE',
  6: 'ELF i386', 7: 'ELF amd64', 8: 'ELF arm',
  // 现代 UPX format ID（conf.h UPX_F_*）：18/22/23/24/25 为 ELF32/64/ARM/PE32/PE64
  18: 'ELF i386', 22: 'ELF amd64', 23: 'ELF arm', 24: 'Win32 PE', 25: 'Win64 PE',
  26: 'ELF arm64', 29: 'Mach-O i386', 30: 'Mach-O amd64',
};

const isMagicAt = (bytes: Uint8Array, offset: number): boolean =>
  bytes[offset] === UPX_MAGIC[0] && bytes[offset + 1] === UPX_MAGIC[1]
  && bytes[offset + 2] === UPX_MAGIC[2] && bytes[offset + 3] === UPX_MAGIC[3];

// 文件尾 PackHeader（header.S 磁盘布局，32 字节）：
// "UPX!"(0-3) ver u8@4 | format u8@5 | method u8@6 | level u8@7 | u_adler u32@8 |
// c_adler u32@12 | u_len u32@16 | c_len u32@20 | u_file_size u32@24 | filter u8@28 |
// filter_cto u8@29 | n_mru u8@30 | header_checksum u8@31。
const readTrailer = (bytes: Uint8Array, dv: DataView): { version: number; format: number; method: number; uFilesize: number; filter: number } | null => {
  const start = Math.max(0, bytes.length - 64);
  for (let i = bytes.length - 4; i >= start; i--) {
    if (!isMagicAt(bytes, i) || i + 32 > bytes.length) continue;
    return {
      version: bytes[i + 4],
      format: bytes[i + 5],
      method: bytes[i + 6],
      uFilesize: dv.getUint32(i + 24, true),
      filter: bytes[i + 28],
    };
  }
  return null;
};

export const parseUpx = (bytes: Uint8Array): UpxParseResult => {
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let magicCount = 0;
  for (let i = 0; i + 4 <= bytes.length; i++) if (isMagicAt(bytes, i)) magicCount++;
  if (magicCount === 0) return { ok: false, error: '未找到 "UPX!" 魔数——文件未加 UPX 壳。' };
  const trailer = readTrailer(bytes, dv);
  if (!trailer) return { ok: false, error: '找到 UPX 魔数但文件尾 PackHeader 不完整（文件截断？）。' };

  // 压缩块扫描：头部 l_info（l_checksum u32 | l_magic@+4 | l_lsize u2 | l_version u1 | l_format u1，
  // 共 12 字节）之后是 p_info(12: p_progid|p_filesize|p_blocksize)，再往后是
  // [b_info(12: sz_unc u32|sz_cpr u32|b_method u8|b_ftid u8|b_cto8 u8|b_unused u8) + 数据] 序列。
  // 块区起点 = l_magic 位置 - 4（回 l_info 头）+ 12（l_info）+ 12（p_info）= magic + 20。
  const blocks: UpxBlockInfo[] = [];
  let headerMagic = -1;
  for (let i = 100; i + 12 <= bytes.length && i < 0x800; i++) {
    if (isMagicAt(bytes, i)) { headerMagic = i; break; }
  }
  let cursor = headerMagic >= 0 ? headerMagic + 20 : -1;
  while (cursor > 0 && cursor + 12 <= bytes.length && blocks.length < 64) {
    const szUnc = dv.getUint32(cursor, true);
    const szCpr = dv.getUint32(cursor + 4, true);
    const method = bytes[cursor + 8];
    if (szUnc === 0 || szUnc > 0x8000_0000 || szCpr === 0 || szCpr > bytes.length || method < 2 || method > 15) break;
    blocks.push({
      offset: cursor + 12,
      uncompressedSize: szUnc,
      compressedSize: szCpr,
      method: METHOD_NAMES[method] ?? `M${method}`,
      filterId: bytes[cursor + 9],
      filterCto: bytes[cursor + 10],
    });
    cursor += 12 + szCpr;
  }

  return {
    ok: true,
    upxVersion: trailer.version,
    format: FORMAT_NAMES[trailer.format] ?? `F${trailer.format}`,
    method: METHOD_NAMES[trailer.method] ?? `M${trailer.method}`,
    originalSize: trailer.uFilesize,
    packedSize: bytes.length,
    filter: trailer.filter,
    blocks,
  };
};

// ---- UCL getbit 三粒度（getbit.h 语义：MSB-first，缓冲 8/16/32 位小端合成）----

type BitMode = '8' | 'le16' | 'le32';

class NrvBitReader {
  private bb = 0;
  private bc = 0; // le32 专用剩余位计数
  private readonly src: Uint8Array;
  private readonly srcEnd: number;
  private readonly mode: BitMode;
  public ilen: number;
  constructor(src: Uint8Array, _srcStart: number, srcEnd: number, mode: BitMode, ilen: number) {
    void _srcStart; // ilen 已含起点，参数保留调用语义
    this.src = src;
    this.srcEnd = srcEnd;
    this.mode = mode;
    this.ilen = ilen;
  }

  getbit(): number {
    if (this.mode === 'le32') {
      if (this.bc > 0) { this.bc--; return (this.bb >> this.bc) & 1; }
      if (this.ilen + 4 > this.srcEnd) throw new Error('位流输入耗尽');
      this.bb = (this.src[this.ilen] | (this.src[this.ilen + 1] << 8) | (this.src[this.ilen + 2] << 16) | (this.src[this.ilen + 3] << 24)) >>> 0;
      this.ilen += 4;
      this.bc = 31;
      return (this.bb >> 31) & 1;
    }
    const width = this.mode === '8' ? 0xff : 0xffff;
    const shift = this.mode === '8' ? 8 : 16;
    this.bb = (this.bb * 2) & 0xffffffff;
    if (this.bb & width) {
      return (this.bb >>> shift) & 1;
    }
    if (this.mode === '8') {
      if (this.ilen >= this.srcEnd) throw new Error('位流输入耗尽');
      this.bb = this.src[this.ilen++] * 2 + 1;
      return (this.bb >>> 8) & 1;
    }
    if (this.ilen + 2 > this.srcEnd) throw new Error('位流输入耗尽');
    const word = this.src[this.ilen] + this.src[this.ilen + 1] * 256;
    this.ilen += 2;
    this.bb = word * 2 + 1;
    return (this.bb >>> 16) & 1;
  }
}

export interface NrvOutcome {
  data: Uint8Array;
  error?: string;
}

// 三族统一解压（n2b/n2d/n2e_d.c 主循环逐行移植；family 差异集中在偏移/长度编码）。
export const nrvDecompress = (
  src: Uint8Array,
  srcStart: number,
  srcLen: number,
  dstLen: number,
  family: 'nrv2b' | 'nrv2d' | 'nrv2e',
  mode: BitMode,
): NrvOutcome => {
  const srcEnd = srcStart + srcLen;
  const reader = new NrvBitReader(src, srcStart, srcEnd, mode, srcStart);
  const dst = new Uint8Array(dstLen);
  let olen = 0;
  let lastMOff = 1;

  try {
    for (;;) {
      // 字面量：位=1 连续读字节
      while (reader.getbit() === 1) {
        if (reader.ilen >= srcEnd) return { data: dst.subarray(0, olen), error: '字面量读越界' };
        if (olen >= dstLen) return { data: dst.subarray(0, olen), error: '输出越界' };
        dst[olen++] = src[reader.ilen++];
      }
      // 匹配偏移
      let mOff = 1;
      if (family === 'nrv2b') {
        // n2b：m_off = m_off*2 + bit，循环直到终止位=1
        do {
          mOff = mOff * 2 + reader.getbit();
          if (mOff > 0xffffff + 3) throw new Error('偏移过大');
        } while (reader.getbit() === 0);
      } else {
        // n2d/n2e：m_off = m_off*2+bit；终止位 1 则停，否则再补 m_off = (m_off-1)*2+bit
        for (;;) {
          mOff = mOff * 2 + reader.getbit();
          if (mOff > 0xffffff + 3) throw new Error('偏移过大');
          if (reader.getbit() === 1) break;
          mOff = (mOff - 1) * 2 + reader.getbit();
        }
      }
      let mLen: number;
      if (mOff === 2) {
        // M1 转义：复用上次偏移（n2d/n2e 预读 1 位长度）
        mOff = lastMOff;
        mLen = family === 'nrv2b' ? 0 : reader.getbit();
      } else {
        if (reader.ilen >= srcEnd) return { data: dst.subarray(0, olen), error: '偏移低位读越界' };
        mOff = (mOff - 3) * 256 + src[reader.ilen++];
        if (mOff === 0xffffffff) break; // EOF 标记
        if (family === 'nrv2b') {
          mLen = 0;
        } else {
          mLen = (mOff ^ 0xffffffff) & 1; // 偏移 LSB 携带 1 位长度
          mOff >>>= 1;
        }
        lastMOff = ++mOff;
      }
      // 匹配长度（n2b/n2d/n2e 编码不同，逐族对齐 C 原版）
      if (family === 'nrv2b') {
        // n2b：无预置位，两位 getbit 初值
        mLen = reader.getbit();
        mLen = mLen * 2 + reader.getbit();
        if (mLen === 0) {
          mLen = 1;
          do {
            mLen = mLen * 2 + reader.getbit();
            if (mLen >= dstLen) throw new Error('长度过大');
          } while (reader.getbit() === 0);
          mLen += 2;
        }
      } else if (family === 'nrv2d') {
        // n2d：mLen 已预置 1 位（M1 预读 / 偏移 LSB），补 1 位成两位初值
        mLen = mLen * 2 + reader.getbit();
        if (mLen === 0) {
          mLen = 1;
          do {
            mLen = mLen * 2 + reader.getbit();
            if (mLen >= dstLen) throw new Error('长度过大');
          } while (reader.getbit() === 0);
          mLen += 2;
        }
      } else {
        // n2e 长度编码：1+bit / 3+bit / 扩展+3
        if (mLen !== 0) mLen = 1 + reader.getbit();
        else if (reader.getbit() === 1) mLen = 3 + reader.getbit();
        else {
          mLen = 1;
          do {
            mLen = mLen * 2 + reader.getbit();
            if (mLen >= dstLen) throw new Error('长度过大');
          } while (reader.getbit() === 0);
          mLen += 3;
        }
      }
      mLen += mOff > (family === 'nrv2b' ? 0xd00 : 0x500) ? 1 : 0;
      // 拷贝 mLen+1 字节
      if (mOff > olen) throw new Error(`回退越界（off=${mOff} > olen=${olen}）`);
      let mPos = olen - mOff;
      dst[olen++] = dst[mPos++];
      if (olen + mLen > dstLen) return { data: dst.subarray(0, olen), error: '输出越界' };
      do { dst[olen++] = dst[mPos++]; } while (--mLen > 0);
    }
  } catch (error) {
    return { data: dst.subarray(0, olen), error: error instanceof Error ? error.message : String(error) };
  }
  return { data: dst };
};

// UPX calltrick unfilter（filter_impl.cpp v4.2.4 L96-104 COND + ctok.h U() 逐行移植）：
// ftid 0x46/0x49（ctok32 e8e9 bswap_le，0x49 含 jcc 变体）——call/jmp 的 4 字节目标在 filter 时
// 被写成 BE32(偏移+cto)，首字节 == cto8 的恢复为 LE32(jc - ic - 1 - addvalue - cto)。
// unfilter 场景 addvalue=0（p_unix.cpp ft.init(ftid, 0)）。
export const upxUnfilter = (data: Uint8Array, filterId: number, cto8: number): void => {
  if (filterId !== 0x46 && filterId !== 0x49) return; // 其余 filter 族（16 位/ARM）未移植
  const withJcc = (filterId & 0x0f) >= 9; // 0x49 → COND2 启用
  const cto = cto8 << 24;
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  let lastcall = 0;
  const size5 = data.length - 5;
  for (let ic = 0; ic < size5; ic++) {
    const isCallJmp = data[ic] === 0xe8 || data[ic] === 0xe9;
    const isJcc = withJcc && lastcall !== ic && data[ic - 1] === 0x0f && data[ic] >= 0x80 && data[ic] <= 0x8f;
    if (!isCallJmp && !isJcc) continue;
    if (data[ic + 1] !== cto8) continue;
    const jc = ((data[ic + 1] << 24) | (data[ic + 2] << 16) | (data[ic + 3] << 8) | data[ic + 4]) >>> 0; // BE32 读
    const restored = (jc - ic - 1 - cto) >>> 0;
    dv.setUint32(ic + 1, restored, true); // LE32 写
    ic += 4;
    lastcall = ic + 1;
  }
};

// 块级解压入口：按 trailer method 决定 family + bit 粒度。
export const upxDecompressAll = (bytes: Uint8Array, info: UpxInfo): { data: Uint8Array | null; error?: string; blocksDone: number } => {
  if (info.blocks.length === 0) return { data: null, error: '未定位到压缩块（b_info 序列不完整，可试本地 upx -d）', blocksDone: 0 };
  const family = info.method.startsWith('NRV2B') ? 'nrv2b' : info.method.startsWith('NRV2D') ? 'nrv2d' : info.method.startsWith('NRV2E') ? 'nrv2e' : null;
  if (!family) {
    return { data: null, error: `压缩方法 ${info.method} 暂不支持浏览器内解压，请在本地执行 upx -d`, blocksDone: 0 };
  }
  const mode: BitMode = info.method.endsWith('LE32') ? 'le32' : info.method.endsWith('LE16') ? 'le16' : '8';
  const outs: Uint8Array[] = [];
  for (const block of info.blocks) {
    const result = nrvDecompress(bytes, block.offset, block.compressedSize, block.uncompressedSize, family, mode);
    if (result.error) return { data: null, error: `块 @0x${block.offset.toString(16)} 解压失败：${result.error}`, blocksDone: outs.length };
    if (block.filterId !== 0) upxUnfilter(result.data, block.filterId, block.filterCto);
    outs.push(result.data);
  }
  const total = outs.reduce((sum, part) => sum + part.length, 0);
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const part of outs) { merged.set(part, offset); offset += part.length; }
  return { data: merged, blocksDone: outs.length };
};
