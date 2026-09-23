import { detectFlagFormats } from '../codec/smartDecode';
import { zeroWidthDecode } from '../codec/textEncodings';

// 文件自动探测引擎（批次 K 杂项取证域）：魔数识别、信息熵、strings、可疑内容、hexdump、PNG/ZIP 修复。
// 全部为纯函数，输入只读字节、不执行任何内容；调用方负责 20MB 上限与文件读取。

export const MAX_FILE_BYTES = 20 * 1024 * 1024;

export interface MagicRule {
  ext: string;
  name: string;
  offset: number;
  // null = 该位置为通配字节
  bytes: Array<number | null>;
}

// 常见魔数表：主源 sindresorhus/file-type source/index.js（MIT）逐条核对，PCAPNG 补自 IETF draft-tuexen-opsawg-pcapng，SQLITE 补自 sqlite.org 文件格式文档。
export const MAGIC_TABLE: MagicRule[] = [
  { ext: 'png', name: 'PNG image', offset: 0, bytes: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a] },
  { ext: 'jpg', name: 'JPEG image', offset: 0, bytes: [0xff, 0xd8, 0xff] },
  { ext: 'gif', name: 'GIF image', offset: 0, bytes: [0x47, 0x49, 0x46, 0x38, null, 0x61] },
  { ext: 'bmp', name: 'BMP image', offset: 0, bytes: [0x42, 0x4d] },
  { ext: 'webp', name: 'WebP image', offset: 0, bytes: [0x52, 0x49, 0x46, 0x46, null, null, null, null, 0x57, 0x45, 0x42, 0x50] },
  { ext: 'ico', name: 'ICO icon', offset: 0, bytes: [0x00, 0x00, 0x01, 0x00] },
  { ext: 'jar', name: 'Java archive', offset: 0, bytes: [0x50, 0x4b, 0x03, 0x04] },
  { ext: 'apk', name: 'Android package', offset: 0, bytes: [0x50, 0x4b, 0x03, 0x04] },
  { ext: 'rar4', name: 'RAR v4 archive', offset: 0, bytes: [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00] },
  { ext: 'rar5', name: 'RAR v5 archive', offset: 0, bytes: [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00] },
  { ext: '7z', name: '7-Zip archive', offset: 0, bytes: [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c] },
  { ext: 'gz', name: 'Gzip archive', offset: 0, bytes: [0x1f, 0x8b, 0x08] },
  { ext: 'tar', name: 'TAR archive', offset: 257, bytes: [0x75, 0x73, 0x74, 0x61, 0x72] },
  { ext: 'bz2', name: 'Bzip2 archive', offset: 0, bytes: [0x42, 0x5a, 0x68] },
  { ext: 'xz', name: 'XZ archive', offset: 0, bytes: [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00] },
  { ext: 'zst', name: 'Zstandard archive', offset: 0, bytes: [0x28, 0xb5, 0x2f, 0xfd] },
  { ext: 'pdf', name: 'PDF document', offset: 0, bytes: [0x25, 0x50, 0x44, 0x46, 0x2d] },
  { ext: 'pcap', name: 'PCAP capture', offset: 0, bytes: [0xd4, 0xc3, 0xb2, 0xa1] },
  { ext: 'pcapbe', name: 'PCAP capture (big-endian)', offset: 0, bytes: [0xa1, 0xb2, 0xc3, 0xd4] },
  { ext: 'pcapng', name: 'PCAPNG capture', offset: 0, bytes: [0x0a, 0x0d, 0x0d, 0x0a, null, null, null, null, 0x1a, 0x2b, 0x3c, 0x4d] },
  { ext: 'elf', name: 'ELF executable', offset: 0, bytes: [0x7f, 0x45, 0x4c, 0x46] },
  { ext: 'exe', name: 'PE executable (exe/dll)', offset: 0, bytes: [0x4d, 0x5a] },
  { ext: 'macho', name: 'Mach-O binary (32-bit)', offset: 0, bytes: [0xfe, 0xed, 0xfa, 0xce] },
  { ext: 'macho', name: 'Mach-O binary (64-bit)', offset: 0, bytes: [0xcf, 0xfa, 0xed, 0xfe] },
  { ext: 'machobe', name: 'Mach-O binary (byte-swapped)', offset: 0, bytes: [0xce, 0xfa, 0xed, 0xfe] },
  { ext: 'swf', name: 'Adobe Flash SWF', offset: 0, bytes: [0x46, 0x57, 0x53] },
  { ext: 'mp4', name: 'MP4 media', offset: 4, bytes: [0x66, 0x74, 0x79, 0x70] },
  { ext: 'ogg', name: 'OGG media', offset: 0, bytes: [0x4f, 0x67, 0x67, 0x53] },
  { ext: 'wav', name: 'WAV audio', offset: 0, bytes: [0x52, 0x49, 0x46, 0x46, null, null, null, null, 0x57, 0x41, 0x56, 0x45] },
  { ext: 'flac', name: 'FLAC audio', offset: 0, bytes: [0x66, 0x4c, 0x61, 0x43] },
  { ext: 'sqlite', name: 'SQLite 3 database', offset: 0, bytes: [0x53, 0x51, 0x4c, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x20, 0x33, 0x00] },
  { ext: 'wasm', name: 'WebAssembly binary', offset: 0, bytes: [0x00, 0x61, 0x73, 0x6d] },
];

export interface DetectedType {
  ext: string;
  name: string;
}

// 魔数路由组（框架层扩展名→题型域的唯一权威定义）：命中抓包格式 → 流量分析域，可执行格式 → 逆向域。
// CtfToolkit 的文件入口路由与 recommendTools 的推荐工具条都从这里消费，禁止本地重声明（历史上三方漂移）。
export const ROUTE_EXT_GROUPS: { traffic: readonly string[]; reverse: readonly string[] } = {
  traffic: ['pcap', 'pcapbe', 'pcapng'],
  reverse: ['elf', 'exe', 'macho', 'machobe'],
};

// 路由组与魔数表的一致性自检：组内扩展名必须都能被 MAGIC_TABLE 探测出来，否则路由永不命中。
for (const routeExt of [...ROUTE_EXT_GROUPS.traffic, ...ROUTE_EXT_GROUPS.reverse]) {
  if (!MAGIC_TABLE.some(rule => rule.ext === routeExt)) {
    throw new Error(`ROUTE_EXT_GROUPS 引用了魔数表之外的扩展名：${routeExt}`);
  }
}

const magicBytesMatch = (bytes: Uint8Array, rule: MagicRule): boolean => {
  for (let index = 0; index < rule.bytes.length; index += 1) {
    const expected = rule.bytes[index];
    if (expected === null) continue;
    const position = rule.offset + index;
    if (position >= bytes.length || bytes[position] !== expected) return false;
  }
  return true;
};

// 长签名优先（WEBP/PCAPNG 的联合判定优先于裸 RIFF/裸块类型），同家族按签名长度稳定排序。
export const detectFileTypes = (bytes: Uint8Array): DetectedType[] => {
  const hits = MAGIC_TABLE.filter(rule => magicBytesMatch(bytes, rule));
  hits.sort((left, right) => right.bytes.length - left.bytes.length);
  const seen = new Set<string>();
  return hits
    .map(rule => ({ ext: rule.ext, name: rule.name }))
    .filter(hit => {
      if (seen.has(hit.name)) return false;
      seen.add(hit.name);
      return true;
    });
};

// 香农熵（字节粒度，0-8 bits/byte）：≥7.5 判高熵（加密或压缩，熵无法区分两者），文本典型 3.5-5。
export const shannonEntropy = (bytes: Uint8Array): number => {
  if (!bytes.length) return 0;
  const buckets = new Array<number>(256).fill(0);
  for (const byte of bytes) buckets[byte] += 1;
  let entropy = 0;
  for (const count of buckets) {
    if (!count) continue;
    const probability = count / bytes.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
};

export type EntropyLevel = 'empty' | 'low' | 'text' | 'medium' | 'high';

export const entropyLevel = (entropy: number, size: number): EntropyLevel => {
  if (!size) return 'empty';
  if (entropy >= 7.5) return 'high';
  if (entropy >= 6) return 'medium';
  if (entropy >= 3.5) return 'text';
  return 'low';
};

export const entropyVerdictText = (level: EntropyLevel, language: 'zh' | 'en'): string => {
  if (level === 'empty') return language === 'zh' ? '空文件，没有可分析的数据。' : 'Empty file; nothing to analyze.';
  if (level === 'high') return language === 'zh'
    ? '熵值极高（≥7.5）：数据很可能已加密或压缩，直接 strings 大概率看不到明文。'
    : 'Very high entropy (≥7.5): the data is likely encrypted or compressed; plaintext strings are unlikely.';
  if (level === 'medium') return language === 'zh'
    ? '熵值中等：可能是混合内容（文本 + 内嵌数据），建议结合 strings 与 hexdump 判断。'
    : 'Medium entropy: likely mixed content; check strings and the hexdump together.';
  if (level === 'text') return language === 'zh'
    ? '熵值在常见文本区间：内容大概率可直接阅读或含可读字符串。'
    : 'Entropy in the typical text range: content is likely readable or contains readable strings.';
  return language === 'zh' ? '熵值很低：内容高度重复或有大量填充字节。' : 'Very low entropy: highly repetitive content or padding bytes.';
};

// ---- 块级熵（逆向域熵图）----

export const ENTROPY_BLOCK_SIZE = 256;
// 与常量指纹扫描同一条 8MB 红线（constFingerprints.FINGERPRINT_SCAN_LIMIT），本地常量避免模块反向依赖。
const ENTROPY_SCAN_LIMIT = 8 * 1024 * 1024;

export interface EntropyBlock {
  offset: number;
  length: number;
  entropy: number;
}

// 按 256B 块计算香农熵（0-8 bits/byte）：8MB 上限内 O(n) 单遍，渲染与区段标注都在调用方完成。
export const blockEntropy = (bytes: Uint8Array, options?: { blockSize?: number; maxBytes?: number }): EntropyBlock[] => {
  const blockSize = options?.blockSize ?? ENTROPY_BLOCK_SIZE;
  const limit = Math.min(bytes.length, options?.maxBytes ?? ENTROPY_SCAN_LIMIT);
  const blocks: EntropyBlock[] = [];
  const buckets = new Array<number>(256).fill(0);
  let blockStart = 0;
  let blockCount = 0;
  const flush = () => {
    if (!blockCount) return;
    let entropy = 0;
    for (const count of buckets) {
      if (!count) continue;
      const probability = count / blockCount;
      entropy -= probability * Math.log2(probability);
    }
    blocks.push({ offset: blockStart, length: blockCount, entropy });
    buckets.fill(0);
    blockStart += blockCount;
    blockCount = 0;
  };
  for (let position = 0; position < limit; position += 1) {
    if (blockCount === blockSize) flush();
    if (blockCount === 0) blockStart = position;
    buckets[bytes[position]] += 1;
    blockCount += 1;
  }
  flush();
  return blocks;
};

export interface HighEntropyRange {
  startOffset: number;
  endOffset: number;
  blocks: number;
  average: number;
}

// 连续高熵块合并成区段，最多返回 maxRanges 个（按起始偏移排序）——定位加密区/压缩资源区。
// 阈值缺省 6.8：256B 块的随机数据熵期望约 7.2-7.4（样本方差下限更低），沿用整文件的 7.5 会系统性漏报；
// 6.8 仍能干净区分代码/文本段（典型 4-6.5）与加密/压缩段。
export const highEntropyRanges = (
  blocks: EntropyBlock[],
  options?: { threshold?: number; maxRanges?: number },
): HighEntropyRange[] => {
  const threshold = options?.threshold ?? 6.8;
  const maxRanges = options?.maxRanges ?? 12;
  const ranges: HighEntropyRange[] = [];
  let current: { start: number; end: number; total: number; count: number } | null = null;
  const closeCurrent = () => {
    if (!current) return;
    ranges.push({
      startOffset: current.start,
      endOffset: current.end,
      blocks: current.count,
      average: current.total / current.count,
    });
    current = null;
  };
  for (const block of blocks) {
    if (block.entropy >= threshold) {
      if (current && current.end === block.offset) {
        current.end = block.offset + block.length;
        current.total += block.entropy;
        current.count += 1;
      } else {
        closeCurrent();
        current = { start: block.offset, end: block.offset + block.length, total: block.entropy, count: 1 };
      }
    } else {
      closeCurrent();
    }
  }
  closeCurrent();
  return ranges.slice(0, maxRanges);
};

export interface StringsResult {
  values: string[];
  total: number;
}

// GNU strings 惯例：最小长度 4、制表与空格计入；另扫一遍 UTF-16LE（ASCII + 0x00 交替）。
export const extractStrings = (bytes: Uint8Array, options?: { minLength?: number; limit?: number }): StringsResult => {
  const minLength = options?.minLength ?? 4;
  const limit = options?.limit ?? 200;
  const values: string[] = [];
  let total = 0;
  // ASCII 与 UTF-16LE 两遍各自占用 limit 个展示位，避免先扫的一遍把列表挤满后另一遍只计数不展示。
  const pushRun = (run: string, listCap: number) => {
    if (run.length < minLength) return;
    total += 1;
    if (values.length < listCap) values.push(run);
  };
  let run = '';
  for (const byte of bytes) {
    if (byte >= 0x20 && byte <= 0x7e) {
      run += String.fromCharCode(byte);
    } else {
      pushRun(run, limit);
      run = '';
    }
  }
  pushRun(run, limit);
  let wideRun = '';
  const pushWideRun = () => {
    pushRun(wideRun, limit * 2);
    wideRun = '';
  };
  // UTF-16LE 在文件中的对齐任意，偶/奇偏移各扫一遍。
  for (const start of [0, 1]) {
    for (let position = start; position + 1 < bytes.length; position += 2) {
      const low = bytes[position];
      const high = bytes[position + 1];
      if (high === 0 && low >= 0x20 && low <= 0x7e) {
        wideRun += String.fromCharCode(low);
      } else {
        pushWideRun();
      }
    }
    pushWideRun();
  }
  return { values, total };
};

export interface SuspiciousScan {
  flags: Array<{ prefix: string; sample: string }>;
  base64Candidates: string[];
  keywordHits: string[];
}

const CTF_KEYWORDS = ['secret', 'password', 'passwd', 'token', 'begin key', 'private key', 'admin panel'];

// 可疑内容扫描：flag 复用智能解码同一份格式清单；base64 只做特征粗筛（解码验证在用户点击后进行）。
export const scanSuspiciousContent = (text: string): SuspiciousScan => {
  const lower = text.toLowerCase();
  const base64Candidates: string[] = [];
  for (const match of text.matchAll(/[A-Za-z0-9+/]{20,}={0,2}/g)) {
    const candidate = match[0];
    if (!/[0-9]/.test(candidate) || !/[A-Za-z]/.test(candidate)) continue;
    if (base64Candidates.length >= 8) break;
    base64Candidates.push(candidate);
  }
  const keywordHits = CTF_KEYWORDS.filter(keyword => lower.includes(keyword)).slice(0, 8);
  return { flags: detectFlagFormats(text), base64Candidates, keywordHits };
};

const HEXDUMP_ROW = 16;

export const hexdumpPreview = (bytes: Uint8Array, options?: { offset?: number; length?: number }): string => {
  const offset = Math.max(0, options?.offset ?? 0);
  const length = Math.min(bytes.length - offset, options?.length ?? 512);
  const lines: string[] = [];
  for (let row = 0; row < length; row += HEXDUMP_ROW) {
    const slice = bytes.subarray(offset + row, Math.min(offset + row + HEXDUMP_ROW, offset + length));
    let hex = '';
    let ascii = '';
    for (let index = 0; index < HEXDUMP_ROW; index += 1) {
      if (index === 8) hex += ' ';
      if (index < slice.length) {
        hex += slice[index].toString(16).padStart(2, '0').toUpperCase() + ' ';
        const char = slice[index];
        ascii += char >= 0x20 && char <= 0x7e ? String.fromCharCode(char) : '.';
      } else {
        hex += '   ';
        ascii += ' ';
      }
    }
    lines.push(`${(offset + row).toString(16).padStart(8, '0')}  ${hex} |${ascii}|`);
  }
  return lines.join('\n');
};

// ---- PNG ----

const crc32Table = (() => {
  const table = new Uint32Array(256);
  for (let value = 0; value < 256; value += 1) {
    let entry = value;
    for (let bit = 0; bit < 8; bit += 1) entry = entry & 1 ? 0xedb88320 ^ (entry >>> 1) : entry >>> 1;
    table[value] = entry >>> 0;
  }
  return table;
})();

export const crc32Bytes = (bytes: Uint8Array): number => {
  let crc = 0xffffffff;
  for (const byte of bytes) crc = crc32Table[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
};

export interface PngIhdrInfo {
  width: number;
  height: number;
  bitDepth: number;
  colorType: number;
  crcOk: boolean;
}

// IHDR 必为签名后第一个 chunk：宽@16/高@20（u32 大端），CRC@29 覆盖 bytes[12..29)（"IHDR"+13 字节数据）。
export const parsePngIhdr = (bytes: Uint8Array): PngIhdrInfo | null => {
  if (bytes.length < 33) return null;
  for (let index = 0; index < 8; index += 1) if (bytes[index] !== MAGIC_TABLE[0].bytes[index]) return null;
  if (bytes[12] !== 0x49 || bytes[13] !== 0x48 || bytes[14] !== 0x44 || bytes[15] !== 0x52) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const width = view.getUint32(16);
  const height = view.getUint32(20);
  const expectedCrc = view.getUint32(29);
  const actualCrc = crc32Bytes(bytes.subarray(12, 29));
  return { width, height, bitDepth: bytes[24], colorType: bytes[25], crcOk: expectedCrc === actualCrc };
};

const yieldToUi = () => new Promise<void>(resolve => setTimeout(resolve, 0));

// CRC 爆破修复：先试"仅宽被改"，再试"仅高被改"，最后双向 ≤1024。
// 整个枚举在单份副本上原地改写宽高（每次只重算 17 字节 CRC），命中即返回该副本。
export const fixPngDimensions = async (bytes: Uint8Array): Promise<{ bytes: Uint8Array; width: number; height: number } | null> => {
  const ihdr = parsePngIhdr(bytes);
  if (!ihdr) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const expectedCrc = view.getUint32(29);
  if (ihdr.crcOk) return { bytes: bytes.slice(), width: ihdr.width, height: ihdr.height };
  const originalWidth = ihdr.width;
  const originalHeight = ihdr.height;
  const candidate = bytes.slice();
  const candidateView = new DataView(candidate.buffer);
  let steps = 0;
  const check = (width: number, height: number) => {
    candidateView.setUint32(16, width);
    candidateView.setUint32(20, height);
    steps += 1;
    if ((steps & 2047) === 0) return yieldToUi().then(() => crc32Bytes(candidate.subarray(12, 29)) === expectedCrc);
    return crc32Bytes(candidate.subarray(12, 29)) === expectedCrc;
  };
  for (let width = 1; width <= 8192; width += 1) {
    if (await check(width, originalHeight)) return { bytes: candidate, width, height: originalHeight };
  }
  for (let height = 1; height <= 8192; height += 1) {
    if (await check(originalWidth, height)) return { bytes: candidate, width: originalWidth, height };
  }
  for (let width = 1; width <= 1024; width += 1) {
    for (let height = 1; height <= 1024; height += 1) {
      if (await check(width, height)) return { bytes: candidate, width, height };
    }
  }
  return null;
};

// ---- ZIP ----

export type ZipEncryptionState = 'plain' | 'pseudo' | 'encrypted' | 'none';

export interface ZipEncryptionInfo {
  state: ZipEncryptionState;
  localEntries: number;
  centralEntries: number;
}

const readZipFlags = (bytes: Uint8Array): { localFlags: number[]; centralFlags: number[] } => {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const localFlags: number[] = [];
  const centralFlags: number[] = [];
  for (let position = 0; position + 4 <= bytes.length; position += 1) {
    if (bytes[position] === 0x50 && bytes[position + 1] === 0x4b && bytes[position + 2] === 0x03 && bytes[position + 3] === 0x04 && position + 8 <= bytes.length) {
      localFlags.push(view.getUint16(position + 6, true));
      position += 3;
    } else if (bytes[position] === 0x50 && bytes[position + 1] === 0x4b && bytes[position + 2] === 0x01 && bytes[position + 3] === 0x02 && position + 10 <= bytes.length) {
      centralFlags.push(view.getUint16(position + 8, true));
      position += 3;
    }
  }
  return { localFlags, centralFlags };
};

// 伪加密 = 本地头与中心目录的加密标志（bit0）不一致，或全 1 但数据实为未加密；真加密两者一致为 1。
export const detectZipEncryption = (bytes: Uint8Array): ZipEncryptionInfo => {
  const { localFlags, centralFlags } = readZipFlags(bytes);
  if (!localFlags.length && !centralFlags.length) return { state: 'none', localEntries: 0, centralEntries: 0 };
  const all = [...localFlags, ...centralFlags];
  const encryptedCount = all.filter(flag => (flag & 1) === 1).length;
  if (encryptedCount === 0) return { state: 'plain', localEntries: localFlags.length, centralEntries: centralFlags.length };
  if (encryptedCount === all.length) return { state: 'encrypted', localEntries: localFlags.length, centralEntries: centralFlags.length };
  return { state: 'pseudo', localEntries: localFlags.length, centralEntries: centralFlags.length };
};

// 伪加密修复：把所有 general purpose bit flag 的 bit0 清零，其余标志位保留原样。
export const fixZipPseudoEncryption = (bytes: Uint8Array): { bytes: Uint8Array; cleared: number } | null => {
  const patched = bytes.slice();
  const view = new DataView(patched.buffer);
  let cleared = 0;
  for (let position = 0; position + 4 <= patched.length; position += 1) {
    const isLocal = patched[position] === 0x50 && patched[position + 1] === 0x4b && patched[position + 2] === 0x03 && patched[position + 3] === 0x04;
    const isCentral = patched[position] === 0x50 && patched[position + 1] === 0x4b && patched[position + 2] === 0x01 && patched[position + 3] === 0x02;
    if (!isLocal && !isCentral) continue;
    const flagOffset = position + (isLocal ? 6 : 8);
    if (flagOffset + 2 > patched.length) continue;
    const flag = view.getUint16(flagOffset, true);
    if (flag & 1) {
      view.setUint16(flagOffset, flag & ~1, true);
      cleared += 1;
    }
    position += 3;
  }
  return cleared ? { bytes: patched, cleared } : null;
};

// ---- 零宽字符 ----

export interface ZeroWidthExtraction {
  payload: string;
  zeroWidthCount: number;
}

// 文件场景的零宽提取：按 UTF-8 容错解码后收集 U+200B/U+200C 序列，能凑满 8bit 组则按零宽编码解出 payload。
export const extractZeroWidthFromText = (text: string): ZeroWidthExtraction => {
  const zeroWidthCount = (text.match(/[\u200b\u200c]/g) || []).length;
  if (!zeroWidthCount) return { payload: '', zeroWidthCount: 0 };
  let payload = '';
  try {
    payload = zeroWidthDecode(text);
  } catch {
    payload = '';
  }
  return { payload, zeroWidthCount };
};
