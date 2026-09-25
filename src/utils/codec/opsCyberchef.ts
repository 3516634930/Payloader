// CyberChef 对标补齐操作（批次 CC1）：位运算全家桶 / 字节序交换 / 校验和矩阵 /
// 数据抽取器 / 可打印字符串 / FILETIME / Defang / 熵报告 / 文本行工具。
// 全部纯 JS、零依赖；字节类操作输入输出约定与 xor 一致（hex 进出，文本走 UTF-8）。


// ---- 字节输入归一：纯 hex 串按 hex 解，其余按 UTF-8 文本 ----

const isHexString = (input: string): boolean => {
  const compact = input.replace(/\s+/g, '');
  if (compact.length === 0 || compact.length % 2 !== 0) return false;
  return /^[0-9a-fA-F]+$/.test(compact);
};

const inputToBytes = (input: string): Uint8Array => {
  const compact = input.replace(/\s+/g, '');
  return isHexString(input) && compact.length > 0
    ? new Uint8Array(compact.match(/../g)!.map(pair => Number.parseInt(pair, 16)))
    : new TextEncoder().encode(input);
};

// ---- 位运算全家桶 ----

export type BitwiseVariant = 'and' | 'or' | 'xor' | 'add' | 'sub';

// 逐字节 key 循环位运算：key 空 = 单值 0（无变换）。ADD/SUB 为 mod 256。
export const bitwiseWithKey = (bytes: Uint8Array, key: Uint8Array, variant: BitwiseVariant): Uint8Array => {
  const out = new Uint8Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) {
    const k = key.length > 0 ? key[i % key.length] : 0;
    const v = bytes[i];
    out[i] = variant === 'and' ? v & k
      : variant === 'or' ? v | k
        : variant === 'add' ? (v + k) & 0xff
          : variant === 'sub' ? (v - k) & 0xff
            : v ^ k;
  }
  return out;
};

// 按位流整体左/右移 n 位（字节串拼接语义，右侧/左侧补 0，宽度保持字节数）。
export const shiftBits = (bytes: Uint8Array, bits: number, direction: 'left' | 'right'): Uint8Array => {
  const total = bytes.length * 8;
  if (total === 0) return bytes;
  const shift = ((bits % total) + total) % total;
  if (shift === 0) return new Uint8Array(bytes);
  // 展开为位数组再重组（长度受限，简单清晰）。
  const bits2 = new Uint8Array(total);
  for (let i = 0; i < total; i++) bits2[i] = (bytes[i >> 3] >> (7 - (i & 7))) & 1;
  const out = new Uint8Array(bytes.length);
  for (let i = 0; i < total; i++) {
    const srcIndex = direction === 'left' ? i + shift : i - shift;
    const bit = srcIndex >= 0 && srcIndex < total ? bits2[srcIndex] : 0;
    out[i >> 3] |= bit << (7 - (i & 7));
  }
  return out;
};

// 按宽（8/16/32）循环旋转，方向 left/right，n 为位数（自动 mod 宽）。
export const rotateBits = (bytes: Uint8Array, bits: number, width: 8 | 16 | 32, direction: 'left' | 'right'): Uint8Array => {
  const out = new Uint8Array(bytes.length);
  const groups = width / 8;
  const widthBits = width;
  for (let g = 0; g * groups < bytes.length; g++) {
    // 末尾不足一组的直接拷贝。
    if ((g + 1) * groups > bytes.length) {
      out.set(bytes.subarray(g * groups), g * groups);
      break;
    }
    let value = 0;
    for (let j = 0; j < groups; j++) value = (value << 8) | bytes[g * groups + j];
    const n = ((bits % widthBits) + widthBits) % widthBits;
    let rotated = direction === 'left'
      ? ((value << n) | (value >>> (widthBits - n))) & ((2 ** widthBits) - 1)
      : ((value >>> n) | (value << (widthBits - n))) & ((2 ** widthBits) - 1);
    for (let j = groups - 1; j >= 0; j--) {
      out[g * groups + j] = rotated & 0xff;
      rotated >>>= 8;
    }
  }
  return out;
};

// 按字节反转位序（0xA5 ↔ 0xA5 之类）。
export const reverseBitsPerByte = (bytes: Uint8Array): Uint8Array => {
  const out = new Uint8Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) {
    let v = bytes[i];
    v = ((v & 0xf0) >>> 4) | ((v & 0x0f) << 4);
    v = ((v & 0xcc) >>> 2) | ((v & 0x33) << 2);
    out[i] = ((v & 0xaa) >>> 1) | ((v & 0x55) << 1);
  }
  return out;
};

// 字节序交换：按 wordSize 字节分组整组反转（不足一组尾部直接拷贝）。
export const swapEndianness = (bytes: Uint8Array, wordSize: 2 | 4 | 8): Uint8Array => {
  const out = new Uint8Array(bytes.length);
  for (let g = 0; g * wordSize < bytes.length; g++) {
    const end = Math.min((g + 1) * wordSize, bytes.length);
    const group = bytes.subarray(g * wordSize, end);
    out.set(group.slice().reverse(), g * wordSize);
  }
  return out;
};

// ---- 校验和矩阵 ----

const crc16Generic = (bytes: Uint8Array, poly: number, init: number, xorout: number): number => {
  let crc = init & 0xffff;
  for (const b of bytes) {
    crc ^= b << 8;
    for (let i = 0; i < 8; i++) crc = (crc & 0x8000) ? ((crc << 1) ^ poly) & 0xffff : (crc << 1) & 0xffff;
  }
  return (crc ^ xorout) & 0xffff;
};

// 反射算法变体：refin/refout=true 的标准实现（逐位右移）。
const crc16Reflected = (bytes: Uint8Array, poly: number, init: number, xorout: number): number => {
  let crc = init & 0xffff;
  for (const b of bytes) {
    crc ^= b;
    for (let i = 0; i < 8; i++) crc = (crc & 1) ? ((crc >>> 1) ^ poly) & 0xffff : crc >>> 1;
  }
  return (crc ^ xorout) & 0xffff;
};

const CRC16_VARIANTS: Array<{ name: string; run: (bytes: Uint8Array) => number }> = [
  { name: 'CRC-16/ARC', run: b => crc16Reflected(b, 0xA001, 0x0000, 0x0000) },
  { name: 'CRC-16/MODBUS', run: b => crc16Reflected(b, 0xA001, 0xFFFF, 0x0000) },
  { name: 'CRC-16/USB', run: b => crc16Reflected(b, 0xA001, 0xFFFF, 0xFFFF) },
  { name: 'CRC-16/KERMIT', run: b => crc16Reflected(b, 0x8408, 0x0000, 0x0000) },
  { name: 'CRC-16/XMODEM', run: b => crc16Generic(b, 0x1021, 0x0000, 0x0000) },
  { name: 'CRC-16/CCITT-FALSE', run: b => crc16Generic(b, 0x1021, 0xFFFF, 0x0000) },
  { name: 'CRC-16/X-25', run: b => crc16Reflected(b, 0x8408, 0xFFFF, 0xFFFF) },
  { name: 'CRC-16/DNP', run: b => crc16Reflected(b, 0xA6BC, 0x0000, 0xFFFF) },
];

const fletcher = (bytes: Uint8Array, blockSize: 8 | 16 | 32): { sum1: number; sum2: number } => {
  if (blockSize === 8) {
    let sum1 = 0;
    let sum2 = 0;
    for (const b of bytes) {
      sum1 = (sum1 + b) % 255;
      sum2 = (sum2 + sum1) % 255;
    }
    return { sum1, sum2 };
  }
  if (blockSize === 16) {
    // Fletcher-16：data word = 8 位字节（RFC 905），mod 255。
    let sum1 = 0;
    let sum2 = 0;
    for (const b of bytes) {
      sum1 = (sum1 + b) % 255;
      sum2 = (sum2 + sum1) % 255;
    }
    return { sum1, sum2 };
  }
  // Fletcher-32：16 位小端半字，mod 0xffffffff。
  let sum1 = 0xffff;
  let sum2 = 0xffff;
  const mod = 0xffffffff;
  const count = Math.ceil(bytes.length / 2);
  for (let i = 0; i < count; i++) {
    const c0 = bytes[i * 2] ?? 0;
    const c1 = bytes[i * 2 + 1] ?? 0;
    const word = (c1 << 8) | c0;
    sum1 = (sum1 + word) % mod;
    sum2 = (sum2 + sum1) % mod;
  }
  return { sum1: sum1 >>> 0, sum2: sum2 >>> 0 };
};

const luhnChecksumDigit = (digits: string): number => {
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = Number(digits[i]);
    if (Number.isNaN(d)) return -1;
    if (double) { d *= 2; if (d > 9) d -= 9; }
    sum += d;
    double = !double;
  }
  return (10 - (sum % 10)) % 10;
};

export interface ChecksumRow { name: string; value: string }

// 一次算全部常用校验和（CyberChef "Generate all checksums" 对标）。
export const checksumMatrix = (bytes: Uint8Array): ChecksumRow[] => {
  const rows: ChecksumRow[] = [];
  let xor = 0;
  let sum8 = 0;
  let sum16 = 0;
  for (const b of bytes) { xor ^= b; sum8 = (sum8 + b) & 0xff; sum16 = (sum16 + b) & 0xffff; }
  rows.push({ name: 'XOR checksum（逐字节异或）', value: xor.toString(16).padStart(2, '0') });
  rows.push({ name: 'SUM-8', value: sum8.toString(16).padStart(2, '0') });
  rows.push({ name: 'SUM-16', value: sum16.toString(16).padStart(4, '0') });
  for (const variant of CRC16_VARIANTS) {
    rows.push({ name: variant.name, value: variant.run(bytes).toString(16).padStart(4, '0') });
  }
  const f8 = fletcher(bytes, 8);
  rows.push({ name: 'Fletcher-8', value: `${f8.sum1.toString(16).padStart(2, '0')}${f8.sum2.toString(16).padStart(2, '0')}` });
  const f16 = fletcher(bytes, 16);
  rows.push({ name: 'Fletcher-16', value: `${f16.sum1.toString(16).padStart(4, '0')}${f16.sum2.toString(16).padStart(4, '0')}` });
  const f32 = fletcher(bytes, 32);
  rows.push({ name: 'Fletcher-32', value: `${f32.sum1.toString(16).padStart(8, '0')}${f32.sum2.toString(16).padStart(8, '0')}` });
  // Adler-32
  let a = 1;
  let b = 0;
  for (const byte of bytes) {
    a = (a + byte) % 65521;
    b = (b + a) % 65521;
  }
  const adler = ((b << 16) | a) >>> 0;
  rows.push({ name: 'Adler-32', value: adler.toString(16).padStart(8, '0') });
  // CRC-32（ reflected 0xEDB88320，与 zlib 一致）
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let i = 0; i < 8; i++) crc = (crc & 1) ? (crc >>> 1) ^ 0xEDB88320 : crc >>> 1;
  }
  rows.push({ name: 'CRC-32 (zlib)', value: ((crc ^ 0xffffffff) >>> 0).toString(16).padStart(8, '0') });
  // Luhn（纯数字串时才有意义）
  const digitsOnly = Array.from(bytes).every(v => v >= 0x30 && v <= 0x39);
  if (digitsOnly && bytes.length > 0) {
    const luhn = luhnChecksumDigit(new TextDecoder().decode(bytes) + '0');
    rows.push({ name: 'Luhn check digit（含补位）', value: String(luhn) });
  }
  return rows;
};

// ---- 数据抽取器 ----

export type ExtractVariant = 'ips' | 'urls' | 'emails' | 'domains' | 'ipv4-hex';

const EXTRACT_PATTERNS: Record<ExtractVariant, RegExp> = {
  ips: /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g,
  urls: /\bhttps?:\/\/[^\s"'<>()\x5b\x5d{}\\]+/gi,
  emails: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
  domains: /\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}\b/gi,
  'ipv4-hex': /\b(?:[0-9a-fA-F]{1,4}:){3,7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){3,6}:\b/g,
};

export const extractData = (input: string, variant: ExtractVariant): string => {
  const matches = input.match(EXTRACT_PATTERNS[variant]) ?? [];
  return [...new Set(matches)].join('\n') || '（无匹配）';
};

// ---- 可打印字符串提取（unix strings 语义：≥minLen 的可打印 ASCII 序列）----

export const extractPrintableStrings = (bytes: Uint8Array, minLen = 4): string[] => {
  const out: string[] = [];
  let current = '';
  for (const b of bytes) {
    if (b >= 0x20 && b <= 0x7e) {
      current += String.fromCharCode(b);
    } else {
      if (current.length >= minLen) out.push(current);
      current = '';
    }
    if (out.length >= 10000) break;
  }
  if (current.length >= minLen) out.push(current);
  return out;
};

// ---- Windows FILETIME ----

const FILETIME_EPOCH_DELTA = 116_444_736_000_000_000n; // 1601-01-01 → 1970-01-01 的 100ns 数

export const unixToFiletime = (unixSeconds: number): bigint =>
  BigInt(Math.round(unixSeconds * 1_000_000_0)) + FILETIME_EPOCH_DELTA;

export const filetimeToUnix = (filetime: bigint): number =>
  Number((filetime - FILETIME_EPOCH_DELTA)) / 1_000_000_0;

// ---- Defang / Refang ----

export const defang = (input: string): string =>
  input
    .replace(/\./g, '[.]')
    .replace(/:\/\//g, '[:]')
    .replace(/@/g, '[@]')
    .replace(/http/gi, 'hxxp');

export const refang = (input: string): string =>
  input
    .replace(/\[\.\]/g, '.')
    .replace(/\[:\]/g, '://')
    .replace(/\[@\]/g, '@')
    .replace(/hxxp/gi, 'http');

// ---- 熵报告（Entropy / IoC / 频率）----

export interface EntropyReport {
  entropy: number;
  ioc: number;
  length: number;
  uniqueChars: number;
  top5: Array<{ char: string; count: number; freq: number }>;
}

export const entropyReport = (input: string): EntropyReport => {
  const length = input.length;
  if (length === 0) return { entropy: 0, ioc: 0, length: 0, uniqueChars: 0, top5: [] };
  const freq = new Map<string, number>();
  for (const ch of input) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / length;
    entropy -= p * Math.log2(p);
  }
  let coincidences = 0;
  for (const count of freq.values()) coincidences += count * (count - 1);
  const ioc = length > 1 ? coincidences / (length * (length - 1)) : 0;
  const top5 = [...freq.entries()]
    .sort((x, y) => y[1] - x[1])
    .slice(0, 5)
    .map(([char, count]) => ({ char, count, freq: count / length }));
  return { entropy, ioc, length, uniqueChars: freq.size, top5 };
};

// ---- 文本行工具 ----

export type TextToolVariant = 'head' | 'tail' | 'sort' | 'unique' | 'dedupe' | 'strip-blank' | 'reverse-lines' | 'shuffle-order';

export const textLineTool = (input: string, variant: TextToolVariant, count: number): string => {
  const lines = input.split(/\r?\n/);
  switch (variant) {
    case 'head': return lines.slice(0, Math.max(0, count)).join('\n');
    case 'tail': return lines.slice(Math.max(0, lines.length - count)).join('\n');
    case 'sort': return [...lines].sort().join('\n');
    case 'unique': return [...new Set(lines)].join('\n');
    case 'dedupe': return [...new Set(lines)].join('\n'); // 别名：CyberChef Unique
    case 'strip-blank': return lines.filter(line => line.trim().length > 0).join('\n');
    case 'reverse-lines': return [...lines].reverse().join('\n');
    case 'shuffle-order': return [...lines].sort((x, y) => x.localeCompare(y, 'zh')).join('\n'); // 按拼音排序
    default: return input;
  }
};

// re-export 供 transform 使用
export { inputToBytes };
