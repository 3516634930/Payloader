// CRC32 冲突爆破（meet-in-the-middle）与 ZIP 伪加密一键修复。
// 复用 alphabets.ts 的 crc32Table（反射多项式 0xEDB88320），不自建表。
// 核心恒等式：crc(A||B) = Z^|B|(crc(A)) ⊕ crc(B)，Z 为"寄存器平移一个零字节"的 GF(2) 线性映射
// （即 zlib crc32_combine 的零字节矩阵，M 在 GF(2) 上可逆，保证由前缀 CRC 可唯一定出后缀需贡献的 CRC）。
import { crc32Table } from './alphabets';

export const PRINTABLE_ASCII_CHARSET = Array.from({ length: 95 }, (_, index) => String.fromCharCode(0x20 + index)).join('');

export const crc32BytesOf = (bytes: Uint8Array): number => {
  let crc = 0xffffffff;
  for (let index = 0; index < bytes.length; index += 1) {
    crc = (crc >>> 8) ^ crc32Table[(crc ^ bytes[index]) & 0xff];
  }
  return (crc ^ 0xffffffff) >>> 0;
};

// Z^count：寄存器平移 count 个零字节。与 crc32Combine(crc, 0, count) 的矩阵法等价，热循环用查表捷径。
const applyZeroBytes = (crc: number, count: number): number => {
  let value = crc >>> 0;
  for (let index = 0; index < count; index += 1) {
    value = (value >>> 8) ^ crc32Table[value & 0xff];
  }
  return value >>> 0;
};

const gf2MatrixTimes = (matrix: Uint32Array, vector: number): number => {
  let sum = 0;
  let row = 0;
  let bits = vector >>> 0;
  while (bits !== 0) {
    if (bits & 1) sum ^= matrix[row];
    bits >>>= 1;
    row += 1;
  }
  return sum >>> 0;
};

const gf2MatrixSquare = (target: Uint32Array, source: Uint32Array): void => {
  for (let index = 0; index < 32; index += 1) target[index] = gf2MatrixTimes(source, source[index]);
};

// zlib crc32_combine 直译：对 lenB 个零字节建立 32x32 GF(2) 矩阵（1 零位算子反复平方得到按字节二进制分解的算子），
// combine(a, b, lenB) = M_{lenB}·a ⊕ b；lenB=0 按恒等式退化为 a ⊕ b（空串 crc=0 时即 a）。
export const crc32Combine = (crcA: number, crcB: number, lenB: number): number => {
  if (!Number.isInteger(lenB) || lenB < 0) throw new RangeError(`lenB 必须为非负整数，当前 ${lenB}`);
  if (lenB === 0) return (crcA ^ crcB) >>> 0;
  const odd = new Uint32Array(32);
  const even = new Uint32Array(32);
  odd[0] = 0xedb88320;
  let row = 1;
  for (let index = 1; index < 32; index += 1) {
    odd[index] = row;
    row <<= 1;
  }
  gf2MatrixSquare(even, odd);
  gf2MatrixSquare(odd, even);
  let shifted = crcA >>> 0;
  let remaining = lenB;
  for (;;) {
    gf2MatrixSquare(even, odd);
    if (remaining % 2 === 1) shifted = gf2MatrixTimes(even, shifted);
    remaining = Math.floor(remaining / 2);
    if (remaining === 0) break;
    gf2MatrixSquare(odd, even);
    if (remaining % 2 === 1) shifted = gf2MatrixTimes(odd, shifted);
    remaining = Math.floor(remaining / 2);
    if (remaining === 0) break;
  }
  return (shifted ^ crcB) >>> 0;
};

export const findCrc32Preimages = (
  targetCrc: number,
  length: number,
  charset: string = PRINTABLE_ASCII_CHARSET,
  maxSolutions: number = 16,
): string[] => {
  if (!Number.isInteger(length) || length < 2 || length > 5) {
    throw new Error(
      `CRC32 原像爆破仅支持长度 2-5，当前 length=${length}：len<2 无枚举意义；len=6 时默认字符集的前缀枚举达 95^4≈8100 万次（分钟级），` +
        '且信息论上 95^5≈77 亿种组合已远超 2^32 的 CRC32 空间（len≥5 解通常不唯一但可命中），更长长度没有爆破价值。',
    );
  }
  if (!Number.isInteger(targetCrc) || targetCrc < 0 || targetCrc > 0xffffffff) {
    throw new Error(`targetCrc 必须是 0 到 0xFFFFFFFF 之间的整数，当前 ${targetCrc}`);
  }
  if (!Number.isInteger(maxSolutions) || maxSolutions < 1) {
    throw new Error(`maxSolutions 必须为正整数，当前 ${maxSolutions}`);
  }
  const uniqueChars = Array.from(new Set(Array.from(charset)));
  if (uniqueChars.length === 0) throw new Error('字符集为空：至少需要一个字符');
  const codes = uniqueChars.map((char) => {
    const code = char.codePointAt(0);
    if (code === undefined || code > 0xff) {
      throw new Error(`字符集含非 latin1 字符 ${JSON.stringify(char)}：解按字节匹配，仅支持码点 0x00-0xFF`);
    }
    return code;
  });
  const target = targetCrc >>> 0;
  // 末 2 字节贡献表：crc 贡献值 -> 后缀数组（同一贡献可能对应多个后缀，必须存数组）
  const suffixMap = new Map<number, string[]>();
  for (let i = 0; i < codes.length; i += 1) {
    for (let j = 0; j < codes.length; j += 1) {
      const suffix = String.fromCharCode(codes[i], codes[j]);
      const crc = crc32BytesOf(Uint8Array.of(codes[i], codes[j]));
      const bucket = suffixMap.get(crc);
      if (bucket === undefined) suffixMap.set(crc, [suffix]);
      else bucket.push(suffix);
    }
  }
  // 枚举前 length-2 字节前缀（len=2 时前缀为空，退化为 95^2 直接查表），
  // 对每个前缀由 Z^2 逆推出末 2 字节必须贡献的 CRC 并查表，命中即得完整原像。
  const prefixLength = length - 2;
  const solutions: string[] = [];
  const path: number[] = new Array<number>(prefixLength);
  const search = (depth: number, register: number): void => {
    if (solutions.length >= maxSolutions) return;
    if (depth === prefixLength) {
      const needed = (target ^ applyZeroBytes((register ^ 0xffffffff) >>> 0, 2)) >>> 0;
      const hits = suffixMap.get(needed);
      if (hits !== undefined) {
        const prefix = String.fromCharCode(...path);
        for (const suffix of hits) {
          if (solutions.length >= maxSolutions) break;
          solutions.push(prefix + suffix);
        }
      }
      return;
    }
    for (let i = 0; i < codes.length; i += 1) {
      path[depth] = codes[i];
      search(depth + 1, (register >>> 8) ^ crc32Table[(register ^ codes[i]) & 0xff]);
    }
  };
  search(0, 0xffffffff);
  return solutions;
};

export interface ZipPseudoFixChange {
  offset: number;
  field: string;
  before: number;
  after: number;
}

export interface ZipPseudoFixResult {
  fixed: Uint8Array | null;
  changes: ZipPseudoFixChange[];
}

const ZIP_EOCD_SIGNATURE = 0x06054b50;
const ZIP_CENTRAL_SIGNATURE = 0x02014b50;
const ZIP_LOCAL_SIGNATURE = 0x04034b50;

const readLe16 = (bytes: Uint8Array, offset: number): number => (bytes[offset] | (bytes[offset + 1] << 8)) & 0xffff;
const readLe32 = (bytes: Uint8Array, offset: number): number =>
  (bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24)) >>> 0;

const findEocdOffset = (bytes: Uint8Array): number => {
  if (bytes.length < 22) return -1;
  const minOffset = Math.max(0, bytes.length - 22 - 0xffff);
  for (let offset = bytes.length - 22; offset >= minOffset; offset -= 1) {
    if (readLe32(bytes, offset) === ZIP_EOCD_SIGNATURE) return offset;
  }
  return -1;
};

// 仅支持经典 ZIP：无 EOCD、无条目、0xFFFFFFFF 偏移哨兵（ZIP64）、坏签名、越界一律按"结构异常"整体放弃（fixed=null）。
// 任一条目的 central-directory 或 local-file-header flag bit0 置位即视为疑似伪加密，两处 bit0 成对清零，其余位不动。
export const fixZipPseudoEncryption = (bytes: Uint8Array): ZipPseudoFixResult => {
  const invalid: ZipPseudoFixResult = { fixed: null, changes: [] };
  const eocdOffset = findEocdOffset(bytes);
  if (eocdOffset < 0) return invalid;
  const entryCount = readLe16(bytes, eocdOffset + 10);
  let cursor = readLe32(bytes, eocdOffset + 16);
  if (entryCount === 0 || cursor === 0xffffffff) return invalid;
  const changes: ZipPseudoFixChange[] = [];
  for (let entry = 0; entry < entryCount; entry += 1) {
    if (cursor + 46 > bytes.length || readLe32(bytes, cursor) !== ZIP_CENTRAL_SIGNATURE) return invalid;
    const centralFlagOffset = cursor + 8;
    const centralFlag = readLe16(bytes, centralFlagOffset);
    const nameLength = readLe16(bytes, cursor + 28);
    const extraLength = readLe16(bytes, cursor + 30);
    const commentLength = readLe16(bytes, cursor + 32);
    const localOffset = readLe32(bytes, cursor + 42);
    if (localOffset === 0xffffffff || localOffset + 30 > bytes.length) return invalid;
    if (readLe32(bytes, localOffset) !== ZIP_LOCAL_SIGNATURE) return invalid;
    const localFlagOffset = localOffset + 6;
    const localFlag = readLe16(bytes, localFlagOffset);
    if ((centralFlag & 1) !== 0 || (localFlag & 1) !== 0) {
      const centralAfter = centralFlag & ~1;
      const localAfter = localFlag & ~1;
      if (centralAfter !== centralFlag) {
        changes.push({ offset: centralFlagOffset, field: 'central-directory', before: centralFlag, after: centralAfter });
      }
      if (localAfter !== localFlag) {
        changes.push({ offset: localFlagOffset, field: 'local-file-header', before: localFlag, after: localAfter });
      }
    }
    cursor += 46 + nameLength + extraLength + commentLength;
  }
  const fixed = bytes.slice();
  for (const change of changes) {
    fixed[change.offset] = change.after & 0xff;
    fixed[change.offset + 1] = (change.after >>> 8) & 0xff;
  }
  return { fixed, changes };
};

interface ReportParams {
  crc?: number;
  length?: number;
  charset?: string;
  maxSolutions?: number;
  zipHex?: string;
}

// 只按"已知键="前的空白切分，charset 值内部允许含空格
const REPORT_KEY_SPLIT = /\s+(?=(?:crc|length|charset|zipHex|maxSolutions|max)=)/i;
const ZIP_HEX_LIMIT = 4 * 1024 * 1024;

const hexDigitValue = (code: number): number => {
  if (code >= 48 && code <= 57) return code - 48;
  if (code >= 97 && code <= 102) return code - 87;
  if (code >= 65 && code <= 70) return code - 55;
  return -1;
};

const decodeHex = (hex: string): Uint8Array => {
  if (hex.length % 2 !== 0) throw new Error('zipHex 长度必须为偶数（每字节两个十六进制字符）');
  const out = new Uint8Array(hex.length >> 1);
  for (let index = 0; index < out.length; index += 1) {
    const hi = hexDigitValue(hex.charCodeAt(index * 2));
    const lo = hexDigitValue(hex.charCodeAt(index * 2 + 1));
    if (hi < 0 || lo < 0) throw new Error('zipHex 含非十六进制字符');
    out[index] = (hi << 4) | lo;
  }
  return out;
};

const encodeHexPrefix = (bytes: Uint8Array, count: number): string => {
  let hex = '';
  const limit = Math.min(count, bytes.length);
  for (let index = 0; index < limit; index += 1) hex += bytes[index].toString(16).padStart(2, '0');
  return hex;
};

// 报告入口：crc=0x1a2b3c4d length=4 charset=... maxSolutions=16 走原像爆破；
// zipHex=504b0304...（≤4MB hex）走伪加密修复。返回 JSON 字符串。
export const crc32AttackReport = (value: string): string => {
  const trimmed = value.trim();
  if (trimmed === '') {
    throw new Error('输入为空：需要 crc=0x1a2b3c4d length=4 charset=0123456789（原像爆破）或 zipHex=504b0304…（伪加密修复）');
  }
  const params: ReportParams = {};
  for (const token of trimmed.split(REPORT_KEY_SPLIT)) {
    const eq = token.indexOf('=');
    if (eq <= 0) {
      throw new Error(`无法解析参数段 ${JSON.stringify(token)}：格式为 key=value，支持 crc / length / charset / zipHex / maxSolutions`);
    }
    const key = token.slice(0, eq).toLowerCase();
    const val = token.slice(eq + 1);
    if (key === 'crc') {
      if (!/^(0[xX][0-9a-fA-F]{1,8}|\d{1,10})$/.test(val)) {
        throw new Error(`crc 值非法：${JSON.stringify(val)}，支持 0x 前缀十六进制（≤8 位）或十进制`);
      }
      const parsed = Number(val);
      if (parsed > 0xffffffff) throw new Error(`crc 超出 32 位无符号范围：${val}`);
      params.crc = parsed;
    } else if (key === 'length') {
      if (!/^\d+$/.test(val)) throw new Error(`length 值非法：${JSON.stringify(val)}，需为 2-5 的整数`);
      params.length = Number(val);
    } else if (key === 'charset') {
      params.charset = val;
    } else if (key === 'maxsolutions' || key === 'max') {
      if (!/^[1-9]\d*$/.test(val)) throw new Error(`maxSolutions 值非法：${JSON.stringify(val)}，需为正整数`);
      params.maxSolutions = Number(val);
    } else if (key === 'ziphex') {
      params.zipHex = val.trim();
    }
  }
  if (params.zipHex !== undefined) {
    if (params.zipHex === '') throw new Error('zipHex 为空：请提供 ZIP 文件的十六进制字节流');
    if (params.zipHex.length > ZIP_HEX_LIMIT) {
      throw new Error(`zipHex 长度 ${params.zipHex.length} 超过上限 ${ZIP_HEX_LIMIT} 字符（即 2MB 二进制）`);
    }
    const result = fixZipPseudoEncryption(decodeHex(params.zipHex));
    if (result.fixed === null) {
      return JSON.stringify({
        mode: 'zip-pseudo-fix',
        fixed: false,
        changeCount: 0,
        changes: [],
        fixedBytes: 0,
        fixedPreviewHex: '',
        note: '未找到 EOCD 或中央目录条目：不是可解析的经典 ZIP（ZIP64 与损坏结构不在支持范围）',
      }, null, 2);
    }
    return JSON.stringify({
      mode: 'zip-pseudo-fix',
      fixed: true,
      changeCount: result.changes.length,
      changes: result.changes,
      fixedBytes: result.fixed.length,
      fixedPreviewHex: encodeHexPrefix(result.fixed, 32),
      note: result.changes.length === 0
        ? '所有条目的 general purpose bit flag bit0 均为 0：不是伪加密 ZIP'
        : `已把 ${result.changes.length} 处 bit0 加密标志清零（central-directory 与 local-file-header 成对处理）；仅支持经典 ZIP，不支持 ZIP64`,
    }, null, 2);
  }
  if (params.crc === undefined) {
    throw new Error('缺少 crc=… 或 zipHex=… 参数：例如 crc=0x1a2b3c4d length=4 charset=0123456789 或 zipHex=504b0304…');
  }
  const length = params.length ?? 4;
  const charset = params.charset ?? PRINTABLE_ASCII_CHARSET;
  const maxSolutions = params.maxSolutions ?? 16;
  const charsetSize = new Set(Array.from(charset)).size;
  const startedAt = Date.now();
  const solutions = findCrc32Preimages(params.crc, length, charset, maxSolutions);
  const elapsedMs = Date.now() - startedAt;
  const note = solutions.length === 0
    ? `字符集（${charsetSize} 字符）内穷举完毕仍无原像：目标 CRC、长度或字符集不匹配`
    : `命中 ${solutions.length} 组${length >= 5 ? '；95^5≈77 亿种组合远超 2^32 的 CRC32 空间，len≥5 的解通常不唯一但可命中，请按题目上下文筛选' : ''}`;
  return JSON.stringify({
    target: `0x${(params.crc >>> 0).toString(16).padStart(8, '0')}`,
    length,
    charsetSize,
    solutions,
    elapsedMs,
    note,
  }, null, 2);
};
