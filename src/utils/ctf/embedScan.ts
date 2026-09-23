// 嵌入数据扫描纯函数引擎（misc 域 binwalk 式需求）：全文件魔数滑窗、PNG IEND/JPEG EOI 尾附检测、
// PNG chunk 枚举。全部只读字节、无 DOM 依赖；zTXt/iTXt 只做结构解析，解压由消费方 async 做。
import { crc32Bytes } from './fileDetect';

// 扫描上限：前 8MB（需求红线）；尾附检测与 chunk 枚举覆盖全文件（两者都是 O(n) 单遍）。
export const EMBED_SCAN_LIMIT = 8 * 1024 * 1024;

// PNG 签名（与 fileDetect.MAGIC_TABLE 同源 sindresorhus/file-type；此处用具体数字类型便于字节数组操作）。
const PNG_SIGNATURE = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];

export interface EmbeddedHit {
  ext: string;
  name: string;
  offset: number;
}

// 嵌入扫描关注"藏进别的文件里的东西"，签名表取图片题高频载体；与 fileDetect 的全量
// MAGIC_TABLE 分开——那里服务"整个文件是什么"，这里只列值得提取的子签名。
const EMBED_SIGNATURES: Array<{ ext: string; name: string; bytes: number[] }> = [
  { ext: 'zip', name: 'ZIP archive', bytes: [0x50, 0x4b, 0x03, 0x04] },
  { ext: 'png', name: 'PNG image', bytes: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a] },
  { ext: 'jpg', name: 'JPEG image', bytes: [0xff, 0xd8, 0xff] },
  { ext: 'gz', name: 'Gzip archive', bytes: [0x1f, 0x8b, 0x08] },
  { ext: 'rar4', name: 'RAR v4 archive', bytes: [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00] },
  { ext: 'rar5', name: 'RAR v5 archive', bytes: [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00] },
  { ext: '7z', name: '7-Zip archive', bytes: [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c] },
];

export interface EmbeddedScanOptions {
  scanLimit?: number;
  // 每类签名最多列出几个：压缩包内含大量本地头时防刷屏。
  maxHitsPerType?: number;
}

// 全文件嵌入签名扫描：跳过 offset 0（文件自身签名），每类签名用首字节 indexOf 跳转
// （避免 8MB × 7 规则的朴素滑窗），命中后按命中间隔推进防止同一位置重复计数。
// 文件本身就是 zip 家族时不扫 zip 签名——其 local/central header 是自身结构，必命中一批噪声；
// 非 zip 文件里的 PK 头照报（正是"图片尾附 zip"场景）。
export const scanEmbeddedSignatures = (bytes: Uint8Array, options: EmbeddedScanOptions = {}): EmbeddedHit[] => {
  const scanLimit = Math.min(bytes.length, options.scanLimit ?? EMBED_SCAN_LIMIT);
  const maxHitsPerType = options.maxHitsPerType ?? 4;
  const carrierIsZip = bytes.length >= 4
    && ((bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 0x03 && bytes[3] === 0x04)
      || (bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 0x01 && bytes[3] === 0x02));
  const hits: EmbeddedHit[] = [];
  for (const signature of EMBED_SIGNATURES) {
    if (signature.ext === 'zip' && carrierIsZip) continue;
    const first = signature.bytes[0];
    // 从偏移 1 起扫：offset 0 是文件自身签名，不是"嵌入"。
    let position = 1;
    let perType = 0;
    while (position < scanLimit && perType < maxHitsPerType) {
      const found = indexOfByte(bytes, first, position);
      if (found < 0 || found >= scanLimit) break;
      if (matchesAt(bytes, signature.bytes, found)) {
        hits.push({ ext: signature.ext, name: signature.name, offset: found });
        perType += 1;
        position = found + signature.bytes.length;
      } else {
        position = found + 1;
      }
    }
  }
  hits.sort((left, right) => left.offset - right.offset);
  return hits;
};

const indexOfByte = (bytes: Uint8Array, value: number, from: number): number => bytes.indexOf(value, from);

const matchesAt = (bytes: Uint8Array, signature: number[], offset: number): boolean => {
  if (offset + signature.length > bytes.length) return false;
  for (let index = 0; index < signature.length; index += 1) {
    if (bytes[offset + index] !== signature[index]) return false;
  }
  return true;
};

export interface TrailerHit {
  // 尾附数据起始偏移（容器正式结构结束处）。
  offset: number;
  trailing: Uint8Array;
}

// PNG 尾附检测：遍历 chunk 到 IEND，IEND（含 4B CRC）之后仍有剩余即为尾附数据。
// 结构损坏（IEND 前长度越界）返回 null——那种文件先交给宽高修复/用户人工判断。
export const findPngTrailer = (bytes: Uint8Array): TrailerHit | null => {
  if (!matchesAt(bytes, PNG_SIGNATURE, 0)) return null;
  let position = 8;
  while (position + 8 <= bytes.length) {
    const length = (bytes[position] << 24 | bytes[position + 1] << 16 | bytes[position + 2] << 8 | bytes[position + 3]) >>> 0;
    const type = String.fromCharCode(bytes[position + 4], bytes[position + 5], bytes[position + 6], bytes[position + 7]);
    const next = position + 12 + length;
    if (next > bytes.length) return null;
    if (type === 'IEND') {
      return next < bytes.length ? { offset: next, trailing: bytes.subarray(next) } : null;
    }
    position = next;
  }
  return null;
};

// JPEG 尾附检测：marker 链解析。段 marker 带 2B 大端长度；SOS(FFDA) 后进入熵编码，
// 逐字节跳过填充 FF00 与重启标记 FFD0-D7，遇到 FFD9 即 EOI。
export const findJpegTrailer = (bytes: Uint8Array): TrailerHit | null => {
  if (bytes.length < 4 || bytes[0] !== 0xff || bytes[1] !== 0xd8) return null;
  let position = 2;
  let inScan = false;
  while (position < bytes.length) {
    if (inScan) {
      const current = bytes[position];
      if (current !== 0xff) {
        position += 1;
        continue;
      }
      const marker = position + 1 < bytes.length ? bytes[position + 1] : 0;
      if (marker === 0x00 || (marker >= 0xd0 && marker <= 0xd7)) {
        position += 2;
        continue;
      }
      if (marker === 0xd9) {
        const eoiEnd = position + 2;
        return eoiEnd < bytes.length ? { offset: eoiEnd, trailing: bytes.subarray(eoiEnd) } : null;
      }
      // 熵编码区出现其他 FFxx 属于结构异常；保守终止，不误报尾附。
      return null;
    }
    if (bytes[position] !== 0xff) {
      position += 1;
      continue;
    }
    // 跳过连续填充 FF。
    while (position < bytes.length && bytes[position] === 0xff) position += 1;
    if (position >= bytes.length) return null;
    const marker = bytes[position];
    if (marker === 0xd9) {
      const eoiEnd = position + 1;
      return eoiEnd < bytes.length ? { offset: eoiEnd, trailing: bytes.subarray(eoiEnd) } : null;
    }
    if (marker === 0xda) {
      position += 1;
      if (position + 2 > bytes.length) return null;
      const segmentLength = (bytes[position] << 8) | bytes[position + 1];
      position += segmentLength;
      inScan = true;
      continue;
    }
    if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) {
      position += 1;
      continue;
    }
    position += 1;
    if (position + 2 > bytes.length) return null;
    const segmentLength = (bytes[position] << 8) | bytes[position + 1];
    if (segmentLength < 2) return null;
    position += segmentLength;
  }
  return null;
};

export interface PngChunkInfo {
  type: string;
  length: number;
  crcOk: boolean;
  // 数据区起始偏移（chunk 长度字段之后 8 字节）。
  dataStart: number;
  // tEXt/zTXt/iTXt 的解析结果；其它类型为 null。
  text: PngTextChunk | null;
}

export interface PngTextChunk {
  keyword: string;
  // tEXt 的明文 / iTXt 未压缩时的文本（latin1 解码，字节透明）。
  text?: string;
  // zTXt 恒压缩；iTXt 压缩标志为 1 时压缩。解压（deflate）由消费方 async 做。
  compressed?: boolean;
  compressedBytes?: Uint8Array;
}

export interface PngChunkList {
  chunks: PngChunkInfo[];
  // 达到 maxChunks 上限被截断时为 true（动画 PNG 等合法文件可能超出）。
  truncated: boolean;
}

// PNG 全量 chunk 枚举：类型/长度/CRC 校验 + 文本 chunk（tEXt/zTXt/iTXt，flag 常见藏点）。
// 损坏结构在当前位置截断（保留已解析部分），不抛异常——取证场景"能看到多少给多少"。
export const enumeratePngChunks = (bytes: Uint8Array, options: { maxChunks?: number } = {}): PngChunkList => {
  const maxChunks = options.maxChunks ?? 256;
  const chunks: PngChunkInfo[] = [];
  if (!matchesAt(bytes, PNG_SIGNATURE, 0)) return { chunks, truncated: false };
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let position = 8;
  let truncated = false;
  while (position + 8 <= bytes.length) {
    if (chunks.length >= maxChunks) {
      truncated = true;
      break;
    }
    const length = view.getUint32(position);
    if (position + 12 + length > bytes.length) break;
    const type = String.fromCharCode(bytes[position + 4], bytes[position + 5], bytes[position + 6], bytes[position + 7]);
    const dataStart = position + 8;
    const dataEnd = dataStart + length;
    const expectedCrc = view.getUint32(dataEnd);
    const actualCrc = crc32Bytes(bytes.subarray(position + 4, dataEnd));
    chunks.push({
      type,
      length,
      crcOk: expectedCrc === actualCrc,
      dataStart,
      text: parseTextChunk(bytes, type, dataStart, dataEnd),
    });
    position = dataEnd + 4;
    if (type === 'IEND') break;
  }
  return { chunks, truncated };
};

const latin1 = new TextDecoder('latin1');

const parseTextChunk = (bytes: Uint8Array, type: string, start: number, end: number): PngTextChunk | null => {
  const nullAt = (from: number): number => {
    for (let index = from; index < end; index += 1) if (bytes[index] === 0) return index;
    return -1;
  };
  if (type === 'tEXt') {
    const split = nullAt(start);
    if (split < 0) return null;
    return { keyword: latin1.decode(bytes.subarray(start, split)), text: latin1.decode(bytes.subarray(split + 1, end)) };
  }
  if (type === 'zTXt') {
    const split = nullAt(start);
    if (split < 0 || split + 2 > end) return null;
    return {
      keyword: latin1.decode(bytes.subarray(start, split)),
      compressed: true,
      compressedBytes: bytes.slice(split + 2, end),
    };
  }
  if (type === 'iTXt') {
    let cursor = start;
    const split = nullAt(cursor);
    if (split < 0) return null;
    const keyword = latin1.decode(bytes.subarray(cursor, split));
    cursor = split + 1;
    if (cursor + 2 > end) return null;
    const compressionFlag = bytes[cursor];
    cursor += 2; // 压缩标志 + 压缩方法
    const langSplit = nullAt(cursor);
    if (langSplit < 0) return null;
    cursor = langSplit + 1;
    const translatedSplit = nullAt(cursor);
    if (translatedSplit < 0) return null;
    cursor = translatedSplit + 1;
    if (compressionFlag === 1) {
      return { keyword, compressed: true, compressedBytes: bytes.slice(cursor, end) };
    }
    return { keyword, text: latin1.decode(bytes.subarray(cursor, end)) };
  }
  return null;
};
