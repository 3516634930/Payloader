// ZIP 密码爆破引擎（离线 CTF 工具箱：纯 JS 本地执行，不联网/不 eval/零新依赖）。
// 支持两类口令加密：
// - ZipCrypto：APPNOTE.txt XIII 经典 PKZIP 流密码。keys 初值 0x12345678/0x23456789/0x34567890，
//   update_keys 查 crc32Table，stream byte = ((keys[2]|2) * ((keys[2]|2)^1)) >>> 8；数据区前置 12 字节
//   加密头，快速校验字节取 header[10..11] 对 CRC32 高 16 位（flag bit3 置位时 header[11] 对 DOS 时间高字节）。
// - WinZip AES（AE-1/AE-2）：extra field 0x9901（data = version(2)+'AE'(2)+strength(1)+真实压缩方法(2)）。
//   数据区 = salt(8/12/16) || 2 字节口令验证值 || AES-CTR 密文 || 10 字节 HMAC-SHA1 截断认证码；
//   PBKDF2-HMAC-SHA1×1000 派生 2*keyLen+2 字节（AES key || HMAC key || 验证值），CTR 计数器为全零 128 位大端，
//   认证码覆盖密文（encrypt-and-MAC）。
// 口令字节约定：ZipCrypto 按 latin1（Info-ZIP/爆破器惯例，ASCII 口令无歧义）；WinZip AES 按 UTF-8（规范要求）。
// 解压边界：仅 stored(method 0) 条目出内容预览；deflate 等压缩条目命中后返回提示文案
// （本仓无 inflate，长期项：接 CompressionStream('deflate-raw')）。
import { crc32Table } from '../codec/alphabets';
import { crc32BytesOf } from '../codec/crc32Attack';

export interface ZipEncryptedEntry {
  fileName: string;
  localHeaderOffset: number;
  compressedSize: number;
  method: 'zipcrypto' | 'aes-128' | 'aes-192' | 'aes-256' | 'unknown';
  crc32: number;
}

export interface BruteProgress {
  tried: number;
  total: number;
  password: string | null;
  previewText: string | null;
}

const EOCD_SIGNATURE = 0x06054b50;
const CENTRAL_SIGNATURE = 0x02014b50;
const LOCAL_SIGNATURE = 0x04034b50;
const AES_EXTRA_ID = 0x9901;
const AES_EXTRA_DATA_SIZE = 7;
const ZIPCRYPTO_HEADER_SIZE = 12;
const AES_AUTH_CODE_SIZE = 10;
const DEFAULT_TIME_BUDGET_MS = 15000;
// 让步/进度节流粒度：每 512 个口令 setTimeout(0) 让出主线程并回报一次进度（任务约束 256~1024）
const YIELD_EVERY = 512;
const PREVIEW_LIMIT = 256;

// deflate 等压缩条目命中后的统一提示（previewText 语义：stored 为真实内容前 256 字节可打印预览，压缩条目为本提示）
const COMPRESSED_HIT_HINT =
  '已命中口令；该条目为压缩存储（deflate 等压缩方法），本工具暂不内置解压预览，请用此口令在系统解压软件中打开提取内容';

const AES_STRENGTH_METHOD: Record<1 | 2 | 3, ZipEncryptedEntry['method']> = {
  1: 'aes-128',
  2: 'aes-192',
  3: 'aes-256',
};

const AES_PARAMETERS: Record<'aes-128' | 'aes-192' | 'aes-256', { keyLength: number; saltLength: number }> = {
  'aes-128': { keyLength: 16, saltLength: 8 },
  'aes-192': { keyLength: 24, saltLength: 12 },
  'aes-256': { keyLength: 32, saltLength: 16 },
};

const readLe16 = (bytes: Uint8Array, offset: number): number => (bytes[offset] | (bytes[offset + 1] << 8)) & 0xffff;
const readLe32 = (bytes: Uint8Array, offset: number): number =>
  (bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24)) >>> 0;

const findEocdOffset = (bytes: Uint8Array): number => {
  if (bytes.length < 22) return -1;
  const minOffset = Math.max(0, bytes.length - 22 - 0xffff);
  for (let offset = bytes.length - 22; offset >= minOffset; offset -= 1) {
    if (readLe32(bytes, offset) === EOCD_SIGNATURE) return offset;
  }
  return -1;
};

const utf8Decoder = new TextDecoder();

const decodeFileName = (bytes: Uint8Array, offset: number, length: number, utf8: boolean): string => {
  const view = bytes.subarray(offset, offset + length);
  if (utf8) return utf8Decoder.decode(view);
  let name = '';
  for (let index = 0; index < view.length; index += 1) name += String.fromCharCode(view[index]);
  return name;
};

interface AesExtraInfo {
  strength: 1 | 2 | 3;
  realMethod: number;
}

// 在 [offset, offset+length) 的 extra 区扫描 0x9901，返回强度与底层真实压缩方法
const parseAesExtra = (bytes: Uint8Array, offset: number, length: number): AesExtraInfo | null => {
  let cursor = offset;
  const end = offset + length;
  while (cursor + 4 <= end) {
    const id = readLe16(bytes, cursor);
    const size = readLe16(bytes, cursor + 2);
    if (size > end - cursor - 4) return null;
    if (id === AES_EXTRA_ID && size >= AES_EXTRA_DATA_SIZE) {
      const strength = bytes[cursor + 8];
      if (strength < 1 || strength > 3) return null;
      return { strength: strength as 1 | 2 | 3, realMethod: readLe16(bytes, cursor + 9) };
    }
    cursor += 4 + size;
  }
  return null;
};

export const detectEncryptedEntries = (bytes: Uint8Array): ZipEncryptedEntry[] => {
  const eocdOffset = findEocdOffset(bytes);
  if (eocdOffset < 0) {
    throw new Error('未找到 EOCD 记录：不是可解析的经典 ZIP（损坏结构或 ZIP64 不在支持范围）');
  }
  const entryCount = readLe16(bytes, eocdOffset + 10);
  if (entryCount === 0) throw new Error('中央目录条目数为 0：该 ZIP 没有任何条目，无加密可言');
  let cursor = readLe32(bytes, eocdOffset + 16);
  if (cursor === 0xffffffff) throw new Error('检测到 ZIP64（中央目录偏移为 0xFFFFFFFF 哨兵）：暂不支持');
  const entries: ZipEncryptedEntry[] = [];
  for (let index = 0; index < entryCount; index += 1) {
    if (cursor + 46 > bytes.length || readLe32(bytes, cursor) !== CENTRAL_SIGNATURE) {
      throw new Error(`第 ${index + 1} 个中央目录条目越界或签名损坏：不是可解析的经典 ZIP`);
    }
    const flag = readLe16(bytes, cursor + 8);
    const method = readLe16(bytes, cursor + 10);
    const crc32 = readLe32(bytes, cursor + 16);
    const compressedSize = readLe32(bytes, cursor + 20);
    const nameLength = readLe16(bytes, cursor + 28);
    const extraLength = readLe16(bytes, cursor + 30);
    const commentLength = readLe16(bytes, cursor + 32);
    const localHeaderOffset = readLe32(bytes, cursor + 42);
    if (compressedSize === 0xffffffff || localHeaderOffset === 0xffffffff) {
      throw new Error('检测到 ZIP64 尺寸/偏移哨兵（0xFFFFFFFF）：暂不支持');
    }
    if (cursor + 46 + nameLength + extraLength > bytes.length) {
      throw new Error(`第 ${index + 1} 个条目的文件名/extra 区越界：不是可解析的经典 ZIP`);
    }
    if ((flag & 1) !== 0) {
      let encryption: ZipEncryptedEntry['method'];
      if (method === 99) {
        const aes = parseAesExtra(bytes, cursor + 46 + nameLength, extraLength);
        encryption = aes === null ? 'unknown' : AES_STRENGTH_METHOD[aes.strength];
      } else if ((flag & 0x40) !== 0) {
        // bit6 强加密（RC2/DES 等 SRP 协商）：未支持
        encryption = 'unknown';
      } else {
        encryption = 'zipcrypto';
      }
      entries.push({
        fileName: decodeFileName(bytes, cursor + 46, nameLength, (flag & 0x800) !== 0),
        localHeaderOffset,
        compressedSize,
        method: encryption,
        crc32,
      });
    }
    cursor += 46 + nameLength + extraLength + commentLength;
  }
  if (entries.length === 0) {
    throw new Error('未发现加密条目：所有条目 bit0 均为 0，不是口令加密的 ZIP（伪加密请先用 CRC32 冲突工具修复）');
  }
  return entries;
};

// ---- ZipCrypto 核心（热路径：update_keys 逐步内联，避免函数调用开销） ----

const ZIPCRYPTO_KEY0 = 0x12345678;
const ZIPCRYPTO_KEY1 = 0x23456789;
const ZIPCRYPTO_KEY2 = 0x34567890;

const decryptEncryptionHeader = (bytes: Uint8Array, dataOffset: number, password: string): Uint8Array => {
  let key0 = ZIPCRYPTO_KEY0;
  let key1 = ZIPCRYPTO_KEY1;
  let key2 = ZIPCRYPTO_KEY2;
  for (let index = 0; index < password.length; index += 1) {
    const c = password.charCodeAt(index) & 0xff;
    key0 = ((key0 >>> 8) ^ crc32Table[(key0 ^ c) & 0xff]) >>> 0;
    key1 = (Math.imul(key1 + (key0 & 0xff), 134775813) + 1) >>> 0;
    key2 = ((key2 >>> 8) ^ crc32Table[(key2 ^ ((key1 >>> 24) & 0xff)) & 0xff]) >>> 0;
  }
  const header = new Uint8Array(ZIPCRYPTO_HEADER_SIZE);
  for (let index = 0; index < ZIPCRYPTO_HEADER_SIZE; index += 1) {
    const temp = (key2 | 2) & 0xffff;
    const plain = bytes[dataOffset + index] ^ (((temp * (temp ^ 1)) >>> 8) & 0xff);
    header[index] = plain;
    key0 = ((key0 >>> 8) ^ crc32Table[(key0 ^ plain) & 0xff]) >>> 0;
    key1 = (Math.imul(key1 + (key0 & 0xff), 134775813) + 1) >>> 0;
    key2 = ((key2 >>> 8) ^ crc32Table[(key2 ^ ((key1 >>> 24) & 0xff)) & 0xff]) >>> 0;
  }
  return header;
};

const decryptZipCryptoPayload = (bytes: Uint8Array, dataOffset: number, compressedSize: number, password: string): Uint8Array => {
  let key0 = ZIPCRYPTO_KEY0;
  let key1 = ZIPCRYPTO_KEY1;
  let key2 = ZIPCRYPTO_KEY2;
  for (let index = 0; index < password.length; index += 1) {
    const c = password.charCodeAt(index) & 0xff;
    key0 = ((key0 >>> 8) ^ crc32Table[(key0 ^ c) & 0xff]) >>> 0;
    key1 = (Math.imul(key1 + (key0 & 0xff), 134775813) + 1) >>> 0;
    key2 = ((key2 >>> 8) ^ crc32Table[(key2 ^ ((key1 >>> 24) & 0xff)) & 0xff]) >>> 0;
  }
  const output = new Uint8Array(compressedSize - ZIPCRYPTO_HEADER_SIZE);
  for (let index = 0; index < compressedSize; index += 1) {
    const temp = (key2 | 2) & 0xffff;
    const plain = bytes[dataOffset + index] ^ (((temp * (temp ^ 1)) >>> 8) & 0xff);
    if (index >= ZIPCRYPTO_HEADER_SIZE) output[index - ZIPCRYPTO_HEADER_SIZE] = plain;
    key0 = ((key0 >>> 8) ^ crc32Table[(key0 ^ plain) & 0xff]) >>> 0;
    key1 = (Math.imul(key1 + (key0 & 0xff), 134775813) + 1) >>> 0;
    key2 = ((key2 >>> 8) ^ crc32Table[(key2 ^ ((key1 >>> 24) & 0xff)) & 0xff]) >>> 0;
  }
  return output;
};

// ---- WinZip AES 核心（WebCrypto：PBKDF2 + AES-CTR + HMAC-SHA1） ----

// AE-1/AE-2 固定零计数器；WebCrypto length=64（低 64 位计数）与 128 位大端自增在 <2^64 块内等价
const AES_CTR_ZERO_COUNTER = new Uint8Array(16);
const passwordEncoder = new TextEncoder();

// 优先裸 crypto 全局：node:vm 沙箱的 globalThis 被替换为白名单对象，裸 crypto 才能命中注入的宿主 WebCrypto
const getSubtle = (): SubtleCrypto | undefined => {
  const api = typeof crypto !== 'undefined' ? crypto : undefined;
  return api !== undefined && api.subtle !== undefined ? api.subtle : undefined;
};

// ---- 爆破上下文与单口令尝试 ----

interface CandidateOutcome {
  hit: boolean;
  content: Uint8Array | null;
}

interface ZipCryptoContext {
  kind: 'zipcrypto';
  dataOffset: number;
  compressedSize: number;
  crc32: number;
  useTimeCheck: boolean;
  expectedByte10: number;
  expectedByte11: number;
  realMethod: number;
}

interface AesContext {
  kind: 'aes';
  dataOffset: number;
  compressedSize: number;
  keyLength: number;
  saltLength: number;
  realMethod: number;
  // 一次性拷贝出 ArrayBuffer 兜底视图：WebCrypto BufferSource 不接受 ArrayBufferLike 的 subarray 视图
  cipherData: Uint8Array<ArrayBuffer>;
}

type EntryContext = ZipCryptoContext | AesContext;

const NO_HIT: CandidateOutcome = { hit: false, content: null };

const prepareEntryContext = (bytes: Uint8Array, entry: ZipEncryptedEntry): EntryContext => {
  if (entry.method === 'unknown') {
    throw new Error(`条目 ${JSON.stringify(entry.fileName)} 加密类型未知（AES extra 缺失/损坏或强加密 bit6）：无法爆破`);
  }
  const offset = entry.localHeaderOffset;
  if (!Number.isInteger(offset) || offset < 0 || offset + 30 > bytes.length || readLe32(bytes, offset) !== LOCAL_SIGNATURE) {
    throw new Error('本地文件头签名不匹配或越界：条目偏移已失效（文件可能被截断或二次加工过）');
  }
  const localFlag = readLe16(bytes, offset + 6);
  const localMethod = readLe16(bytes, offset + 8);
  const nameLength = readLe16(bytes, offset + 26);
  const extraLength = readLe16(bytes, offset + 28);
  const dataOffset = offset + 30 + nameLength + extraLength;
  const compressedSize = entry.compressedSize;
  if (!Number.isInteger(compressedSize) || compressedSize < 0 || dataOffset + compressedSize > bytes.length) {
    throw new Error('加密数据越界：compressedSize 超出文件实际长度');
  }
  const localExtra = parseAesExtra(bytes, offset + 30 + nameLength, extraLength);
  const realMethod = localMethod === 99 ? (localExtra === null ? -1 : localExtra.realMethod) : localMethod;
  if (realMethod < 0) throw new Error('method=99 但本地头 AES extra field 缺失/损坏：无法确定底层压缩方法');
  if (entry.method === 'zipcrypto') {
    if (compressedSize < ZIPCRYPTO_HEADER_SIZE) throw new Error('ZipCrypto 条目数据不足 12 字节加密头：结构异常');
    const useTimeCheck = (localFlag & 0x0008) !== 0;
    return {
      kind: 'zipcrypto',
      dataOffset,
      compressedSize,
      crc32: entry.crc32 >>> 0,
      useTimeCheck,
      expectedByte10: useTimeCheck ? -1 : (entry.crc32 >>> 16) & 0xff,
      expectedByte11: useTimeCheck ? (readLe16(bytes, offset + 10) >>> 8) & 0xff : (entry.crc32 >>> 24) & 0xff,
      realMethod,
    };
  }
  const parameters = AES_PARAMETERS[entry.method];
  if (compressedSize < parameters.saltLength + 2 + AES_AUTH_CODE_SIZE) {
    throw new Error('AES 条目数据长度异常：不足以容纳 salt + 口令验证值 + 认证码');
  }
  return {
    kind: 'aes',
    dataOffset,
    compressedSize,
    keyLength: parameters.keyLength,
    saltLength: parameters.saltLength,
    realMethod,
    cipherData: new Uint8Array(bytes.subarray(dataOffset, dataOffset + compressedSize)),
  };
};

const tryZipCryptoCandidate = (bytes: Uint8Array, context: ZipCryptoContext, password: string): CandidateOutcome => {
  // 快速校验：只解 12 字节头比对校验字节（bit3 → 仅 header[11] 对 DOS 时间高字节，其余 2 字节对 CRC32 高 16 位）
  const header = decryptEncryptionHeader(bytes, context.dataOffset, password);
  if (header[11] !== context.expectedByte11) return NO_HIT;
  if (!context.useTimeCheck && header[10] !== context.expectedByte10) return NO_HIT;
  if (context.realMethod !== 0) {
    // deflate 等压缩条目：无 inflate 无法做 CRC 终验，2 字节校验即判命中（误报率 ≤ 1/65536）
    return { hit: true, content: null };
  }
  const payload = decryptZipCryptoPayload(bytes, context.dataOffset, context.compressedSize, password);
  if (crc32BytesOf(payload) !== context.crc32) return NO_HIT; // 校验字节碰撞被 CRC 终验拦截
  return { hit: true, content: payload };
};

const tryWinZipAesCandidate = async (
  context: AesContext,
  password: string,
): Promise<CandidateOutcome> => {
  const subtle = getSubtle();
  if (subtle === undefined) throw new Error('当前环境无 WebCrypto（crypto.subtle）：WinZip AES 爆破不可用');
  const cipherData = context.cipherData;
  const salt = cipherData.subarray(0, context.saltLength);
  const baseKey = await subtle.importKey('raw', passwordEncoder.encode(password), 'PBKDF2', false, ['deriveBits']);
  const derived = new Uint8Array(
    await subtle.deriveBits(
      { name: 'PBKDF2', hash: 'SHA-1', iterations: 1000, salt },
      baseKey,
      (context.keyLength * 2 + 2) * 8,
    ),
  );
  // 2 字节口令验证值快筛（派生尾 2 字节 vs 数据区 salt 后 2 字节）：错误口令在此止步，不做 AES/HMAC
  const verificationOffset = context.keyLength * 2;
  if (
    derived[verificationOffset] !== cipherData[context.saltLength] ||
    derived[verificationOffset + 1] !== cipherData[context.saltLength + 1]
  ) {
    return NO_HIT;
  }
  const encrypted = cipherData.subarray(context.saltLength + 2, cipherData.length - AES_AUTH_CODE_SIZE);
  const aesKey = await subtle.importKey('raw', derived.subarray(0, context.keyLength), 'AES-CTR', false, ['decrypt']);
  const plain =
    encrypted.length === 0
      ? new Uint8Array(0)
      : new Uint8Array(await subtle.decrypt({ name: 'AES-CTR', counter: AES_CTR_ZERO_COUNTER, length: 64 }, aesKey, encrypted));
  const macKey = await subtle.importKey(
    'raw',
    derived.subarray(context.keyLength, context.keyLength * 2),
    { name: 'HMAC', hash: 'SHA-1' },
    false,
    ['sign'],
  );
  const mac = new Uint8Array(await subtle.sign('HMAC', macKey, encrypted)); // 认证码覆盖密文
  for (let index = 0; index < AES_AUTH_CODE_SIZE; index += 1) {
    if (mac[index] !== cipherData[cipherData.length - AES_AUTH_CODE_SIZE + index]) return NO_HIT;
  }
  return { hit: true, content: plain };
};

const buildPrintablePreview = (content: Uint8Array): string => {
  const limit = Math.min(content.length, PREVIEW_LIMIT);
  let preview = '';
  for (let index = 0; index < limit; index += 1) {
    const byte = content[index];
    preview += byte === 9 || byte === 10 || byte === 13 || (byte >= 0x20 && byte <= 0x7e) ? String.fromCharCode(byte) : '.';
  }
  return preview;
};

// node:vm 跨 realm：Symbol.iterator 逐 realm 独立，宿主数组在沙箱内查不到沙箱符号；
// Array.isArray 是跨 realm 可靠判定——数组走下标迭代，其余（本模块生成器等）走 Symbol.iterator
const iterateCandidates = (candidates: Iterable<string>): Iterator<string> => {
  if (Array.isArray(candidates)) {
    const array = candidates as string[];
    let index = 0;
    const iterator: Iterator<string> = {
      next: () => {
        if (index < array.length) {
          const value = array[index];
          index += 1;
          return { done: false, value };
        }
        return { done: true, value: undefined };
      },
    };
    return iterator;
  }
  const factory = (candidates as { [Symbol.iterator]?: () => Iterator<string> })[Symbol.iterator];
  if (typeof factory !== 'function') {
    throw new Error('candidates 必须是字符串数组或可迭代对象（数组/Set/本模块生成器）');
  }
  return factory.call(candidates);
};

const candidateTotal = (candidates: Iterable<string>): number => {
  if (Array.isArray(candidates)) return candidates.length;
  const size = (candidates as { size?: unknown }).size;
  return typeof size === 'number' ? size : Number.POSITIVE_INFINITY;
};

const yieldToMainThread = (): Promise<void> => new Promise((resolve) => setTimeout(resolve, 0));

export const bruteZipPassword = async (
  bytes: Uint8Array,
  entry: ZipEncryptedEntry,
  candidates: Iterable<string>,
  options?: { onProgress?: (progress: BruteProgress) => void; timeBudgetMs?: number },
): Promise<BruteProgress> => {
  if (entry.method === 'unknown') {
    throw new Error(`条目 ${JSON.stringify(entry.fileName)} 加密类型未知（AES extra 缺失/损坏或强加密 bit6）：无法爆破`);
  }
  const budget = options?.timeBudgetMs ?? DEFAULT_TIME_BUDGET_MS;
  if (!Number.isFinite(budget) || budget < 0) {
    throw new Error(`timeBudgetMs 必须为非负有限数字，当前 ${String(options?.timeBudgetMs)}`);
  }
  const onProgress = options?.onProgress;
  const total = candidateTotal(candidates);
  const iterator = iterateCandidates(candidates);
  const context = prepareEntryContext(bytes, entry);
  const deadline = Date.now() + budget;
  let tried = 0;
  for (;;) {
    const next = iterator.next();
    if (next.done === true) break;
    const candidate = next.value;
    tried += 1;
    const outcome =
      context.kind === 'zipcrypto'
        ? tryZipCryptoCandidate(bytes, context, candidate)
        : await tryWinZipAesCandidate(context, candidate);
    if (outcome.hit) {
      const previewText =
        context.realMethod === 0 ? buildPrintablePreview(outcome.content ?? new Uint8Array(0)) : COMPRESSED_HIT_HINT;
      const final: BruteProgress = { tried, total, password: candidate, previewText };
      onProgress?.(final);
      return final;
    }
    if (Date.now() >= deadline) break;
    if (tried % YIELD_EVERY === 0) {
      onProgress?.({ tried, total, password: null, previewText: null });
      await yieldToMainThread();
      if (Date.now() >= deadline) break;
    }
  }
  const finalProgress: BruteProgress = { tried, total, password: null, previewText: null };
  onProgress?.(finalProgress);
  return finalProgress;
};

// 掩码候选：按长度分段（先全部 len=min，再 min+1…）的定长逐位枚举，惰性生成器——95^5 级空间不落内存。
// startIndex 是全局枚举序号（跨长度累计），内部用 mixed-radix 里程计直接跳到起点，不逐个空转。
export function* maskCandidates(
  charset: string,
  minLength: number,
  maxLength: number,
  startIndex = 0,
): Generator<string, void, unknown> {
  const uniqueChars = Array.from(new Set(Array.from(charset)));
  if (uniqueChars.length === 0) throw new Error('字符集为空：至少需要一个字符');
  for (const char of uniqueChars) {
    const code = char.codePointAt(0);
    if (code === undefined || code > 0xff) {
      throw new Error(`字符集含非 latin1 字符 ${JSON.stringify(char)}：掩码候选按字节爆破，仅支持码点 0x00-0xFF`);
    }
  }
  if (!Number.isInteger(minLength) || minLength < 1) throw new Error(`minLength 必须为 ≥1 的整数，当前 ${minLength}`);
  if (!Number.isInteger(maxLength) || maxLength < minLength) {
    throw new Error(`maxLength 必须为 ≥ minLength（${minLength}）的整数，当前 ${maxLength}`);
  }
  if (!Number.isInteger(startIndex) || startIndex < 0) throw new Error(`startIndex 必须为非负整数，当前 ${startIndex}`);
  const size = uniqueChars.length;
  const codes = uniqueChars.map((char) => char.charCodeAt(0) & 0xff);
  let skipRemaining = startIndex;
  for (let length = minLength; length <= maxLength; length += 1) {
    const space = size ** length; // 超出 2^53 时仅 startIndex 跳越计数失真，逐位枚举本身不受影响
    if (skipRemaining >= space) {
      skipRemaining -= space;
      continue;
    }
    const digits = new Array<number>(length);
    let rest = skipRemaining;
    for (let position = 0; position < length; position += 1) {
      const unit = size ** (length - 1 - position);
      const digit = Math.floor(rest / unit);
      digits[position] = digit;
      rest -= digit * unit;
    }
    skipRemaining = 0;
    for (;;) {
      let password = '';
      for (let position = 0; position < length; position += 1) password += String.fromCharCode(codes[digits[position]]);
      yield password;
      let position = length - 1;
      while (position >= 0) {
        digits[position] += 1;
        if (digits[position] < size) break;
        digits[position] = 0;
        position -= 1;
      }
      if (position < 0) break;
    }
  }
}

// 内置 CTF 高频弱口令表（数字/键盘序/通用弱口令/CTF 与 flag 系列/恶意样本惯例 infected/压缩工具/年份）
const DICTIONARY: readonly string[] = Array.from(
  new Set([
    '000000', '111111', '1111111', '11111111', '121212', '112233', '123123', '123321', '1234', '12345',
    '123456', '1234567', '12345678', '123456789', '1234567890', '654321', '666666', '888888', '88888888', '999999',
    '102030', '147258', '147258369', '987654321', '520520', '5201314', '123',
    'password', 'password1', 'password123', 'passw0rd', 'Passw0rd', 'p@ssw0rd', 'P@ssw0rd', 'pass', 'passwd', 'pwd',
    'secret', 'secret123', 'admin', 'admin123', 'admin@123', 'administrator', 'root', 'root123', 'toor', 'guest',
    'test', 'test123', 'testtest', 'changeme', 'default', 'letmein', 'welcome', 'monkey', 'dragon', 'master',
    'sunshine', 'princess', 'football', 'baseball', 'superman', 'batman', 'whatever', 'qwerty', 'qwerty123', 'qwertyuiop',
    'asdfgh', 'zxcvbnm', 'qazwsx', '1qaz2wsx', '2wsx3edc', 'zaq12wsx', '1q2w3e4r', '123qwe', 'trustno1', 'starwars',
    'qwe123', 'abc123', 'a123456', 'iloveyou', 'woaini1314',
    'ctf', 'CTF', 'ctf123', 'ctf2024', 'ctf2025', 'ctf2026', 'buuctf', 'nssctf', 'hgame', 'flag', 'FLAG',
    'flag123', 'flag2024', 'flag2025', 'flag2026', 'fl4g', 'f1ag', 'getflag', 'key',
    'infected', 'virus', 'malware', 'sample', 'unpacked',
    // 真题高频动物/宠物名（János=fish、祥云杯系等）与 CTF 场景补充
    'fish', 'cat', 'dog', 'panda', 'rabbit', 'tigger', 'shadow', 'hunter', 'killer', 'player',
    'qwe', 'asd', 'zxc', 'qaz', 'wsx', '1234qwer', 'qwer1234', '0000000000', '121314', '131413',
    'misc', 'crypto', 'stego', 'reverse', 'pwn', 'web', 'hacker', 'security', 'challenge', 'answer',
    'zip', 'unzip', 'archive', 'compressed', 'encrypted', 'pkzip', 'winzip', 'winrar', 'rar', '7z',
    '1990', '1995', '1999', '2000', '2008', '2010', '2013', '2015', '2016', '2017',
    '2018', '2019', '2020', '2021', '2022', '2023', '2024', '2025', '2026',
  ]),
);

export const dictionaryCandidates = (): string[] => Array.from(DICTIONARY);

// 已知口令解密 ZipCrypto 条目：返回去掉 12 字节加密头后的数据（stored 条目即明文内容；
// deflate 条目仍是压缩流，调用方自行 inflate——浏览器层可用 CompressionStream('deflate-raw')）。
// local header 偏移 8 读真实压缩方法一并返回，便于调用方分流。
export interface DecryptedZipEntry {
  bytes: Uint8Array;
  compression: number; // 0=stored 8=deflate
  crcOk: boolean; // CRC32 终验（stored 可直接验；deflate 验的是压缩流字节，解压后应由调用方复验）
}
export const decryptZipCryptoEntry = (bytes: Uint8Array, entry: ZipEncryptedEntry, password: string): DecryptedZipEntry | null => {
  try {
    const nameLen = (bytes[entry.localHeaderOffset + 26] | (bytes[entry.localHeaderOffset + 27] << 8));
    const extraLen = (bytes[entry.localHeaderOffset + 28] | (bytes[entry.localHeaderOffset + 29] << 8));
    const compression = bytes[entry.localHeaderOffset + 8] | (bytes[entry.localHeaderOffset + 9] << 8);
    const dataOffset = entry.localHeaderOffset + 30 + nameLen + extraLen;
    const decrypted = decryptZipCryptoPayload(bytes, dataOffset, entry.compressedSize, password);
    const crcOk = compression === 0 && crc32BytesOf(decrypted) === entry.crc32;
    return { bytes: decrypted, compression, crcOk };
  } catch {
    return null;
  }
};
