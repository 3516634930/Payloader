// OpenStego（github.com/syvaidya/openstego，GPL-2.0）LSB 族隐写提取与闭环编码（批次 SI·B 线）。
// 按 OpenStego 源码语义按规格重写（不抄代码）：纯浏览器 JS、零 eval、零新依赖。
// 总管线：[gzip(RFC1952)] → [可选 PBE 加密] → LSB 插件嵌入。
// - LSBDataHeader（HEADER_VERSION=2）："OPENSTEGO"(9B) + 版本0x02(1B) + dataLength(4B 小端) +
//   channelBitsUsed(1B) + fileNameLen(1B) + useCompression(1B) + useEncryption(1B) +
//   cryptAlgo(8B 空格右填充，加密时短名 "AES128") + fileName。头部固定按 channelBits=1 读写，
//   数据段按头部声明值
// - lsb 插件（顺序，口令不参与位置）：x 先增、x 到 width 才 y++ 的行主序遍历；字节位序 MSB-first；
//   每像素 R→G→B 各取低 channelBits 位、槽内高位在先：bit = ((像素值 >> (16 - 通道*8)) >> (n - 槽内序 - 1)) & 1
// - randlsb 插件（口令驱动位置）：PRNG = java.util.Random（48 位 LCG，BigInt 复刻）。
//   种子 = MD5(UTF8(口令)) hex 前 15 字符按 long 解析；空口令种子 = 98234782。每 bit 消耗
//   4 次 nextInt：x=nextInt(width)、y=nextInt(height)、channel=nextInt(3)、bit=nextInt(channelBits)，
//   key="x_y_channel_bit" 去重。通道映射（与顺序插件相反）：channel 0=蓝、1=绿、2=红，
//   bit 直接为通道内位索引：bit 值 = (rgb >> (channel*8 + bit)) & 1
// - 加密（头声明 AES128）：PBEWithHmacSHA256AndAES_128 = PBKDF2(固定盐
//   [0x28,0x5F,0x71,0xC9,0x1E,0x35,0x0A,0x62], 7 迭代, HMAC-SHA256, 16B key) + AES-128-CBC。
//   密文格式 [1B paramsLen][params（JCE 黑盒）][密文]——IV 定位两种 fallback：先取 params 尾部
//   16 字节（JCE PBES2 参数 DER 末尾的 IV OCTET STRING，编码方向同此），再退而取密文首 16 字节
// - 解压用 DecompressionStream('gzip')，压缩用 CompressionStream('gzip')；MD5 为纯 JS 复刻（RFC 1321）
import type { RgbaImage } from './imageOps';

const OS_MAGIC = 'OPENSTEGO';
const OS_HEADER_VERSION = 0x02;
const OS_FIXED_HEADER = 9 + 1 + 4 + 1 + 1 + 1 + 1 + 8; // 26B 固定头（不含 fileName）
const OS_PBE_SALT = Uint8Array.of(0x28, 0x5f, 0x71, 0xc9, 0x1e, 0x35, 0x0a, 0x62);
const OS_PBE_ITERATIONS = 7;
const RANDLSB_EMPTY_PASSWORD_SEED = 98234782;
const VALID_CHANNEL_BITS = [1, 2, 4, 8];

// ---- 基础字节工具 ----

const asBufferSource = (bytes: Uint8Array): ArrayBuffer => {
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  return buffer;
};

const concatBytes = (...parts: Uint8Array[]): Uint8Array => {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
};

const utf8Encode = (value: string): Uint8Array => new TextEncoder().encode(value);
const utf8DecodeLoose = (bytes: Uint8Array): string => new TextDecoder().decode(bytes);
const bytesToHex = (bytes: Uint8Array): string => Array.from(bytes, value => value.toString(16).padStart(2, '0')).join('');

// ---- MD5（RFC 1321 纯 JS 复刻，randlsb 口令种子与 OpenStego 兼容所需；WebCrypto 无 MD5）----

const MD5_S = new Uint8Array([
  7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
  5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
]);
const MD5_K = new Int32Array(64).map((_, index) => Math.floor(Math.abs(Math.sin(index + 1)) * 4294967296));

export const md5 = (input: Uint8Array): Uint8Array => {
  const paddedLength = (((input.length + 8) >> 6) + 1) << 6;
  const padded = new Uint8Array(paddedLength);
  padded.set(input);
  padded[input.length] = 0x80;
  const view = new DataView(padded.buffer);
  const bitLength = input.length * 8;
  view.setUint32(paddedLength - 8, bitLength % 4294967296, true);
  view.setUint32(paddedLength - 4, Math.floor(bitLength / 4294967296), true);
  let a0 = 0x67452301 | 0;
  let b0 = 0xefcdab89 | 0;
  let c0 = 0x98badcfe | 0;
  let d0 = 0x10325476 | 0;
  const words = new Int32Array(16);
  for (let offset = 0; offset < paddedLength; offset += 64) {
    for (let i = 0; i < 16; i += 1) words[i] = view.getInt32(offset + i * 4, true);
    let a = a0;
    let b = b0;
    let c = c0;
    let d = d0;
    for (let i = 0; i < 64; i += 1) {
      let f: number;
      let g: number;
      if (i < 16) {
        f = (b & c) | (~b & d);
        g = i;
      } else if (i < 32) {
        f = (d & b) | (~d & c);
        g = (5 * i + 1) & 15;
      } else if (i < 48) {
        f = b ^ c ^ d;
        g = (3 * i + 5) & 15;
      } else {
        f = c ^ (b | ~d);
        g = (7 * i) & 15;
      }
      const rotated = (f + a + MD5_K[i] + words[g]) | 0;
      a = d;
      d = c;
      c = b;
      b = (b + ((rotated << MD5_S[i]) | (rotated >>> (32 - MD5_S[i])))) | 0;
    }
    a0 = (a0 + a) | 0;
    b0 = (b0 + b) | 0;
    c0 = (c0 + c) | 0;
    d0 = (d0 + d) | 0;
  }
  const digest = new Uint8Array(16);
  const out = new DataView(digest.buffer);
  out.setInt32(0, a0, true);
  out.setInt32(4, b0, true);
  out.setInt32(8, c0, true);
  out.setInt32(12, d0, true);
  return digest;
};

// ---- java.util.Random 复刻（48 位 LCG，BigInt 承载乘法进位）----

export class JavaRandom {
  private seedValue = 0n;

  constructor(seed: number | bigint) {
    this.seedValue = (BigInt(seed) ^ 0x5deece66dn) & 0xffffffffffffn;
  }

  // next(bits)：seed = (seed*0x5DEECE66D + 0xB) & (2^48-1)，返回 seed >>> (48-bits) 低 bits 位
  next(bits: number): number {
    this.seedValue = (this.seedValue * 0x5deece66dn + 0xbn) & 0xffffffffffffn;
    return Number((this.seedValue >> BigInt(48 - bits)) & ((1n << BigInt(bits)) - 1n));
  }

  // nextInt()：next(32) 按 Java int 解释（有符号）
  nextInt(): number;

  // nextInt(bound)：2 的幂走 (bound*next(31))>>31 快速路径；否则拒绝采样（int32 溢出即拒绝）
  nextInt(bound: number): number;

  nextInt(bound?: number): number {
    if (bound === undefined) return this.next(32) | 0;
    if (bound <= 0) throw new Error(`nextInt 上界 ${bound} 非法：必须为正数`);
    if ((bound & (bound - 1)) === 0) return Number((BigInt(bound) * BigInt(this.next(31))) >> 31n);
    let bits = 0;
    let value = 0;
    do {
      bits = this.next(31);
      value = bits % bound;
    } while (bits - value + (bound - 1) > 0x7fffffff);
    return value;
  }
}

// ---- WebCrypto / 流式压缩原语 ----

const subtleCrypto = (): SubtleCrypto => {
  // 优先裸 crypto 全局：node:vm 沙箱的 globalThis 是白名单对象，裸 crypto 才命中注入的宿主 WebCrypto
  const api = typeof crypto !== 'undefined' ? crypto : undefined;
  if (api === undefined || api.subtle === undefined) {
    throw new Error('当前环境无 WebCrypto（crypto.subtle）：OpenStego 加解密不可用');
  }
  return api.subtle;
};

const aesCbcEncrypt = async (keyBytes: Uint8Array, iv: Uint8Array, data: Uint8Array): Promise<Uint8Array> => {
  const subtle = subtleCrypto();
  const key = await subtle.importKey('raw', asBufferSource(keyBytes), { name: 'AES-CBC' }, false, ['encrypt']);
  return new Uint8Array(await subtle.encrypt({ name: 'AES-CBC', iv: asBufferSource(iv) }, key, asBufferSource(data)));
};

const aesCbcDecrypt = async (keyBytes: Uint8Array, iv: Uint8Array, data: Uint8Array): Promise<Uint8Array> => {
  const subtle = subtleCrypto();
  const key = await subtle.importKey('raw', asBufferSource(keyBytes), { name: 'AES-CBC' }, false, ['decrypt']);
  return new Uint8Array(await subtle.decrypt({ name: 'AES-CBC', iv: asBufferSource(iv) }, key, asBufferSource(data)));
};

const pbkdf2Sha256 = async (password: string, salt: Uint8Array, iterations: number, lengthBytes: number): Promise<Uint8Array> => {
  const subtle = subtleCrypto();
  const material = await subtle.importKey('raw', asBufferSource(utf8Encode(password)), 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: asBufferSource(salt), iterations },
    material,
    lengthBytes * 8,
  ));
};

const streamToBytes = async (stream: ReadableStream<Uint8Array>): Promise<Uint8Array> => {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    if (value) {
      chunks.push(value);
      size += value.length;
    }
  }
  const out = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
};

const gzip = async (input: Uint8Array): Promise<Uint8Array> => {
  const Ctor = globalThis.CompressionStream;
  if (Ctor === undefined) throw new Error('当前环境不支持 CompressionStream：gzip 压缩不可用');
  return streamToBytes(new Blob([asBufferSource(input)]).stream().pipeThrough(new Ctor('gzip')));
};

const gunzip = async (input: Uint8Array): Promise<Uint8Array> => {
  const Ctor = globalThis.DecompressionStream;
  if (Ctor === undefined) throw new Error('当前环境不支持 DecompressionStream：gzip 解压不可用');
  if (!(input[0] === 0x1f && input[1] === 0x8b)) throw new Error('数据无 gzip 魔数 1f 8b：不是 gzip 载荷（解密 IV 定位或口令可能不对）');
  return streamToBytes(new Blob([asBufferSource(input)]).stream().pipeThrough(new Ctor('gzip')));
};

// ---- PBEWithHmacSHA256AndAES_128 ----

const pbeKey = (password: string): Promise<Uint8Array> => pbkdf2Sha256(password, OS_PBE_SALT, OS_PBE_ITERATIONS, 16);

// 编码方向：params 直接写 16 字节随机 IV（与真实 OpenStego 的 JCE PBES2 参数 DER 末尾 IV 兼容，命中 paramsTail 模式）
const pbeEncrypt = async (plain: Uint8Array, password: string): Promise<Uint8Array> => {
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const cipher = await aesCbcEncrypt(await pbeKey(password), iv, plain);
  return concatBytes(Uint8Array.of(16), iv, cipher);
};

type PbeIvMode = 'paramsTail' | 'ciphertextPrefix';

const pbeDecrypt = async (encrypted: Uint8Array, password: string, ivMode: PbeIvMode): Promise<Uint8Array> => {
  if (encrypted.length < 1) throw new Error('加密载荷为空');
  const paramsLen = encrypted[0];
  if (1 + paramsLen + 16 > encrypted.length) throw new Error(`paramsLen=${paramsLen} 与载荷长度 ${encrypted.length} 不匹配：密文格式非预期`);
  const params = encrypted.slice(1, 1 + paramsLen);
  const body = encrypted.slice(1 + paramsLen);
  let iv: Uint8Array;
  let cipherData: Uint8Array;
  if (ivMode === 'ciphertextPrefix') {
    iv = body.slice(0, 16);
    cipherData = body.slice(16);
  } else {
    if (paramsLen < 16) throw new Error(`params 长度 ${paramsLen} 不足 16 字节：无法作 IV 源`);
    iv = params.slice(paramsLen - 16);
    cipherData = body;
  }
  return aesCbcDecrypt(await pbeKey(password), iv, cipherData);
};

const pbeDecryptWithFallback = async (
  encrypted: Uint8Array,
  password: string,
  notes: string[],
  validate?: (plain: Uint8Array) => void,
): Promise<Uint8Array> => {
  const modes: Array<{ name: string; ivMode: PbeIvMode }> = [
    { name: 'params 尾部 16 字节（JCE PBES2 参数 DER 末尾的 IV）', ivMode: 'paramsTail' },
    { name: '密文首 16 字节', ivMode: 'ciphertextPrefix' },
  ];
  const failures: string[] = [];
  for (const mode of modes) {
    try {
      const plain = await pbeDecrypt(encrypted, password, mode.ivMode);
      if (validate) validate(plain);
      notes.push(`PBEWithHmacSHA256AndAES_128 解密成功（IV 定位：${mode.name}）`);
      return plain;
    } catch (error) {
      failures.push(`${mode.name}：${error instanceof Error ? error.message : String(error)}`);
    }
  }
  throw new Error(`PBE 解密两种 IV 定位均失败（${failures.join('；')}）——口令错误或密文格式非预期`);
};

// ---- LSBDataHeader ----

interface OpenStegoHeader {
  dataLength: number;
  channelBitsUsed: number;
  fileNameLength: number;
  useCompression: boolean;
  useEncryption: boolean;
  cryptAlgo: string;
  fileName: string;
}

const buildHeader = (
  dataLength: number,
  channelBits: number,
  nameBytes: Uint8Array,
  useCompression: boolean,
  useEncryption: boolean,
): Uint8Array => {
  const out = new Uint8Array(OS_FIXED_HEADER + nameBytes.length);
  out.set(utf8Encode(OS_MAGIC), 0);
  out[9] = OS_HEADER_VERSION;
  out[10] = dataLength & 0xff;
  out[11] = (dataLength >>> 8) & 0xff;
  out[12] = (dataLength >>> 16) & 0xff;
  out[13] = (dataLength >>> 24) & 0xff;
  out[14] = channelBits;
  out[15] = nameBytes.length;
  out[16] = useCompression ? 1 : 0;
  out[17] = useEncryption ? 1 : 0;
  out.fill(0x20, 18, 26);
  if (useEncryption) out.set(utf8Encode('AES128'), 18);
  out.set(nameBytes, OS_FIXED_HEADER);
  return out;
};

const parseFixedHeader = (fixed: Uint8Array): OpenStegoHeader => {
  if (fixed.length < OS_FIXED_HEADER) {
    throw new Error(`提取流仅 ${fixed.length} 字节，不足 OpenStego 固定头 ${OS_FIXED_HEADER} 字节：不是 OpenStego 载体`);
  }
  const magic = utf8DecodeLoose(fixed.slice(0, 9));
  if (magic !== OS_MAGIC) {
    throw new Error(`魔数 "${magic}" ≠ "OPENSTEGO"：不是 OpenStego 载体`);
  }
  const version = fixed[9];
  if (version !== OS_HEADER_VERSION) {
    throw new Error(`头部版本 0x${version.toString(16)} ≠ 0x02：不支持的 OpenStego 版本`);
  }
  const channelBitsUsed = fixed[14];
  if (!VALID_CHANNEL_BITS.includes(channelBitsUsed)) {
    throw new Error(`channelBitsUsed=${channelBitsUsed} 非法（合法 1/2/4/8）`);
  }
  return {
    dataLength: (fixed[10] | (fixed[11] << 8) | (fixed[12] << 16) | (fixed[13] << 24)) >>> 0,
    channelBitsUsed,
    fileNameLength: fixed[15],
    useCompression: fixed[16] === 1,
    useEncryption: fixed[17] === 1,
    cryptAlgo: String.fromCharCode(...Array.from(fixed.slice(18, 26))).replace(/\s+$/g, ''),
    fileName: '',
  };
};

// ---- 槽位（每像素 R/G/B 一个"槽"，槽容量 = 当前阶段 channelBits）----

// randlsb 的口令种子：Long.parseLong(MD5(UTF8(口令)) hex 前 15 字符, 16)
const randlsbSeed = (password: string): bigint => {
  const hex = bytesToHex(md5(utf8Encode(password)));
  return BigInt(`0x${hex.slice(0, 15)}`);
};

class RandomSlotSource {
  private rng: JavaRandom;

  private used = new Set<string>();

  private channelBits: number;

  private width: number;

  private height: number;

  // 空口令（randlsb 无口令嵌入的兼容场景）用 OpenStego 固定种子
  constructor(width: number, height: number, channelBits: number, password?: string) {
    const seed = password !== undefined && password.length > 0 ? randlsbSeed(password) : RANDLSB_EMPTY_PASSWORD_SEED;
    this.rng = new JavaRandom(seed);
    this.channelBits = channelBits;
    this.width = width;
    this.height = height;
  }

  setChannelBits(channelBits: number): void {
    this.channelBits = channelBits;
  }

  // 每 bit 消耗 4 次 nextInt，key 去重；槽位耗尽抛错防死循环
  next(): { pixel: number; rgbaOffset: number; bit: number } {
    const capacity = this.width * this.height * 3 * this.channelBits;
    for (;;) {
      if (this.used.size >= capacity) {
        throw new Error(`随机 LSB 槽位耗尽（容量 ${capacity} 位）：图像容量不足`);
      }
      const x = this.rng.nextInt(this.width);
      const y = this.rng.nextInt(this.height);
      const channel = this.rng.nextInt(3);
      const bit = this.rng.nextInt(this.channelBits);
      const key = `${x}_${y}_${channel}_${bit}`;
      if (this.used.has(key)) continue;
      this.used.add(key);
      // 通道 0=蓝、1=绿、2=红 → RGBA 偏移 2/1/0
      return { pixel: y * this.width + x, rgbaOffset: 2 - channel, bit };
    }
  }
}

// 顺序 lsb：x 先增（行主序）、每像素 R→G→B、槽内高位在先；state.slot 跨阶段（头 1bit/数据 nbit）连续消耗
const readBitsSequential = (
  data: ArrayLike<number>,
  width: number,
  height: number,
  byteCount: number,
  channelBits: number,
  state: { slot: number },
): Uint8Array => {
  const total = byteCount * 8;
  const out = new Uint8Array(byteCount);
  let produced = 0;
  while (produced < total) {
    if (state.slot >= width * height * 3) {
      throw new Error(`顺序 LSB 槽位耗尽（需 ${total} 位、${Math.ceil(total / channelBits)} 槽，图像仅 ${width * height * 3} 槽）：容量不足`);
    }
    const pixel = Math.floor(state.slot / 3);
    const channel = state.slot % 3; // 0=R 1=G 2=B（顺序插件 R→G→B）
    const value = data[pixel * 4 + channel];
    for (let k = 0; k < channelBits && produced < total; k += 1) {
      const bit = (value >> (channelBits - 1 - k)) & 1;
      out[produced >> 3] |= bit << (7 - (produced & 7));
      produced += 1;
    }
    state.slot += 1;
  }
  return out;
};

const writeBitsSequential = (
  target: Uint8ClampedArray,
  width: number,
  height: number,
  bytes: Uint8Array,
  channelBits: number,
  state: { slot: number },
): void => {
  const total = bytes.length * 8;
  let consumed = 0;
  while (consumed < total) {
    if (state.slot >= width * height * 3) {
      throw new Error(`顺序 LSB 槽位耗尽（需 ${total} 位，图像仅 ${width * height * 3} 槽）：容量不足，请增大图像或降低 channelBits`);
    }
    const pixel = Math.floor(state.slot / 3);
    const channel = state.slot % 3;
    const base = pixel * 4 + channel;
    for (let k = 0; k < channelBits && consumed < total; k += 1) {
      const bit = (bytes[consumed >> 3] >> (7 - (consumed & 7))) & 1;
      const shift = channelBits - 1 - k;
      target[base] = (target[base] & (~(1 << shift) & 0xff)) | (bit << shift);
      consumed += 1;
    }
    state.slot += 1;
  }
};

// randlsb 读：每 bit 一个随机槽（通道内第 bit 位，低位索引语义与顺序插件相反）
const readBitsRandom = (data: ArrayLike<number>, source: RandomSlotSource, byteCount: number, channelBits: number): Uint8Array => {
  source.setChannelBits(channelBits);
  const out = new Uint8Array(byteCount);
  for (let produced = 0; produced < byteCount * 8; produced += 1) {
    const slot = source.next();
    const bit = (data[slot.pixel * 4 + slot.rgbaOffset] >> slot.bit) & 1;
    out[produced >> 3] |= bit << (7 - (produced & 7));
  }
  return out;
};

const writeBitsRandom = (target: Uint8ClampedArray, source: RandomSlotSource, bytes: Uint8Array, channelBits: number): void => {
  source.setChannelBits(channelBits);
  for (let consumed = 0; consumed < bytes.length * 8; consumed += 1) {
    const slot = source.next();
    const bit = (bytes[consumed >> 3] >> (7 - (consumed & 7))) & 1;
    const base = slot.pixel * 4 + slot.rgbaOffset;
    target[base] = (target[base] & (~(1 << slot.bit) & 0xff)) | (bit << slot.bit);
  }
};

// ---- 公开接口 ----

export interface OpenStegoResult {
  fileName: string;
  data: Uint8Array;
  notes: string[];
}

export interface OpenStegoEncodeMessage {
  data: Uint8Array | string;
  fileName?: string;
  password?: string;
  compress?: boolean; // 默认 true（OpenStego 默认启用 gzip）
  channelBits?: number; // 默认 1
  plugin?: 'lsb' | 'randlsb'; // 默认：有口令 randlsb、无口令 lsb
}

const extractWithPlugin = async (image: RgbaImage, plugin: 'lsb' | 'randlsb', password?: string): Promise<OpenStegoResult> => {
  const { data, width, height } = image;
  const notes: string[] = [];
  let header: OpenStegoHeader;
  let payload: Uint8Array;
  if (plugin === 'randlsb') {
    const source = new RandomSlotSource(width, height, 1, password);
    header = parseFixedHeader(readBitsRandom(data, source, OS_FIXED_HEADER, 1));
    header.fileName = utf8DecodeLoose(readBitsRandom(data, source, header.fileNameLength, 1));
    payload = readBitsRandom(data, source, header.dataLength, header.channelBitsUsed);
    notes.push('命中 randlsb 插件（口令 MD5 种子驱动 java.util.Random 位置序列）');
  } else {
    const state = { slot: 0 };
    header = parseFixedHeader(readBitsSequential(data, width, height, OS_FIXED_HEADER, 1, state));
    header.fileName = utf8DecodeLoose(readBitsSequential(data, width, height, header.fileNameLength, 1, state));
    payload = readBitsSequential(data, width, height, header.dataLength, header.channelBitsUsed, state);
    notes.push('命中顺序 lsb 插件（x 先增、R→G→B，每通道低 channelBitsUsed 位、槽内高位在先）');
  }
  if (header.useEncryption) {
    if (!password) throw new Error('头部声明 useEncryption=1（AES128）但未提供口令：请补口令后重试');
    if (header.cryptAlgo !== 'AES128') {
      throw new Error(`不支持的加密算法 "${header.cryptAlgo}"（当前仅复刻 PBEWithHmacSHA256AndAES_128，头部短名 AES128）`);
    }
    // 解密结果若声明压缩则先用 gzip 魔数校验，避免 padding 碰巧合法时误选 IV 定位
    const validate = header.useCompression
      ? (plain: Uint8Array) => {
          if (!(plain[0] === 0x1f && plain[1] === 0x8b)) throw new Error('解密结果无 gzip 魔数 1f 8b');
        }
      : undefined;
    payload = await pbeDecryptWithFallback(payload, password, notes, validate);
  }
  if (header.useCompression) {
    const before = payload.length;
    payload = await gunzip(payload);
    notes.push(`useCompression=1：gzip 解压 ${before}B → ${payload.length}B（DecompressionStream）`);
  }
  return { fileName: header.fileName, data: payload, notes };
};

// 自动双试：有口令先 randlsb 再 lsb；无口令只 lsb。notes 记录命中的插件与 IV 定位模式
export const openstegoDecodeFromPixels = async (image: RgbaImage, password?: string): Promise<OpenStegoResult> => {
  const plugins: Array<'lsb' | 'randlsb'> = password ? ['randlsb', 'lsb'] : ['lsb'];
  const failures: string[] = [];
  for (const plugin of plugins) {
    try {
      return await extractWithPlugin(image, plugin, password);
    } catch (error) {
      failures.push(`${plugin}：${error instanceof Error ? error.message : String(error)}`);
    }
  }
  throw new Error(`OpenStego 提取失败（${plugins.join(' → ')} 双试均未通过）：${failures.join('；')}`);
};

// 编码方向（自造闭环向量用）：返回嵌入后的图像副本
export const openstegoEncode = async (image: RgbaImage, message: OpenStegoEncodeMessage): Promise<RgbaImage> => {
  const { width, height } = image;
  const plugin = message.plugin ?? (message.password ? 'randlsb' : 'lsb');
  const channelBits = message.channelBits ?? 1;
  if (!VALID_CHANNEL_BITS.includes(channelBits)) throw new Error(`channelBits=${channelBits} 非法（合法 1/2/4/8）`);
  const raw = typeof message.data === 'string' ? utf8Encode(message.data) : message.data;
  const nameBytes = utf8Encode(message.fileName ?? '');
  if (nameBytes.length > 255) throw new Error(`文件名 ${nameBytes.length}B 超过 1 字节长度字段上限 255B`);
  const useCompression = message.compress ?? true;
  let payload = useCompression ? await gzip(raw) : raw;
  const useEncryption = message.password !== undefined;
  if (message.password) payload = await pbeEncrypt(payload, message.password);
  if (payload.length > 0xffffffff) throw new Error('数据超过 4B 长度字段上限');
  const headerBytes = buildHeader(payload.length, channelBits, nameBytes, useCompression, useEncryption);
  const out = new Uint8ClampedArray(width * height * 4);
  const sourceLength = Math.min(out.length, image.data.length);
  for (let i = 0; i < sourceLength; i += 1) out[i] = image.data[i];
  if (plugin === 'randlsb') {
    const source = new RandomSlotSource(width, height, 1, message.password);
    writeBitsRandom(out, source, headerBytes, 1);
    writeBitsRandom(out, source, payload, channelBits);
  } else {
    const state = { slot: 0 };
    writeBitsSequential(out, width, height, headerBytes, 1, state);
    writeBitsSequential(out, width, height, payload, channelBits, state);
  }
  return { data: out, width, height };
};
