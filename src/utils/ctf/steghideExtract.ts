// steghide 0.5.1 提取方向（批次 SI·B 线，CTF 高频"给定口令提取"场景）。
// 语义按 GPL 源码规格重写（sources.debian.org/src/steghide/0.5.1+git20240220-2，不抄代码）：
// - PseudoRandomSource.cc：LCG，A=1367208549、C=1，mod 2^32；getValue(n)=⌊n·V/2^32⌋（先除后乘的
//   double 运算与 C++ 表达式逐操作对齐，IEEE754 结果一致；32 位乘法回绕用 Math.imul）
// - Selector.cc：懒计算 Fisher-Yates 变体（X/Y 数组 + Xreversed 值→下标哈希），calculate 的
//   分支顺序逐行对齐（hit 分支三段 if、末尾 X[j]>j 的 Y 链回填，缺一不可）
// - 种子：LE32(MD5(pw)[0:4]) ^ [4:8] ^ [8:12] ^ [12:16]（BitString LSB-first 读 4 个小端字）
// - EmbData.cc：位流 [Magic 24bit=0x73688D][版本一元码，版本 0 = 单个 0 位][EncAlgo 5bit]
//   [EncMode 3bit][NPlainBits 32bit][密文]，全 LSB-first；每个嵌入值 = 连续 SamplesPerVertex 个
//   被选样本 getEmbeddedValue 之和 mod EmbValueModulus（base-modulus 数字流按 appendNAry 展开）
// - MCryptPP/MHashKeyGen（mhash keygen_mcrypt.c 语义）：无盐 KEYGEN_MCRYPT，
//   D1=MD5(pw)、D2=MD5(pw‖D1)、…逐轮拼接，rijndael-128 取 32 字节 = AES-256；密文 = IV(16B)‖CBC，
//   密文位长 = 128 + ⌈NPlainBits/128⌉·128
// - 明文位流 = 压缩标志(1)[未压位长(32)+zlib 流] 校验标志(1)[CRC32(32)] 文件名(NUL 结尾) 数据
// 纯浏览器 JS、零运行时联网、零 eval、零新 npm 依赖；解密用 WebCrypto AES-CBC（受控尾块手法
// 绕开 PKCS#7 剥尾，见 aesCbcDecryptAll 注释），解压用 DecompressionStream('deflate')（zlib 封装）。
// CRC 注意：steghide 的校验是 mhash 的 MHASH_CRC32（非反射、多项式 0x04C11DB7、MSB 先行，
// 初值/终值均取反），与 zlib 反射 CRC32（0xEDB88320，crc32Attack.ts 的 crc32BytesOf）不同，
// 故此处自建同语义表；mhash 以小端字节序出摘要（WORDS_BIGENDIAN 时先交换再 memcpy），经
// BitString LSB-first 读回即寄存器终值本身，可直接与流中字段比对。
// 嵌入方向（图论匹配）不在本批范围；本批载体：24bpp BMP + 16bit PCM WAV。
import { md5Bytes } from '../codec/crypto';

// ---- 常量（EmbData.h / EncryptionAlgorithm / EncryptionMode） ----

export const STEGHIDE_MAGIC = 0x73688d;
const STEGHIDE_NBITS_MAGIC = 24;
const STEGHIDE_CODE_VERSION = 0;
export const STEGHIDE_ENC_ALGO_IREP_SIZE = 5;
export const STEGHIDE_ENC_MODE_IREP_SIZE = 3;
const STEGHIDE_NBITS_NPLAINBITS = 32;
const STEGHIDE_NBITS_NUNCOMPRESSED = 32;
const STEGHIDE_NBITS_CRC32 = 32;
const AES_BLOCK_BITS = 128;
const AES_BLOCK_BYTES = 16;

// 算法/模式整数表示（EncryptionAlgorithm.cc / EncryptionMode.cc 的 Translations 表序号）
const ENC_ALGO_NAMES = [
  'none', 'twofish', 'rijndael-128', 'rijndael-192', 'rijndael-256', 'saferplus', 'rc2', 'xtea',
  'serpent', 'safer-sk64', 'safer-sk128', 'cast-256', 'loki97', 'gost', 'threeway', 'cast-128',
  'blowfish', 'des', 'tripledes', 'enigma', 'arcfour', 'panama', 'wake',
];
const ENC_MODE_NAMES = ['ecb', 'cbc', 'ofb', 'cfb', 'nofb', 'ncfb', 'ctr', 'stream'];

// 记账：本批未支持的载体/加密组合（抛中文"暂不支持"时逐项列明）
export const STEGHIDE_UNSUPPORTED_CARRIERS = [
  '1/4/8bpp 调色板 BMP（本批仅 24bpp BMP）',
  '8bit PCM WAV（本批仅 16bit PCM WAV）',
  '非 rijndael-128+cbc / none 的加密组合（本批仅这两档）',
];

// ---- PseudoRandomSource（LCG） ----

export class PseudoRandomSource {
  private value: number;

  constructor(seed: number) {
    this.value = seed >>> 0;
  }

  peek(): number {
    return this.value;
  }

  // UWORD32 自然回绕：先推进再取值；返回 floor(n × V / 2^32)
  getValue(n: number): number {
    this.value = (Math.imul(1367208549, this.value) + 1) >>> 0;
    return Math.floor(n * (this.value / 4294967296));
  }
}

// ---- Selector（位置置换） ----

// 种子 = 4 个小端 32 位字异或（BitString::getValue LSB-first 语义）
export const steghideSelectorSeed = (passphrase: Uint8Array): number => {
  const hash = md5Bytes(passphrase);
  let seed = 0;
  for (let i = 0; i < 4; i += 1) {
    const word =
      hash[i * 4] | (hash[i * 4 + 1] << 8) | (hash[i * 4 + 2] << 16) | (hash[i * 4 + 3] << 24);
    seed ^= word;
  }
  return seed >>> 0;
};

export class SteghideSelector {
  private readonly maximum: number;
  private readonly prandom: PseudoRandomSource;
  private readonly x: number[] = [];
  private readonly y: number[] = [];
  private readonly xReversed = new Map<number, number>();
  private numInArray = 0;

  constructor(maximum: number, seed: number) {
    this.maximum = maximum;
    this.prandom = new PseudoRandomSource(seed);
  }

  at(index: number): number {
    if (index >= this.maximum) throw new Error(`Selector 下标越界：${index} ≥ 样本数 ${this.maximum}`);
    this.calculate(index + 1);
    return this.x[index];
  }

  // Selector.cc::calculate 的懒计算分支，逐行对齐：
  // - k 从 {j..Maximum-1} 取；命中 X[i]==k（i<j）时用 Y[i] 替代，并按 X[j]/X[i] 与 j 的大小
  //   维护 Y 链（Y[i] 的二次 idxX 命中要继续换成 Y[l]）；未命中则 X[j]=k、Y[j]=j
  // - 每轮末尾 X[j]>j 时对 Y[j] 再做一次链回填
  private calculate(m: number): void {
    let j = this.numInArray;
    if (m > this.numInArray) {
      this.numInArray = m;
      while (this.x.length < m) this.x.push(0);
      while (this.y.length < m) this.y.push(0);
    }
    for (; j < m; j += 1) {
      const k = j + this.prandom.getValue(this.maximum - j);
      const hit = this.idxX(k, j);
      if (hit >= 0) {
        this.setX(j, this.y[hit]);
        if (this.x[j] > j) this.y[j] = j;
        if (this.x[hit] > j) {
          this.y[hit] = j;
          const l = this.idxX(this.y[hit], j);
          if (l >= 0) this.y[hit] = this.y[l];
        }
      } else {
        this.setX(j, k);
        this.y[j] = j;
      }
      if (this.x[j] > j) {
        const i = this.idxX(this.y[j], j);
        if (i >= 0) this.y[j] = this.y[i];
      }
    }
  }

  // 值→下标哈希查找；仅当命中的下标 < m 才算数（含过期表项的语义）
  private idxX(v: number, m: number): number {
    const found = this.xReversed.get(v);
    if (found !== undefined && found < m) return found;
    return -1;
  }

  private setX(i: number, v: number): void {
    this.x[i] = v;
    this.xReversed.set(v, i);
  }
}

// ---- LSB-first 位串（BitString 语义：位 i = 字节 i/8 的第 i%8 位，先低后高） ----

export class LsbBits {
  private data = new Uint8Array(64);
  private bitLength = 0;

  get length(): number {
    return this.bitLength;
  }

  private ensure(bytesNeeded: number): void {
    if (this.data.length >= bytesNeeded) return;
    let size = this.data.length;
    while (size < bytesNeeded) size *= 2;
    const grown = new Uint8Array(size);
    grown.set(this.data);
    this.data = grown;
  }

  appendBit(bit: number): void {
    if (this.bitLength % 8 === 0) this.ensure(this.bitLength / 8 + 1);
    if (bit) this.data[this.bitLength >> 3] |= 1 << (this.bitLength & 7);
    this.bitLength += 1;
  }

  appendValue(value: number, nBits: number): void {
    for (let i = 0; i < nBits; i += 1) this.appendBit((value >>> i) & 1);
  }

  appendBytes(bytes: Uint8Array): void {
    for (let i = 0; i < bytes.length; i += 1) this.appendValue(bytes[i], 8);
  }

  appendBits(other: LsbBits): void {
    for (let i = 0; i < other.bitLength; i += 1) this.appendBit(other.getBit(i));
  }

  getBit(index: number): number {
    if (index >= this.bitLength) throw new Error(`位读取越界：${index} ≥ ${this.bitLength} 位`);
    return (this.data[index >> 3] >>> (index & 7)) & 1;
  }

  // nBits ≤ 32，LSB-first 组值（BitString::getValue 同形）
  getValue(start: number, nBits: number): number {
    let value = 0;
    for (let i = 0; i < nBits; i += 1) value |= this.getBit(start + i) << i;
    return value >>> 0;
  }

  toBytes(): Uint8Array {
    if (this.bitLength % 8 !== 0) throw new Error('位长不是 8 的倍数，无法按字节取出');
    return this.data.slice(0, this.bitLength / 8);
  }

  static fromBytes(bytes: Uint8Array, bitLength = bytes.length * 8): LsbBits {
    const bits = new LsbBits();
    bits.ensure(bytes.length);
    bits.data.set(bytes);
    bits.bitLength = bitLength;
    if (bitLength % 8 !== 0) bits.data[bitLength >> 3] &= (1 << (bitLength & 7)) - 1;
    return bits;
  }
}

// ---- base-modulus 数字流读取（提取端把被选样本的嵌入值流还原成位流） ----

export class NaryDigitReader {
  private readonly nextDigit: () => number;
  private readonly arityNBits: number;
  private buffer = new LsbBits();
  private consumed = 0;

  constructor(nextDigit: () => number, arityNBits: number) {
    this.nextDigit = nextDigit;
    this.arityNBits = arityNBits;
  }

  private fill(nBits: number): void {
    while (this.buffer.length - this.consumed < nBits) {
      this.buffer.appendValue(this.nextDigit(), this.arityNBits);
    }
  }

  private advance(nBits: number): void {
    this.consumed += nBits;
    if (this.consumed > 1 << 17 && this.consumed * 2 > this.buffer.length) {
      const keep = this.buffer.length - this.consumed;
      const fresh = new LsbBits();
      for (let i = 0; i < keep; i += 1) fresh.appendBit(this.buffer.getBit(this.consumed + i));
      this.buffer = fresh;
      this.consumed = 0;
    }
  }

  readBit(): number {
    this.fill(1);
    const bit = this.buffer.getBit(this.consumed);
    this.advance(1);
    return bit;
  }

  readBits(nBits: number): number {
    this.fill(nBits);
    const value = this.buffer.getValue(this.consumed, nBits);
    this.advance(nBits);
    return value;
  }

  // 从当前位偏移按 LSB-first 打包出 count 字节（位偏移不必字节对齐）
  readBytes(count: number): Uint8Array {
    this.fill(count * 8);
    const out = new Uint8Array(count);
    for (let i = 0; i < count * 8; i += 1) {
      if (this.buffer.getBit(this.consumed + i)) out[i >> 3] |= 1 << (i & 7);
    }
    this.advance(count * 8);
    return out;
  }
}

// ---- 载体（BMP / WAV） ----

interface SteghideCarrier {
  numSamples: number;
  modulus: number;
  samplesPerVertex: number;
  embeddedValue(pos: number): number;
  describe: string;
}

const asBufferSource = (bytes: Uint8Array): ArrayBuffer => {
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  return buffer;
};

const byteAt = (bytes: Uint8Array, offset: number): number => {
  if (offset < 0 || offset >= bytes.length) throw new Error('文件提前结束：载体数据不足');
  return bytes[offset];
};

const u16At = (bytes: Uint8Array, offset: number): number => byteAt(bytes, offset) | (byteAt(bytes, offset + 1) << 8);

const u32At = (bytes: Uint8Array, offset: number): number =>
  (byteAt(bytes, offset) | (byteAt(bytes, offset + 1) << 8) |
    (byteAt(bytes, offset + 2) << 16) | (byteAt(bytes, offset + 3) << 24)) >>> 0;

// BmpFile.cc 语义：'BM' + WIN(40)/OS2(12) 头、biCompression 必须为 0；样本序 = 文件扫描线序
// （自底向上、行内左→右）；BitmapData 按去 pad 的行存储（calcIndex 用未 pad 行长）；
// 24bpp 样本 = 1 像素（BGR 三字节），EValue = ((R&1^G&1)<<1)|((R&1^B&1))，modulus=4、spv=2。
export const parseBmpCarrier = (bytes: Uint8Array): SteghideCarrier => {
  if (byteAt(bytes, 0) !== 0x42 || byteAt(bytes, 1) !== 0x4d) throw new Error('不是 BMP 文件（缺 BM 魔数）');
  const offBits = u32At(bytes, 10);
  const headerSize = u32At(bytes, 14);
  let width: number;
  let height: number;
  let bitCount: number;
  if (headerSize === 40) {
    width = u32At(bytes, 18);
    height = u32At(bytes, 22);
    bitCount = u16At(bytes, 28);
    const compression = u32At(bytes, 30);
    if (compression !== 0) throw new Error(`暂不支持：压缩 BMP（biCompression=${compression}）`);
  } else if (headerSize === 12) {
    width = u16At(bytes, 18);
    height = u16At(bytes, 20);
    bitCount = u16At(bytes, 24);
  } else {
    throw new Error(`暂不支持：BMP 头大小 ${headerSize}（仅支持 BITMAPINFOHEADER 40 / BITMAPCOREHEADER 12）`);
  }
  if (width === 0 || height === 0 || width * height > 0x40000000) throw new Error('BMP 尺寸非法');
  if (bitCount !== 24) {
    throw new Error(
      `暂不支持：${bitCount}bpp BMP——${STEGHIDE_UNSUPPORTED_CARRIERS[0]}（提取语义为 idx%${bitCount === 8 ? 4 : 2}，待后续批次）`,
    );
  }
  const lineBytes = width * 3;
  const padding = (4 - (lineBytes % 4)) % 4;
  const rowStride = lineBytes + padding;
  const dataEnd = offBits + rowStride * (height - 1) + lineBytes;
  if (dataEnd > bytes.length) throw new Error('BMP 数据区越界：stego 文件过短或已损坏');
  return {
    numSamples: width * height,
    modulus: 4,
    samplesPerVertex: 2,
    embeddedValue(pos: number): number {
      const row = Math.floor(pos / width);
      const column = pos % width;
      const index = offBits + row * rowStride + column * 3;
      const r = byteAt(bytes, index + 2);
      const g = byteAt(bytes, index + 1);
      const b = byteAt(bytes, index);
      return (((r & 1) ^ (g & 1)) << 1) | ((r & 1) ^ (b & 1));
    },
    describe: `${width}×${height} 24bpp BMP（${rowStride}B/行，其中行尾 pad ${padding}B）`,
  };
};

// WavFile.cc 语义：RIFF/WAVE；第一块必须是 fmt 且 FormatTag=1（PCM）；fmt 长 16 或 18（附加 0）；
// 之后逐块跳过直到 data；样本 = data 块顺序的 16bit 小端有符号值；EValue = v&1（即 (v-MinValue)%2，
// MinValue=-32768 为偶数，与 LSB 等价），modulus=2、spv=2。
export const parseWavCarrier = (bytes: Uint8Array): SteghideCarrier => {
  const tag = (offset: number) => String.fromCharCode(byteAt(bytes, offset), byteAt(bytes, offset + 1), byteAt(bytes, offset + 2), byteAt(bytes, offset + 3));
  if (tag(0) !== 'RIFF' || tag(8) !== 'WAVE') throw new Error('不是 WAV 文件（缺 RIFF/WAVE 魔数）');
  let pos = 12;
  if (tag(pos) !== 'fmt ') throw new Error('WAV 第一个块不是 fmt：与 steghide 读取约定不符');
  const fmtLength = u32At(bytes, pos + 4);
  const formatTag = u16At(bytes, pos + 8);
  if (formatTag !== 1) throw new Error(`暂不支持：非 PCM WAV（FormatTag=0x${formatTag.toString(16)}）`);
  const bitsPerSample = u16At(bytes, pos + 8 + 14);
  if (!(fmtLength === 16 || (fmtLength === 18 && u16At(bytes, pos + 8 + 16) === 0))) {
    throw new Error(`WAV fmt 块异常（长度 ${fmtLength}）：不是 steghide 可读的 PCM 头`);
  }
  if (bitsPerSample !== 16) {
    throw new Error(`暂不支持：${bitsPerSample}bit PCM WAV——${STEGHIDE_UNSUPPORTED_CARRIERS[1]}（提取语义为 (v-MinValue)%2）`);
  }
  pos += 8 + fmtLength;
  while (tag(pos) !== 'data') {
    pos += 8 + u32At(bytes, pos + 4);
    if (pos + 8 > bytes.length) throw new Error('WAV 中未找到 data 块：文件提前结束');
  }
  const dataStart = pos + 8;
  const dataLength = u32At(bytes, pos + 4);
  const numSamples = Math.floor(dataLength / 2);
  if (dataStart + numSamples * 2 > bytes.length) throw new Error('WAV data 块越界：stego 文件过短或已损坏');
  return {
    numSamples,
    modulus: 2,
    samplesPerVertex: 2,
    embeddedValue(samplePos: number): number {
      const low = byteAt(bytes, dataStart + samplePos * 2);
      const high = byteAt(bytes, dataStart + samplePos * 2 + 1);
      const signed = ((low | (high << 8)) << 16) >> 16;
      return signed & 1;
    },
    describe: `16bit PCM WAV（data 块 ${numSamples} 个样本）`,
  };
};

// ---- 加密（MHashKeyGen KEYGEN_MCRYPT + WebCrypto AES-256-CBC） ----

// mhash keygen_mcrypt.c：无盐；每轮 MD5(pw ‖ 已生成密钥前缀)，产出 16 字节直至 keySize
export const steghideKeygen = (passphrase: Uint8Array, keySize: number): Uint8Array => {
  const key = new Uint8Array(keySize);
  let produced = 0;
  while (produced < keySize) {
    const material = new Uint8Array(passphrase.length + produced);
    material.set(passphrase, 0);
    material.set(key.subarray(0, produced), passphrase.length);
    const digest = md5Bytes(material);
    const take = Math.min(16, keySize - produced);
    key.set(digest.subarray(0, take), produced);
    produced += take;
  }
  return key;
};

// WebCrypto AES-CBC 解密必按 PKCS#7 剥掉尾块的"padding 长度"字节，而 steghide 的填充是随机位
// （padRandom，非 PKCS#7），直接解密会随机丢 0~16 字节甚至抛 OperationError。
// 手法：在密文尾拼一个受控块 Z = AESenc(V‖V, IV=0) 的前 16 字节（即 AESdec(Z)=V），
// 令 V 的末字节 = 密文末字节 ⊕ 0x01，则最终块解密出 ...01 结尾——WebCrypto 恰好剪 1 字节且剪的是
// 受控块的尾巴，真实明文（含随机填充）完整保留；调用方按 NPlainBits 位截断即可。
const aesCbcDecryptAll = async (keyBytes: Uint8Array, iv: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array> => {
  if (ciphertext.length === 0) return new Uint8Array(0);
  if (ciphertext.length % AES_BLOCK_BYTES !== 0) throw new Error('AES 密文长度不是 16 字节的倍数');
  const key = await crypto.subtle.importKey('raw', asBufferSource(keyBytes), { name: 'AES-CBC' }, false, ['encrypt', 'decrypt']);
  const controlled = new Uint8Array(AES_BLOCK_BYTES * 2);
  controlled[AES_BLOCK_BYTES - 1] = ciphertext[ciphertext.length - 1] ^ 0x01;
  const encryptedBlock = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-CBC', iv: asBufferSource(new Uint8Array(AES_BLOCK_BYTES)) }, key, asBufferSource(controlled)),
  );
  const input = new Uint8Array(ciphertext.length + AES_BLOCK_BYTES);
  input.set(ciphertext, 0);
  input.set(encryptedBlock.subarray(0, AES_BLOCK_BYTES), ciphertext.length);
  const padded = new Uint8Array(
    await crypto.subtle.decrypt({ name: 'AES-CBC', iv: asBufferSource(iv) }, key, asBufferSource(input)),
  );
  return padded.subarray(0, ciphertext.length);
};

// ---- zlib 解压（DecompressionStream('deflate') 即 zlib 封装） ----

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

const inflateZlib = async (input: Uint8Array): Promise<Uint8Array> => {
  const Ctor = globalThis.DecompressionStream;
  if (Ctor === undefined) throw new Error('当前环境不支持 DecompressionStream：zlib 解压不可用');
  try {
    return await streamToBytes(new Blob([asBufferSource(input)]).stream().pipeThrough(new Ctor('deflate')));
  } catch {
    throw new Error('zlib 解压失败：压缩数据损坏（口令可能不正确）');
  }
};

// ---- mhash 语义 CRC32（MHASH_CRC32：非反射 0x04C11DB7，MSB 先行，初值/终值取反） ----

const CRC32_MSB_TABLE = Array.from({ length: 256 }, (_, n) => {
  let value = (n << 24) >>> 0;
  for (let bit = 0; bit < 8; bit += 1) {
    value = value & 0x80000000 ? ((value << 1) ^ 0x04c11db7) >>> 0 : (value << 1) >>> 0;
  }
  return value >>> 0;
});

export const steghideCrc32 = (bytes: Uint8Array): number => {
  let crc = 0xffffffff;
  for (let i = 0; i < bytes.length; i += 1) {
    crc = (((crc << 8) >>> 0) ^ CRC32_MSB_TABLE[(crc >>> 24) ^ bytes[i]]) >>> 0;
  }
  return (crc ^ 0xffffffff) >>> 0;
};

// ---- 提取主流程 ----

export interface SteghideExtractResult {
  fileName: string;
  data: Uint8Array;
  crcOk: boolean;
  notes: string[];
}

const runSteghideExtract = async (carrier: SteghideCarrier, passphrase: string): Promise<SteghideExtractResult> => {
  const notes: string[] = [];
  notes.push(`载体：${carrier.describe}，${carrier.numSamples} 样本，modulus=${carrier.modulus}，每顶点 ${carrier.samplesPerVertex} 样本`);

  const passphraseBytes = new TextEncoder().encode(passphrase);
  const selector = new SteghideSelector(carrier.numSamples, steghideSelectorSeed(passphraseBytes));
  const arityNBits = Math.round(Math.log2(carrier.modulus));
  let sampleIndex = 0;
  const nextDigit = (): number => {
    let value = 0;
    for (let j = 0; j < carrier.samplesPerVertex; j += 1) {
      if (sampleIndex >= carrier.numSamples) throw new Error('载体样本不足以容纳嵌入数据（stego 文件过短或口令错误）');
      value = (value + carrier.embeddedValue(selector.at(sampleIndex))) % carrier.modulus;
      sampleIndex += 1;
    }
    return value;
  };
  const reader = new NaryDigitReader(nextDigit, arityNBits);

  // READ_MAGIC
  const magic = reader.readBits(STEGHIDE_NBITS_MAGIC);
  if (magic !== STEGHIDE_MAGIC) {
    throw new Error('无法用该口令提取数据：嵌入流魔数不匹配（口令错误，或载体不含 steghide 数据）');
  }

  // READ_VERSION：一元码，读到 0 为止；版本号必须 ≤ CodeVersion(=0)
  let version = STEGHIDE_CODE_VERSION;
  for (;;) {
    if (reader.readBit() === 1) {
      version += 1;
      if (version > 32) throw new Error('版本一元码超长：数据损坏');
    } else {
      break;
    }
  }
  if (version > STEGHIDE_CODE_VERSION) {
    throw new Error(`嵌入数据版本 ${version} 超出本实现支持（≤ ${STEGHIDE_CODE_VERSION}）`);
  }

  // READ_ENCINFO
  const encAlgoIndex = reader.readBits(STEGHIDE_ENC_ALGO_IREP_SIZE);
  const encModeIndex = reader.readBits(STEGHIDE_ENC_MODE_IREP_SIZE);
  const encAlgoName = ENC_ALGO_NAMES[encAlgoIndex] ?? `未知(${encAlgoIndex})`;
  const encModeName = ENC_MODE_NAMES[encModeIndex] ?? `未知(${encModeIndex})`;
  if (encAlgoIndex !== 0 && !(encAlgoIndex === 2 && encModeIndex === 1)) {
    throw new Error(`暂不支持：加密组合 ${encAlgoName}/${encModeName}——${STEGHIDE_UNSUPPORTED_CARRIERS[2]}`);
  }

  // READ_NPLAINBITS
  const nPlainBits = reader.readBits(STEGHIDE_NBITS_NPLAINBITS);
  if (nPlainBits === 0 || nPlainBits > 0x40000000) throw new Error('明文位长字段非法：数据损坏或口令错误');

  // READ_ENCRYPTED：密文位长 = IV(128) + ⌈NPlainBits/128⌉·128（none 算法则原样透传）
  let plainBytes: Uint8Array;
  if (encAlgoIndex === 0) {
    const byteCount = Math.ceil(nPlainBits / 8);
    plainBytes = reader.readBytes(byteCount);
    notes.push('加密：none（明文透传）');
  } else {
    const encryptedBits = AES_BLOCK_BITS + Math.ceil(nPlainBits / AES_BLOCK_BITS) * AES_BLOCK_BITS;
    const encrypted = reader.readBytes(encryptedBits / 8);
    const keyBytes = steghideKeygen(passphraseBytes, 32); // rijndael-128 在 libmcrypt 的最大密钥长 = 32B → AES-256
    let decrypted: Uint8Array;
    try {
      decrypted = await aesCbcDecryptAll(keyBytes, encrypted.subarray(0, AES_BLOCK_BYTES), encrypted.subarray(AES_BLOCK_BYTES));
    } catch {
      throw new Error('AES-256-CBC 解密失败：密文损坏或载体被改动');
    }
    plainBytes = decrypted;
    notes.push('加密：rijndael-128（32B 密钥 = AES-256）+ CBC，密文 = IV‖CBC');
  }
  notes.push(`明文位长 NPlainBits = ${nPlainBits}（${Math.ceil(nPlainBits / 8)}B）`);

  // 截断到 NPlainBits 位（丢弃 padRandom 随机填充；末字节高位清零对齐 clearUnused 语义）
  const plain = LsbBits.fromBytes(plainBytes, nPlainBits);
  let position = 0;

  // 压缩标志 + [未压位长 + zlib 流]
  const compressed = plain.getBit(position);
  position += 1;
  let working = plain;
  if (compressed) {
    if (position + STEGHIDE_NBITS_NUNCOMPRESSED > plain.length) throw new Error('明文过短：读不到未压缩位长');
    const nUncompressedBits = plain.getValue(position, STEGHIDE_NBITS_NUNCOMPRESSED);
    position += STEGHIDE_NBITS_NUNCOMPRESSED;
    const zlibBitCount = plain.length - position;
    if (zlibBitCount % 8 !== 0) throw new Error('嵌入数据长度无效：zlib 流未按字节对齐');
    const zlibBytes = new Uint8Array(zlibBitCount / 8);
    for (let i = 0; i < zlibBitCount; i += 1) {
      if (plain.getBit(position + i)) zlibBytes[i >> 3] |= 1 << (i & 7);
    }
    const inflated = await inflateZlib(zlibBytes);
    if (inflated.length * 8 < nUncompressedBits) throw new Error('zlib 解压长度不足：数据损坏');
    working = LsbBits.fromBytes(inflated, nUncompressedBits);
    position = 0;
    notes.push(`压缩：zlib（解压 ${zlibBytes.length}B → ${Math.ceil(nUncompressedBits / 8)}B，未压位长 ${nUncompressedBits}）`);
  } else {
    notes.push('压缩：无');
  }

  // 校验标志 + [CRC32]
  if (position >= working.length) throw new Error('明文过短：读不到校验标志');
  const hasChecksum = working.getBit(position) === 1;
  position += 1;
  let storedCrc: number | null = null;
  if (hasChecksum) {
    if (position + STEGHIDE_NBITS_CRC32 > working.length) throw new Error('明文过短：读不到 CRC32');
    storedCrc = working.getValue(position, STEGHIDE_NBITS_CRC32);
    position += STEGHIDE_NBITS_CRC32;
  }

  // 文件名：NUL 结尾的 8bit 字节序列
  let fileName = '';
  for (;;) {
    if (position + 8 > working.length) throw new Error('文件名无 NUL 结尾：数据损坏或口令错误');
    const charCode = working.getValue(position, 8);
    position += 8;
    if (charCode === 0) break;
    fileName += String.fromCharCode(charCode);
  }

  // 数据：剩余位必须是 8 的倍数
  const dataBitCount = working.length - position;
  if (dataBitCount < 0 || dataBitCount % 8 !== 0) throw new Error('嵌入数据长度无效（数据段不是整字节）');
  const data = new Uint8Array(dataBitCount / 8);
  for (let i = 0; i < dataBitCount; i += 1) {
    if (working.getBit(position + i)) data[i >> 3] |= 1 << (i & 7);
  }

  const crcOk = storedCrc === null ? true : steghideCrc32(data) === storedCrc;
  if (storedCrc === null) {
    notes.push('CRC32：未嵌入（无校验）');
  } else {
    notes.push(`CRC32：${crcOk ? '校验通过' : '校验失败（提取数据可能损坏）'}（0x${storedCrc.toString(16).padStart(8, '0')}）`);
  }
  notes.push(`文件名：${fileName === '' ? '（空）' : fileName}，数据：${data.length}B`);

  return { fileName, data, crcOk, notes };
};

// ---- 对外接口 ----

export const steghideExtractBmp = async (bytes: Uint8Array, passphrase: string): Promise<SteghideExtractResult> =>
  runSteghideExtract(parseBmpCarrier(bytes), passphrase);

export const steghideExtractWav = async (bytes: Uint8Array, passphrase: string): Promise<SteghideExtractResult> =>
  runSteghideExtract(parseWavCarrier(bytes), passphrase);
