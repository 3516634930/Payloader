// RAR3（RAR 3.x / RAR4 容器，签名 Rar!\x1a\x07\x00）口令加密引擎：密钥派生 + 口令快筛 + 数据解密。
// 对标随波逐流"rar密码字典爆破"的底层算法层；与 rarInspect（结构解析）/rarExtract（LZ 解压）
// 配套，但加密语义自包含。纯函数、同步、只读输入、无 DOM/eval/网络/依赖。
//
// 算法依据（逐行对照翻译，以源码为准；调研于 2026-09，源码均为当期 master）：
// - 密钥派生：unrar crypt3.cpp `CryptData::SetKey30` + sha1.cpp `sha1_process_rar29`
//   （镜像 elfmz/far2l plugins/multiarc/src/formats/rar/unrar/，与 debian-calibre/unrar-nonfree 同源）：
//   口令按 UTF-16 逐码元拆双字节（WideToRaw，低位在前、无 NUL 终止）接 8 字节 salt 作种子；
//   单一运行 SHA-1 连续喂入 0x40000=262144 轮（每轮 = 种子全部字节 + 3 字节小端轮号），
//   每 0x4000 轮从"带填充的当前摘要"取第 19 字节拼 16 字节 IV；最终摘要前 16 字节按 4 字节
//   组内字节反转成 AES-128 密钥。
// - "自定义 SHA-1"差异点：sha1_process_rar29 在种子超过 64 字节（口令 ≥29 字符）时，把每个
//   完整块的 16 个消息字经 4 轮 W 扩展后按小端写回种子缓冲（跨轮持续变异）——这正是 rarfile
//   `rar3_s2k_core`（markokr/rarfile src/rarfile/crypto.py，rar3_corrupt_block）的由来，
//   本文件 rar3CorruptBlock 与其逐式等价（顺序原地 k 循环 + 模 16 索引，复现 blk() 宏的
//   顺序依赖）；≤64 字节种子（CTF 口令常态）不触发该分支。
// - p7zip CPP/7zip/Crypto/RarAes.cpp `CDecoder::CalcKey`（p7zip-project/p7zip）三重印证：
//   kNumRounds=1<<18、kAesKeySize=16（AES-128-CBC）、`UpdatePswDataSha1` 同款块变异、
//   IV 取 digest[4*4+3]、密钥 `_key[i*4+j]=digest[i*4+3-j]`。
// - 快速校验口径更正（重要，纠任务书预期）：RAR3 **没有**"salt 后紧跟 2 字节口令校验字节"
//   的头内字段——那是 RAR5 的 PswCheck。RAR3 的等价快筛是解密首个 16 字节数据块做结构校验，
//   口径取 John the Ripper src/rar_common.h `check_rar`：method 0x30 存储条目走"尾块零填充
//   早筛 + 全量解密 CRC32 终验"（definitive）；压缩条目走首块早筛——PPM 块要求 Reset 位
//   置位且 MaxMB<128，LZ 块要求 KeepOldTable 不置位且首张 20 项预表构成完备 canonical 码
//   （`check_huffman`，误报率约千分之一，与 john 的早筛一致；终验由 rarExtract 解压 CRC 兜底）。
// 红线：不碰文件系统；解密输出仅为输入等长（对齐块数）的新副本，绝不改入参。

import { crc32BytesOf } from '../codec/crc32Attack';

// —— 纯 JS SHA-1（增量式；项目 codec/crypto.ts 仅有 md5/md4 与异步 WebCrypto 摘要，
// 无同步 SHA-1——爆破每口令一次派生，WebCrypto 异步且 SubtleCrypto 不可同步，故自写） ——

interface Sha1Context {
  state: Uint32Array; // 5 个 32 位状态字
  count: number; // 已喂入总字节数（缓冲字节数恒为 count & 63）
  buffer: Uint8Array; // 64 字节待变换尾块
}

const rotl32 = (value: number, count: number): number => ((value << count) | (value >>> (32 - count))) >>> 0;

// FIPS-197 之外这里也用：SHA-1 消息扩展 80 字暂存（单线程同步，模块级复用零分配）
const SHA1_W = new Uint32Array(80);

const sha1Transform = (state: Uint32Array, block: Uint8Array, offset: number): void => {
  const w = SHA1_W;
  for (let i = 0; i < 16; i += 1) {
    const j = offset + i * 4;
    w[i] = ((block[j] << 24) | (block[j + 1] << 16) | (block[j + 2] << 8) | block[j + 3]) >>> 0;
  }
  for (let i = 16; i < 80; i += 1) {
    w[i] = rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
  }
  let a = state[0];
  let b = state[1];
  let c = state[2];
  let d = state[3];
  let e = state[4];
  // 80 步按 4 组展开（f/k 组内常量，免逐轮分支）
  for (let i = 0; i < 20; i += 1) {
    const t = (rotl32(a, 5) + ((b & c) | (~b & d)) + e + 0x5a827999 + w[i]) >>> 0;
    e = d; d = c; c = rotl32(b, 30); b = a; a = t;
  }
  for (let i = 20; i < 40; i += 1) {
    const t = (rotl32(a, 5) + (b ^ c ^ d) + e + 0x6ed9eba1 + w[i]) >>> 0;
    e = d; d = c; c = rotl32(b, 30); b = a; a = t;
  }
  for (let i = 40; i < 60; i += 1) {
    const t = (rotl32(a, 5) + ((b & c) | (b & d) | (c & d)) + e + 0x8f1bbcdc + w[i]) >>> 0;
    e = d; d = c; c = rotl32(b, 30); b = a; a = t;
  }
  for (let i = 60; i < 80; i += 1) {
    const t = (rotl32(a, 5) + (b ^ c ^ d) + e + 0xca62c1d6 + w[i]) >>> 0;
    e = d; d = c; c = rotl32(b, 30); b = a; a = t;
  }
  state[0] = (state[0] + a) >>> 0;
  state[1] = (state[1] + b) >>> 0;
  state[2] = (state[2] + c) >>> 0;
  state[3] = (state[3] + d) >>> 0;
  state[4] = (state[4] + e) >>> 0;
};

const sha1Init = (): Sha1Context => ({
  state: Uint32Array.of(0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0),
  count: 0,
  buffer: new Uint8Array(64),
});

// 标准 SHA-1 增量喂入（对应 unrar sha1_process；64 字节组块即变换）
const sha1Process = (context: Sha1Context, data: Uint8Array): void => {
  let i = 0;
  let j = context.count & 63;
  context.count += data.length;
  if (j + data.length > 63) {
    context.buffer.set(data.subarray(0, 64 - j), j);
    sha1Transform(context.state, context.buffer, 0);
    i = 64 - j;
    for (; i + 63 < data.length; i += 64) sha1Transform(context.state, data, i);
    j = 0;
  }
  if (data.length > i) context.buffer.set(data.subarray(i), j);
};

// 非破坏性"当前摘要"：复制状态后按标准填充（0x80 + 零 + 大端 64 位位长）终结——
// 对应 unrar 的 `sha1_context tempc=c; sha1_done(&tempc,digest)` 与 Python hashlib 的
// digest() 后可继续 update 语义。RAR3 派生的 IV 窃取/最终密钥都取这种带填充摘要。
const sha1DigestSnapshot = (context: Sha1Context): Uint8Array => {
  const state = new Uint32Array(context.state);
  const buffer = context.buffer.slice();
  const bitLength = context.count * 8;
  const high = Math.floor(bitLength / 0x100000000);
  const low = bitLength >>> 0;
  let position = context.count & 63;
  buffer[position] = 0x80;
  position += 1;
  if (position !== 56) {
    if (position > 56) {
      // 消息尾落在 56..63：0x80 块先补零变换掉（unrar sha1_done 的 `if (BufPos==0)
      // SHA1Transform(...)` 行——漏掉它则 56-63 边界摘要错误），再起第二块装长度
      buffer.fill(0, position, 64);
      position = 0;
      sha1Transform(state, buffer, 0);
    }
    buffer.fill(0, position, 56);
  }
  buffer[56] = high >>> 24;
  buffer[57] = (high >>> 16) & 0xff;
  buffer[58] = (high >>> 8) & 0xff;
  buffer[59] = high & 0xff;
  buffer[60] = low >>> 24;
  buffer[61] = (low >>> 16) & 0xff;
  buffer[62] = (low >>> 8) & 0xff;
  buffer[63] = low & 0xff;
  sha1Transform(state, buffer, 0);
  const digest = new Uint8Array(20);
  for (let i = 0; i < 5; i += 1) {
    digest[i * 4] = state[i] >>> 24;
    digest[i * 4 + 1] = (state[i] >>> 16) & 0xff;
    digest[i * 4 + 2] = (state[i] >>> 8) & 0xff;
    digest[i * 4 + 3] = state[i] & 0xff;
  }
  return digest;
};

// 一次性 SHA-1（独立可复用的纯 JS 哈希；项目内此前无同步 SHA-1 实现）
export const sha1Bytes = (source: Uint8Array): Uint8Array => {
  const context = sha1Init();
  sha1Process(context, source);
  return sha1DigestSnapshot(context);
};

// —— RAR3 专用拉伸链 ——

// RAR3_KDF_ROUNDS：unrar `const uint HashRounds=0x40000`（262144 轮；p7zip kNumRounds=1<<18 同值）
const RAR3_KDF_ROUNDS = 0x40000;
// 每 0x4000 轮窃取一次 IV 字节（HashRounds/16；16 组 × 0x4000 = 0x40000）
const RAR3_KDF_IV_INTERVAL = 0x4000;
// 口令按 128 字符截断（rarfile `RAR_MAX_PASSWORD * 2` 字节口径；unrar MAXPASSWORD 同量级）
const RAR3_MAX_PASSWORD_CHARS = 128;

// rar3CorruptBlock：种子 >64 字节时对完整 64 字节块的变异——16 个大端字读入，做 4 遍
// SHA-1 W 扩展（顺序原地，w[k]=rotl(w[(k+13)%16]^w[(k+8)%16]^w[(k+2)%16]^w[k],1)，复现
// unrar blk() 宏/unrar sha1_process_rar29 的 RawPut4 回写顺序依赖），再按小端写回（组内字节
// 反转）。与 rarfile rar3_corrupt_block / p7zip UpdatePswDataSha1 逐式等价。
const rar3CorruptBlock = (seed: Uint8Array, position: number): void => {
  const words = new Uint32Array(16);
  for (let i = 0; i < 16; i += 1) {
    const j = position + i * 4;
    words[i] = ((seed[j] << 24) | (seed[j + 1] << 16) | (seed[j + 2] << 8) | (seed[j + 3])) >>> 0;
  }
  for (let pass = 0; pass < 4; pass += 1) {
    for (let k = 0; k < 16; k += 1) {
      words[k] = rotl32(words[(k + 13) % 16] ^ words[(k + 8) % 16] ^ words[(k + 2) % 16] ^ words[k], 1);
    }
  }
  for (let i = 0; i < 16; i += 1) {
    const j = position + i * 4;
    seed[j] = words[i] & 0xff;
    seed[j + 1] = (words[i] >>> 8) & 0xff;
    seed[j + 2] = (words[i] >>> 16) & 0xff;
    seed[j + 3] = words[i] >>> 24;
  }
};

export interface Rar3DerivedKeys {
  aesKey: Uint8Array; // 16 字节 AES-128 密钥
  iv: Uint8Array; // 16 字节 CBC IV
}

// RAR3 口令 → AES-128 密钥 + IV（同步纯 JS）：
// 种子 = 口令 UTF-16LE 双字节流（无 NUL 终止）‖salt（0 或 8 字节）；
// 单一运行 SHA-1 连续 0x40000 轮（每轮喂 种子+3 字节小端轮号；>64 字节种子逐块变异）；
// IV[i] = 第 i*0x4000 轮后带填充摘要的第 19 字节；AES 密钥 = 末轮摘要前 16 字节按
// 4 字节组内反转。salt 长度非 0/8 视为误用返回 null。
export const deriveRar3Keys = (password: string, salt: Uint8Array): Rar3DerivedKeys | null => {
  if (salt.length !== 0 && salt.length !== 8) return null;
  const passwordLength = password.length > RAR3_MAX_PASSWORD_CHARS ? RAR3_MAX_PASSWORD_CHARS : password.length;
  const seedLength = passwordLength * 2 + salt.length;
  const seed = new Uint8Array(seedLength + 3); // 尾 3 字节 = 每轮重写的小端轮号
  for (let i = 0; i < passwordLength; i += 1) {
    const code = password.charCodeAt(i);
    seed[i * 2] = code & 0xff;
    seed[i * 2 + 1] = (code >>> 8) & 0xff;
  }
  seed.set(salt, passwordLength * 2);

  const context = sha1Init();
  const iv = new Uint8Array(16);
  for (let round = 0; round < RAR3_KDF_ROUNDS; round += 1) {
    seed[seedLength] = round & 0xff;
    seed[seedLength + 1] = (round >>> 8) & 0xff;
    seed[seedLength + 2] = (round >>> 16) & 0xff;
    const bufferPosition = context.count & 63; // 喂入前的缓冲占位（块变异起点依赖它）
    sha1Process(context, seed);
    if (seedLength > 64 && bufferPosition + seedLength > 63) {
      // 与 unrar sha1_process_rar29 一致：首个越界块由内部缓冲补齐不回写；
      // data 内起于 64-bufferPosition 的完整块逐块变异（跨轮缓冲持续变异）
      let dpos = 64 - bufferPosition;
      while (dpos + 64 <= seedLength) {
        rar3CorruptBlock(seed, dpos);
        dpos += 64;
      }
    }
    if ((round % RAR3_KDF_IV_INTERVAL) === 0) {
      iv[round / RAR3_KDF_IV_INTERVAL] = sha1DigestSnapshot(context)[19];
    }
  }
  const digest = sha1DigestSnapshot(context);
  const aesKey = new Uint8Array(16);
  for (let word = 0; word < 4; word += 1) {
    for (let byte = 0; byte < 4; byte += 1) {
      aesKey[word * 4 + byte] = digest[word * 4 + 3 - byte];
    }
  }
  return { aesKey, iv };
};

// —— 纯 JS AES-128 解密（项目内仅有 WebCrypto/crypto-js 动态加载两条异步路，爆破热路径
// 每口令要同步解 1-2 块，故自写；表驱动，S 盒由 GF(2^8) 现场计算避免 256 值手抄笔误） ——

const gmul = (a: number, b: number): number => {
  let product = 0;
  let x = a;
  let y = b;
  for (let i = 0; i < 8; i += 1) {
    if (y & 1) product ^= x;
    const high = x & 0x80;
    x = (x << 1) & 0xff;
    if (high !== 0) x ^= 0x1b;
    y >>>= 1;
  }
  return product & 0xff;
};

// S 盒 = GF(2^8) 乘法逆 + 仿射变换（FIPS-197 §5.1.1）；逆 S 盒按 sbox 反查构造
const AES_SBOX = (() => {
  const inverse = new Uint8Array(256);
  for (let a = 1; a < 256; a += 1) {
    for (let b = 1; b < 256; b += 1) {
      if (gmul(a, b) === 1) {
        inverse[a] = b;
        break;
      }
    }
  }
  const sbox = new Uint8Array(256);
  for (let a = 0; a < 256; a += 1) {
    // 仿射变换的循环移位是 8 位域内（rotl8），不是 32 位
    const x = inverse[a];
    const rotl8 = (value: number, count: number): number => ((value << count) | (value >>> (8 - count))) & 0xff;
    sbox[a] = (x ^ rotl8(x, 1) ^ rotl8(x, 2) ^ rotl8(x, 3) ^ rotl8(x, 4) ^ 0x63) & 0xff;
  }
  return sbox;
})();

const AES_INV_SBOX = (() => {
  const inv = new Uint8Array(256);
  for (let a = 0; a < 256; a += 1) inv[AES_SBOX[a]] = a;
  return inv;
})();

// AES-128 轮密钥扩展（FIPS-197 §5.2）：11 组 × 16 字节 = 176 字节
const aes128ExpandKey = (key: Uint8Array): Uint8Array => {
  if (key.length !== 16) throw new Error(`AES-128 密钥必须 16 字节，当前 ${key.length}`);
  const roundKeys = new Uint8Array(176);
  roundKeys.set(key);
  let rcon = 1;
  for (let i = 16; i < 176; i += 4) {
    let t0 = roundKeys[i - 4];
    let t1 = roundKeys[i - 3];
    let t2 = roundKeys[i - 2];
    let t3 = roundKeys[i - 1];
    if (i % 16 === 0) {
      // RotWord + SubWord + Rcon
      const first = t0;
      t0 = AES_SBOX[t1] ^ rcon;
      t1 = AES_SBOX[t2];
      t2 = AES_SBOX[t3];
      t3 = AES_SBOX[first];
      rcon = ((rcon << 1) ^ (rcon >= 0x80 ? 0x1b : 0)) & 0xff;
    }
    roundKeys[i] = roundKeys[i - 16] ^ t0;
    roundKeys[i + 1] = roundKeys[i - 15] ^ t1;
    roundKeys[i + 2] = roundKeys[i - 14] ^ t2;
    roundKeys[i + 3] = roundKeys[i - 13] ^ t3;
  }
  return roundKeys;
};

// InvShiftRows：行 r 循环右移 r（列主序：state[4c+r] ← state[4*((c+4-r)%4)+r]）
const invShiftRows = (state: Uint8Array): void => {
  const source = state.slice();
  for (let column = 0; column < 4; column += 1) {
    for (let row = 0; row < 4; row += 1) {
      state[column * 4 + row] = source[((column + 4 - row) % 4) * 4 + row];
    }
  }
};

const invMixColumn = (state: Uint8Array, column: number): void => {
  const base = column * 4;
  const s0 = state[base];
  const s1 = state[base + 1];
  const s2 = state[base + 2];
  const s3 = state[base + 3];
  state[base] = gmul(s0, 14) ^ gmul(s1, 11) ^ gmul(s2, 13) ^ gmul(s3, 9);
  state[base + 1] = gmul(s0, 9) ^ gmul(s1, 14) ^ gmul(s2, 11) ^ gmul(s3, 13);
  state[base + 2] = gmul(s0, 13) ^ gmul(s1, 9) ^ gmul(s2, 14) ^ gmul(s3, 11);
  state[base + 3] = gmul(s0, 11) ^ gmul(s1, 13) ^ gmul(s2, 9) ^ gmul(s3, 14);
};

// AES-128 单块解密（FIPS-197 §5.3 InvCipher，直观版：逐步 InvShiftRows/InvSubBytes/
// AddRoundKey/InvMixColumns，轮密钥倒序）
export const aes128DecryptBlock = (roundKeys: Uint8Array, cipher: Uint8Array, cipherOffset: number, out: Uint8Array, outOffset: number): void => {
  const state = cipher.slice(cipherOffset, cipherOffset + 16);
  const addRoundKey = (round: number): void => {
    for (let i = 0; i < 16; i += 1) state[i] ^= roundKeys[round * 16 + i];
  };
  addRoundKey(10);
  for (let round = 9; round >= 1; round -= 1) {
    invShiftRows(state);
    for (let i = 0; i < 16; i += 1) state[i] = AES_INV_SBOX[state[i]];
    addRoundKey(round);
    for (let column = 0; column < 4; column += 1) invMixColumn(state, column);
  }
  invShiftRows(state);
  for (let i = 0; i < 16; i += 1) state[i] = AES_INV_SBOX[state[i]];
  addRoundKey(0);
  out.set(state, outOffset);
};

// AES-128-CBC 解密：输入须 ≥16 字节，仅解完整块（尾随不足一块的字节按 unrar 口径
// 本就不参与解密——它只按 16 对齐长度读）。输出为新副本，长度 = 对齐块数 × 16。
export const aes128CbcDecrypt = (key: Uint8Array, iv: Uint8Array, data: Uint8Array): Uint8Array => {
  if (iv.length !== 16) throw new Error(`AES-CBC IV 必须 16 字节，当前 ${iv.length}`);
  const blocks = Math.floor(data.length / 16);
  const out = new Uint8Array(blocks * 16);
  if (blocks === 0) return out;
  const roundKeys = aes128ExpandKey(key);
  let previous = iv.slice();
  const decrypted = new Uint8Array(16);
  for (let block = 0; block < blocks; block += 1) {
    aes128DecryptBlock(roundKeys, data, block * 16, decrypted, 0);
    for (let i = 0; i < 16; i += 1) out[block * 16 + i] = decrypted[i] ^ previous[i];
    previous = data.slice(block * 16, block * 16 + 16);
  }
  return out;
};

// —— 口令快筛与流解密 ——

// 快筛/解密所需的条目加密要素（rarBrute 的 RarEncryptedEntry 结构性满足本接口；
// salt 在文件头名区之后，数据区自 dataOffset 起 packedSize 字节——布局对齐 rarInspect 注释）
export interface Rar3QuickCheck {
  salt: Uint8Array;
  dataOffset: number;
  packedSize: number;
  unpSize: number;
  method: number; // 0x30 存储 / 0x31-0x35 压缩
  fileCrc: number; // 解压后内容的 CRC32（文件头 +16）
}

// 首块 20 项预表 canonical 校验（john check_huffman 同款早筛）：MSB-first 位流，
// 前 2 位是 PPM/KeepOldTable 标志，随后 20 个 4 位码长（0xF 转义：0=字面 15，n>0=n+2 个零），
// 要求码长集非空且恰好完备（Kraft 等式成立）。位流不足处按 0 补齐（确定性，优于 john
// 的未初始化余量读法）。
const checkFirstHuffmanTable = (plain: Uint8Array): boolean => {
  let bitPosition = 2; // 跳过 PPM 位与 KeepOldTable 位
  const readBits = (count: number): number => {
    let value = 0;
    for (let i = 0; i < count; i += 1) {
      const byteIndex = bitPosition >> 3;
      const bit = byteIndex < plain.length ? (plain[byteIndex] >> (7 - (bitPosition & 7))) & 1 : 0;
      value = (value << 1) | bit;
      bitPosition += 1;
    }
    return value;
  };
  const lengths = new Uint8Array(20);
  let index = 0;
  while (index < 20) {
    const length = readBits(4);
    if (length === 15) {
      const zeroCount = readBits(4);
      if (zeroCount === 0) {
        lengths[index] = 15;
        index += 1;
      } else {
        for (let k = 0; k < zeroCount + 2 && index < 20; k += 1) index += 1; // 零串位（lengths 初值即 0）
      }
    } else {
      lengths[index] = length;
      index += 1;
    }
  }
  const counts = new Uint32Array(16);
  for (let i = 0; i < 20; i += 1) counts[lengths[i] & 0xf] += 1;
  counts[0] = 0;
  if (counts[1] === 0 && counts[2] === 0 && counts[3] === 0 && counts[4] === 0) {
    let any = false;
    for (let len = 5; len < 16; len += 1) if (counts[len] !== 0) any = true;
    if (!any) return false; // 全零码长：无任何码字
  }
  let left = 1;
  for (let len = 1; len < 16; len += 1) {
    left = left * 2 - counts[len];
    if (left < 0) return false; // 过订阅
  }
  return left === 0; // 必须恰好完备
};

// RAR3 口令快筛（不解压即可高置信判定）：存储条目走尾块零填充早筛 + 全量 CRC32 终验
// （零误报）；压缩条目解首 ≤2 块做 john 式结构早筛——LZ 块要求 KeepOldTable 不置位且首张
// 20 项预表构成完备 canonical 码（`check_huffman`，误报率约千分之一，rarBrute 会再用
// rarExtract 解压 CRC 二段终验否决残余误报）。PPMd 形态的流（plain[0] 最高位为 1）一律
// 拒绝：rarExtract 不解压 PPM，无法终验，接受它只会放行垃圾流的误报（真 -m5 PPM 加密
// 档案因此不在爆破支持范围，与全站 PPM 边界一致）。
export const checkRar3Password = (bytes: Uint8Array, entry: Rar3QuickCheck, password: string): boolean => {
  if (entry.method < 0x30 || entry.method > 0x35) {
    throw new Error(`METHOD=0x${entry.method.toString(16)} 越界（合法 0x30 存储-0x35 最佳），无法校验口令`);
  }
  const keys = deriveRar3Keys(password, entry.salt);
  if (keys === null) {
    throw new Error('salt 长度非法（必须 0 或 8 字节）：条目探测结果损坏');
  }
  const dataEnd = entry.dataOffset + entry.packedSize;
  if (entry.dataOffset < 0 || dataEnd > bytes.length || dataEnd < 16) {
    throw new Error(`加密数据区越界：起于 ${entry.dataOffset} 长 ${entry.packedSize} 字节，输入仅 ${bytes.length} 字节（文件截断）`);
  }
  const data = bytes.subarray(entry.dataOffset, dataEnd);
  if (entry.method === 0x30) {
    // 存储条目：明文 = unpSize 字节 + 零填充到 16 对齐（WinRAR 加密侧口径，john check_rar
    // 的 padding 早筛即依赖它）。先解尾块查零填充（错口令即止步），再全量 CRC32 终验。
    if (entry.unpSize % 16 !== 0) {
      const padStart = entry.unpSize % 16;
      let lastCipher: Uint8Array;
      let lastIv: Uint8Array;
      if (entry.packedSize < 32) {
        lastCipher = data.subarray(0, 16);
        lastIv = keys.iv;
      } else {
        lastCipher = data.subarray(data.length - 16);
        lastIv = data.subarray(data.length - 32, data.length - 16);
      }
      const tail = aes128CbcDecrypt(keys.aesKey, lastIv, lastCipher);
      for (let i = padStart; i < 16; i += 1) {
        if (tail[i] !== 0) return false;
      }
    }
    const plain = aes128CbcDecrypt(keys.aesKey, keys.iv, data);
    if (plain.length < entry.unpSize) return false;
    return crc32BytesOf(plain.subarray(0, entry.unpSize)) === (entry.fileCrc >>> 0);
  }
  // 压缩条目：解首 ≤2 块（checkFirstHuffmanTable 最坏需 2+4*(20+20)=162 位）做结构早筛
  const blocks = Math.min(2, Math.floor(data.length / 16));
  const plain = aes128CbcDecrypt(keys.aesKey, keys.iv, data.subarray(0, blocks * 16));
  if (plain.length === 0) return false;
  if ((plain[0] & 0x80) !== 0) {
    // PPMd 形态流：rarExtract 不解压 PPM，无法 CRC 终验——按不支持处理直接拒绝
    // （john 对 PPM 做 Reset/MaxMB 位校验后放行，是因为它带完整 PPM 解压器；本引擎没有）
    return false;
  }
  if ((plain[0] & 0x40) !== 0) return false; // LZ 块首表前 KeepOldTable 不可置位
  return checkFirstHuffmanTable(plain);
};

// RAR3 加密数据流整段解密：返回明文字节（长度 = 对齐块数 × 16，尾块零填充按 WinRAR
// 加密口径原样保留，由调用方按 unpSize/解压流程裁剪）。data 不足一块或派生失败返回 null。
export const decryptRar3Stream = (data: Uint8Array, password: string, salt: Uint8Array): Uint8Array | null => {
  if (data.length < 16) return null;
  const keys = deriveRar3Keys(password, salt);
  if (keys === null) return null;
  return aes128CbcDecrypt(keys.aesKey, keys.iv, data);
};
