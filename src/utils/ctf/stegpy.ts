// stegpy（github.com/izcoser/stegpy，MIT）PNG/BMP 载体顺序 LSB 隐写提取与闭环编码（批次 SI·B 线）。
// 语义按 stegpy 源码（steg.py / crypt.py）核实复刻：纯浏览器 JS、零 eval、零新依赖。
// - 纯顺序 LSB、无 PRNG；每宿主字节承载 bits∈{1,2,4}（默认 2）。位深标记藏宿主第 0 字节 bit4-5：
//   编码 host[0]=(host[0]&207)|operand（operand 0/16/32 对应 bits 1/2/4），解码 bits=2**((host[0]&48)>>4)
// - "低位组在前"：divisor=8/bits 个宿主字节承载 1 个消息字节，消息第 j 字节的第 i 组位于宿主
//   j*divisor+i、贡献 (host&mask)<<bits*i（等价 stegpy 的 host[i::divisor] 切片语义）
// - 消息头："stegv3"(6B) + 消息长度(4B 大端) + 文件名长(1B) + 文件名(UTF-8) + 数据；解码校验魔数
// - 口令模式（-p）：LSB 里存的是 Fernet 令牌的 base64url 文本，内层是再包一层的 stegv3 头+数据。
//   key=PBKDF2-HMAC-SHA256(口令,16B 盐,100000 迭代,32B)：前 16B 作 HMAC-SHA256 签名钥、后 16B 作
//   AES-128-CBC 加密钥；令牌 = 0x80||时间戳8B||IV16B||密文(PKCS7)||HMAC32B。盐定位两种 fallback：
//   A. content[:16] 为盐 + 余下为令牌（stegpy crypt.py 的 salt=content[:16] 语义，编码方向同此）；
//   B. 整段为标准 Fernet 令牌、盐取令牌内 IV 前 16 字节。PBKDF2/AES/HMAC 全走 WebCrypto，异步接口
// - 载体语义：PNG/BMP 载体的宿主字节流是"解码后的像素字节"（Pillow→numpy 逐字节，含 alpha 通道），
//   调用方传解码后的 RGBA/RGB 字节；WAV 载体是原始文件字节、跳过前 10000（stegpyDecodeFromBytes）
// - JPEG DCT 版（stegpy 对 JPEG 走 DCT 系数）不在本文件，A 线系数层另做

const STEGPY_MAGIC = 'stegv3';
const STEGPY_FIXED_HEADER = 11; // 6 魔数 + 4 消息长度(大端) + 1 文件名长
const WAV_SKIP_BYTES = 10000;
const FERNET_ITERATIONS = 100000;

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

const tryUtf8DecodeStrict = (bytes: Uint8Array): string | undefined => {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return undefined;
  }
};

const timingSafeEqual = (left: Uint8Array, right: Uint8Array): boolean => {
  if (left.length !== right.length) return false;
  let diff = 0;
  for (let i = 0; i < left.length; i += 1) diff |= left[i] ^ right[i];
  return diff === 0;
};

const B64URL_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

// base64url 编码（带 = 填充，Fernet urlsafe_b64encode 形态）
const base64UrlEncode = (bytes: Uint8Array): string => {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i];
    const b1 = i + 1 < bytes.length ? bytes[i + 1] : 0;
    const b2 = i + 2 < bytes.length ? bytes[i + 2] : 0;
    const has1 = i + 1 < bytes.length;
    const has2 = i + 2 < bytes.length;
    out += B64URL_ALPHABET[b0 >> 2];
    out += B64URL_ALPHABET[((b0 & 3) << 4) | (b1 >> 4)];
    out += has1 ? B64URL_ALPHABET[((b1 & 15) << 2) | (b2 >> 6)] : '=';
    out += has2 ? B64URL_ALPHABET[b2 & 63] : '=';
  }
  return out;
};

// 宽容 base64/base64url 解码：容忍 +/- 与 /_ 混用、空白与缺失的填充
const base64UrlDecode = (text: string): Uint8Array => {
  const merged = text.replace(/\s/g, '').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  if (merged.length % 4 === 1) throw new Error('base64 载荷长度非法（%4==1）');
  const values = new Uint8Array(merged.length);
  for (let i = 0; i < merged.length; i += 1) {
    const value = B64URL_ALPHABET.indexOf(merged[i]);
    if (value < 0) throw new Error(`base64 载荷含非法字符 "${merged[i]}"`);
    values[i] = value;
  }
  const out = new Uint8Array(Math.floor((merged.length * 3) / 4));
  let pos = 0;
  let acc = 0;
  let bits = 0;
  for (let i = 0; i < values.length; i += 1) {
    acc = (acc << 6) | values[i];
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[pos] = (acc >> bits) & 0xff;
      pos += 1;
    }
  }
  return out;
};

// ---- WebCrypto 原语（AES-CBC / PBKDF2-HMAC-SHA256 / HMAC-SHA256）----

const subtleCrypto = (): SubtleCrypto => {
  // 优先裸 crypto 全局：node:vm 沙箱的 globalThis 是白名单对象，裸 crypto 才命中注入的宿主 WebCrypto
  const api = typeof crypto !== 'undefined' ? crypto : undefined;
  if (api === undefined || api.subtle === undefined) {
    throw new Error('当前环境无 WebCrypto（crypto.subtle）：stegpy 口令模式加解密不可用');
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

const hmacSha256 = async (keyBytes: Uint8Array, data: Uint8Array): Promise<Uint8Array> => {
  const subtle = subtleCrypto();
  const key = await subtle.importKey('raw', asBufferSource(keyBytes), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await subtle.sign('HMAC', key, asBufferSource(data)));
};

// ---- stegv3 帧结构 ----

const readStegpyHeaderFields = (bytes: Uint8Array): { dataLength: number; nameLength: number } => {
  if (bytes.length < STEGPY_FIXED_HEADER) {
    throw new Error(`提取流仅 ${bytes.length} 字节，不足 stegv3 最小头部 ${STEGPY_FIXED_HEADER} 字节：不是 stegpy 载体`);
  }
  const magic = utf8DecodeLoose(bytes.slice(0, 6));
  if (magic !== STEGPY_MAGIC) {
    throw new Error(`魔数 "${magic}" ≠ "stegv3"：不是 stegpy 载体（检查宿主是否为解码后的像素字节流、位深标记是否正确）`);
  }
  return {
    dataLength: ((bytes[6] << 24) | (bytes[7] << 16) | (bytes[8] << 8) | bytes[9]) >>> 0,
    nameLength: bytes[10],
  };
};

const parseStegpyFrame = (bytes: Uint8Array): { fileName: string; data: Uint8Array } => {
  const fields = readStegpyHeaderFields(bytes);
  const total = STEGPY_FIXED_HEADER + fields.nameLength + fields.dataLength;
  if (bytes.length < total) {
    throw new Error(`stegv3 头声明 ${fields.dataLength}B 数据 + ${fields.nameLength}B 文件名，超出提取流 ${bytes.length}B：载体不完整或位深取错`);
  }
  return {
    fileName: utf8DecodeLoose(bytes.slice(STEGPY_FIXED_HEADER, STEGPY_FIXED_HEADER + fields.nameLength)),
    data: bytes.slice(STEGPY_FIXED_HEADER + fields.nameLength, total),
  };
};

const buildStegpyFrame = (fileName: string, data: Uint8Array): Uint8Array => {
  const nameBytes = utf8Encode(fileName);
  if (nameBytes.length > 255) throw new Error(`文件名 ${nameBytes.length}B 超过 1 字节长度字段上限 255B`);
  const out = new Uint8Array(STEGPY_FIXED_HEADER + nameBytes.length + data.length);
  out.set(utf8Encode(STEGPY_MAGIC), 0);
  out[6] = (data.length >>> 24) & 0xff;
  out[7] = (data.length >>> 16) & 0xff;
  out[8] = (data.length >>> 8) & 0xff;
  out[9] = data.length & 0xff;
  out[10] = nameBytes.length;
  out.set(nameBytes, STEGPY_FIXED_HEADER);
  out.set(data, STEGPY_FIXED_HEADER + nameBytes.length);
  return out;
};

// ---- 顺序 LSB 位流（低位组在前）----

const lsbDepthOf = (host: ArrayLike<number>): number => {
  const marker = (host[0] & 48) >> 4;
  if (marker === 3) {
    throw new Error('宿主第 0 字节 bit4-5 标记为 bits=8：不是合法 stegpy 位深标记（合法 1/2/4）');
  }
  return 2 ** marker;
};

const operandOfBits = (bits: 1 | 2 | 4): number => {
  if (bits === 1) return 0;
  if (bits === 2) return 16;
  return 32;
};

const extractLsbStream = (host: ArrayLike<number>, bits: number, byteCount: number): Uint8Array => {
  const divisor = 8 / bits;
  const mask = (1 << bits) - 1;
  const available = Math.floor(host.length / divisor);
  if (byteCount > available) {
    throw new Error(`LSB 载荷需要 ${byteCount} 字节（divisor=${divisor}），宿主仅可容纳 ${available} 字节：容量不足或载体字节流/位深不对`);
  }
  const out = new Uint8Array(byteCount);
  for (let j = 0; j < byteCount; j += 1) {
    let value = 0;
    for (let i = 0; i < divisor; i += 1) {
      value |= (host[j * divisor + i] & mask) << (bits * i);
    }
    out[j] = value & 0xff;
  }
  return out;
};

const embedLsbStream = (host: Uint8Array, message: Uint8Array, bits: number): void => {
  const divisor = 8 / bits;
  const mask = (1 << bits) - 1;
  for (let j = 0; j < message.length; j += 1) {
    for (let i = 0; i < divisor; i += 1) {
      const index = j * divisor + i;
      host[index] = (host[index] & (mask ^ 0xff)) | ((message[j] >> (bits * i)) & mask);
    }
  }
};

// ---- Fernet（stegpy 口令模式）----

// 按 Fernet 规格解开单个令牌：key 前 16B 签名、后 16B 加密；HMAC 失败即抛错
const fernetOpenToken = async (token: Uint8Array, key: Uint8Array): Promise<Uint8Array> => {
  if (token[0] !== 0x80) throw new Error('令牌版本字节非 0x80：不是 Fernet 令牌');
  if (token.length < 1 + 8 + 16 + 16 + 32) throw new Error(`令牌长度 ${token.length} 小于最小合法结构 73 字节`);
  if ((token.length - 57) % 16 !== 0) throw new Error('令牌密文段长度非 16 字节块对齐：不是合法 Fernet 令牌');
  const message = token.slice(0, token.length - 32);
  const given = token.slice(token.length - 32);
  const computed = await hmacSha256(key.slice(16, 32), message);
  if (!timingSafeEqual(given, computed)) throw new Error('HMAC-SHA256 校验失败（口令错误或令牌损坏）');
  return aesCbcDecrypt(key.slice(0, 16), token.slice(9, 25), token.slice(25, token.length - 32));
};

// 编码方向按"盐=前 16 字节 + 标准 Fernet 令牌"组装（对应下方 fallback A）
const fernetEncrypt = async (plain: Uint8Array, password: string): Promise<Uint8Array> => {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const key = await pbkdf2Sha256(password, salt, FERNET_ITERATIONS, 32);
  const cipher = await aesCbcEncrypt(key.slice(0, 16), iv, plain);
  const head = new Uint8Array(9);
  head[0] = 0x80;
  const stamp = BigInt(Date.now());
  for (let i = 0; i < 8; i += 1) head[1 + i] = Number((stamp >> BigInt(8 * (7 - i))) & 0xffn);
  const message = concatBytes(head, iv, cipher);
  const mac = await hmacSha256(key.slice(16, 32), message);
  return concatBytes(salt, message, mac);
};

// 解码方向：两种盐定位 fallback（A：content[:16]；B：盐=令牌内 IV），HMAC 校验定胜负
const fernetDecrypt = async (content: Uint8Array, password: string): Promise<Uint8Array> => {
  const attempts: Array<{ name: string; salt: Uint8Array; token: Uint8Array }> = [
    { name: '盐=载荷前 16 字节（stegpy crypt.py 的 salt=content[:16] 语义）', salt: content.slice(0, 16), token: content.slice(16) },
    { name: '盐=令牌内 IV（标准 Fernet 外部盐形态）', salt: content.slice(9, 25), token: content.slice() },
  ];
  const failures: string[] = [];
  for (const attempt of attempts) {
    try {
      const key = await pbkdf2Sha256(password, attempt.salt, FERNET_ITERATIONS, 32);
      return await fernetOpenToken(attempt.token, key);
    } catch (error) {
      failures.push(`${attempt.name}：${error instanceof Error ? error.message : String(error)}`);
    }
  }
  throw new Error(`Fernet 口令解密失败（两种盐定位均未通过：${failures.join('；')}）——口令错误或载荷非 stegpy 加密形态`);
};

// ---- 公开接口 ----

export interface StegpyResult {
  magic: string;
  fileName: string;
  data: Uint8Array;
  text?: string;
}

export interface StegpyEncodeMessage {
  data: Uint8Array | string;
  fileName?: string;
  bits?: 1 | 2 | 4;
  password?: string;
}

const stegpyDecodeHost = async (host: ArrayLike<number>, password: string | undefined, hostLabel: string): Promise<StegpyResult> => {
  if (host.length < 1) throw new Error(`${hostLabel}为空：无法读取位深标记`);
  const bits = lsbDepthOf(host);
  const summary = readStegpyHeaderFields(extractLsbStream(host, bits, STEGPY_FIXED_HEADER));
  const outer = parseStegpyFrame(extractLsbStream(host, bits, STEGPY_FIXED_HEADER + summary.nameLength + summary.dataLength));
  if (password === undefined) {
    return { magic: STEGPY_MAGIC, fileName: outer.fileName, data: outer.data, text: tryUtf8DecodeStrict(outer.data) };
  }
  const tokenText = tryUtf8DecodeStrict(outer.data);
  if (tokenText === undefined) {
    throw new Error('口令模式下载荷应为 Fernet 令牌的 base64url 文本，但外层数据含非 UTF-8 字节：不是加密的 stegpy 载荷');
  }
  const inner = parseStegpyFrame(await fernetDecrypt(base64UrlDecode(tokenText), password));
  return { magic: STEGPY_MAGIC, fileName: inner.fileName, data: inner.data, text: tryUtf8DecodeStrict(inner.data) };
};

// PNG/BMP 载体：pixels 传"解码后的像素字节流"（RGBA/RGB 逐字节，含 alpha；stegpy 的 Pillow→numpy 语义）
export const stegpyDecodeFromPixels = (pixels: Uint8Array | ArrayLike<number>, password?: string): Promise<StegpyResult> =>
  stegpyDecodeHost(pixels, password, '像素字节流');

// WAV 载体：raw 传原始文件字节，内部跳过前 10000 字节（stegpy WAV 模式固定偏移）
export const stegpyDecodeFromBytes = async (raw: Uint8Array, password?: string): Promise<StegpyResult> => {
  if (raw.length <= WAV_SKIP_BYTES) {
    throw new Error(`WAV 原始字节长度 ${raw.length} 未超过跳过阈值 ${WAV_SKIP_BYTES}：stegpy WAV 载体要求跳过前 10000 字节后仍有数据`);
  }
  return stegpyDecodeHost(raw.subarray(WAV_SKIP_BYTES), password, 'WAV 原始字节（跳过前 10000）');
};

// 编码方向（自造闭环向量用）：返回嵌入后的宿主字节副本。口令模式下外层为空文件名 +
// base64url(Fernet(内层 stegv3 帧))，解码侧剥两层还原
export const stegpyEncode = async (host: Uint8Array, message: StegpyEncodeMessage): Promise<Uint8Array> => {
  const bits = message.bits ?? 2;
  const fileName = message.fileName ?? '';
  const payload = typeof message.data === 'string' ? utf8Encode(message.data) : message.data;
  const frame = message.password !== undefined
    ? buildStegpyFrame('', utf8Encode(base64UrlEncode(await fernetEncrypt(buildStegpyFrame(fileName, payload), message.password))))
    : buildStegpyFrame(fileName, payload);
  const divisor = 8 / bits;
  if (frame.length * divisor > host.length) {
    throw new Error(`载荷帧 ${frame.length}B（divisor=${divisor}）需要 ${frame.length * divisor} 个宿主字节，超出宿主容量 ${host.length}：请降低位深或换更大载体`);
  }
  const out = new Uint8Array(host.length);
  out.set(host);
  out[0] = (out[0] & 207) | operandOfBits(bits);
  embedLsbStream(out, frame, bits);
  return out;
};
