// RouterPassView 兼容的路由器备份文件解析（批次 RP）：魔数表分流 → 按类型解密/解压 →
// 抽取密码类字段。三条已验证主路径：
// ① TP-Link conf.bin（TD-W8970/9970/Archer 系）：16B MD5 头 + DES-ECB（密钥表）+
//    TP-Link 自研 LZSS（语义对齐 sta-c0000/tpconf_bin_xml L140-189：16 字节块位图、
//    大端 u32 长度默认 + 自动端序切换、get_dict_ld 偏移编码）→ XML
// ② TP-Link WR841N/WA855RE config.bin：144B 头 + DES-ECB key 478DA50BF9E3D2CF + zlib → JSON
// ③ rom-0（ZyNOS TD-W8901G/W8951ND）：LZS 解压（16-bit LE 控制掩码 LSB-first）→ 明文含密码
// 通用兜底：RouterPassView type 100-106 家族（gzip/deflate/zlib/XOR-0xFF/+0x80/XML/Base64）。
// 全部本地计算零联网；DES 用内置 crypto-js（运行时不解密不外传）。

import CryptoJS from 'crypto-js';

// ---- 魔数表（NirSoft RouterPassView Detected File Type 精简版）----

export type RouterFamily = 'tplink-conf' | 'tplink-wr841n' | 'rom0' | 'asus' | 'dlink' | 'siemens' | 'generic-transform' | 'unknown';

export interface RouterDetect {
  family: RouterFamily;
  typeName: string;
  startOffset: number;
}

const startsWith = (bytes: Uint8Array, offset: number, ascii: string): boolean => {
  for (let i = 0; i < ascii.length; i++) {
    if (bytes[offset + i] !== ascii.charCodeAt(i)) return false;
  }
  return true;
};

export const detectRouterFile = (bytes: Uint8Array): RouterDetect => {
  if (bytes.length >= 4 && startsWith(bytes, 0, 'HDR1')) return { family: 'asus', typeName: 'Asus HDR1', startOffset: 8 };
  if (bytes.length >= 8 && startsWith(bytes, 0, '<psitree')) return { family: 'siemens', typeName: 'Siemens <psitree> XML', startOffset: 0 };
  if (bytes.length >= 4 && startsWith(bytes, 0, 'DS0')) return { family: 'dlink', typeName: 'Edimax/D-Link DS0', startOffset: 4 };
  if (bytes.length >= 4 && startsWith(bytes, 0, 'LMMC')) return { family: 'dlink', typeName: 'D-Link LMMC', startOffset: 4 };
  if (bytes.length >= 6 && (startsWith(bytes, 0, 'DLB') || startsWith(bytes, 0, 'DDC') || startsWith(bytes, 0, 'ZXL'))) {
    return { family: 'dlink', typeName: 'D-Link DLB/DDC/ZXL', startOffset: 6 };
  }
  // TP-Link conf.bin：无固定魔数，特征 = 前 16 字节 MD5 头 + 解密后首 4 字节为大端合理长度。
  // WR841N：144 字节头（16 MD5 + 固件元数据），offset 144 起为 DES-ECB 密文。
  if (bytes.length > 160) {
    // WR841N 试探：用默认 key 解密首块，解出 zlib 头 78 9C/78 DA 即命中
    const probe = desEcbDecrypt(bytes.subarray(144, 152), TPLINK_DEFAULT_KEY);
    if (probe && (probe[0] === 0x78)) return { family: 'tplink-wr841n', typeName: 'TP-Link WR841N 系 config.bin', startOffset: 144 };
  }
  if (bytes.length > 32) {
    const probe = desEcbDecrypt(bytes.subarray(16, 24), TPLINK_DEFAULT_KEY);
    if (probe) {
      const beLen = (probe[0] << 24) | (probe[1] << 16) | (probe[2] << 8) | probe[3];
      const leLen = (probe[3] << 24) | (probe[2] << 16) | (probe[1] << 8) | probe[0];
      if ((beLen > 0 && beLen < 0x40000) || (leLen > 0 && leLen < 0x40000)) {
        return { family: 'tplink-conf', typeName: 'TP-Link conf.bin（tpconf 系 DES+LZSS）', startOffset: 16 };
      }
    }
  }
  // rom-0：文件名特征 + 无魔数（由调用方按文件名兜底）；通用变换族
  if (bytes.length > 2 && bytes[0] === 0x1f && bytes[1] === 0x8b) return { family: 'generic-transform', typeName: 'gzip（RouterPassView type 100）', startOffset: 0 };
  if (bytes.length > 2 && bytes[0] === 0x78 && (bytes[1] === 0x9c || bytes[1] === 0xda || bytes[1] === 0x01)) return { family: 'generic-transform', typeName: 'zlib（RouterPassView type 102）', startOffset: 0 };
  if (bytes.length > 5 && startsWith(bytes, 0, '<?xml')) return { family: 'generic-transform', typeName: '明文 XML', startOffset: 0 };
  return { family: 'unknown', typeName: '未知格式', startOffset: 0 };
};

// ---- DES-ECB（crypto-js，无填充逐块）----

// 字节数组 → crypto-js WordArray（按小端字打包，crypto-js 标准口径）
type CryptoWordArray = ReturnType<typeof CryptoJS.lib.WordArray.create>;
const bytesToWordArray = (bytes: Uint8Array): CryptoWordArray => {
  const words: number[] = [];
  for (let i = 0; i < bytes.length; i++) {
    words[i >>> 2] = (words[i >>> 2] | 0) | (bytes[i] << (24 - (i % 4) * 8));
  }
  return CryptoJS.lib.WordArray.create(words, bytes.length);
};

// TP-Link DES 密钥表（tpconf_bin_xml.py KEYS，L33 起）
const TPLINK_KEYS: Record<string, Uint8Array> = {
  default: Uint8Array.from([0x47, 0x8d, 0xa5, 0x0b, 0xf9, 0xe3, 0xd2, 0xcf]),
  'xz005-g6-un-v1': Uint8Array.from([0x45, 0xee, 0x92, 0x32, 0xcf, 0x5b, 0x1d, 0xfe]),
  'ex230v-v1': Uint8Array.from([0x40, 0xb4, 0x93, 0x33, 0xc9, 0x0b, 0x1d, 0xfe]),
  'vc220-g3u': Uint8Array.from([0x40, 0xec, 0xc4, 0x3a, 0xca, 0x0a, 0x1d, 0xfe]),
  'bsn3000x-v1': Uint8Array.from([0x44, 0xbf, 0xc3, 0x3b, 0x9d, 0x0c, 0x1d, 0xfd]),
  'ex221-g5v1': Uint8Array.from([0x45, 0xe8, 0x90, 0x6f, 0x9a, 0x0a, 0x1d, 0xfe]),
  'ex530v-v1': Uint8Array.from([0x40, 0xba, 0xc6, 0x6c, 0xca, 0x5a, 0x1c, 0xfe]),
};
export const TPLINK_DEFAULT_KEY = TPLINK_KEYS.default;

const keyToCryptoJs = (key: Uint8Array): string =>
  Array.from(key).map(b => b.toString(16).padStart(2, '0')).join('');

// 无填充 DES-ECB 解密：非 8 整数倍尾部保留原文。
export const desEcbDecrypt = (ciphertext: Uint8Array, key: Uint8Array): Uint8Array | null => {
  if (ciphertext.length < 8) return null;
  const blocks = Math.floor(ciphertext.length / 8) * 8;
  try {
    const decrypted = CryptoJS.DES.decrypt(
      CryptoJS.lib.CipherParams.create({ ciphertext: bytesToWordArray(ciphertext.subarray(0, blocks)) }),
      CryptoJS.enc.Hex.parse(keyToCryptoJs(key)),
      { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.NoPadding },
    );
    const out = new Uint8Array(ciphertext.length);
    const words = decrypted.words;
    for (let i = 0; i < blocks; i++) out[i] = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
    for (let i = blocks; i < ciphertext.length; i++) out[i] = ciphertext[i];
    return out;
  } catch {
    return null;
  }
};
void bytesToWordArray;

// ---- MD5（校验头）----
export const md5Hex = (bytes: Uint8Array): string => CryptoJS.MD5(bytesToWordArray(bytes)).toString(CryptoJS.enc.Hex);

// ---- TP-Link LZSS uncompress（tpconf_bin_xml.py L140-189 逐行移植）----

// 端序自动：大端优先，超 0x40000 切小端。
export const tplinkLzssUncompress = (src: Uint8Array): { data: Uint8Array; littleEndian: boolean } | { error: string } => {
  if (src.length < 8) return { error: '数据过短' };
  let littleEndian = false;
  let size = (src[0] << 24) | (src[1] << 16) | (src[2] << 8) | src[3];
  if (size <= 0 || size > 0x40000) {
    littleEndian = true;
    size = (src[3] << 24) | (src[2] << 16) | (src[1] << 8) | src[0];
  }
  if (size <= 0 || size > 0x40000) return { error: '压缩长度字段非法（非 TP-Link LZSS 流）' };
  const dst = new Uint8Array(size);
  let sP = 4;
  let dP = 0;
  let block16Countdown = 0;
  let block16DictBits = 0;
  const getBit = (): number => {
    if (block16Countdown > 0) {
      block16Countdown -= 1;
    } else {
      block16DictBits = src[sP] | (src[sP + 1] << 8);
      sP += 2;
      block16Countdown = 0xf;
    }
    block16DictBits = (block16DictBits << 1) & 0x1ffff;
    return block16DictBits & 0x10000 ? 1 : 0;
  };
  const getDictLd = (): number => {
    let bits = 1;
    for (;;) {
      bits = (bits << 1) + getBit();
      if (getBit() === 0) break;
    }
    return bits;
  };
  dst[dP++] = src[sP++];
  while (dP < size) {
    if (sP >= src.length) break;
    if (getBit() === 1) {
      const numChars = getDictLd() + 2;
      const msB = (getDictLd() - 2) << 8;
      const lsB = src[sP++];
      let offset = dP - (lsB + 1 + msB);
      if (offset < 0) return { error: `LZSS 回退越界（offset=${offset}）` };
      for (let i = 0; i < numChars && dP < size; i++) {
        dst[dP++] = dst[offset++];
      }
    } else {
      dst[dP++] = src[sP++];
    }
  }
  return { data: dst, littleEndian };
};

// ---- rom-0 LZS（ZyNOS：16-bit LE 控制掩码 LSB-first；1=字面量 0=匹配 12bit offset + 4bit len）----

export const rom0LzsDecompress = (src: Uint8Array, maxOut = 0x8000): Uint8Array | null => {
  const out = new Uint8Array(maxOut);
  let op = 0;
  let sp = 0;
  let ctrl = 0;
  let ctrlBits = 0;
  const getBit = (): number => {
    if (ctrlBits === 0) {
      if (sp + 2 > src.length) return -1;
      ctrl = src[sp] | (src[sp + 1] << 8);
      sp += 2;
      ctrlBits = 16;
    }
    const bit = ctrl & 1;
    ctrl >>>= 1;
    ctrlBits -= 1;
    return bit;
  };
  while (op < maxOut) {
    const bit = getBit();
    if (bit < 0) break;
    if (bit === 1) {
      if (sp >= src.length) break;
      out[op++] = src[sp++];
    } else {
      // 匹配：12-bit offset + 4-bit 长度（len = nibble + 3；nibble 0 扩展）
      let offset = 0;
      for (let i = 0; i < 12; i++) {
        const b = getBit();
        if (b < 0) return op > 0 ? out.subarray(0, op) : null;
        offset = (offset << 1) | b;
      }
      let lengthNibble = 0;
      for (let i = 0; i < 4; i++) {
        const b = getBit();
        if (b < 0) return op > 0 ? out.subarray(0, op) : null;
        lengthNibble = (lengthNibble << 1) | b;
      }
      let length = lengthNibble + 3;
      if (lengthNibble === 15) {
        // 扩展长度：读字节直到 < 0xff
        for (;;) {
          if (sp >= src.length) break;
          const extra = src[sp++];
          length += extra;
          if (extra < 0xff) break;
        }
      }
      const from = op - offset - 1;
      if (from < 0) return op > 0 ? out.subarray(0, op) : null;
      for (let i = 0; i < length && op < maxOut; i++) out[op++] = out[from + i];
    }
  }
  return out.subarray(0, op);
};

// ---- 密码字段抽取 ----

export interface RouterSecretHit {
  field: string;
  value: string;
}

const SECRET_FIELD_PATTERN = /(password|passwd|pwd|psk|passphrase|key|secret|pin|wpakey|sharedkey)/i;

export const extractRouterSecrets = (text: string): RouterSecretHit[] => {
  const hits: RouterSecretHit[] = [];
  // XML 形态：<pppoePassword>xxx</pppoePassword> / <wpaPskKey ...>xxx</wpaPskKey>
  const xmlMatches = text.matchAll(/<([A-Za-z0-9_.-]*?(?:password|passwd|pwd|psk|passphrase|key|secret|pin)[A-Za-z0-9_.-]*)(?:\s[^>]*)?>([^<]{1,128})<\/\1>/gi);
  for (const match of xmlMatches) {
    hits.push({ field: match[1], value: match[2] });
  }
  // JSON 形态："password": "xxx"
  const jsonMatches = text.matchAll(/"([^"]*?(?:password|passwd|pwd|psk|key|secret|pin)[^"]*)"\s*:\s*"([^"]{0,128})"/gi);
  for (const match of jsonMatches) {
    hits.push({ field: match[1], value: match[2] });
  }
  // key=value 形态（含 ini）
  const kvMatches = text.matchAll(/([A-Za-z0-9_]*(?:password|passwd|pwd|psk|key|secret|pin)[A-Za-z0-9_]*)\s*[=:]\s*([^\s"<>]{1,64})/gi);
  for (const match of kvMatches) {
    hits.push({ field: match[1], value: match[2] });
  }
  // 去重
  const seen = new Set<string>();
  return hits.filter(hit => {
    const key = `${hit.field}=${hit.value}`;
    if (seen.has(key) || !hit.value) return false;
    seen.add(key);
    return true;
  });
};
void SECRET_FIELD_PATTERN;

// ---- 主入口 ----

export interface RouterConfigResult {
  ok: boolean;
  typeName: string;
  steps: string[];
  content: string | null;
  secrets: RouterSecretHit[];
  error?: string;
}

// ---- 纯 JS raw-deflate 兜底解压器（RFC 1951；DecompressionStream 不可用/跨 realm 失败时走此路）----
const inflateRaw = (input: Uint8Array, startBit: number, expectedMax: number): Uint8Array | null => {
  let bitPos = startBit;
  const readBits = (count: number): number => {
    let value = 0;
    for (let i = 0; i < count; i++) {
      const byte = input[bitPos >> 3];
      if (byte === undefined) return -1;
      value |= ((byte >> (bitPos & 7)) & 1) << i;
      bitPos += 1;
    }
    return value;
  };
  const buildHuffman = (lengths: Uint8Array): { counts: Uint16Array; symbols: Uint16Array } | null => {
    const maxBits = 15;
    const counts = new Uint16Array(maxBits + 1);
    for (const len of lengths) counts[len] += 1;
    counts[0] = 0;
    const offsets = new Uint16Array(maxBits + 2);
    for (let i = 1; i <= maxBits; i++) offsets[i + 1] = offsets[i] + counts[i];
    const symbols = new Uint16Array(lengths.length);
    for (let sym = 0; sym < lengths.length; sym++) {
      if (lengths[sym] !== 0) symbols[offsets[lengths[sym]]++] = sym;
    }
    return { counts, symbols };
  };
  const decodeHuffman = (table: { counts: Uint16Array; symbols: Uint16Array }): number => {
    let code = 0;
    let first = 0;
    let index = 0;
    for (let len = 1; len <= 15; len++) {
      const bit = readBits(1);
      if (bit < 0) return -1;
      code |= bit;
      const count = table.counts[len];
      if (code - first < count) return table.symbols[index + (code - first)];
      index += count;
      first = (first + count) << 1;
      code <<= 1;
    }
    return -1;
  };
  const lengthBase = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
  const lengthExtra = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
  const distBase = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577];
  const distExtra = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];
  const out = new Uint8Array(expectedMax);
  let op = 0;
  for (;;) {
    const final = readBits(1);
    if (final < 0) return null;
    const blockType = readBits(2);
    if (blockType < 0) return null;
    if (blockType === 0) {
      // stored 块：字节对齐 + len/nlen 校验 + 原样拷贝
      bitPos = (bitPos + 7) & ~7;
      const p = bitPos >> 3;
      if (p + 4 > input.length) return null;
      const len = input[p] | (input[p + 1] << 8);
      const nlen = input[p + 2] | (input[p + 3] << 8);
      if ((len ^ 0xffff) !== nlen) return null;
      if (p + 4 + len > input.length || op + len > out.length) return null;
      out.set(input.subarray(p + 4, p + 4 + len), op);
      op += len;
      bitPos = (p + 4 + len) << 3;
    } else if (blockType === 1 || blockType === 2) {
      let litTable: { counts: Uint16Array; symbols: Uint16Array };
      let distTable: { counts: Uint16Array; symbols: Uint16Array };
      if (blockType === 1) {
        const litLens = new Uint8Array(288);
        for (let i = 0; i < 144; i++) litLens[i] = 8;
        for (let i = 144; i < 256; i++) litLens[i] = 9;
        for (let i = 256; i < 280; i++) litLens[i] = 7;
        for (let i = 280; i < 288; i++) litLens[i] = 8;
        litTable = buildHuffman(litLens)!;
        distTable = buildHuffman(new Uint8Array(30).fill(5))!;
      } else {
        const hlit = readBits(5) + 257;
        const hdist = readBits(5) + 1;
        const hclen = readBits(4) + 4;
        if (hlit < 0 || hdist < 0 || hclen < 0) return null;
        const order = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];
        const codeLens = new Uint8Array(19);
        for (let i = 0; i < hclen; i++) {
          const v = readBits(3);
          if (v < 0) return null;
          codeLens[order[i]] = v;
        }
        const codeTable = buildHuffman(codeLens);
        if (!codeTable) return null;
        const lens = new Uint8Array(hlit + hdist);
        let li = 0;
        while (li < hlit + hdist) {
          const sym = decodeHuffman(codeTable);
          if (sym < 0) return null;
          if (sym < 16) {
            lens[li++] = sym;
          } else if (sym === 16) {
            if (li === 0) return null;
            const repeat = 3 + (readBits(2) & 3);
            const prev = lens[li - 1];
            for (let j = 0; j < repeat && li < hlit + hdist; j++) lens[li++] = prev;
          } else if (sym === 17) {
            li += 3 + (readBits(3) & 7);
          } else {
            li += 11 + (readBits(7) & 127);
          }
        }
        if (li > hlit + hdist) return null;
        litTable = buildHuffman(lens.subarray(0, hlit))!;
        distTable = buildHuffman(lens.subarray(hlit))!;
      }
      for (;;) {
        const sym = decodeHuffman(litTable);
        if (sym < 0) return null;
        if (sym < 256) {
          if (op >= out.length) return null;
          out[op++] = sym;
        } else if (sym === 256) {
          break;
        } else {
          const li = sym - 257;
          if (li >= lengthBase.length) return null;
          const extra = readBits(lengthExtra[li]);
          if (extra < 0) return null;
          const length = lengthBase[li] + extra;
          const dsym = decodeHuffman(distTable);
          if (dsym < 0 || dsym >= distBase.length) return null;
          const dextra = readBits(distExtra[dsym]);
          if (dextra < 0) return null;
          const distance = distBase[dsym] + dextra;
          if (distance > op) return null;
          let from = op - distance;
          if (op + length > out.length) return null;
          for (let i = 0; i < length; i++) out[op++] = out[from++];
        }
      }
    } else {
      return null;
    }
    if (final === 1) break;
  }
  return out.subarray(0, op);
};

const inflateZlib = async (bytes: Uint8Array): Promise<Uint8Array | null> => {
  try {
    const ds = new DecompressionStream('deflate');
    const writer = ds.writable.getWriter();
    const chunks: Uint8Array[] = [];
    const reader = ds.readable.getReader();
    const readAll = async () => {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        chunks.push(value);
      }
    };
    // 沙箱/短数据下并发读写有竞态（readable 可能先于写入结束）：先写完再消费
    await writer.write(new Uint8Array(bytes));
    await writer.close();
    await readAll();
    const total = chunks.reduce((sum, c) => sum + c.length, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) { out.set(chunk, offset); offset += chunk.length; }
    return out;
  } catch {
    // 兜底：纯 JS raw-deflate（RFC 1951）——vm 沙箱的跨 realm DecompressionStream 会抛
    // 空 message 异常，且部分旧环境无该 API；zlib 头 2 字节剥离，尾部 adler 忽略。
    if (bytes.length < 6) return null;
    return inflateRaw(bytes, 16, Math.max(1024, bytes.length * 12));
  }
};

export const analyzeRouterConfig = async (fileName: string, bytes: Uint8Array): Promise<RouterConfigResult> => {
  const steps: string[] = [];
  const lowerName = fileName.toLowerCase();
  const detect = detectRouterFile(bytes);
  const textDecoder = new TextDecoder('utf-8', { fatal: false });

  // rom-0 按文件名识别（无魔数）
  const family = lowerName.includes('rom-0') || lowerName.includes('rom0') ? 'rom0' : detect.family;
  if (family === 'rom0' && detect.family === 'unknown') detect.typeName = 'rom-0（ZyNOS 备份）';

  // ① TP-Link conf.bin
  if (family === 'tplink-conf') {
    steps.push(`识别：${detect.typeName}`);
    // MD5 校验（允许尾部 ≤8 字节填充）
    const head = Array.from(bytes.subarray(0, 16)).map(b => b.toString(16).padStart(2, '0')).join('');
    let md5Ok = false;
    for (let pad = 0; pad < 8; pad++) {
      if (bytes.length <= 16 + pad) break;
      if (md5Hex(bytes.subarray(16, bytes.length - pad)) === head) { md5Ok = true; break; }
    }
    steps.push(md5Ok ? 'MD5 校验通过（default 密钥）' : 'MD5 校验未过（仍尝试解密；可换非默认密钥的机型）');
    for (const [name, key] of Object.entries(TPLINK_KEYS)) {
      const decrypted = desEcbDecrypt(bytes.subarray(16), key);
      if (!decrypted) continue;
      const lz = tplinkLzssUncompress(decrypted);
      if ('error' in lz) continue;
      const text = textDecoder.decode(lz.data);
      if (text.includes('<') && text.length > 16) {
        steps.push(`DES 解密（${name}）+ LZSS 解压（${lz.littleEndian ? '小端' : '大端'}长度）→ XML ${lz.data.length} 字节`);
        return { ok: true, typeName: detect.typeName, steps, content: text, secrets: extractRouterSecrets(text) };
      }
    }
    return { ok: false, typeName: detect.typeName, steps, content: null, secrets: [], error: '全部密钥解密后未得到合法 LZSS/XML 流' };
  }

  // ② WR841N
  if (family === 'tplink-wr841n') {
    steps.push('识别：TP-Link WR841N 系（144 字节头 + DES-ECB + zlib）');
    const decrypted = desEcbDecrypt(bytes.subarray(144), TPLINK_DEFAULT_KEY);
    if (!decrypted) return { ok: false, typeName: detect.typeName, steps, content: null, secrets: [], error: 'DES 解密失败' };
    steps.push('DES-ECB 解密完成（key 478DA50BF9E3D2CF）');
    const inflated = await inflateZlib(decrypted);
    if (!inflated) return { ok: false, typeName: detect.typeName, steps, content: null, secrets: [], error: 'zlib 解压失败（可能非 WR841N 布局）' };
    const text = textDecoder.decode(inflated);
    steps.push(`zlib 解压 → ${inflated.length} 字节`);
    return { ok: true, typeName: detect.typeName, steps, content: text, secrets: extractRouterSecrets(text) };
  }

  // ③ rom-0
  if (family === 'rom0') {
    steps.push('识别：rom-0（ZyNOS LZS）');
    const decompressed = rom0LzsDecompress(bytes.subarray(4));
    if (!decompressed || decompressed.length === 0) {
      return { ok: false, typeName: detect.typeName, steps, content: null, secrets: [], error: 'LZS 解压失败' };
    }
    const text = textDecoder.decode(decompressed);
    steps.push(`LZS 解压 → ${decompressed.length} 字节（含明文配置）`);
    return { ok: true, typeName: detect.typeName, steps, content: text, secrets: extractRouterSecrets(text) };
  }

  // ④ 通用变换族
  if (family === 'generic-transform') {
    steps.push(`识别：${detect.typeName}`);
    if (detect.typeName.startsWith('gzip') || detect.typeName.startsWith('zlib')) {
      const format = detect.typeName.startsWith('gzip') ? 'gzip' : 'deflate';
      const stream = new DecompressionStream(format as 'gzip' | 'deflate');
      const writer = stream.writable.getWriter();
      const chunks: Uint8Array[] = [];
      const reader = stream.readable.getReader();
      const readAll = async () => { for (;;) { const { done, value } = await reader.read(); if (done) break; chunks.push(value); } };
      await Promise.all([readAll, writer.write(new Uint8Array(bytes)).then(() => writer.close())]);
      const total = chunks.reduce((s, c) => s + c.length, 0);
      const out = new Uint8Array(total);
      let o = 0;
      for (const c of chunks) { out.set(c, o); o += c.length; }
      const text = textDecoder.decode(out);
      steps.push(`${format} 解压 → ${total} 字节`);
      return { ok: true, typeName: detect.typeName, steps, content: text, secrets: extractRouterSecrets(text) };
    }
    const text = textDecoder.decode(bytes);
    return { ok: true, typeName: detect.typeName, steps, content: text, secrets: extractRouterSecrets(text) };
  }

  // ⑤ 明文 XML / 其他：直接抽取
  const text = textDecoder.decode(bytes);
  if (text.includes('<') || detect.family === 'asus' || detect.family === 'siemens' || detect.family === 'dlink') {
    steps.push(`识别：${detect.typeName}（明文或部分加密，直接抽取字段）`);
    return { ok: true, typeName: detect.typeName, steps, content: text, secrets: extractRouterSecrets(text) };
  }
  return { ok: false, typeName: '未知格式', steps: ['未识别的路由器备份格式'], content: null, secrets: [], error: '未识别（支持 TP-Link conf.bin/WR841N/rom-0/Asus/D-Link/gzip/zlib/XML）' };
};
