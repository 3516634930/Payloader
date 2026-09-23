// 逆向域常量指纹扫描（纯 JS，零联网零依赖）：在二进制前 8MB 内滑窗匹配加密/散列/校验/编码/结构/壳特征常量。
// 常量值全部取自公开标准（FIPS 197 AES、RFC 1321 MD5、FIPS 180 SHA、RFC 4648 Base64、
// TEA/XXTEA delta 0x9E3779B9、CRC-32 poly 0xEDB88320 反射表、UPX/mbed TLS/SQLite 官方文档），
// 数值型常量同时给小端/大端两个字节序列（同一常量 id），命中按常量去重、只报首偏移。

export interface LocText {
  zh: string;
  en: string;
}

export type FingerprintCategory = 'cipher' | 'hash' | 'checksum' | 'encoding' | 'structure' | 'packer' | 'library';

export const FINGERPRINT_SCAN_LIMIT = 8 * 1024 * 1024;

interface FingerprintPattern {
  // 字节序列模式（滑窗精确匹配）；与 text 二选一。
  bytes?: number[];
  // 同一常量的多形态区分标签（如 小端/大端），随首命中一起输出。
  label?: LocText;
  // 文本模式（latin1 视角的正则源）；用于版本字符串等变长特征。
  text?: string;
}

export interface FingerprintDef {
  id: string;
  name: string;
  category: FingerprintCategory;
  meaning: LocText;
  suggestion: LocText;
  // 命中后建议切换到的题型域（如密码域解密）；缺省不跳转。
  switchModuleId?: string;
  patterns: FingerprintPattern[];
}

const le = (value: number, width: 4 | 8 = 4): number[] => {
  const out: number[] = [];
  for (let index = 0; index < width; index += 1) out.push((value >>> (index * 8)) & 0xff);
  return out;
};

const be = (value: number, width: 4 | 8 = 4): number[] => {
  const out: number[] = [];
  for (let index = width - 1; index >= 0; index -= 1) out.push((value >>> (index * 8)) & 0xff);
  return out;
};

const bytesOf = (text: string): number[] => Array.from(text, char => char.charCodeAt(0) & 0xff);

const hexBytes = (hex: string): number[] => {
  const out: number[] = [];
  for (let index = 0; index < hex.length; index += 2) out.push(Number.parseInt(hex.slice(index, index + 2), 16));
  return out;
};

export const FINGERPRINT_DEFS: FingerprintDef[] = [
  {
    id: 'tea-family-delta',
    name: 'TEA / XTEA / XXTEA delta 0x9E3779B9',
    category: 'cipher',
    meaning: {
      zh: 'TEA 家族分组密码的黄金比例常量（0x9E3779B9），三种 TEA 变体共用同一 delta。',
      en: 'The golden-ratio delta (0x9E3779B9) shared by the TEA cipher family (TEA/XTEA/XXTEA).',
    },
    suggestion: {
      zh: '疑似 TEA 家族加密：去「密码与编码」域搜 TEA / XTEA / XXTEA，结合 strings 里疑似密钥尝试解密。',
      en: 'Likely TEA-family encryption: search TEA / XTEA / XXTEA in Ciphers & Encoding and try keys from strings.',
    },
    switchModuleId: 'cipher',
    patterns: [
      { bytes: le(0x9e3779b9), label: { zh: '小端（x86 常见）', en: 'little-endian (typical on x86)' } },
      { bytes: be(0x9e3779b9), label: { zh: '大端', en: 'big-endian' } },
    ],
  },
  {
    id: 'aes-sbox',
    name: 'AES S-box（正向替换表首行）',
    category: 'cipher',
    meaning: {
      zh: 'AES 正向 S-box 首行 0x63,0x7C,0x77,0x7B…，二进制内实现 AES 加密（或查表）的直接证据。',
      en: 'First row of the AES forward S-box (0x63,0x7C,0x77,0x7B…): the binary implements AES (or a table lookup) itself.',
    },
    suggestion: {
      zh: '疑似 AES：找 16/24/32 字节硬编码密钥（strings 可疑串）→「密码与编码」域试 AES 系列（ECB/CBC 常见）。',
      en: 'Likely AES: look for a 16/24/32-byte hardcoded key, then try AES modes (ECB/CBC first) in Ciphers & Encoding.',
    },
    switchModuleId: 'cipher',
    patterns: [{ bytes: hexBytes('637C777BF26B6FC53001672BFED7AB76') }],
  },
  {
    id: 'aes-inverse-sbox',
    name: 'AES 逆 S-box（逆向替换表首行）',
    category: 'cipher',
    meaning: {
      zh: 'AES 逆 S-box 首行 0x52,0x09,0x6A,0xD5…，二进制内实现 AES 解密，通常伴随正向表同时出现。',
      en: 'First row of the AES inverse S-box (0x52,0x09,0x6A,0xD5…): the binary implements AES decryption.',
    },
    suggestion: {
      zh: '疑似 AES 解密实现：同上找密钥；若只有逆表，密文可能需先经别的变换再解。',
      en: 'Likely AES decryption; find the key as above. If only the inverse table is present, ciphertext may need another transform first.',
    },
    switchModuleId: 'cipher',
    patterns: [{ bytes: hexBytes('52096AD53036A538BF40A39E81F3D7FB') }],
  },
  {
    id: 'md5-sha1-iv',
    name: 'MD5 / SHA-1 初始向量（67452301 EFCDAB89…）',
    category: 'hash',
    meaning: {
      zh: 'MD5 与 SHA-1 共用的初始化常量（小端内存形态 01234567 89ABCDEF…）；两者前 4 字相同，需看后续常量区分。',
      en: 'The shared MD5/SHA-1 initialization constants (little-endian form 01234567 89ABCDEF…); their first four words are identical.',
    },
    suggestion: {
      zh: '疑似 MD5/SHA-1：strings 找可疑「摘要比对」十六进制串（32 位=MD5、40 位=SHA-1）→ 密码域 hash 工具对撞。',
      en: 'Likely MD5/SHA-1: find the hex digest in strings (32 hex = MD5, 40 = SHA-1) and attack it in Ciphers & Encoding.',
    },
    switchModuleId: 'cipher',
    patterns: [
      { bytes: hexBytes('0123456789ABCDEFFEDCBA9876543210'), label: { zh: '小端（x86 常见）', en: 'little-endian (typical on x86)' } },
      { bytes: hexBytes('67452301EFCDAB8998BADCFE10325476'), label: { zh: '大端', en: 'big-endian' } },
    ],
  },
  {
    id: 'sha256-iv',
    name: 'SHA-256 初始向量（6A09E667…）',
    category: 'hash',
    meaning: {
      zh: 'SHA-256 的 H0..H3 初始化常量，二进制内实现 SHA-256。',
      en: 'SHA-256 initial hash values H0..H3: the binary implements SHA-256.',
    },
    suggestion: {
      zh: '疑似 SHA-256：strings 找 64 位十六进制摘要 → 密码域 hash 工具验证/对撞。',
      en: 'Likely SHA-256: find a 64-hex digest in strings and verify/crack it in Ciphers & Encoding.',
    },
    switchModuleId: 'cipher',
    patterns: [
      { bytes: hexBytes('67E6096A85AE67BB72F36E3C3AF54FA5'), label: { zh: '小端（x86 常见）', en: 'little-endian (typical on x86)' } },
      { bytes: hexBytes('6A09E667BB67AE853C6EF372A54FF53A'), label: { zh: '大端', en: 'big-endian' } },
    ],
  },
  {
    id: 'crc32-table',
    name: 'CRC-32 查找表（77073096…）',
    category: 'checksum',
    meaning: {
      zh: '标准反射 CRC-32（poly 0xEDB88320）查找表首项，校验逻辑或 zip 解析的标志。',
      en: 'First entries of the standard reflected CRC-32 table (poly 0xEDB88320): checksum logic or ZIP parsing.',
    },
    suggestion: {
      zh: 'CRC 常用于结果校验而非加密：若题目比对 CRC，考虑碰撞/篡改；若数据带 CRC 可用于定位正确解。',
      en: 'CRC is for validation, not encryption: for CRC comparisons consider collisions/tampering; embedded CRCs help locate the right answer.',
    },
    patterns: [
      { bytes: hexBytes('00000000963007772C610EEEBA510999'), label: { zh: '小端表项', en: 'little-endian entries' } },
      { bytes: hexBytes('0000000077300796EE0E612C990951BA'), label: { zh: '大端表项', en: 'big-endian entries' } },
    ],
  },
  {
    id: 'base64-alphabet',
    name: 'Base64 标准字母表',
    category: 'encoding',
    meaning: {
      zh: 'RFC 4648 标准 Base64 字母表完整 64 字符，二进制内实现 Base64 编解码。',
      en: 'The full RFC 4648 Base64 alphabet: the binary implements Base64 itself.',
    },
    suggestion: {
      zh: '数据可能被 Base64 编码后再处理：strings 里找 4 的倍数长度的可疑串 → 密码域 Base64 解码。',
      en: 'Data may be Base64-wrapped: hunt for suspicious 4-multiple-length strings, decode in Ciphers & Encoding.',
    },
    switchModuleId: 'cipher',
    patterns: [{ bytes: bytesOf('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/') }],
  },
  {
    id: 'base64-urlsafe-alphabet',
    name: 'Base64 URL-safe 字母表（-_）',
    category: 'encoding',
    meaning: {
      zh: 'URL-safe Base64 变体字母表（+/ 换成 -_），常见于 JWT/令牌处理代码。',
      en: 'The URL-safe Base64 alphabet (-_ instead of +/), common in JWT/token code.',
    },
    suggestion: {
      zh: '疑似令牌/JWT 逻辑：strings 找含 - _ 的三段式点分串 → 密码域 JWT 工具解析。',
      en: 'Likely token/JWT logic: look for dot-separated strings containing - and _ and parse them in Ciphers & Encoding.',
    },
    switchModuleId: 'cipher',
    patterns: [{ bytes: bytesOf('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_') }],
  },
  {
    id: 'embedded-png',
    name: 'PNG 签名（内嵌图像）',
    category: 'structure',
    meaning: {
      zh: 'PNG 文件签名 89 50 4E 47…。非 PNG 文件中命中 = 内嵌了一张图片（资源或隐藏数据）。',
      en: 'The PNG signature. Inside a non-PNG file this means an embedded image (resource or hidden data).',
    },
    suggestion: {
      zh: '可从该偏移截取到 IEND 生成独立 PNG（「杂项取证」域可进一步验证）；偏移 0 命中则本文件就是 PNG。',
      en: 'Carve from this offset to IEND for a standalone PNG (verify in Misc & Forensics); offset 0 simply means this file is a PNG.',
    },
    patterns: [{ bytes: hexBytes('89504E470D0A1A0A') }],
  },
  {
    id: 'png-iend',
    name: 'PNG IEND 结束块（AE 42 60 82）',
    category: 'structure',
    meaning: {
      zh: 'IEND chunk 类型 + 固定 CRC（AE426082），PNG 数据结束的标志位。',
      en: 'The IEND chunk type with its fixed CRC (AE426082): marks the end of PNG data.',
    },
    suggestion: {
      zh: 'IEND 之后若还有数据（见嵌入扫描/熵图），通常就是附加的隐藏内容。',
      en: 'Data after IEND (see the embedded scan / entropy map) is usually the appended hidden payload.',
    },
    patterns: [{ bytes: hexBytes('49454E44AE426082') }],
  },
  {
    id: 'embedded-zip',
    name: 'ZIP 本地文件头（PK\x03\x04）',
    category: 'structure',
    meaning: {
      zh: 'ZIP 本地文件头签名。非压缩包文件中命中 = 内嵌了一个 zip（或该文件本身是 zip 家族）。',
      en: 'The ZIP local file header. Inside a non-archive file this means an embedded zip (or the file itself is a ZIP).',
    },
    suggestion: {
      zh: '可从该偏移切割出独立 zip；zip 的伪加密/密码问题去「杂项取证」域处理。',
      en: 'Carve a standalone zip from this offset; pseudo-encryption/password issues go to Misc & Forensics.',
    },
    patterns: [{ bytes: hexBytes('504B0304') }],
  },
  {
    id: 'embedded-gif',
    name: 'GIF 签名（GIF8）',
    category: 'structure',
    meaning: {
      zh: 'GIF87a/89a 签名前缀，非 GIF 文件中命中 = 内嵌 GIF（动图逐帧藏数据是常见出题点）。',
      en: 'The GIF87a/89a prefix. Inside a non-GIF file this means an embedded GIF (per-frame hidden data is a common trick).',
    },
    suggestion: {
      zh: '切出 GIF 后逐帧看内容；帧差/调色板都是常见藏 flag 的位置。',
      en: 'Carve the GIF and inspect frame by frame; frame diffs and palettes often hide the flag.',
    },
    patterns: [{ bytes: hexBytes('47494638') }],
  },
  {
    id: 'embedded-pdf',
    name: 'PDF 文件头（%PDF-）',
    category: 'structure',
    meaning: {
      zh: 'PDF 文件头，非 PDF 文件中命中 = 内嵌 PDF 文档。',
      en: 'The PDF header. Inside a non-PDF file this means an embedded PDF document.',
    },
    suggestion: {
      zh: '从该偏移切割出独立 PDF 查看；PDF 对象流里也常有附加文本。',
      en: 'Carve a standalone PDF from this offset; extra text often hides in PDF object streams.',
    },
    patterns: [{ bytes: hexBytes('255044462D') }],
  },
  {
    id: 'sqlite-header',
    name: 'SQLite 3 数据库头（SQLite format 3）',
    category: 'structure',
    meaning: {
      zh: 'SQLite 数据库文件 16 字节头，命中 = 内嵌了一个 SQLite 数据库。',
      en: "The 16-byte SQLite 3 database header: an embedded SQLite database.",
    },
    suggestion: {
      zh: '切割出 .db 文件后用任意 SQLite 工具打开翻表；记录里常直接藏着 flag。',
      en: 'Carve the .db and open it with any SQLite tool; flags often sit right in the tables.',
    },
    patterns: [{ bytes: bytesOf('SQLite format 3\x00') }],
  },
  {
    id: 'upx-magic',
    name: 'UPX 壳魔数（UPX!）',
    category: 'packer',
    meaning: {
      zh: 'UPX 加壳头部魔数，二进制被 UPX 加壳。',
      en: 'The UPX packer header magic: the binary is UPX-packed.',
    },
    suggestion: {
      zh: '先脱壳再分析：upx -d challenge；脱壳后 strings/熵图会明显变化。',
      en: 'Unpack first: run `upx -d challenge`; strings and the entropy map will change drastically.',
    },
    patterns: [{ bytes: hexBytes('55505821') }],
  },
  {
    id: 'upx-banner',
    name: 'UPX 加壳横幅字符串',
    category: 'packer',
    meaning: {
      zh: '"packed with the UPX" 横幅，UPX 加壳的强特征（比魔数更不易被裁剪掉）。',
      en: 'The "packed with the UPX" banner: a strong UPX signature that survives header trimming.',
    },
    suggestion: {
      zh: 'upx -d 脱壳后重扫；若 -d 失败说明壳被魔改，需手动 dump。',
      en: 'Unpack with `upx -d` and rescan; if -d fails the packer was modified — dump manually.',
    },
    patterns: [{ text: 'packed with the UPX' }],
  },
  {
    id: 'mbedtls-version',
    name: 'mbed TLS 版本字符串',
    category: 'library',
    meaning: {
      zh: '静态链接 mbed TLS 库的版本串，程序使用 mbedtls 实现加密逻辑。',
      en: 'A statically linked mbed TLS version string: crypto is implemented with mbedtls.',
    },
    suggestion: {
      zh: '按版本找对应算法实现特征（常伴随 AES 表/SHA IV）；密钥可能是硬编码 strings 可疑串。',
      en: 'Match the version to its algorithm traits (often alongside AES tables / SHA IVs); keys are often hardcoded strings.',
    },
    patterns: [{ text: 'mbed TLS \\d+\\.\\d+\\.\\d+' }],
  },
];

export interface FingerprintHit {
  id: string;
  name: string;
  category: FingerprintCategory;
  // 首次命中偏移（多形态/多次命中取最小）。
  offset: number;
  // 首命中模式的字节长度（文本模式按命中串长度计）。
  length: number;
  // 窗口内该常量的总命中次数（多形态 + 多次出现合计）。
  hits: number;
  label?: LocText;
  meaning: LocText;
  suggestion: LocText;
  switchModuleId?: string;
}

const compileBytePatterns = () => {
  const byFirstByte = new Map<number, Array<{ def: FingerprintDef; pattern: FingerprintPattern; bytes: number[] }>>();
  for (const def of FINGERPRINT_DEFS) {
    for (const pattern of def.patterns) {
      if (!pattern.bytes) continue;
      const first = pattern.bytes[0];
      const bucket = byFirstByte.get(first) ?? [];
      bucket.push({ def, pattern, bytes: pattern.bytes });
      byFirstByte.set(first, bucket);
    }
  }
  // 长模式优先：同位置多命中时（如 SHA-1 完整 IV vs MD5 前 4 字）首命中 label 归长模式。
  for (const bucket of byFirstByte.values()) bucket.sort((left, right) => right.bytes.length - left.bytes.length);
  return byFirstByte;
};

const BYTE_PATTERNS = compileBytePatterns();

interface TextPattern {
  def: FingerprintDef;
  pattern: FingerprintPattern;
  regex: RegExp;
}

const TEXT_PATTERNS: TextPattern[] = FINGERPRINT_DEFS.flatMap(def =>
  def.patterns
    .filter(pattern => pattern.text)
    .map(pattern => ({ def, pattern, regex: new RegExp(pattern.text!, 'g') })),
);

// 滑窗扫描：只扫前 maxBytes（默认/上限 8MB）；字节模式用首字节索引加速，
// 文本模式在 latin1 视角上跑正则。命中按常量 id 去重，输出按偏移升序。
export const scanConstFingerprints = (
  bytes: Uint8Array,
  options?: { maxBytes?: number },
): FingerprintHit[] => {
  const maxBytes = Math.min(bytes.length, options?.maxBytes ?? FINGERPRINT_SCAN_LIMIT, FINGERPRINT_SCAN_LIMIT);
  const state = new Map<string, { def: FingerprintDef; offset: number; length: number; hits: number; label?: LocText }>();
  const record = (def: FingerprintDef, offset: number, length: number, label?: LocText) => {
    const existing = state.get(def.id);
    if (!existing) {
      state.set(def.id, { def, offset, length, hits: 1, label });
      return;
    }
    existing.hits += 1;
    if (offset < existing.offset) {
      existing.offset = offset;
      existing.length = length;
      existing.label = label;
    }
  };

  for (let position = 0; position < maxBytes; position += 1) {
    const bucket = BYTE_PATTERNS.get(bytes[position]);
    if (!bucket) continue;
    for (const entry of bucket) {
      const patternBytes = entry.bytes;
      if (position + patternBytes.length > maxBytes) continue;
      let matched = true;
      for (let index = 1; index < patternBytes.length; index += 1) {
        if (bytes[position + index] !== patternBytes[index]) {
          matched = false;
          break;
        }
      }
      if (matched) record(entry.def, position, patternBytes.length, entry.pattern.label);
    }
  }

  if (TEXT_PATTERNS.length && maxBytes > 0) {
    // latin1 视角 1 字符 = 1 字节，正则 index 直接可用作字节偏移。
    const latin1 = new TextDecoder('latin1').decode(bytes.subarray(0, maxBytes));
    for (const entry of TEXT_PATTERNS) {
      entry.regex.lastIndex = 0;
      for (let match = entry.regex.exec(latin1); match; match = entry.regex.exec(latin1)) {
        record(entry.def, match.index, match[0].length);
        if (match[0].length === 0) entry.regex.lastIndex += 1;
      }
    }
  }

  return [...state.values()]
    .map(({ def, offset, length, hits, label }) => ({
      id: def.id,
      name: def.name,
      category: def.category,
      offset,
      length,
      hits,
      label,
      meaning: def.meaning,
      suggestion: def.suggestion,
      switchModuleId: def.switchModuleId,
    }))
    .sort((left, right) => left.offset - right.offset);
};
