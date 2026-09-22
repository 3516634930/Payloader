// 批次 O Lane A：Base/Rot 组 11 操作（parityBases）。码表与形状探针同源，全部纯文本进出、零联网、零动态代码执行。
// 算法定义与来源（2026-09-22 调研）：
// - Base92：thenoviceoof/base92（91 个键盘可打字符 + '~' 空串符，13 bit 一对，MSB-first）https://github.com/thenoviceoof/base92
// - Base100：AdamNiederer/base100（每字节映射连续 emoji 码点，byte 0 → U+1F3F7）https://github.com/AdamNiederer/base100
// - Base85 RFC1924：RFC 1924 §4 字母表 + CPython b85 4 字节组编解码语义 https://www.rfc-editor.org/rfc/rfc1924 https://github.com/python/cpython/blob/main/Lib/base64.py
// - Base62 ASCII 变体：无公开权威向量，按 0-9a-zA-Z 字母表大数模式实现（dcode.fr/Base-62 与短链服务常见流派）
// - Base64 Multiline：RFC 4648 Base64 + RFC 2045 §6.8 76 列折行 https://datatracker.ietf.org/doc/html/rfc4648#section-10 https://datatracker.ietf.org/doc/html/rfc2045#section-6.8
// - Base64 Case-Mangled：无公开权威实现，束搜索按解码结果可打印字节占比打分启发式恢复大小写
// - Base Custom：大数进制 + base58 式前导零字节保留（表长 ≥16 且无重复字符）
// - Base Multi-Decoding：无公开权威实现，按 CTF 套娃 Base 题惯例递归剥离 Base16/32/64/91
// - Rot18：字母 ROT13 + 数字 ROT5 https://en.wikipedia.org/wiki/ROT13
// - Rot Special：无公开权威定义，按随波逐流工具 ROT 系列惯例实现（http://1o1o.xyz）：字母 ROT13、数字 ROT5、其余可打印 ASCII 33-126 做 ROT47
import { base64ToBytes, bytesToBase64, bytesToHex, decodeBase32Bytes, decodeBase91, hexToBytes } from './bases';
import { utf8Decoder, utf8Encoder } from './alphabets';
import type { Direction, Operation, OperationId, ParamKey } from './types';
import type { ParityShapeProbe, ParityVector } from './parityTypes';

const BASE100_FIRST = 0x1F3F7;
const BASE100_LAST = 0x1F3F7 + 255;
const base92Alphabet = ['!', ...Array.from({ length: 61 }, (_, index) => String.fromCharCode(35 + index)), ...Array.from({ length: 29 }, (_, index) => String.fromCharCode(97 + index))].join('');
const base85Rfc1924Alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~';
const base62AsciiAlphabet = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';

const bytesToText = (bytes: Uint8Array): string => {
  const text = utf8Decoder.decode(bytes);
  return text.includes('�') ? bytesToHex(bytes) : text;
};

const printableRatio = (text: string): number => {
  if (!text) return 0;
  let printable = 0;
  let total = 0;
  for (const char of text) {
    const code = char.codePointAt(0) ?? 0;
    total += 1;
    if ((code >= 32 && code <= 126) || code === 9 || code === 10 || code === 13) printable += 1;
  }
  return printable / total;
};

const requireCleanBase64 = (value: string): string => {
  const compact = value.replace(/\s+/g, '');
  if (!compact) return '';
  const body = compact.replace(/=+$/, '');
  if (!/^[A-Za-z0-9+/]+$/.test(body)) throw new Error('Base64 含字母表之外的字符');
  if (compact.length % 4 === 1) throw new Error('Base64 长度非法（模 4 余 1），无法解码');
  return compact;
};

// Base92：bit 队列 MSB-first，每 13 bit 输出 [chunk//91, chunk%91] 一对；尾部 <7 bit 补到 6 bit 出 1 字符，否则补到 13 bit 出 2 字符。
const base92Value = (char: string): number => {
  const index = base92Alphabet.indexOf(char);
  if (index < 0) throw new Error(`Base92 非法字符: ${char}`);
  return index;
};

const encodeBase92 = (value: string): string => {
  const bytes = utf8Encoder.encode(value);
  if (!bytes.length) return '~';
  let buffer = 0;
  let bits = 0;
  let output = '';
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 13) {
      const chunk = buffer >> (bits - 13);
      buffer &= (1 << (bits - 13)) - 1;
      bits -= 13;
      output += base92Alphabet[Math.floor(chunk / 91)] + base92Alphabet[chunk % 91];
    }
  }
  if (bits > 0) {
    if (bits < 7) {
      output += base92Alphabet[buffer << (6 - bits)];
    } else {
      const chunk = buffer << (13 - bits);
      output += base92Alphabet[Math.floor(chunk / 91)] + base92Alphabet[chunk % 91];
    }
  }
  return output;
};

const decodeBase92 = (value: string): string => {
  const text = value.trim();
  if (!text) return '';
  if (text === '~') return '';
  if (text.length === 1) throw new Error('单个字符不是合法的 Base92 编码');
  let buffer = 0;
  let bits = 0;
  const bytes: number[] = [];
  let index = 0;
  while (index < text.length - 1) {
    const chunk = base92Value(text[index]) * 91 + base92Value(text[index + 1]);
    if (chunk >= 8192) throw new Error('Base92 字符对超出 13 bit 表示范围');
    buffer = (buffer << 13) | chunk;
    bits += 13;
    while (bits >= 8) {
      bytes.push(buffer >> (bits - 8));
      buffer &= (1 << (bits - 8)) - 1;
      bits -= 8;
    }
    index += 2;
  }
  if (index < text.length) {
    buffer = (buffer << 6) | base92Value(text[index]);
    bits += 6;
    while (bits >= 8) {
      bytes.push(buffer >> (bits - 8));
      buffer &= (1 << (bits - 8)) - 1;
      bits -= 8;
    }
  }
  return bytesToText(new Uint8Array(bytes));
};

// Base100：每个 UTF-8 字节 b → 码点 0x1F3F7 + b；解码为码点差值。
const encodeBase100 = (value: string): string => {
  const bytes = utf8Encoder.encode(value);
  let output = '';
  for (const byte of bytes) output += String.fromCodePoint(BASE100_FIRST + byte);
  return output;
};

const decodeBase100 = (value: string): string => {
  const compact = value.replace(/\s+/g, '');
  if (!compact) return '';
  const bytes: number[] = [];
  for (const char of compact) {
    const codePoint = char.codePointAt(0) ?? 0;
    if (codePoint < BASE100_FIRST || codePoint > BASE100_LAST) throw new Error(`Base100 密文包含 emoji 码点范围之外的字符: ${char}`);
    bytes.push(codePoint - BASE100_FIRST);
  }
  return bytesToText(new Uint8Array(bytes));
};

// Base85 RFC1924：4 字节大端一组 → 5 字符（85 进制 MSB-first）；尾部 n 字节补零出 n+1 字符；解码尾部补 '~'(84) 出 k-1 字节。
const base85Digit = (char: string): number => {
  const digit = base85Rfc1924Alphabet.indexOf(char);
  if (digit < 0) throw new Error(`Base85 非法字符: ${char}`);
  return digit;
};

const encodeBase85Rfc1924 = (value: string): string => {
  const bytes = utf8Encoder.encode(value);
  let output = '';
  for (let index = 0; index < bytes.length; index += 4) {
    const realLength = Math.min(4, bytes.length - index);
    let word = 0;
    for (let position = 0; position < 4; position += 1) word = word * 256 + (position < realLength ? bytes[index + position] : 0);
    const digits: number[] = [];
    for (let position = 0; position < 5; position += 1) {
      digits.unshift(word % 85);
      word = Math.floor(word / 85);
    }
    output += digits.slice(0, realLength + 1).map(digit => base85Rfc1924Alphabet[digit]).join('');
  }
  return output;
};

const decodeBase85Rfc1924 = (value: string): string => {
  const compact = value.replace(/\s+/g, '');
  if (!compact) return '';
  if (compact.length % 5 === 1) throw new Error('Base85 尾组长度非法（单个字符不成组）');
  const bytes: number[] = [];
  for (let index = 0; index < compact.length; index += 5) {
    const realLength = Math.min(5, compact.length - index);
    let word = 0;
    for (let position = 0; position < 5; position += 1) {
      const digit = position < realLength ? base85Digit(compact[index + position]) : 84;
      if (word > Math.floor(0xFFFFFFFF / 85)) throw new Error('Base85 数据溢出 32 bit 表示范围');
      word = word * 85 + digit;
    }
    if (word > 0xFFFFFFFF) throw new Error('Base85 数据溢出 32 bit 表示范围');
    for (let byteIndex = 0; byteIndex < realLength - 1; byteIndex += 1) bytes.push((word >>> (24 - 8 * byteIndex)) & 255);
  }
  return bytesToText(new Uint8Array(bytes));
};

// Base62 ASCII 变体：整体字节串视作大整数转 62 进制（0-9a-zA-Z），前导 0 字节用首字符保留。
const encodeBase62Ascii = (value: string): string => {
  const bytes = utf8Encoder.encode(value);
  if (!bytes.length) return '';
  let number = 0n;
  for (const byte of bytes) number = (number << 8n) + BigInt(byte);
  let output = '';
  while (number > 0n) {
    output = base62AsciiAlphabet[Number(number % 62n)] + output;
    number /= 62n;
  }
  for (const byte of bytes) {
    if (byte === 0) output = base62AsciiAlphabet[0] + output;
    else break;
  }
  return output;
};

const decodeBase62Ascii = (value: string): string => {
  const clean = value.trim();
  if (!clean) return '';
  let number = 0n;
  for (const char of clean) {
    const index = base62AsciiAlphabet.indexOf(char);
    if (index < 0) throw new Error(`Base62 ASCII 变体非法字符: ${char}`);
    number = number * 62n + BigInt(index);
  }
  const bytes: number[] = [];
  while (number > 0n) {
    bytes.unshift(Number(number & 255n));
    number >>= 8n;
  }
  for (const char of clean) {
    if (char === base62AsciiAlphabet[0]) bytes.unshift(0);
    else break;
  }
  return bytesToText(new Uint8Array(bytes));
};

// Base64 Multiline：标准 Base64 按 76 列折行；解码忽略全部空白。
const encodeBase64Multiline = (value: string): string => {
  if (!value) return '';
  const encoded = bytesToBase64(utf8Encoder.encode(value));
  return encoded.match(/.{1,76}/g)?.join('\n') ?? '';
};

const decodeBase64Multiline = (value: string): string => {
  const compact = requireCleanBase64(value);
  if (!compact) return '';
  return bytesToText(base64ToBytes(compact));
};

// Base64 Case-Mangled：base64 每 4 字符块独立解码出 3 字节，逐块穷举 2^n 大小写组合，
// 按 CTF 文本字节权重（小写字母/数字 1.5、{}_ - 2、其余可打印 0.5、不可打印 -2）取块内最优，同分偏向少改写。
const base64CharValue = (char: string): number => {
  const code = char.charCodeAt(0);
  if (code >= 65 && code <= 90) return code - 65;
  if (code >= 97 && code <= 122) return code - 97 + 26;
  if (code >= 48 && code <= 57) return code - 48 + 52;
  if (char === '+') return 62;
  if (char === '/') return 63;
  throw new Error(`Base64 含字母表之外的字符: ${char}`);
};

const caseMangledByteWeight = (byte: number): number => {
  if (byte >= 97 && byte <= 122) return 1.5;
  if (byte >= 48 && byte <= 57) return 1.5;
  if (byte === 123 || byte === 125 || byte === 95 || byte === 45) return 2;
  if ((byte >= 32 && byte <= 126) || byte === 9 || byte === 10 || byte === 13) return 0.5;
  return -2;
};

const decodeBase64CaseMangled = (value: string): string => {
  const compact = requireCleanBase64(value);
  if (!compact) return '';
  const body = compact.replace(/=+$/, '');
  const direct = utf8Decoder.decode(base64ToBytes(compact));
  if (!direct.includes('�') && printableRatio(direct) >= 0.95) return direct;
  const bytes: number[] = [];
  for (let index = 0; index < body.length; index += 4) {
    const block = body.slice(index, index + 4);
    const options = [...block].map(char => {
      const lower = char.toLowerCase();
      const upper = char.toUpperCase();
      return lower !== upper ? [char, char === lower ? upper : lower] : [char, char];
    });
    let bestBytes: number[] = [];
    let bestWeight = Number.NEGATIVE_INFINITY;
    let bestFlips = Number.POSITIVE_INFINITY;
    for (let variant = 0; variant < (1 << block.length); variant += 1) {
      let buffer = 0;
      let bits = 0;
      const out: number[] = [];
      let weight = 0;
      let flips = 0;
      for (let position = 0; position < block.length; position += 1) {
        const flip = (variant >> position) & 1;
        const pair = options[position];
        if (pair[flip] !== pair[0]) flips += 1;
        buffer = (buffer << 6) | base64CharValue(pair[flip]);
        bits += 6;
        if (bits >= 8) {
          const byte = (buffer >>> (bits - 8)) & 255;
          out.push(byte);
          weight += caseMangledByteWeight(byte);
          bits -= 8;
          buffer &= (1 << bits) - 1;
        }
      }
      if (weight > bestWeight || (weight === bestWeight && flips < bestFlips)) {
        bestWeight = weight;
        bestFlips = flips;
        bestBytes = out;
      }
    }
    bytes.push(...bestBytes);
  }
  const text = utf8Decoder.decode(new Uint8Array(bytes));
  if (text.includes('�') || printableRatio(text) < 0.9) throw new Error('Base64 大小写错乱解码失败：启发式未能恢复可读文本');
  return text;
};

// Base64 ↔ Hex：utf8 字节为中介的双向转换。
const base64ToHexText = (value: string): string => {
  const compact = requireCleanBase64(value);
  if (!compact) return '';
  return bytesToHex(base64ToBytes(compact));
};

const hexToBase64Text = (value: string): string => {
  if (!value.trim()) return '';
  return bytesToBase64(hexToBytes(value));
};

// Base Custom：大数进制 + base58 式前导零字节保留；表长 <16 或含重复字符报错。
const requireCustomAlphabet = (secret: string): string[] => {
  if (!secret) throw new Error('Base 自定义表需要提供字母表（secret 参数，默认为标准 Base64 表）');
  const chars = [...secret];
  if (chars.length < 16) throw new Error('Base 自定义表字母表至少需要 16 个字符');
  if (new Set(chars).size !== chars.length) throw new Error('Base 自定义表字母表存在重复字符');
  return chars;
};

const encodeBaseCustom = (value: string, secret: string): string => {
  const chars = requireCustomAlphabet(secret);
  const bytes = utf8Encoder.encode(value);
  if (!bytes.length) return '';
  const radix = BigInt(chars.length);
  let number = 0n;
  for (const byte of bytes) number = (number << 8n) + BigInt(byte);
  let output = '';
  while (number > 0n) {
    output = chars[Number(number % radix)] + output;
    number /= radix;
  }
  for (const byte of bytes) {
    if (byte === 0) output = chars[0] + output;
    else break;
  }
  return output;
};

const decodeBaseCustom = (value: string, secret: string): string => {
  const chars = requireCustomAlphabet(secret);
  const digitByChar = new Map(chars.map((char, index) => [char, index]));
  const clean = value.trim();
  if (!clean) return '';
  const radix = BigInt(chars.length);
  let number = 0n;
  for (const char of clean) {
    const digit = digitByChar.get(char);
    if (digit === undefined) throw new Error(`Base 自定义表包含字母表之外的字符: ${char}`);
    number = number * radix + BigInt(digit);
  }
  const bytes: number[] = [];
  while (number > 0n) {
    bytes.unshift(Number(number & 255n));
    number >>= 8n;
  }
  for (const char of clean) {
    if (char === chars[0]) bytes.unshift(0);
    else break;
  }
  return bytesToText(new Uint8Array(bytes));
};

// Base Multi-Decoding：单层按 hex → base64 → base32 → base91 尝试，解码结果需 ≥90% 可打印才算剥层成功；最多 12 层。
const candidateText = (text: string): string | null => {
  if (!text || text.includes('�')) return null;
  if (printableRatio(text) < 0.9) return null;
  return text;
};

const stripOneBaseLayer = (value: string): string | null => {
  const compact = value.replace(/\s+/g, '');
  if (compact.length >= 8 && compact.length % 2 === 0 && /^[0-9a-f]+$/i.test(compact)) {
    const text = candidateText(utf8Decoder.decode(hexToBytes(compact)));
    if (text) return text;
  }
  const body = compact.replace(/=+$/, '');
  const padding = compact.length - body.length;
  if (compact.length >= 8 && compact.length % 4 === 0 && padding <= 2 && /^[A-Za-z0-9+/]+$/.test(body)) {
    const text = candidateText(utf8Decoder.decode(base64ToBytes(compact)));
    if (text) return text;
  }
  if (compact.length >= 8 && compact.length % 8 === 0 && (/^[A-Z2-7]+={0,6}$/.test(compact) || /^[a-z2-7]+={0,6}$/.test(compact))) {
    const text = candidateText(utf8Decoder.decode(decodeBase32Bytes(compact)));
    if (text) return text;
  }
  if (compact.length >= 4) {
    // base91 字符集很宽，解码抛错即视为该层不是 base91（探测机制，非吞错）
    try {
      const text = candidateText(decodeBase91(compact));
      if (text) return text;
    } catch {
      // 该层不是合法 Base91，继续
    }
  }
  return null;
};

const decodeBaseMultiLayer = (value: string): string => {
  let current = value.trim();
  if (!current) return '';
  let layers = 0;
  for (let depth = 0; depth < 12; depth += 1) {
    const stripped = stripOneBaseLayer(current);
    if (stripped === null) break;
    current = stripped;
    layers += 1;
  }
  if (layers === 0) throw new Error('Base 混合多重解码：未能识别可剥离的 Base16/32/64/91 层');
  return current;
};

// Rot18：字母 ROT13 + 数字 ROT5，自反。
const mapRot18 = (value: string): string => {
  let output = '';
  for (const char of value) {
    const code = char.charCodeAt(0);
    if (code >= 65 && code <= 90) output += String.fromCharCode((code - 65 + 13) % 26 + 65);
    else if (code >= 97 && code <= 122) output += String.fromCharCode((code - 97 + 13) % 26 + 97);
    else if (code >= 48 && code <= 57) output += String.fromCharCode((code - 48 + 5) % 10 + 48);
    else output += char;
  }
  return output;
};

// Rot Special：按原字符类别逐字符映射——字母 ROT13、数字 ROT5、其余可打印 ASCII 33-126 做 ROT47；编码/解码同一函数。
const mapRotSpecial = (value: string): string => {
  let output = '';
  for (const char of value) {
    const code = char.charCodeAt(0);
    if (code >= 65 && code <= 90) output += String.fromCharCode((code - 65 + 13) % 26 + 65);
    else if (code >= 97 && code <= 122) output += String.fromCharCode((code - 97 + 13) % 26 + 97);
    else if (code >= 48 && code <= 57) output += String.fromCharCode((code - 48 + 5) % 10 + 48);
    else if (code >= 33 && code <= 126) output += String.fromCharCode(33 + (code - 33 + 47) % 94);
    else output += char;
  }
  return output;
};

export const parityBaseOperations: Operation[] = [
  {
    id: 'base92',
    category: 'binary',
    name: { zh: 'Base92', en: 'Base92' },
    summary: { zh: 'thenoviceoof Base92 高密度编码：91 个键盘可打字符加 ~ 空串符，每 13 bit 输出一对字符，密度高于 Base64 与 Base85。', en: 'thenoviceoof Base92: 91 typeable characters plus ~ for empty input, emitting a character pair per 13 bits; denser than Base64 and Base85.' },
  },
  {
    id: 'base100',
    category: 'binary',
    name: { zh: 'Base100（Emoji）', en: 'Base100 (Emoji)' },
    summary: { zh: '把每个字节映射成一个连续 emoji 区段（U+1F3F7 起）的趣味编码，输出整串表情。', en: 'Playful encoding mapping every byte into a consecutive emoji codepoint block starting at U+1F3F7.' },
  },
  {
    id: 'base85-rfc1924',
    category: 'binary',
    name: { zh: 'Base85（RFC 1924）', en: 'Base85 (RFC 1924)' },
    summary: { zh: 'RFC 1924 字母表的 Base85：4 字节一组转 5 字符，与 Python b85encode/b85decode 互通。', en: 'Base85 over the RFC 1924 alphabet: 4 bytes to 5 characters, interoperable with Python b85encode/b85decode.' },
  },
  {
    id: 'base62-ascii',
    category: 'binary',
    name: { zh: 'Base62 ASCII 变体', en: 'Base62 (0-9a-zA-Z)' },
    summary: { zh: '0-9a-zA-Z 顺序字母表的 Base62 大数编码，整体字节串视作一个大整数转 62 进制。', en: 'Base62 big-integer encoding over the 0-9a-zA-Z alphabet; the whole byte string is treated as one number.' },
  },
  {
    id: 'base64-multiline',
    category: 'binary',
    name: { zh: 'Base64 多行', en: 'Base64 Multiline' },
    summary: { zh: '标准 Base64 结果按 76 列折行（RFC 2045），解码时自动忽略换行与空白。', en: 'Standard Base64 wrapped at 76 columns per RFC 2045; decoding ignores line breaks and whitespace.' },
  },
  {
    id: 'base64-case-mangled',
    category: 'binary',
    name: { zh: 'Base64 大小写错乱解码', en: 'Base64 Case-Mangled Decoding' },
    summary: { zh: '对被统一大写/小写破坏的 Base64 做启发式大小写恢复，按解码结果可读性打分。', en: 'Heuristically restores letter casing of a Base64 string that lost it, scoring decoded readability.' },
    supportsEncode: false,
    decodeLabel: { zh: '恢复大小写并解码', en: 'Restore casing and decode' },
  },
  {
    id: 'base64-to-hex',
    category: 'binary',
    name: { zh: 'Base64 转 Hex', en: 'Base64 to Hex' },
    summary: { zh: 'Base64 与 Hex 双向互转，方便快速换算 payload 的两种常见形态。', en: 'Converts between Base64 and Hex in both directions.' },
    encodeLabel: { zh: 'Hex → Base64', en: 'Hex → Base64' },
    decodeLabel: { zh: 'Base64 → Hex', en: 'Base64 → Hex' },
  },
  {
    id: 'base-custom',
    category: 'binary',
    name: { zh: 'Base 自定义表', en: 'Base Custom Alphabet' },
    summary: { zh: '用自定义字母表（secret 参数，至少 16 个不重复字符）做大数进制编码，默认给标准 Base64 表。', en: 'Big-integer base encoding over a custom alphabet (secret param, at least 16 unique characters); defaults to the standard Base64 table.' },
    params: ['secret'],
  },
  {
    id: 'base-multi-decode',
    category: 'binary',
    name: { zh: 'Base 混合多重解码', en: 'Base16-32-64-91 Multi-Decoding' },
    summary: { zh: '递归识别并剥离 Base16/32/64/91 多层嵌套编码，常用于套娃 Base 题。', en: 'Recursively detects and peels nested Base16/32/64/91 layers for wrapped payloads.' },
    supportsEncode: false,
    decodeLabel: { zh: '逐层剥离解码', en: 'Peel layers and decode' },
  },
  {
    id: 'rot18',
    category: 'crypto',
    name: { zh: 'Rot18', en: 'Rot18' },
    summary: { zh: '字母做 ROT13、数字做 ROT5 的自反变换，常用于含数字的古典混合题。', en: 'Self-inverse transform applying ROT13 to letters and ROT5 to digits.' },
  },
  {
    id: 'rot-special',
    category: 'crypto',
    name: { zh: 'Rot Special', en: 'Rot Special' },
    summary: { zh: '按字符类别组合旋转：字母 ROT13、数字 ROT5、其余可打印 ASCII 符号 ROT47（随波逐流 Rot Special 流派）。', en: 'Category-wise combined ROT: ROT13 letters, ROT5 digits, and ROT47 for other printable ASCII (SuiBoZhuLiu Rot Special style).' },
  },
];

export const parityBaseDefaultParams: Partial<Record<ParamKey, string>> = {
  // secret 是全局共享键（operations.ts 字面量统一给空串）：base-custom 需要用户在密钥栏填自定义字母表。
};

export const parityBaseTransform = async (id: OperationId, direction: Direction, input: string, params: Record<ParamKey, string>): Promise<string> => {
  switch (id) {
    case 'base92': return direction === 'encode' ? encodeBase92(input) : decodeBase92(input);
    case 'base100': return direction === 'encode' ? encodeBase100(input) : decodeBase100(input);
    case 'base85-rfc1924': return direction === 'encode' ? encodeBase85Rfc1924(input) : decodeBase85Rfc1924(input);
    case 'base62-ascii': return direction === 'encode' ? encodeBase62Ascii(input) : decodeBase62Ascii(input);
    case 'base64-multiline': return direction === 'encode' ? encodeBase64Multiline(input) : decodeBase64Multiline(input);
    case 'base64-case-mangled':
      if (direction === 'encode') throw new Error('Base64 大小写错乱解码只支持解码方向');
      return decodeBase64CaseMangled(input);
    case 'base64-to-hex': return direction === 'encode' ? hexToBase64Text(input) : base64ToHexText(input);
    case 'base-custom': return direction === 'encode' ? encodeBaseCustom(input, params.secret) : decodeBaseCustom(input, params.secret);
    case 'base-multi-decode':
      if (direction === 'encode') throw new Error('Base 混合多重解码只支持解码方向');
      return decodeBaseMultiLayer(input);
    case 'rot18': return mapRot18(input);
    case 'rot-special': return mapRotSpecial(input);
    default: throw new Error(`parityBases 未支持的操作: ${id}`);
  }
};

// 形状探针：与码表同源；阈值防误报（base100 要求 ≥6 个 emoji 且 95% 命中；多重解码要求严格 base64 外形且一层解码后仍是高置信 base 载荷）。
const looksLikeBase100 = (value: string): boolean => {
  const chars = [...value.replace(/\s+/g, '')];
  if (chars.length < 6) return false;
  const hits = chars.filter(char => {
    const codePoint = char.codePointAt(0) ?? 0;
    return codePoint >= BASE100_FIRST && codePoint <= BASE100_LAST;
  }).length;
  return hits / chars.length >= 0.95;
};

const looksLikeBaseMulti = (value: string): boolean => {
  const compact = value.replace(/\s+/g, '');
  if (compact.length < 12) return false;
  const body = compact.replace(/=+$/, '');
  const padding = compact.length - body.length;
  if (compact.length % 4 !== 0 || padding > 2 || !/^[A-Za-z0-9+/]+$/.test(body)) return false;
  const inner = utf8Decoder.decode(base64ToBytes(compact));
  if (inner.includes('�') || inner.length < 8) return false;
  const cleanInner = inner.replace(/\s+/g, '');
  if (/^[0-9a-f]+$/.test(cleanInner) && cleanInner.length % 2 === 0) return true;
  if (/^[A-Z2-7]+={0,6}$/.test(cleanInner) || /^[a-z2-7]+={0,6}$/.test(cleanInner)) return true;
  const innerBody = cleanInner.replace(/=+$/, '');
  if (/^[A-Za-z0-9+/]+$/.test(innerBody) && cleanInner.length % 4 === 0 && printableRatio(inner) >= 0.9) return true;
  return false;
};

export const parityBaseLooksLike: ParityShapeProbe[] = [
  { id: 'base100', label: 'Base100 Emoji 密文', test: looksLikeBase100 },
  { id: 'base-multi-decode', label: '多重 Base 嵌套密文', test: looksLikeBaseMulti },
];

export const parityBaseVectors: ParityVector[] = [
  // 权威：thenoviceoof/base92 README（https://github.com/thenoviceoof/base92）
  { id: 'base92', plain: 'hello world', cipher: 'Fc_$aOTdKnsM*k' },
  { id: 'base92', plain: 'flag{base92_13bit}' },
  // 权威：AdamNiederer/base100 算法（byte → U+1F3F7+byte，https://github.com/AdamNiederer/base100）
  { id: 'base100', plain: 'Hello!', cipher: '\u{1F43F}\u{1F45C}\u{1F463}\u{1F463}\u{1F466}\u{1F418}' },
  { id: 'base100', plain: 'flag{emoji}' },
  // 权威：RFC 1924 §4 字母表 + CPython b85 语义（https://github.com/python/cpython/blob/main/Lib/base64.py）
  { id: 'base85-rfc1924', plain: 'Hello', cipher: 'NM&qnZv' },
  { id: 'base85-rfc1924', plain: 'flag{rfc1924}' },
  // 无公开权威向量，按 0-9a-zA-Z 大数模式自造 round-trip
  // 自造 round-trip（不设 cipher，避免计入权威对拍数）：0-9a-zA-Z 大数模式，dcode 流派
  { id: 'base62-ascii', plain: 'Hello123' },
  { id: 'base62-ascii', plain: 'flag{base62_ascii}' },
  // 权威：RFC 4648 §10 测试向量（https://datatracker.ietf.org/doc/html/rfc4648#section-10）
  { id: 'base64-multiline', plain: 'foobar', cipher: 'Zm9vYmFy' },
  // 76 列折行按 RFC 2045 §6.8 自造：58 字节 → 80 字符 → 76+4
  { id: 'base64-multiline', plain: 'A'.repeat(58), cipher: `${'QUFB'.repeat(19)}\nQQ==` },
  // 启发式自造：全大写破坏的 base64('flag{case_mangled}')，direction=decode 单向
  { id: 'base64-case-mangled', plain: 'flag{case_mangled}', cipher: 'ZMXHZ3TJYXNLX21HBMDSZWR9', direction: 'decode' },
  // 权威：RFC 4648 §10（foobar ↔ 666f6f626172）与 node Buffer 对拍
  { id: 'base64-to-hex', plain: '666f6f626172', cipher: 'Zm9vYmFy' },
  { id: 'base64-to-hex', plain: '00ff10', cipher: 'AP8Q' },
  // 权威：Wikipedia Base58 示例（Hello World! → 2NEpo7TZRRrLZSi2U，https://en.wikipedia.org/wiki/Base58）
  { id: 'base-custom', plain: 'Hello World!', cipher: '2NEpo7TZRRrLZSi2U', params: { secret: '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz' } },
  // 标准表交叉对拍：96 bit 输入在大数模式下与 RFC 4648 Base64 位对位一致
  { id: 'base-custom', plain: 'flag{custom}', cipher: 'ZmxhZ3tjdXN0b219', params: { secret: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/' } },
  // 自造：base64(base64('123456')) 双层嵌套，direction=decode 单向
  { id: 'base-multi-decode', plain: '123456', cipher: 'TVRJek5EVTI=', direction: 'decode' },
  // 自造：base64(hex('flag{layers})) 嵌套，direction=decode 单向
  { id: 'base-multi-decode', plain: 'flag{layers}', cipher: 'NjY2YzYxNjc3YjZjNjE3OTY1NzI3Mzdk', direction: 'decode' },
  // 权威：Wikipedia ROT13/ROT18（Hello → Uryyb；https://en.wikipedia.org/wiki/ROT13）
  { id: 'rot18', plain: 'Hello, World! 12345', cipher: 'Uryyb, Jbeyq! 67890' },
  // 无公开权威向量，按随波逐流 Rot Special 惯例定义自造 round-trip
  { id: 'rot-special', plain: 'Hello, World. 123', cipher: 'Uryyb[ Jbeyq] 678' },
];
