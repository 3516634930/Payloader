// CODEC-IMPORTS
import { base32Alphabet, base32HexAlphabet, base45Alphabet, base58Alphabet, base62Alphabet, base91Alphabet, crockfordBase32Alphabet, latin1Decoder, utf8Decoder, utf8Encoder } from './alphabets';
// CODEC-IMPORTS-END
export const label = (value: { zh: string; en: string }, language: 'zh' | 'en') => value[language] || value.zh;
export const bytesToHex = (bytes: Uint8Array) => Array.from(bytes).map(byte => byte.toString(16).padStart(2, '0')).join('');
export const bytesToBuffer = (bytes: Uint8Array) => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
export const hexToBytes = (value: string) => {
  const clean = value.replace(/\\x/gi, '').replace(/0x/gi, '').replace(/[^0-9a-f]/gi, '');
  if (!clean) return new Uint8Array();
  if (clean.length % 2 !== 0) throw new Error('Hex 长度必须是偶数');
  return new Uint8Array(clean.match(/.{2}/g)?.map(byte => Number.parseInt(byte, 16)) || []);
};

export const bytesToBase64 = (bytes: Uint8Array) => {
  let binary = '';
  for (let index = 0; index < bytes.length; index += 0x8000) {
    binary += String.fromCharCode(...bytes.slice(index, index + 0x8000));
  }
  return btoa(binary);
};

export const base64ToBase64Url = (value: string) => value.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');

export const base64ToBytes = (value: string) => {
  const normalized = value.trim().replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, char => char.charCodeAt(0));
};

export const textToBase64 = (value: string) => bytesToBase64(utf8Encoder.encode(value));
export const base64ToText = (value: string) => utf8Decoder.decode(base64ToBytes(value));
export const toBase64Url = (value: string) => textToBase64(value).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');

export const fromBase64Url = (value: string) => base64ToText(value);

export const getBase32Alphabet = (variant: string) => {
  if (variant === 'hex') return base32HexAlphabet;
  if (variant === 'decimal') return crockfordBase32Alphabet;
  return base32Alphabet;
};

export const normalizeBase32Input = (value: string, variant: string) => {
  const clean = value.toUpperCase().replace(/\s+/g, '').replace(/=+$/g, '');
  if (variant !== 'decimal') return clean;
  return clean.replace(/-/g, '').replace(/[IL]/g, '1').replace(/O/g, '0');
};

export const encodeBase32 = (value: string, variant = 'special') => {
  const selectedAlphabet = getBase32Alphabet(variant);
  const bytes = utf8Encoder.encode(value);
  let bits = 0;
  let bitLength = 0;
  let output = '';
  for (const byte of bytes) {
    bits = (bits << 8) | byte;
    bitLength += 8;
    while (bitLength >= 5) {
      output += selectedAlphabet[(bits >>> (bitLength - 5)) & 31];
      bitLength -= 5;
    }
  }
  if (bitLength > 0) output += selectedAlphabet[(bits << (5 - bitLength)) & 31];
  return variant === 'decimal' ? output : output.padEnd(Math.ceil(output.length / 8) * 8, '=');
};

export const decodeBase32Bytes = (value: string, variant = 'special') => {
  const selectedAlphabet = getBase32Alphabet(variant);
  const clean = normalizeBase32Input(value, variant);
  let bits = 0;
  let bitLength = 0;
  const bytes: number[] = [];
  for (const char of clean) {
    const index = selectedAlphabet.indexOf(char);
    if (index < 0) throw new Error(`Base32 非法字符: ${char}`);
    bits = (bits << 5) | index;
    bitLength += 5;
    if (bitLength >= 8) {
      bytes.push((bits >>> (bitLength - 8)) & 255);
      bitLength -= 8;
    }
  }
  return new Uint8Array(bytes);
};

export const decodeBase32 = (value: string, variant = 'special') => utf8Decoder.decode(decodeBase32Bytes(value, variant));

export const encodeBase45 = (value: string) => {
  const bytes = utf8Encoder.encode(value);
  let output = '';
  for (let index = 0; index < bytes.length; index += 2) {
    if (index + 1 < bytes.length) {
      let number = bytes[index] * 256 + bytes[index + 1];
      output += base45Alphabet[number % 45];
      number = Math.floor(number / 45);
      output += base45Alphabet[number % 45];
      number = Math.floor(number / 45);
      output += base45Alphabet[number % 45];
    } else {
      let number = bytes[index];
      output += base45Alphabet[number % 45];
      number = Math.floor(number / 45);
      output += base45Alphabet[number % 45];
    }
  }
  return output;
};

export const decodeBase45 = (value: string) => {
  const clean = value.trim().replace(/\s+/g, '');
  if (!clean) return '';
  const bytes: number[] = [];
  for (let index = 0; index < clean.length;) {
    const c1 = base45Alphabet.indexOf(clean[index]);
    const c2 = base45Alphabet.indexOf(clean[index + 1]);
    if (c1 < 0 || c2 < 0) throw new Error('Base45 包含非法字符');
    if (index + 2 < clean.length) {
      const c3 = base45Alphabet.indexOf(clean[index + 2]);
      if (c3 < 0) throw new Error('Base45 包含非法字符');
      const number = c1 + c2 * 45 + c3 * 2025;
      if (number > 0xffff) throw new Error('Base45 数据块超出范');
      bytes.push(Math.floor(number / 256), number % 256);
      index += 3;
    } else {
      const number = c1 + c2 * 45;
      if (number > 0xff) throw new Error('Base45 单字节数据块超出范围');
      bytes.push(number);
      index += 2;
    }
  }
  return utf8Decoder.decode(new Uint8Array(bytes));
};

export const bytesFromTextOrHex = (value: string) => {
  const clean = value.trim().replace(/\\x/gi, '').replace(/0x/gi, '').replace(/[\s,;:_-]/g, '');
  if (clean && clean.length % 2 === 0 && /^[0-9a-f]+$/i.test(clean)) return hexToBytes(clean);
  return utf8Encoder.encode(value);
};

export const encodeBase58Bytes = (bytes: Uint8Array) => {
  let number = 0n;
  for (const byte of bytes) number = (number << 8n) + BigInt(byte);
  let output = '';
  while (number > 0n) {
    const remainder = Number(number % 58n);
    output = base58Alphabet[remainder] + output;
    number /= 58n;
  }
  for (const byte of bytes) {
    if (byte === 0) output = base58Alphabet[0] + output;
    else break;
  }
  return output || base58Alphabet[0];
};

export const decodeBase58Bytes = (value: string) => {
  let number = 0n;
  const clean = value.trim();
  for (const char of clean) {
    const index = base58Alphabet.indexOf(char);
    if (index < 0) throw new Error(`Base58 非法字符: ${char}`);
    number = number * 58n + BigInt(index);
  }
  const bytes: number[] = [];
  while (number > 0n) {
    bytes.unshift(Number(number & 255n));
    number >>= 8n;
  }
  for (const char of clean) {
    if (char === base58Alphabet[0]) bytes.unshift(0);
    else break;
  }
  return new Uint8Array(bytes);
};

export const encodeBase58 = (value: string) => encodeBase58Bytes(utf8Encoder.encode(value));
export const decodeBase58 = (value: string) => { const bytes = decodeBase58Bytes(value); const text = utf8Decoder.decode(bytes); return text.includes('�') ? bytesToHex(bytes) : text; };

export const sha256Bytes = async (bytes: Uint8Array) => new Uint8Array(await crypto.subtle.digest('SHA-256', bytesToBuffer(bytes)));

export const base58CheckChecksum = async (payload: Uint8Array) => (await sha256Bytes(await sha256Bytes(payload))).slice(0, 4);

export const encodeBase58Check = async (value: string, versionHex: string) => {
  const version = hexToBytes(versionHex || '00');
  if (!version.length) throw new Error('Base58Check 版本字节不能为空，例如 00、6f、80');
  const body = new Uint8Array([...version, ...bytesFromTextOrHex(value)]);
  const checksum = await base58CheckChecksum(body);
  return encodeBase58Bytes(new Uint8Array([...body, ...checksum]));
};

export const decodeBase58Check = async (value: string) => {
  const bytes = decodeBase58Bytes(value);
  if (bytes.length < 5) throw new Error('Base58Check 数据过短，至少需要 1 字节版本和 4 字节 checksum');
  const body = bytes.slice(0, -4);
  const checksum = bytes.slice(-4);
  const expected = await base58CheckChecksum(body);
  const payload = body.slice(1);
  const checksumValid = bytesToHex(checksum) === bytesToHex(expected);
  return JSON.stringify({
    versionHex: bytesToHex(body.slice(0, 1)),
    payloadHex: bytesToHex(payload),
    payloadText: utf8Decoder.decode(payload).replace(/\p{Cc}/gu, '.'),
    checksumHex: bytesToHex(checksum),
    expectedChecksumHex: bytesToHex(expected),
    checksumValid,
    totalBytes: bytes.length,
  }, null, 2);
};

export const bech32Charset = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
export const bech32Generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
export const bech32Constants = { special: 1, hex: 0x2bc830a3 } as const;

export const bech32Polymod = (values: number[]) => {
  let checksum = 1;
  for (const value of values) {
    const top = checksum >>> 25;
    checksum = ((checksum & 0x1ffffff) << 5) ^ value;
    for (let index = 0; index < 5; index += 1) {
      if ((top >>> index) & 1) checksum ^= bech32Generator[index];
    }
  }
  return checksum >>> 0;
};

export const bech32HrpExpand = (hrp: string) => [
  ...Array.from(hrp, char => char.charCodeAt(0) >>> 5),
  0,
  ...Array.from(hrp, char => char.charCodeAt(0) & 31),
];

export const convertBits = (data: number[], fromBits: number, toBits: number, pad: boolean) => {
  let accumulator = 0;
  let bits = 0;
  const maxValue = (1 << toBits) - 1;
  const output: number[] = [];
  for (const value of data) {
    if (value < 0 || value >> fromBits) throw new Error('Bech32 数据包含超出位宽的值');
    accumulator = (accumulator << fromBits) | value;
    bits += fromBits;
    while (bits >= toBits) {
      bits -= toBits;
      output.push((accumulator >>> bits) & maxValue);
    }
  }
  if (pad) {
    if (bits > 0) output.push((accumulator << (toBits - bits)) & maxValue);
  } else if (bits >= fromBits || ((accumulator << (toBits - bits)) & maxValue)) {
    throw new Error('Bech32 padding 非零或不完整');
  }
  return output;
};

export const bech32CreateChecksum = (hrp: string, data: number[], variant: string) => {
  const constant = variant === 'hex' ? bech32Constants.hex : bech32Constants.special;
  const values = [...bech32HrpExpand(hrp), ...data, 0, 0, 0, 0, 0, 0];
  const polymod = bech32Polymod(values) ^ constant;
  return Array.from({ length: 6 }, (_, index) => (polymod >>> (5 * (5 - index))) & 31);
};

export const bech32VerifyVariant = (hrp: string, data: number[]) => {
  const check = bech32Polymod([...bech32HrpExpand(hrp), ...data]);
  if (check === bech32Constants.special) return 'bech32';
  if (check === bech32Constants.hex) return 'bech32m';
  return null;
};

export const normalizeBech32Hrp = (value: string) => {
  const hrp = value.trim().toLowerCase() || 'bc';
  if (!Array.from(hrp).every(char => {
    const code = char.charCodeAt(0);
    return code >= 33 && code <= 126;
  })) throw new Error('Bech32 HRP 只能包含 ASCII 33-126 范围字符');
  return hrp;
};

export const encodeBech32 = (value: string, hrpValue: string, variant: string) => {
  const hrp = normalizeBech32Hrp(hrpValue);
  const data = convertBits(Array.from(bytesFromTextOrHex(value)), 8, 5, true);
  const checksum = bech32CreateChecksum(hrp, data, variant);
  const payload = [...data, ...checksum].map(item => bech32Charset[item]).join('');
  return `${hrp}1${payload}`;
};

// BIP-173/BIP-350 segwit 地址 hrp：这些前缀下数据部分首词是 witness version（0-16），不属于程序数据。
const SEGWIT_HRPS = ['bc', 'tb', 'bcrt', 'tbs'];

export const decodeBech32 = (value: string) => {
  const clean = value.trim();
  if (!clean) throw new Error('Bech32 输入为空');
  if (clean !== clean.toLowerCase() && clean !== clean.toUpperCase()) throw new Error('Bech32 不允许大小写混用');
  const lower = clean.toLowerCase();
  const separator = lower.lastIndexOf('1');
  if (separator < 1 || separator + 7 > lower.length) throw new Error('Bech32 分隔符或 checksum 长度无效');
  const hrp = lower.slice(0, separator);
  const data = Array.from(lower.slice(separator + 1), char => {
    const index = bech32Charset.indexOf(char);
    if (index < 0) throw new Error(`Bech32 非法字符: ${char}`);
    return index;
  });
  const variant = bech32VerifyVariant(hrp, data);
  const words = data.slice(0, -6);
  // segwit 地址剥离 witness version 首词再 5→8 转换（BIP-173 segwit_addr.decode 语义）——
  // 否则 P2WPKH/P2WSH 因 padding 非零抛错、Taproot 32 字节程序静默错位丢位。
  // 长度门（剩余词数 32/52 = 程序 20/32 字节，覆盖 P2WPKH/P2WSH/P2TR）：本仓编码器不写版本词，
  // hrp 为 bc/tb 的普通数据首词也可能 ≤16，无长度门会误剥。
  const witnessVersion = SEGWIT_HRPS.includes(hrp)
    && words.length > 0 && words[0] <= 16
    && (words.length === 33 || words.length === 53)
    ? words[0]
    : null;
  const programWords = witnessVersion === null ? words : words.slice(1);
  const bytes = new Uint8Array(convertBits(programWords, 5, 8, false));
  return JSON.stringify({
    hrp,
    variant: variant || 'checksum-invalid',
    checksumValid: Boolean(variant),
    witnessVersion,
    programBytes: bytes.length,
    dataWords: words,
    dataHex: bytesToHex(bytes),
    dataText: utf8Decoder.decode(bytes).replace(/\p{Cc}/gu, '.'),
  }, null, 2);
};

export const encodeBase62 = (value: string) => {
  const bytes = utf8Encoder.encode(value);
  let number = 0n;
  for (const byte of bytes) number = (number << 8n) + BigInt(byte);
  let output = '';
  while (number > 0n) {
    const remainder = Number(number % 62n);
    output = base62Alphabet[remainder] + output;
    number /= 62n;
  }
  for (const byte of bytes) {
    if (byte === 0) output = base62Alphabet[0] + output;
    else break;
  }
  return output || base62Alphabet[0];
};

export const decodeBase62 = (value: string) => {
  let number = 0n;
  const clean = value.trim();
  for (const char of clean) {
    const index = base62Alphabet.indexOf(char);
    if (index < 0) throw new Error(`Base62 非法字符: ${char}`);
    number = number * 62n + BigInt(index);
  }
  const bytes: number[] = [];
  while (number > 0n) {
    bytes.unshift(Number(number & 255n));
    number >>= 8n;
  }
  for (const char of clean) {
    if (char === base62Alphabet[0]) bytes.unshift(0);
    else break;
  }
  return utf8Decoder.decode(new Uint8Array(bytes));
};

export const encodeBase36 = (value: string) => {
  const bytes = utf8Encoder.encode(value);
  let number = 0n;
  for (const byte of bytes) number = (number << 8n) + BigInt(byte);
  let output = number.toString(36).toUpperCase();
  const leadingZeros = Array.from(bytes).findIndex(byte => byte !== 0);
  const zeroCount = leadingZeros < 0 ? bytes.length : leadingZeros;
  if (zeroCount > 0) output = `${'0'.repeat(zeroCount)}${output === '0' ? '' : output}`;
  return output || '0';
};

export const decodeBase36 = (value: string) => {
  const clean = value.trim().replace(/\s+/g, '').toUpperCase();
  if (!/^[0-9A-Z]+$/.test(clean)) throw new Error('Base36 非法字符，只允许 0-9A-Z');
  let number = 0n;
  for (const char of clean) number = number * 36n + BigInt(Number.parseInt(char, 36));
  const bytes: number[] = [];
  while (number > 0n) {
    bytes.unshift(Number(number & 255n));
    number >>= 8n;
  }
  for (const char of clean) {
    if (char === '0') bytes.unshift(0);
    else break;
  }
  return utf8Decoder.decode(new Uint8Array(bytes));
};

export const encodeBase91 = (value: string) => {
  const bytes = utf8Encoder.encode(value);
  let queue = 0;
  let bits = 0;
  let output = '';
  for (const byte of bytes) {
    queue |= byte << bits;
    bits += 8;
    if (bits > 13) {
      let entry = queue & 8191;
      if (entry > 88) {
        queue >>= 13;
        bits -= 13;
      } else {
        entry = queue & 16383;
        queue >>= 14;
        bits -= 14;
      }
      output += base91Alphabet[entry % 91] + base91Alphabet[Math.floor(entry / 91)];
    }
  }
  if (bits) {
    output += base91Alphabet[queue % 91];
    if (bits > 7 || queue > 90) output += base91Alphabet[Math.floor(queue / 91)];
  }
  return output;
};

export const decodeBase91 = (value: string) => {
  let queue = 0;
  let bits = 0;
  let valueBuffer = -1;
  const bytes: number[] = [];
  for (const char of value.replace(/\s+/g, '')) {
    const digit = base91Alphabet.indexOf(char);
    if (digit < 0) throw new Error(`Base91 非法字符: ${char}`);
    if (valueBuffer < 0) {
      valueBuffer = digit;
    } else {
      valueBuffer += digit * 91;
      queue |= valueBuffer << bits;
      bits += (valueBuffer & 8191) > 88 ? 13 : 14;
      do {
        bytes.push(queue & 255);
        queue >>= 8;
        bits -= 8;
      } while (bits > 7);
      valueBuffer = -1;
    }
  }
  if (valueBuffer >= 0) bytes.push((queue | (valueBuffer << bits)) & 255);
  return utf8Decoder.decode(new Uint8Array(bytes));
};

export const encodeAscii85 = (value: string) => {
  const bytes = utf8Encoder.encode(value);
  let output = '';
  for (let index = 0; index < bytes.length; index += 4) {
    const chunk = bytes.slice(index, index + 4);
    const padded = new Uint8Array(4);
    padded.set(chunk);
    let number = new DataView(padded.buffer).getUint32(0, false);
    if (chunk.length === 4 && number === 0) {
      output += 'z';
      continue;
    }
    const chars = Array.from({ length: 5 }, () => {
      const char = String.fromCharCode((number % 85) + 33);
      number = Math.floor(number / 85);
      return char;
    }).reverse().join('');
    output += chars.slice(0, chunk.length + 1);
  }
  return `<~${output}~>`;
};

export const decodeAscii85 = (value: string) => {
  const clean = value.trim().replace(/^<~/, '').replace(/~>$/, '').replace(/\s+/g, '');
  if (!clean) return '';
  const expanded = clean.replace(/z/g, '!!!!!');
  const bytes: number[] = [];
  for (let index = 0; index < expanded.length; index += 5) {
    const chunk = expanded.slice(index, index + 5);
    const padded = chunk.padEnd(5, 'u');
    let number = 0;
    for (const char of padded) {
      const code = char.charCodeAt(0);
      if (code < 33 || code > 117) throw new Error('ASCII85 包含非法字符');
      number = number * 85 + (code - 33);
    }
    const buffer = new Uint8Array(4);
    new DataView(buffer.buffer).setUint32(0, number >>> 0, false);
    const usefulBytes = chunk.length < 5 ? chunk.length - 1 : 4;
    for (let itemIndex = 0; itemIndex < usefulBytes; itemIndex += 1) bytes.push(buffer[itemIndex]);
  }
  return utf8Decoder.decode(new Uint8Array(bytes));
};

export const encodeZ85 = (value: string) => {
  const z85Alphabet = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#';
  const bytes = utf8Encoder.encode(value);
  if (bytes.length % 4 !== 0) throw new Error('Z85 编码要求 UTF-8 字节长度是 4 的倍数');
  let output = '';
  for (let index = 0; index < bytes.length; index += 4) {
    let number = new DataView(bytes.buffer, bytes.byteOffset + index, 4).getUint32(0, false);
    const chars = Array.from({ length: 5 }, () => {
      const char = z85Alphabet[number % 85];
      number = Math.floor(number / 85);
      return char;
    }).reverse();
    output += chars.join('');
  }
  return output;
};

export const decodeZ85 = (value: string) => {
  const z85Alphabet = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#';
  const clean = value.trim().replace(/\s+/g, '');
  if (clean.length % 5 !== 0) throw new Error('Z85 解码要求长度是 5 的倍数');
  const bytes: number[] = [];
  for (let index = 0; index < clean.length; index += 5) {
    let number = 0;
    for (const char of clean.slice(index, index + 5)) {
      const digit = z85Alphabet.indexOf(char);
      if (digit < 0) throw new Error(`Z85 非法字符: ${char}`);
      number = number * 85 + digit;
    }
    const buffer = new Uint8Array(4);
    new DataView(buffer.buffer).setUint32(0, number >>> 0, false);
    bytes.push(...buffer);
  }
  return utf8Decoder.decode(new Uint8Array(bytes));
};

export const uuByte = (value: number) => value ? String.fromCharCode((value & 0x3f) + 32) : '`';

export const uuLineEncode = (chunk: Uint8Array) => {
  let output = uuByte(chunk.length);
  for (let index = 0; index < chunk.length; index += 3) {
    const a = chunk[index] || 0;
    const b = chunk[index + 1] || 0;
    const c = chunk[index + 2] || 0;
    output += uuByte(a >> 2);
    output += uuByte(((a << 4) | (b >> 4)) & 0x3f);
    output += uuByte(((b << 2) | (c >> 6)) & 0x3f);
    output += uuByte(c & 0x3f);
  }
  return output;
};

export const encodeUuencode = (value: string, blockLabel: string) => {
  const bytes = utf8Encoder.encode(value);
  const filename = (blockLabel || 'payload.txt').trim().replace(/\s+/g, '_') || 'payload.txt';
  const lines = [`begin 644 ${filename}`];
  for (let index = 0; index < bytes.length; index += 45) lines.push(uuLineEncode(bytes.slice(index, index + 45)));
  lines.push('`', 'end');
  return lines.join('\n');
};

export const decodeUuencode = (value: string) => {
  const lines = value.trim().split(/\r?\n/);
  const begin = lines.findIndex(line => /^begin\s+\d+\s+/.test(line));
  if (begin < 0) throw new Error('UUencode 缺少 begin ');
  const bytes: number[] = [];
  for (const line of lines.slice(begin + 1)) {
    if (line === 'end') break;
    if (!line) continue;
    const length = (line.charCodeAt(0) - 32) & 0x3f;
    if (length === 0) continue;
    const data = line.slice(1);
    const decoded: number[] = [];
    for (let index = 0; index < data.length; index += 4) {
      const chunk = data.slice(index, index + 4).padEnd(4, '`');
      const values = Array.from(chunk).map(char => (char.charCodeAt(0) - 32) & 0x3f);
      decoded.push((values[0] << 2) | (values[1] >> 4));
      decoded.push(((values[1] & 15) << 4) | (values[2] >> 2));
      decoded.push(((values[2] & 3) << 6) | values[3]);
    }
    bytes.push(...decoded.slice(0, length));
  }
  // 二进制载荷无损：UU/XX 可携带任意字节，latin1 输出保证 ≥0x80 字节不被 utf8 解码损坏。
  return latin1Decoder.decode(new Uint8Array(bytes));
};

export const xxencodeAlphabet = '+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

export const xxLineEncode = (chunk: Uint8Array) => {
  let output = xxencodeAlphabet[chunk.length & 0x3f];
  for (let index = 0; index < chunk.length; index += 3) {
    const a = chunk[index] || 0;
    const b = chunk[index + 1] || 0;
    const c = chunk[index + 2] || 0;
    output += xxencodeAlphabet[a >> 2];
    output += xxencodeAlphabet[((a << 4) | (b >> 4)) & 0x3f];
    output += xxencodeAlphabet[((b << 2) | (c >> 6)) & 0x3f];
    output += xxencodeAlphabet[c & 0x3f];
  }
  return output;
};

export const encodeXxencode = (value: string) => {
  const bytes = utf8Encoder.encode(value);
  const lines = ['begin 6xx payload.txt'];
  for (let index = 0; index < bytes.length; index += 45) lines.push(xxLineEncode(bytes.slice(index, index + 45)));
  lines.push('+', 'end');
  return lines.join('\n');
};

export const decodeXxencode = (value: string) => {
  const lines = value.trim().split(/\r?\n/);
  const begin = lines.findIndex(line => /^begin\s+\S+\s+/.test(line));
  if (begin < 0) throw new Error('XXencode 缺少 begin 行');
  const dataLines = lines.slice(begin + 1);
  const bytes: number[] = [];
  for (const line of dataLines) {
    if (/^end\s*$/i.test(line)) break;
    if (!line) continue;
    const length = xxencodeAlphabet.indexOf(line[0]);
    if (length < 0) throw new Error('XXencode 含字母表之外的字符');
    if (length === 0) continue;
    const data = line.slice(1);
    const decoded: number[] = [];
    for (let index = 0; index < data.length; index += 4) {
      const chunk = data.slice(index, index + 4).padEnd(4, '+');
      const values = Array.from(chunk).map(char => {
        const alphabetIndex = xxencodeAlphabet.indexOf(char);
        if (alphabetIndex < 0) throw new Error('XXencode 含字母表之外的字符');
        return alphabetIndex;
      });
      decoded.push((values[0] << 2) | (values[1] >> 4));
      decoded.push(((values[1] & 15) << 4) | (values[2] >> 2));
      decoded.push(((values[2] & 3) << 6) | values[3]);
    }
    bytes.push(...decoded.slice(0, length));
  }
  // 二进制载荷无损：UU/XX 可携带任意字节，latin1 输出保证 ≥0x80 字节不被 utf8 解码损坏。
  return latin1Decoder.decode(new Uint8Array(bytes));
};

export const zBase32Alphabet = 'ybndrfg8ejkmcpqxot1uwisza345h769';

export const encodeZBase32 = (value: string) => {
  const bytes = utf8Encoder.encode(value);
  let output = '';
  let accumulator = 0;
  let bits = 0;
  for (const byte of bytes) {
    accumulator = ((accumulator << 8) | byte) & 0xffff;
    bits += 8;
    while (bits >= 5) {
      output += zBase32Alphabet[(accumulator >>> (bits - 5)) & 0x1f];
      bits -= 5;
    }
  }
  if (bits > 0) output += zBase32Alphabet[(accumulator << (5 - bits)) & 0x1f];
  return output;
};

export const decodeZBase32 = (value: string) => {
  const clean = value.replace(/\s+/g, '').toLowerCase();
  if (!clean) throw new Error('请输入 z-base-32 文本');
  const bytes = new Uint8Array(Math.floor(clean.length * 5 / 8));
  let position = 0;
  let accumulator = 0;
  let bits = 0;
  for (const char of clean) {
    const alphabetIndex = zBase32Alphabet.indexOf(char);
    if (alphabetIndex < 0) throw new Error('z-base-32 含字母表之外的字符');
    accumulator = ((accumulator << 5) | alphabetIndex) & 0xffff;
    bits += 5;
    if (bits >= 8) {
      bytes[position] = (accumulator >>> (bits - 8)) & 0xff;
      position += 1;
      bits -= 8;
    }
  }
  return utf8Decoder.decode(bytes);
};

// Base32768：15 bit/字符的 Unicode 高密度编码，码点范围表取自 qntm/base32768 v5.0.1（MIT）。
// 末尾不足 15 bit 时补 1 填充：8-14 bit 用 15-bit 表，1-7 bit 补满 7 bit 用 7-bit 表。
export const base32768PairStrings = ['ҠҿԀԟڀڿݠޟ߀ߟကဟႠႿᄀᅟᆀᆟᇠሿበቿዠዿጠጿᎠᏟᐠᙟᚠᛟកសᠠᡟᣀᣟᦀᦟ᧠᧿ᨠᨿᯀᯟᰀᰟᴀᴟ⇠⇿⋀⋟⍀⏟␀␟─❟➀➿⠀⥿⦠⦿⨠⩟⪀⪿⫠⭟ⰀⰟⲀⳟⴀⴟⵀⵟ⺠⻟㇀㇟㐀䶟䷀龿ꀀꑿ꒠꒿ꔀꗿꙀꙟꚠꛟ꜀ꝟꞀꞟꡀꡟ', 'ƀƟɀʟ'];

let base32768Tables: { encode: Record<number, string[]>; decode: Record<string, [number, number]> } | null = null;

export const ensureBase32768Tables = () => {
  if (base32768Tables) return base32768Tables;
  const encode: Record<number, string[]> = {};
  const decode: Record<string, [number, number]> = {};
  base32768PairStrings.forEach((pairString, r) => {
    const numZBits = 15 - 8 * r;
    const repertoire: string[] = [];
    const pairs = pairString.match(/../gu) || [];
    for (const pair of pairs) {
      const first = pair.charCodeAt(0);
      const last = pair.charCodeAt(1);
      for (let codePoint = first; codePoint <= last; codePoint += 1) repertoire.push(String.fromCodePoint(codePoint));
    }
    encode[numZBits] = repertoire;
    repertoire.forEach((chr, z) => { decode[chr] = [numZBits, z]; });
  });
  base32768Tables = { encode, decode };
  return base32768Tables;
};

export const encodeBase32768 = (value: string) => {
  const tables = ensureBase32768Tables();
  const bytes = utf8Encoder.encode(value);
  let output = '';
  let z = 0;
  let numZBits = 0;
  for (const uint8 of bytes) {
    for (let j = 7; j >= 0; j -= 1) {
      z = (z << 1) | ((uint8 >> j) & 1);
      numZBits += 1;
      if (numZBits === 15) {
        output += tables.encode[15][z];
        z = 0;
        numZBits = 0;
      }
    }
  }
  if (numZBits !== 0) {
    while (!(numZBits in tables.encode)) {
      z = (z << 1) + 1;
      numZBits += 1;
    }
    output += tables.encode[numZBits][z];
  }
  return output;
};

export const decodeBase32768 = (value: string) => {
  const tables = ensureBase32768Tables();
  const text = value.replace(/\s+/g, '');
  if (!text) throw new Error('请输入 Base32768 文本');
  const bytes: number[] = [];
  let uint8 = 0;
  let numUint8Bits = 0;
  for (let index = 0; index < text.length; index += 1) {
    const entry = tables.decode[text[index]];
    if (!entry) throw new Error(`Base32768 含无法识别的字符: ${text[index]}`);
    const [numZBits, z] = entry;
    if (numZBits !== 15 && index !== text.length - 1) throw new Error('Base32768 校验字符出现在末尾之前');
    for (let j = numZBits - 1; j >= 0; j -= 1) {
      uint8 = (uint8 << 1) | ((z >> j) & 1);
      numUint8Bits += 1;
      if (numUint8Bits === 8) {
        bytes.push(uint8);
        uint8 = 0;
        numUint8Bits = 0;
      }
    }
  }
  if (uint8 !== (1 << numUint8Bits) - 1) throw new Error('Base32768 填充位校验失败');
  return utf8Decoder.decode(new Uint8Array(bytes));
};

// 表内占比 + 生僻范围字符（Myanmar/Georgian/Hangul Jamo/彝文/瓦伊文等常见文本不会出现的区段）
// 联合判断。Base32768 码点表覆盖大量常用 CJK，仅靠占比会把中文正文误判为候选。
export const looksLikeBase32768 = (value: string, requireExotic: boolean) => {
  const compact = value.replace(/\s+/g, '');
  if (compact.length < 6) return false;
  const tables = ensureBase32768Tables();
  let hits = 0;
  let exotic = 0;
  for (const char of compact) {
    if (tables.decode[char]) hits += 1;
    if (/[\u1000-\u11ff\u1780-\u17ff\ua000-\ua4cf\ua500-\ua63f]/u.test(char)) exotic += 1;
  }
  return hits >= compact.length * 0.9 && (!requireExotic || exotic > 0);
};

// ==================== JSFuck / aaencode / jjencode 静态还原 ====================
// 安全底线：本区块严禁 eval、动态函数构造与任何真实代码执行。
// "执行"由 sxEvaluate 静态模拟：Function 构造器访问只产生标记对象，函数体仅以本
// 求值器的受限子集递归求值；一旦函数体出现 alert 类调用或求值失败，立即把函数体
// 字符串作为"还原源码"捕获并终止。步数、嵌套深度、字符串长度、输入长度四重上限。

export interface SxCtorRef { kind: 'ctor'; name: string }
export interface SxOpaqueFn { kind: 'opaque'; name: string }
export interface SxNativeFn { kind: 'native'; name: string; call: (args: SxValue[]) => SxValue }
export interface SxRegexVal { kind: 'regex'; source: string; flags: string }
export interface SxExecRef { kind: 'exec'; body: string }
export interface SxPlainObj { [key: string]: SxValue }

export type SxValue = string | number | boolean | undefined | null | SxValue[] | SxPlainObj | SxCtorRef | SxOpaqueFn | SxNativeFn | SxRegexVal | SxExecRef;
