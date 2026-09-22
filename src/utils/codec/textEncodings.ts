// CODEC-IMPORTS
import { alphabet, baudotFigures, baudotFiguresShift, baudotLetters, baudotLettersShift, bubbleBabbleConsonants, bubbleBabbleVowels, crc16Table, crc32Table, dnaMaps, gsm7DefaultAlphabet, gsm7ExtensionAlphabet, gsm7ReverseAlphabet, keyboardRows, morseMap, natoWords, reverseBaudotFigures, reverseBaudotLetters, reverseDnaMaps, reverseGsm7ExtensionAlphabet, reverseMorseMap, reverseNatoWords, utf7DirectChars, utf8Decoder, utf8Encoder, zeroWidthOne, zeroWidthZero } from './alphabets';
import { base64ToBytes, bytesToBase64, bytesToHex, hexToBytes } from './bases';
// CODEC-IMPORTS-END
export const htmlEncode = (value: string, variant: string) => {
  if (variant === 'decimal') return Array.from(value).map(char => `&#${char.codePointAt(0)};`).join('');
  if (variant === 'hex') return Array.from(value).map(char => `&#x${char.codePointAt(0)?.toString(16)};`).join('');
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
};

export const htmlNamedEntities: Record<string, string> = {
  amp: '&',
  apos: "'",
  gt: '>',
  lt: '<',
  nbsp: '\u00a0',
  quot: '"',
};

export const htmlDecodeFallback = (value: string) => value.replace(/&(?:(#x[0-9a-f]+)|(#\d+)|([a-z][a-z0-9]+));/gi, (match, hex, decimal, named) => {
  if (hex) {
    const codePoint = Number.parseInt(hex.slice(2), 16);
    return Number.isSafeInteger(codePoint) && codePoint <= 0x10ffff ? String.fromCodePoint(codePoint) : match;
  }
  if (decimal) {
    const codePoint = Number.parseInt(decimal.slice(1), 10);
    return Number.isSafeInteger(codePoint) && codePoint <= 0x10ffff ? String.fromCodePoint(codePoint) : match;
  }
  return htmlNamedEntities[String(named).toLowerCase()] || match;
});

export const htmlDecode = (value: string) => {
  if (typeof document === 'undefined' || typeof document.createElement !== 'function') return htmlDecodeFallback(value);
  const textarea = document.createElement('textarea');
  textarea.innerHTML = value;
  return textarea.value;
};

export const xmlDecode = (value: string) => value
  .replace(/&amp;/g, '&')
  .replace(/&lt;/g, '<')
  .replace(/&gt;/g, '>')
  .replace(/&quot;/g, '"')
  .replace(/&apos;/g, "'")
  .replace(/&#(\d+);/g, (_, n) => String.fromCodePoint(Number(n)))
  .replace(/&#x([0-9a-fA-F]+);/g, (_, h) => String.fromCodePoint(parseInt(h, 16)));

export const xmlEncode = (value: string, variant: string) => {
  if (variant === 'decimal') return Array.from(value).map(char => `&#${char.codePointAt(0)};`).join('');
  if (variant === 'hex') return Array.from(value).map(char => `&#x${char.codePointAt(0)?.toString(16)};`).join('');
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
};

export const unicodeEncode = (value: string, variant: string) => {
  if (variant === 'hex') {
    return Array.from(utf8Encoder.encode(value)).map(byte => `\\x${byte.toString(16).padStart(2, '0')}`).join('');
  }
  if (variant === 'brace') {
    return Array.from(value).map(char => `\\u{${char.codePointAt(0)?.toString(16)}}`).join('');
  }
  return Array.from(value).map(char => {
    const units = [];
    for (let index = 0; index < char.length; index += 1) {
      units.push(`\\u${char.charCodeAt(index).toString(16).padStart(4, '0')}`);
    }
    return units.join('');
  }).join('');
};

export const unicodeDecode = (value: string) => value
  .replace(/\\u\{([0-9a-fA-F]+)\}/g, (_, hex) => String.fromCodePoint(Number.parseInt(hex, 16)))
  .replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) => String.fromCharCode(Number.parseInt(hex, 16)))
  .replace(/(?:\\x[0-9a-fA-F]{2})+/g, match => utf8Decoder.decode(hexToBytes(match)));

export const utf16BeBytes = (value: string) => {
  const bytes: number[] = [];
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    bytes.push((unit >>> 8) & 255, unit & 255);
  }
  return new Uint8Array(bytes);
};

export const utf16BeToText = (bytes: Uint8Array) => {
  if (bytes.length % 2 !== 0) throw new Error('UTF-7 shifted sequence must decode to even UTF-16BE bytes');
  let output = '';
  for (let index = 0; index < bytes.length; index += 2) {
    output += String.fromCharCode((bytes[index] << 8) | bytes[index + 1]);
  }
  return output;
};

export const utf7Encode = (value: string) => {
  let output = '';
  let shifted = '';
  const flush = () => {
    if (!shifted) return;
    output += `+${bytesToBase64(utf16BeBytes(shifted)).replace(/=+$/g, '')}-`;
    shifted = '';
  };
  for (const char of Array.from(value)) {
    if (char === '+') {
      flush();
      output += '+-';
    } else if (utf7DirectChars.has(char)) {
      flush();
      output += char;
    } else {
      shifted += char;
    }
  }
  flush();
  return output;
};

export const utf7Decode = (value: string) => value.replace(/\+([A-Za-z0-9+/]*)(-?)/g, (_match, body: string) => {
  if (!body) return '+';
  const padded = body.padEnd(Math.ceil(body.length / 4) * 4, '=');
  return utf16BeToText(base64ToBytes(padded));
});

export const cStringEncode = (value: string) => Array.from(value).map(char => {
  if (char === '\n') return '\\n';
  if (char === '\r') return '\\r';
  if (char === '\t') return '\\t';
  if (char === '\b') return '\\b';
  if (char === '\f') return '\\f';
  if (char === '\v') return '\\v';
  if (char === '\\') return '\\\\';
  if (char === '"') return '\\"';
  if (char === "'") return "\\'";
  const codePoint = char.codePointAt(0) || 0;
  if (codePoint >= 0x20 && codePoint <= 0x7e) return char;
  if (codePoint <= 0xff) return `\\x${codePoint.toString(16).padStart(2, '0')}`;
  if (codePoint <= 0xffff) return `\\u${codePoint.toString(16).padStart(4, '0')}`;
  return `\\U${codePoint.toString(16).padStart(8, '0')}`;
}).join('');

export const cStringDecode = (value: string) => value.replace(/\\(U[0-9a-fA-F]{8}|u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|[0-7]{1,3}|[nrtbfv0'"\\])/g, (_match, escape: string) => {
  if (escape === 'n') return '\n';
  if (escape === 'r') return '\r';
  if (escape === 't') return '\t';
  if (escape === 'b') return '\b';
  if (escape === 'f') return '\f';
  if (escape === 'v') return '\v';
  if (escape === '0') return '\0';
  if (escape === '"' || escape === "'" || escape === '\\') return escape;
  if (escape[0] === 'x') return String.fromCharCode(Number.parseInt(escape.slice(1), 16));
  if (escape[0] === 'u' || escape[0] === 'U') return String.fromCodePoint(Number.parseInt(escape.slice(1), 16));
  return String.fromCharCode(Number.parseInt(escape, 8));
});

export const decodeJavaScriptEscapes = (value: string) => value
  .replace(/\\\r?\n/g, '')
  .replace(/\\(u\{[0-9a-fA-F]+\}|u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|0(?!\d)|[nrtbfv"'\\`])/g, (_match, escape: string) => {
    if (escape === 'n') return '\n';
    if (escape === 'r') return '\r';
    if (escape === 't') return '\t';
    if (escape === 'b') return '\b';
    if (escape === 'f') return '\f';
    if (escape === 'v') return '\v';
    if (escape === '0') return '\0';
    if (escape === '"' || escape === "'" || escape === '`' || escape === '\\') return escape;
    if (escape.startsWith('u{')) return String.fromCodePoint(Number.parseInt(escape.slice(2, -1), 16));
    if (escape[0] === 'u' || escape[0] === 'x') return String.fromCodePoint(Number.parseInt(escape.slice(1), 16));
    return escape;
  });

export const jsStringDecode = (value: string) => {
  const trimmed = value.trim();
  if (!trimmed) return '';
  if (
    (trimmed.startsWith('"') && trimmed.endsWith('"'))
    || (trimmed.startsWith("'") && trimmed.endsWith("'"))
    || (trimmed.startsWith('`') && trimmed.endsWith('`'))
  ) {
    const quote = trimmed[0];
    if (quote === '"') {
      return JSON.parse(trimmed);
    }
    return decodeJavaScriptEscapes(trimmed.slice(1, -1));
  }
  return decodeJavaScriptEscapes(trimmed);
};

export const jsonStringDecode = (value: string) => {
  const trimmed = value.trim();
  if (!trimmed) return '';
  try {
    const parsed = JSON.parse(trimmed);
    return typeof parsed === 'string' ? parsed : JSON.stringify(parsed, null, 2);
  } catch {
    return jsStringDecode(trimmed);
  }
};

export const separatorValue = (separator: string) => {
  if (separator === 'comma') return ',';
  if (separator === 'newline') return '\n';
  return ' ';
};

export const binaryEncode = (value: string, separator: string) => Array.from(utf8Encoder.encode(value))
  .map(byte => byte.toString(2).padStart(8, '0'))
  .join(separatorValue(separator));

export const binaryDecode = (value: string) => {
  const chunks = value.match(/[01]{8}/g) || [];
  if (!chunks.length) throw new Error('没有找到 8 位二进制字节');
  return utf8Decoder.decode(new Uint8Array(chunks.map(chunk => Number.parseInt(chunk, 2))));
};

export const asciiEncode = (value: string, separator: string) => Array.from(value)
  .map(char => String(char.codePointAt(0)))
  .join(separatorValue(separator));

export const asciiDecode = (value: string) => value
  .split(/[\s,;|]+/)
  .filter(Boolean)
  .map(code => String.fromCodePoint(Number.parseInt(code, 10)))
  .join('');

export const octalEncode = (value: string, separator: string) => Array.from(utf8Encoder.encode(value))
  .map(byte => byte.toString(8).padStart(3, '0'))
  .join(separatorValue(separator));

export const octalDecode = (value: string) => {
  const clean = value.trim();
  const tokens = clean.match(/\\[0-7]{1,3}|0o[0-7]+|0[0-7]{1,3}|[0-7]{1,3}/gi) || [];
  const normalized = tokens.length
    ? tokens.map(token => token.replace(/^\\/u, '').replace(/^0o/iu, '').replace(/^0(?=[0-7])/u, ''))
    : /^[0-7]+$/.test(clean) && clean.length % 3 === 0
      ? clean.match(/.{3}/g) || []
      : [];
  if (!normalized.length) throw new Error('没有找到八进制字');
  return utf8Decoder.decode(new Uint8Array(normalized.map(token => Number.parseInt(token, 8))));
};

export const a1z26Encode = (value: string, separator: string) => Array.from(value.toUpperCase())
  .map(char => {
    const index = alphabet.indexOf(char);
    return index >= 0 ? String(index + 1) : char.trim() ? char : '/';
  })
  .join(separatorValue(separator));

export const a1z26Decode = (value: string) => value
  .trim()
  .split(/[\s,;|/.-]+/)
  .filter(Boolean)
  .map(token => {
    const number = Number.parseInt(token, 10);
    return number >= 1 && number <= 26 ? alphabet[number - 1] : token;
  })
  .join('');

export const morseEncode = (value: string) => Array.from(value.toUpperCase())
  .map(char => (char === ' ' ? '/' : morseMap[char] || char))
  .join(' ');

export const morseDecode = (value: string) => value
  .trim()
  .split(/\s+/)
  .map(code => (code === '/' ? ' ' : reverseMorseMap[code] || code))
  .join('');

// Pollux cipher: digits represent ·  —  × (dot/dash/separator) based on a key
// Common CTF variant: 0=dot(·), 1=dash(—), 8/9=separator; others are noise
export const polluxDecode = (value: string) => {
  // mapping[digit] → '.', '-', ' ', or noise (skip)
  // default mapping: 0→. 1→- 2→. 3→- 4→. 5→- 6→. 7→- 8→' ' 9→' '
  const dotChars = new Set('024');
  const dashChars = new Set('135');
  const sepChars = new Set('6789 ');
  let morse = '';
  for (const ch of value.replace(/[^0-9 ]/g, '')) {
    if (dotChars.has(ch)) morse += '.';
    else if (dashChars.has(ch)) morse += '-';
    else if (sepChars.has(ch)) morse += ' ';
  }
  return morseDecode(morse);
};

export const natoEncode = (value: string, separator: string) => Array.from(value.toUpperCase())
  .map(char => (char === ' ' ? '/' : natoWords[char] || char))
  .join(separatorValue(separator));

export const natoDecode = (value: string) => value
  .trim()
  .replace(/\bx[-\s]ray\b/gi, 'Xray')  // normalize X-Ray / X Ray → Xray before splitting
  .split(/[\s,;|-]+/)
  .filter(Boolean)
  .map(token => (token === '/' ? ' ' : reverseNatoWords[token.toLowerCase()] || token))
  .join('');

export const baudotEncode = (value: string, separator: string) => {
  let mode: 'letters' | 'figures' = 'letters';
  const output: string[] = [];
  for (const rawChar of Array.from(value)) {
    const char = rawChar.toUpperCase();
    if (baudotLetters[char]) {
      if (mode !== 'letters') {
        output.push(baudotLettersShift);
        mode = 'letters';
      }
      output.push(baudotLetters[char]);
      continue;
    }
    if (baudotFigures[rawChar]) {
      if (mode !== 'figures') {
        output.push(baudotFiguresShift);
        mode = 'figures';
      }
      output.push(baudotFigures[rawChar]);
      continue;
    }
    if (rawChar === '\t') output.push(baudotLetters[' ']);
  }
  return output.join(separatorValue(separator));
};

export const baudotDecode = (value: string) => {
  const chunks = value.match(/[01]{5}/g) || [];
  if (!chunks.length) throw new Error('Baudot 解码需要 5-bit 二进制分组');
  let mode: 'letters' | 'figures' = 'letters';
  return chunks.map(chunk => {
    if (chunk === baudotLettersShift) {
      mode = 'letters';
      return '';
    }
    if (chunk === baudotFiguresShift) {
      mode = 'figures';
      return '';
    }
    return mode === 'letters'
      ? reverseBaudotLetters[chunk] || '?'
      : reverseBaudotFigures[chunk] || '?';
  }).join('');
};

export const bcdEncode = (value: string, separator: string) => {
  const digits = value.replace(/\D/g, '');
  if (!digits) throw new Error('BCD 编码需要十进制数字');
  return Array.from(digits).map(digit => Number(digit).toString(2).padStart(4, '0')).join(separatorValue(separator));
};

export const bcdDecode = (value: string) => {
  const chunks = value.match(/[01]{4}/g) || [];
  if (!chunks.length) throw new Error('BCD 解码需要 4-bit 二进制分组');
  return chunks.map(chunk => {
    const digit = Number.parseInt(chunk, 2);
    if (digit > 9) throw new Error(`BCD nibble ${chunk} 超出 0-9 范围`);
    return String(digit);
  }).join('');
};

export const parseBinaryOrDecimalTokens = (value: string) => value
  .trim()
  .split(/[\s,;|]+/)
  .filter(Boolean)
  .map(token => {
    const binary = /^0b([01]+)$/i.exec(token);
    if (binary) return { raw: token, value: BigInt(`0b${binary[1]}`), width: binary[1].length, binary: true };
    const decimal = /^0d(\d+)$/i.exec(token);
    if (decimal) {
      const parsed = BigInt(decimal[1]);
      return { raw: token, value: parsed, width: Math.max(1, parsed.toString(2).length), binary: false };
    }
    if (/^[01]+$/.test(token)) return { raw: token, value: BigInt(`0b${token}`), width: token.length, binary: true };
    if (/^\d+$/.test(token)) {
      const parsed = BigInt(token);
      return { raw: token, value: parsed, width: Math.max(1, parsed.toString(2).length), binary: false };
    }
    throw new Error(`无法解析整数: ${token}；二进制可用 0b 前缀，十进制可用 0d 前缀`);
  });

export const bigIntToBinary = (value: bigint, width: number) => value.toString(2).padStart(width, '0');

export const grayEncode = (value: string, separator: string) => {
  const tokens = parseBinaryOrDecimalTokens(value);
  if (!tokens.length) throw new Error('Gray Code 编码需要二进制或十进制整数');
  return tokens
    .map(token => {
      const gray = token.value ^ (token.value >> 1n);
      return token.binary ? bigIntToBinary(gray, token.width) : gray.toString();
    })
    .join(separatorValue(separator));
};

export const grayDecode = (value: string, separator: string) => {
  const tokens = parseBinaryOrDecimalTokens(value);
  if (!tokens.length) throw new Error('Gray Code 解码需要二进制或十进制整数');
  return tokens
    .map(token => {
      let binary = token.value;
      for (let shifted = binary >> 1n; shifted > 0n; shifted >>= 1n) binary ^= shifted;
      return token.binary ? bigIntToBinary(binary, token.width) : binary.toString();
    })
    .join(separatorValue(separator));
};

export const dnaEncode = (value: string, variant: string, separator: string) => {
  const map = dnaMaps[variant] || dnaMaps.special;
  return Array.from(utf8Encoder.encode(value))
    .map(byte => byte.toString(2).padStart(8, '0').match(/../g)?.map(pair => map[pair]).join('') || '')
    .join(separatorValue(separator));
};

export const dnaDecode = (value: string, variant: string) => {
  const map = reverseDnaMaps[variant] || reverseDnaMaps.special;
  const clean = value.toUpperCase().replace(/[^ACGT]/g, '');
  if (!clean || clean.length % 4 !== 0) throw new Error('DNA 解码需要 A/C/G/T，且长度为 4 的倍数');
  const bits = Array.from(clean).map(base => {
    const pair = map[base];
    if (!pair) throw new Error(`未知 DNA 碱基: ${base}`);
    return pair;
  }).join('');
  const bytes = bits.match(/.{8}/g)?.map(chunk => Number.parseInt(chunk, 2)) || [];
  return utf8Decoder.decode(new Uint8Array(bytes));
};

export const zeroWidthEncode = (value: string) => Array.from(utf8Encoder.encode(value))
  .map(byte => byte.toString(2).padStart(8, '0'))
  .join('')
  .replace(/0/g, zeroWidthZero)
  .replace(/1/g, zeroWidthOne);

export const zeroWidthDecode = (value: string) => {
  const bits = Array.from(value)
    .filter(char => char === zeroWidthZero || char === zeroWidthOne)
    .map(char => (char === zeroWidthZero ? '0' : '1'))
    .join('');
  if (!bits || bits.length % 8 !== 0) throw new Error('零宽字符解码需要完整的 8-bit 字节序列');
  const bytes = bits.match(/.{8}/g)?.map(chunk => Number.parseInt(chunk, 2)) || [];
  return utf8Decoder.decode(new Uint8Array(bytes));
};

export const packGsm7Septets = (septets: number[]) => {
  const output: number[] = [];
  let accumulator = 0;
  let bitCount = 0;
  for (const septet of septets) {
    accumulator |= (septet & 0x7f) << bitCount;
    bitCount += 7;
    while (bitCount >= 8) {
      output.push(accumulator & 0xff);
      accumulator >>>= 8;
      bitCount -= 8;
    }
  }
  if (bitCount > 0) output.push(accumulator & 0xff);
  return new Uint8Array(output);
};

export const unpackGsm7Septets = (bytes: Uint8Array) => {
  const septets: number[] = [];
  let accumulator = 0;
  let bitCount = 0;
  for (const byte of bytes) {
    accumulator |= byte << bitCount;
    bitCount += 8;
    while (bitCount >= 7) {
      septets.push(accumulator & 0x7f);
      accumulator >>>= 7;
      bitCount -= 7;
    }
  }
  return septets;
};

export const gsm7SeptetsToText = (septets: number[]) => {
  let output = '';
  for (let index = 0; index < septets.length; index += 1) {
    const septet = septets[index];
    if (septet === 0x1b) {
      const next = septets[index + 1];
      if (next == null) throw new Error('GSM 7-bit 格式错误：末尾 ESC 缺少扩展字符');
      const extended = reverseGsm7ExtensionAlphabet[next];
      if (extended == null) throw new Error(`GSM 7-bit 格式错误：未知扩展码 0x${next.toString(16).padStart(2, '0')}`);
      output += extended;
      index += 1;
      continue;
    }
    output += gsm7DefaultAlphabet[septet] || '?';
  }
  return output;
};

export type Gsm7PackedPayload = {
  encoding?: string;
  septetCount: number;
  packedHex: string;
};

export const parseGsm7SeptetCount = (value: unknown) => {
  const numeric = typeof value === 'number'
    ? value
    : typeof value === 'string' && /^\d+$/.test(value.trim())
      ? Number(value.trim())
      : Number.NaN;
  if (!Number.isSafeInteger(numeric) || numeric < 0) throw new Error('GSM 7-bit septetCount 必须是非负整数');
  return numeric;
};

export const unpackCountedGsm7Septets = (bytes: Uint8Array, septetCount: number) => {
  const expectedByteLength = Math.ceil((septetCount * 7) / 8);
  if (bytes.length !== expectedByteLength) {
    throw new Error(`GSM 7-bit 长度不一致：${septetCount} septets 应为 ${expectedByteLength} bytes，实际为 ${bytes.length}`);
  }
  const unpacked = unpackGsm7Septets(bytes);
  if (septetCount > unpacked.length) throw new Error('GSM 7-bit septetCount 超出 packed 数据容量');
  const septets = unpacked.slice(0, septetCount);
  if (bytesToHex(packGsm7Septets(septets)) !== bytesToHex(bytes)) {
    throw new Error('GSM 7-bit packed 数据包含非零填充位或与 septetCount 不一致');
  }
  return septets;
};

export const parseCountedGsm7Payload = (value: string): Gsm7PackedPayload | null => {
  const text = value.trim();
  if (text.startsWith('{')) {
    let payload: Record<string, unknown>;
    try {
      payload = JSON.parse(text) as Record<string, unknown>;
    } catch {
      throw new Error('GSM 7-bit JSON 格式错误');
    }
    const packedHex = payload.packedHex ?? payload.hex;
    const septetCount = payload.septetCount ?? payload.septets ?? payload.length;
    if (typeof packedHex !== 'string' || septetCount == null) {
      throw new Error('GSM 7-bit JSON 需要 packedHex 和 septetCount');
    }
    return {
      encoding: typeof payload.encoding === 'string' ? payload.encoding : undefined,
      septetCount: parseGsm7SeptetCount(septetCount),
      packedHex,
    };
  }

  if (/\b(?:septetCount|septets|packedHex)\b/i.test(text)) {
    const countMatch = text.match(/\b(?:septetCount|septets)\s*[:=]\s*(\d+)/i);
    const hexMatch = text.match(/\b(?:packedHex|hex)\s*[:=]\s*((?:0x)?[0-9a-f][0-9a-f\s:_-]*)/i);
    if (!countMatch || !hexMatch) throw new Error('GSM 7-bit 显式长度格式需要 septetCount 和 packedHex');
    return {
      septetCount: parseGsm7SeptetCount(countMatch[1]),
      packedHex: hexMatch[1],
    };
  }
  return null;
};

export const gsm7Encode = (value: string) => {
  const septets: number[] = [];
  for (const char of Array.from(value)) {
    const direct = gsm7ReverseAlphabet.get(char);
    if (direct != null) {
      septets.push(direct);
      continue;
    }
    const extended = gsm7ExtensionAlphabet[char];
    if (extended != null) {
      septets.push(0x1b, extended);
      continue;
    }
    throw new Error(`GSM 7-bit 不支持字符: ${char}`);
  }
  return JSON.stringify({
    encoding: 'gsm7-packed',
    septetCount: septets.length,
    packedHex: bytesToHex(packGsm7Septets(septets)),
  }, null, 2);
};

export const gsm7Decode = (value: string) => {
  const counted = parseCountedGsm7Payload(value);
  if (counted) {
    const bytes = hexToBytes(counted.packedHex);
    return gsm7SeptetsToText(unpackCountedGsm7Septets(bytes, counted.septetCount));
  }

  const bytes = hexToBytes(value);
  const septets = unpackGsm7Septets(bytes);
  if (bytes.length > 0 && bytes.length % 7 === 0 && septets[septets.length - 1] === 0) {
    throw new Error('GSM 7-bit 裸 Hex 的 septet count 存在歧义；请提供包含 septetCount 和 packedHex 的格式');
  }
  if (bytesToHex(packGsm7Septets(septets)) !== bytesToHex(bytes)) {
    throw new Error('GSM 7-bit packed 数据包含非零填充位；请提供正确的 septetCount');
  }
  return gsm7SeptetsToText(septets);
};

export const yEncEncode = (value: string) => Array.from(utf8Encoder.encode(value))
  .map(byte => {
    const encoded = (byte + 42) & 0xff;
    if (encoded === 0 || encoded === 10 || encoded === 13 || encoded === 61) {
      return `=${String.fromCharCode((encoded + 64) & 0xff)}`;
    }
    return String.fromCharCode(encoded);
  })
  .join('');

export const yEncDecode = (value: string) => {
  const body = value
    .split(/\r?\n/)
    .filter(line => !/^=y(?:begin|part|end)\b/i.test(line))
    .join('\n');
  const bytes: number[] = [];
  for (let index = 0; index < body.length; index += 1) {
    let encoded = body.charCodeAt(index) & 0xff;
    if (body[index] === '=') {
      index += 1;
      if (index >= body.length) throw new Error('yEnc 转义序列不完');
      encoded = (body.charCodeAt(index) - 64) & 0xff;
    }
    bytes.push((encoded - 42) & 0xff);
  }
  return utf8Decoder.decode(new Uint8Array(bytes));
};

export const bubbleIndex = (alphabet: string, char: string, label: string) => {
  const index = alphabet.indexOf(char);
  if (index < 0) throw new Error(`Bubble Babble ${label} 字符不合法: ${char}`);
  return index;
};

export const bubbleBabbleEncode = (value: string) => {
  const bytes = utf8Encoder.encode(value);
  let seed = 1;
  let output = 'x';
  const rounds = Math.floor(bytes.length / 2) + 1;
  for (let round = 0; round < rounds; round += 1) {
    if (round + 1 < rounds || bytes.length % 2 !== 0) {
      const byte1 = bytes[round * 2];
      output += bubbleBabbleVowels[(((byte1 >>> 6) & 3) + seed) % 6];
      output += bubbleBabbleConsonants[(byte1 >>> 2) & 15];
      output += bubbleBabbleVowels[((byte1 & 3) + Math.floor(seed / 6)) % 6];
      if (round + 1 < rounds) {
        const byte2 = bytes[round * 2 + 1];
        output += bubbleBabbleConsonants[(byte2 >>> 4) & 15];
        output += '-';
        output += bubbleBabbleConsonants[byte2 & 15];
        seed = (seed * 5 + byte1 * 7 + byte2) % 36;
      }
    } else {
      output += bubbleBabbleVowels[seed % 6];
      output += bubbleBabbleConsonants[16];
      output += bubbleBabbleVowels[Math.floor(seed / 6)];
    }
  }
  return `${output}x`;
};

export const bubbleBabbleDecode = (value: string) => {
  const clean = value.trim().toLowerCase().replace(/-/g, '');
  if (!/^x[a-z]+x$/.test(clean)) throw new Error('Bubble Babble 必须以 x 开头并以 x 结束');
  const body = clean.slice(1, -1);
  const bytes: number[] = [];
  let seed = 1;
  for (let offset = 0; offset < body.length; offset += 5) {
    const chunk = body.slice(offset, offset + 5);
    if (chunk.length === 3) {
      const c1 = bubbleIndex(bubbleBabbleConsonants, chunk[1], 'consonant');
      if (c1 === 16) break;
      const b1 = (((bubbleIndex(bubbleBabbleVowels, chunk[0], 'vowel') - (seed % 6) + 6) % 6) << 6)
        | (c1 << 2)
        | ((bubbleIndex(bubbleBabbleVowels, chunk[2], 'vowel') - Math.floor(seed / 6) + 6) % 6);
      bytes.push(b1 & 0xff);
      break;
    }
    if (chunk.length !== 5) throw new Error('Bubble Babble 分组长度不合法');
    const b1 = (((bubbleIndex(bubbleBabbleVowels, chunk[0], 'vowel') - (seed % 6) + 6) % 6) << 6)
      | (bubbleIndex(bubbleBabbleConsonants, chunk[1], 'consonant') << 2)
      | ((bubbleIndex(bubbleBabbleVowels, chunk[2], 'vowel') - Math.floor(seed / 6) + 6) % 6);
    const b2 = (bubbleIndex(bubbleBabbleConsonants, chunk[3], 'consonant') << 4)
      | bubbleIndex(bubbleBabbleConsonants, chunk[4], 'consonant');
    bytes.push(b1 & 0xff, b2 & 0xff);
    seed = (seed * 5 + b1 * 7 + b2) % 36;
  }
  return utf8Decoder.decode(new Uint8Array(bytes));
};

export const quotedPrintableEncode = (value: string) => {
  const bytes = utf8Encoder.encode(value);
  let line = '';
  let output = '';
  const push = (segment: string) => {
    if (line.length + segment.length > 73) {
      output += `${line}=\r\n`;
      line = '';
    }
    line += segment;
  };
  for (const byte of bytes) {
    const safe =
      (byte >= 33 && byte <= 60) ||
      (byte >= 62 && byte <= 126) ||
      byte === 9 ||
      byte === 32;
    push(safe ? String.fromCharCode(byte) : `=${byte.toString(16).toUpperCase().padStart(2, '0')}`);
  }
  return output + line;
};

export const quotedPrintableDecode = (value: string) => {
  const normalized = value.replace(/=\r?\n/g, '');
  const bytes: number[] = [];
  for (let index = 0; index < normalized.length; index += 1) {
    const char = normalized[index];
    if (char === '=') {
      const hex = normalized.slice(index + 1, index + 3);
      if (!/^[0-9a-fA-F]{2}$/.test(hex)) throw new Error('Quoted-Printable 十六进制片段不完');
      bytes.push(Number.parseInt(hex, 16));
      index += 2;
    } else {
      bytes.push(char.charCodeAt(0));
    }
  }
  return utf8Decoder.decode(new Uint8Array(bytes));
};

export const encodeUtf16Bytes = (value: string, variant: string, separator: string) => {
  const littleEndian = variant !== 'hex';
  const bytes = Array.from(value).flatMap(char => {
    const unit = char.charCodeAt(0);
    return littleEndian ? [unit & 0xff, unit >> 8] : [unit >> 8, unit & 0xff];
  });
  return bytes.map(byte => byte.toString(16).padStart(2, '0')).join(separatorValue(separator));
};

export const decodeUtf16Bytes = (value: string, variant: string) => {
  const bytes = Array.from(hexToBytes(value));
  if (bytes.length % 2 !== 0) throw new Error('UTF-16 字节序列长度必须为偶数');
  const littleEndian = variant !== 'hex';
  let output = '';
  for (let index = 0; index < bytes.length; index += 2) {
    const unit = littleEndian ? bytes[index] | (bytes[index + 1] << 8) : (bytes[index] << 8) | bytes[index + 1];
    output += String.fromCharCode(unit);
  }
  return output;
};

export const keyboardShift = (value: string, variant: string, decode = false) => {
  const baseDirection = variant === 'hex' ? -1 : 1;
  const direction = decode ? -baseDirection : baseDirection;
  const lookup = new Map<string, string>();
  for (const row of keyboardRows) {
    Array.from(row).forEach((char, index, chars) => {
      const next = chars[index + direction];
      if (next) lookup.set(char, next);
    });
  }
  return Array.from(value).map(char => {
    const lower = char.toLowerCase();
    const mapped = lookup.get(lower);
    if (!mapped) return char;
    return char === lower ? mapped : mapped.toUpperCase();
  }).join('');
};

export const encodeUnixTime = (value: string) => {
  const input = value.trim();
  if (!input) return '';
  const date = new Date(input);
  if (Number.isNaN(date.getTime())) throw new Error('无法解析输入时间，请使用 ISO 时间或浏览器可识别的时间格式');
  return JSON.stringify({
    iso: date.toISOString(),
    unixSeconds: Math.floor(date.getTime() / 1000),
    unixMilliseconds: date.getTime(),
  }, null, 2);
};

export const decodeUnixTime = (value: string): string => {
  const input = value.trim();
  if (!input) return '';
  if (/^[[{]/.test(input)) {
    try {
      const parsed = JSON.parse(input) as Record<string, unknown>;
      const unixMilliseconds = Number(parsed.unixMilliseconds);
      const unixSeconds = Number(parsed.unixSeconds);
      if (Number.isFinite(unixMilliseconds)) return decodeUnixTime(String(Math.trunc(unixMilliseconds)));
      if (Number.isFinite(unixSeconds)) return decodeUnixTime(String(Math.trunc(unixSeconds)));
    } catch {
      // Fall through to raw timestamp parsing.
    }
  }
  if (!/^-?\d+$/.test(input)) throw new Error('时间戳必须是整数');
  const numeric = Number(input);
  const ms = input.length < 13 ? numeric * 1000 : numeric;
  const date = new Date(ms);
  if (Number.isNaN(date.getTime())) throw new Error('时间戳超出可解析范围');
  return JSON.stringify({
    iso: date.toISOString(),
    local: date.toLocaleString(),
    unixSeconds: Math.floor(ms / 1000),
    unixMilliseconds: ms,
  }, null, 2);
};

export const rot47 = (value: string) => Array.from(value).map(char => {
  const code = char.charCodeAt(0);
  return code >= 33 && code <= 126 ? String.fromCharCode(33 + ((code + 14) % 94)) : char;
}).join('');

// ROT8000: rotates within each Unicode script block (Latin, Greek, Cyrillic, digits, etc.)
export const rot8000Blocks: Array<[number, number]> = [
  [0x41, 0x5A], [0x61, 0x7A], [0x30, 0x39],  // A-Z, a-z, 0-9
  [0xC0, 0xD6], [0xD8, 0xF6], [0xF8, 0xFF],  // Latin extended
  [0x0391, 0x03A9], [0x03B1, 0x03C9],          // Greek upper/lower
  [0x0410, 0x042F], [0x0430, 0x044F],          // Cyrillic upper/lower
  [0x4E00, 0x9FFF],                             // CJK unified ideographs
];
export const rot8000 = (value: string) => Array.from(value).map(char => {
  const cp = char.codePointAt(0);
  if (cp == null) return char;
  for (const [lo, hi] of rot8000Blocks) {
    if (cp >= lo && cp <= hi) {
      const size = hi - lo + 1;
      return String.fromCodePoint(lo + ((cp - lo + (size >> 1)) % size));
    }
  }
  return char;
}).join('');

export const caesar = (value: string, shift: number) => Array.from(value).map(char => {
  const code = char.charCodeAt(0);
  const base = code >= 65 && code <= 90 ? 65 : code >= 97 && code <= 122 ? 97 : null;
  if (base == null) return char;
  return String.fromCharCode(base + ((((code - base) + shift) % 26) + 26) % 26);
}).join('');

// Trithemius / progressive Caesar: shift each alpha char by its ALL-character position index
export const trithemiusDecode = (value: string) => {
  let result = '';
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    const base = code >= 65 && code <= 90 ? 65 : code >= 97 && code <= 122 ? 97 : null;
    if (base == null) { result += value[i]; }
    else result += String.fromCharCode(base + (((code - base) - i) % 26 + 26) % 26);
  }
  return result;
};

export const rot18 = (value: string) => Array.from(value).map(char => {
  const code = char.charCodeAt(0);
  if ((code >= 65 && code <= 90) || (code >= 97 && code <= 122)) return caesar(char, 13);
  if (code >= 48 && code <= 57) return String.fromCharCode(((code - 48 + 5) % 10) + 48);
  return char;
}).join('');

export const rotBruteforce = (value: string) => [
  ...Array.from({ length: 25 }, (_, index) => `ROT${index + 1}: ${caesar(value, index + 1)}`),
  `ROT47: ${rot47(value)}`,
  `ROT18 (ROT13+ROT5): ${rot18(value)}`,
].join('\n');

export type EnigmaRotorName = 'I' | 'II' | 'III' | 'IV' | 'V' | 'VI' | 'VII' | 'VIII';
export type EnigmaReflectorName = 'B' | 'C';

export const enigmaRotors: Record<EnigmaRotorName, { wiring: string; notches: string }> = {
  I: { wiring: 'EKMFLGDQVZNTOWYHXUSPAIBRCJ', notches: 'Q' },
  II: { wiring: 'AJDKSIRUXBLHWTMCQGZNPYFVOE', notches: 'E' },
  III: { wiring: 'BDFHJLCPRTXVZNYEIWGAKMUSQO', notches: 'V' },
  IV: { wiring: 'ESOVPZJAYQUIRHXLNFTGKDCMWB', notches: 'J' },
  V: { wiring: 'VZBRGITYUPSDNHLXAWMJQOFECK', notches: 'Z' },
  VI: { wiring: 'JPGVOUMFYQBENHZRDKASXLICTW', notches: 'ZM' },
  VII: { wiring: 'NZJHGRCXMYSWBOUFAIVLPEKQDT', notches: 'ZM' },
  VIII: { wiring: 'FKQHTLXOCBJSPDZRAMEWNIUYGV', notches: 'ZM' },
};

export const enigmaReflectors: Record<EnigmaReflectorName, string> = {
  B: 'YRUHQSLDPXNGOKMIEBFZCWVJAT',
  C: 'FVPJIAOYEDRZXWGCTKUQSBNMHL',
};

export const enigmaGroup = (value: string) => value.match(/.{1,5}/g)?.join(' ') || '';

export const normalizeEnigmaLetters = (value: string, fallback: string, size = 3) => {
  const letters = value.toUpperCase().replace(/[^A-Z]/g, '');
  return (letters || fallback).padEnd(size, 'A').slice(0, size);
};

export const parseEnigmaSettings = (secret: string) => {
  const fields: Record<string, string> = {};
  for (const rawPart of secret.split(/[;\n]/)) {
    const part = rawPart.trim();
    if (!part) continue;
    const match = part.match(/^([a-zA-Z][\w-]*)\s*[:=]\s*(.+)$/);
    if (match) fields[match[1].toLowerCase()] = match[2].trim();
  }
  const rotorSource = fields.rotors || fields.rotor || 'I II III';
  const rotorCandidates = rotorSource.toUpperCase().match(/VIII|VII|VI|IV|III|II|I|V/g) || [];
  const rotors = (rotorCandidates.length ? rotorCandidates : ['I', 'II', 'III']).slice(0, 3) as EnigmaRotorName[];
  if (rotors.length !== 3 || rotors.some(rotor => !enigmaRotors[rotor])) throw new Error('Enigma rotors 需要 3 个转子，例如 rotors=I II III');
  const reflector = ((fields.reflector || fields.ukw || 'B').trim().toUpperCase()[0] || 'B') as EnigmaReflectorName;
  if (!enigmaReflectors[reflector]) throw new Error('Enigma reflector 仅支持 B 或 C');
  const rings = normalizeEnigmaLetters(fields.rings || fields.ring || 'AAA', 'AAA');
  const positions = normalizeEnigmaLetters(fields.positions || fields.position || fields.pos || fields.initial || 'AAA', 'AAA');
  const plugboardPairs = Array.from((fields.plugboard || fields.plugs || '').toUpperCase().matchAll(/[A-Z]{2}/g), item => item[0]);
  const plugboard = new Map<string, string>();
  for (const pair of plugboardPairs) {
    const [left, right] = pair;
    if (left === right) throw new Error(`Plugboard pair ${pair} cannot connect the same letter`);
    if (plugboard.has(left) || plugboard.has(right)) throw new Error(`Plugboard 字母重复: ${pair}`);
    plugboard.set(left, right);
    plugboard.set(right, left);
  }
  return { rotors, reflector, rings, positions, plugboardPairs, plugboard };
};

export const enigmaRotorPass = (value: number, wiring: string, position: number, ring: number, reverse = false) => {
  const shifted = (value + position - ring + 26) % 26;
  const mapped = reverse
    ? wiring.indexOf(alphabet[shifted])
    : alphabet.indexOf(wiring[shifted]);
  return (mapped - position + ring + 26) % 26;
};

export const enigmaTransform = (value: string, secret: string) => {
  const settings = parseEnigmaSettings(secret);
  const rotorSpecs = settings.rotors.map(rotor => enigmaRotors[rotor]);
  const rings = Array.from(settings.rings).map(char => alphabet.indexOf(char));
  const positions = Array.from(settings.positions).map(char => alphabet.indexOf(char));
  let source = value.trim();
  if (source.startsWith('{')) {
    try {
      const parsed = JSON.parse(source) as Record<string, unknown>;
      if (typeof parsed.raw === 'string' && parsed.raw.trim()) source = parsed.raw.trim();
      else if (typeof parsed.output === 'string' && parsed.output.trim()) source = parsed.output.trim();
    } catch {
      // Fall back to raw text extraction.
    }
  }
  const input = source.toUpperCase().replace(/[^A-Z]/g, '');
  if (!input) throw new Error('Enigma 需要至少一个 A-Z 字母');
  const output: string[] = [];
  const plug = (char: string) => settings.plugboard.get(char) || char;

  for (const char of input) {
    const rightAtNotch = rotorSpecs[2].notches.includes(alphabet[positions[2]]);
    const middleAtNotch = rotorSpecs[1].notches.includes(alphabet[positions[1]]);
    if (middleAtNotch) positions[0] = (positions[0] + 1) % 26;
    if (rightAtNotch || middleAtNotch) positions[1] = (positions[1] + 1) % 26;
    positions[2] = (positions[2] + 1) % 26;

    let current = alphabet.indexOf(plug(char));
    for (let index = 2; index >= 0; index -= 1) current = enigmaRotorPass(current, rotorSpecs[index].wiring, positions[index], rings[index]);
    current = alphabet.indexOf(enigmaReflectors[settings.reflector][current]);
    for (let index = 0; index < 3; index += 1) current = enigmaRotorPass(current, rotorSpecs[index].wiring, positions[index], rings[index], true);
    output.push(plug(alphabet[current]));
  }

  const raw = output.join('');
  return JSON.stringify({
    output: enigmaGroup(raw),
    raw,
    inputLetters: input.length,
    settings: {
      rotors: settings.rotors.join(' '),
      reflector: settings.reflector,
      rings: settings.rings,
      initialPositions: settings.positions,
      plugboard: settings.plugboardPairs.join(' '),
    },
    note: 'Enigma 加密和解密是同一变换；保持相同设置并再次处理密文即可还原明文',
  }, null, 2);
};

export const atbashTransform = (value: string) => Array.from(value).map(char => {
  const code = char.charCodeAt(0);
  if (code >= 65 && code <= 90) return String.fromCharCode(90 - (code - 65));
  if (code >= 97 && code <= 122) return String.fromCharCode(122 - (code - 97));
  return char;
}).join('');

export const modInverse = (value: number, modulo: number) => {
  const normalized = ((value % modulo) + modulo) % modulo;
  for (let candidate = 1; candidate < modulo; candidate += 1) {
    if ((normalized * candidate) % modulo === 1) return candidate;
  }
  throw new Error(`${value} 在 mod ${modulo} 下没有乘法逆元`);
};

export const affineTransform = (value: string, aValue: string, bValue: string, decode = false) => {
  const a = Number.parseInt(aValue, 10);
  const b = Number.parseInt(bValue, 10);
  if (!Number.isFinite(a) || !Number.isFinite(b)) throw new Error('Affine 参数 a/b 必须是整数');
  const aNorm = ((a % 26) + 26) % 26;
  if (![1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25].includes(aNorm)) throw new Error(`a=${a}（mod 26=${aNorm}）与 26 不互质，无法做仿射加解密`);
  const inverseA = decode ? modInverse(a, 26) : 0;
  return Array.from(value).map(char => {
    const code = char.charCodeAt(0);
    const base = code >= 65 && code <= 90 ? 65 : code >= 97 && code <= 122 ? 97 : null;
    if (base == null) return char;
    const x = code - base;
    const next = decode ? inverseA * (x - b) : a * x + b;
    return String.fromCharCode(base + ((((next % 26) + 26) % 26)));
  }).join('');
};

export const crc32 = (value: string) => {
  let crc = 0xffffffff;
  for (const byte of utf8Encoder.encode(value)) crc = crc32Table[(crc ^ byte) & 255] ^ (crc >>> 8);
  return ((crc ^ 0xffffffff) >>> 0).toString(16).padStart(8, '0');
};

export const crc16 = (value: string) => {
  let crc = 0xffff;
  for (const byte of utf8Encoder.encode(value)) crc = ((crc >>> 8) ^ crc16Table[(crc ^ byte) & 255]) & 0xffff;
  return crc.toString(16).padStart(4, '0');
};

export const adler32 = (value: string) => {
  let a = 1;
  let b = 0;
  for (const byte of utf8Encoder.encode(value)) {
    a = (a + byte) % 65521;
    b = (b + a) % 65521;
  }
  return (((b << 16) | a) >>> 0).toString(16).padStart(8, '0');
};