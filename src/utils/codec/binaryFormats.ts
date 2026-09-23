// CODEC-IMPORTS
import { utf8Decoder, utf8Encoder } from './alphabets';
import { base64ToBase64Url, base64ToBytes, base64ToText, bytesToBase64, bytesToBuffer, bytesToHex, hexToBytes, textToBase64 } from './bases';
import { bitLength } from './math';
import { gsm7SeptetsToText, unpackGsm7Septets } from './textEncodings';
// CODEC-IMPORTS-END
export const safeJsonValue = (value: unknown, depth = 0, seen = new WeakSet<object>()): unknown => {
  if (depth > 20) return '[Max depth reached]';
  if (typeof value === 'bigint') return `${value.toString()}n`;
  if (value == null || typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') return value;
  if (value instanceof Date) return value.toISOString();
  if (value instanceof ArrayBuffer) return safeJsonValue(new Uint8Array(value), depth + 1, seen);
  if (ArrayBuffer.isView(value)) {
    const bytes = value instanceof Uint8Array ? value : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    let utf8Preview = '';
    try {
      utf8Preview = utf8Decoder.decode(bytes.slice(0, 120)).replace(/\p{Cc}/gu, '.');
    } catch {
      utf8Preview = '';
    }
    return {
      type: value.constructor.name,
      bytes: bytes.length,
      hex: bytesToHex(bytes.slice(0, 160)),
      utf8Preview,
    };
  }
  if (value instanceof Map) {
    return {
      type: 'Map',
      entries: Array.from(value.entries()).map(([key, entry]) => [safeJsonValue(key, depth + 1, seen), safeJsonValue(entry, depth + 1, seen)]),
    };
  }
  if (Array.isArray(value)) return value.map(entry => safeJsonValue(entry, depth + 1, seen));
  if (typeof value === 'object') {
    if (seen.has(value)) return '[Circular]';
    seen.add(value);
    const source = value as Record<string, unknown>;
    const result: Record<string, unknown> = {};
    if (value.constructor?.name && value.constructor.name !== 'Object') result.type = value.constructor.name;
    for (const [key, entry] of Object.entries(source)) result[key] = safeJsonValue(entry, depth + 1, seen);
    return result;
  }
  return String(value);
};

export const parseBinaryEncodedInput = (value: string, label: string) => {
  const text = value.trim();
  if (!text) throw new Error(`${label} 需要输入 Hex 或 Base64 数据`);
  const dataUrl = text.match(/^data:[^,]+,(.+)$/s);
  if (dataUrl) return { encoding: /;base64/i.test(text) ? 'data-url-base64' : 'data-url-percent', bytes: /;base64/i.test(text) ? base64ToBytes(dataUrl[1]) : utf8Encoder.encode(decodeURIComponent(dataUrl[1])) };
  const hexClean = text.replace(/\\x/gi, '').replace(/0x/gi, '').replace(/[^0-9a-f]/gi, '');
  if (/^[0-9a-fA-Fx\\\s:,_-]+$/.test(text) && hexClean.length >= 2 && hexClean.length % 2 === 0) {
    return { encoding: 'hex', bytes: hexToBytes(text) };
  }
  if (/^[A-Za-z0-9+/_=-\s]+$/.test(text)) return { encoding: 'base64/base64url', bytes: base64ToBytes(text) };
  throw new Error(`${label} 输入无法识别，请使用 Hex、Base64 或 Base64URL`);
};

export const parseCbor = async (value: string) => {
  const input = parseBinaryEncodedInput(value, 'CBOR');
  const { decode } = await import('cbor-x');
  return JSON.stringify({
    encoding: input.encoding,
    bytes: input.bytes.length,
    decoded: safeJsonValue(decode(input.bytes)),
  }, null, 2);
};

export const parseMessagePack = async (value: string) => {
  const input = parseBinaryEncodedInput(value, 'MessagePack');
  const { decode } = await import('@msgpack/msgpack');
  return JSON.stringify({
    encoding: input.encoding,
    bytes: input.bytes.length,
    decoded: safeJsonValue(decode(input.bytes, { useBigInt64: true })),
  }, null, 2);
};

export type ProtobufField = {
  offset: number;
  field: number;
  wireType: number;
  wireTypeName: string;
  value?: unknown;
  error?: string;
};

export const protobufWireTypeNames: Record<number, string> = {
  0: 'varint',
  1: 'fixed64',
  2: 'length-delimited',
  3: 'start-group',
  4: 'end-group',
  5: 'fixed32',
};

export type ProtobufReaderClass = typeof import('protobufjs').Reader;

export const looksLikeNestedProtobuf = (bytes: Uint8Array, Reader: ProtobufReaderClass) => {
  if (bytes.length < 2 || bytes.length > 512) return false;
  try {
    const fields = parseProtobufFields(bytes, Reader, 1);
    return fields.length > 0 && fields.every(field => !field.error);
  } catch {
    return false;
  }
};

export const parseProtobufFields = (bytes: Uint8Array, Reader: ProtobufReaderClass, depth = 0): ProtobufField[] => {
  if (depth > 4) return [];
  const reader = Reader.create(bytes) as import('protobufjs').Reader;
  const fields: ProtobufField[] = [];
  while (reader.pos < reader.len && fields.length < 512) {
    const offset = reader.pos;
    try {
      const tag = reader.uint32();
      const field = tag >>> 3;
      const wireType = tag & 7;
      const entry: ProtobufField = {
        offset,
        field,
        wireType,
        wireTypeName: protobufWireTypeNames[wireType] || 'unknown',
      };
      if (!field) {
        entry.error = 'field number 0 is invalid';
        fields.push(entry);
        break;
      }
      if (wireType === 0) {
        const value = reader.uint64().toString();
        entry.value = { uint64: value, int64: value, boolCandidate: value === '0' ? false : value === '1' ? true : null };
      } else if (wireType === 1) {
        const start = reader.pos;
        const fixed64 = reader.fixed64().toString();
        entry.value = { fixed64, doubleCandidate: new DataView(reader.buf.buffer, reader.buf.byteOffset + start, 8).getFloat64(0, true), rawHex: bytesToHex(reader.buf.slice(start, start + 8)) };
      } else if (wireType === 2) {
        const length = reader.uint32();
        const start = reader.pos;
        const end = start + length;
        if (end > reader.len) throw new Error('length-delimited field exceeds buffer length');
        const data = reader.buf.slice(start, end);
        reader.pos = end;
        let utf8Preview = '';
        try { utf8Preview = utf8Decoder.decode(data).replace(/\p{Cc}/gu, '.'); } catch { utf8Preview = ''; }
        entry.value = {
          bytes: data.length,
          hexPreview: bytesToHex(data.slice(0, 128)),
          utf8Preview,
          nestedFields: depth < 3 && looksLikeNestedProtobuf(data, Reader) ? parseProtobufFields(data, Reader, depth + 1) : undefined,
        };
      } else if (wireType === 5) {
        const start = reader.pos;
        const fixed32 = reader.fixed32();
        entry.value = { fixed32, floatCandidate: new DataView(reader.buf.buffer, reader.buf.byteOffset + start, 4).getFloat32(0, true), rawHex: bytesToHex(reader.buf.slice(start, start + 4)) };
      } else if (wireType === 3 || wireType === 4) {
        entry.value = 'group wire types are deprecated; skipped as opaque group boundary';
        reader.skipType(wireType, depth, field);
      } else {
        entry.error = 'unsupported wire type';
        reader.skipType(wireType);
      }
      fields.push(entry);
    } catch (error) {
      fields.push({
        offset,
        field: -1,
        wireType: -1,
        wireTypeName: 'parse-error',
        error: error instanceof Error ? error.message : String(error),
      });
      break;
    }
  }
  return fields;
};

export const parseProtobufRaw = async (value: string) => {
  const input = parseBinaryEncodedInput(value, 'Protobuf');
  const { Reader } = await import('protobufjs');
  const fields = parseProtobufFields(input.bytes, Reader);
  return JSON.stringify({
    encoding: input.encoding,
    bytes: input.bytes.length,
    fields,
  }, null, 2);
};

export const parseBson = async (value: string) => {
  const input = parseBinaryEncodedInput(value, 'BSON');
  const { deserialize, EJSON } = await import('bson');
  const doc = deserialize(input.bytes, { promoteLongs: false, promoteBuffers: false });
  return JSON.stringify({
    encoding: input.encoding,
    bytes: input.bytes.length,
    document: JSON.parse(EJSON.stringify(doc, undefined, 2, { relaxed: true })),
    canonicalEjson: JSON.parse(EJSON.stringify(doc, undefined, 2, { relaxed: false })),
  }, null, 2);
};

export const looksLikeBson = (value: string) => {
  try {
    const bytes = hexToBytes(value);
    if (bytes.length < 5) return false;
    const length = bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24);
    return length === bytes.length && bytes[bytes.length - 1] === 0;
  } catch {
    return false;
  }
};

export const looksLikeProtobufWire = (value: string) => {
  try {
    const bytes = parseBinaryEncodedInput(value, 'Protobuf').bytes;
    if (bytes.length < 2) return false;
    const first = bytes[0];
    const fieldNumber = first >>> 3;
    const wireType = first & 7;
    return fieldNumber > 0 && [0, 1, 2, 5].includes(wireType);
  } catch {
    return false;
  }
};

export const decodeBase64UrlJson = (value: string) => JSON.parse(utf8Decoder.decode(base64ToBytes(value)));

export const base64UrlFieldInfo = (value: unknown) => {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+={0,2}$/.test(value)) return value;
  try {
    const bytes = base64ToBytes(value);
    return {
      base64url: value,
      bytes: bytes.length,
      bits: bytes.length * 8,
      hexPreview: bytesToHex(bytes.slice(0, 64)),
    };
  } catch {
    return value;
  }
};

export const summarizeJwk = (jwk: Record<string, unknown>) => {
  const keyFields = ['n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qi', 'x', 'y', 'k'];
  const params = Object.fromEntries(keyFields
    .filter(key => key in jwk)
    .map(key => [key, base64UrlFieldInfo(jwk[key])]));
  const thumbprintMembers = Object.fromEntries(['crv', 'e', 'k', 'kty', 'n', 'x', 'y']
    .filter(key => key in jwk)
    .map(key => [key, jwk[key]]));
  return {
    kty: jwk.kty,
    use: jwk.use,
    keyOps: jwk.key_ops,
    alg: jwk.alg,
    kid: jwk.kid,
    crv: jwk.crv,
    params,
    thumbprintMembers,
  };
};

export const parseJwkJwe = (value: string) => {
  const text = value.trim().replace(/^Bearer\s+/i, '');
  const compactParts = text.split('.');
  if (compactParts.length === 5) {
    const [protectedHeader, encryptedKey, iv, ciphertext, tag] = compactParts;
    return JSON.stringify({
      format: 'JWE Compact Serialization',
      protectedHeader: decodeBase64UrlJson(protectedHeader),
      encryptedKey: base64UrlFieldInfo(encryptedKey),
      iv: base64UrlFieldInfo(iv),
      ciphertext: base64UrlFieldInfo(ciphertext),
      authenticationTag: base64UrlFieldInfo(tag),
      note: '这里只解析 JOSE/JWE 结构和字段长度，不尝试解密内容。',
    }, null, 2);
  }

  const parsed = JSON.parse(text) as Record<string, unknown>;
  if (Array.isArray(parsed.keys)) {
    return JSON.stringify({
      format: 'JWKS',
      keys: parsed.keys.map(key => summarizeJwk(key as Record<string, unknown>)),
    }, null, 2);
  }
  if ('kty' in parsed) {
    return JSON.stringify({
      format: 'JWK',
      key: summarizeJwk(parsed),
    }, null, 2);
  }
  if ('protected' in parsed || 'ciphertext' in parsed || 'recipients' in parsed) {
    const protectedHeader = typeof parsed.protected === 'string' ? decodeBase64UrlJson(parsed.protected) : null;
    return JSON.stringify({
      format: 'JWE JSON Serialization',
      protectedHeader,
      iv: base64UrlFieldInfo(parsed.iv),
      ciphertext: base64UrlFieldInfo(parsed.ciphertext),
      tag: base64UrlFieldInfo(parsed.tag),
      encryptedKey: base64UrlFieldInfo(parsed.encrypted_key),
      recipients: safeJsonValue(parsed.recipients),
      note: '这里只解析 JWE JSON 字段结构，不尝试解密内容。',
    }, null, 2);
  }
  throw new Error('未识别为 JWK、JWKS 或 JWE');
};

export const readSshUint32 = (bytes: Uint8Array, offset: number) => {
  if (offset + 4 > bytes.length) throw new Error('SSH blob 字段长度不完整');
  return ((bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3]) >>> 0;
};

export const readSshString = (bytes: Uint8Array, offset: number) => {
  const length = readSshUint32(bytes, offset);
  const start = offset + 4;
  const end = start + length;
  if (end > bytes.length) throw new Error('SSH blob string 字段超出范围');
  const data = bytes.slice(start, end);
  return { data, text: utf8Decoder.decode(data), next: end };
};

export const sshMpintInfo = (bytes: Uint8Array) => {
  const stripped = bytes[0] === 0 ? bytes.slice(1) : bytes;
  const value = stripped.length <= 8 ? asn1BytesToBigInt(stripped).toString() : undefined;
  return {
    bytes: bytes.length,
    bits: stripped.length ? bitLength(asn1BytesToBigInt(stripped)) : 0,
    hexPreview: bytesToHex(bytes.slice(0, 64)),
    decimal: value,
  };
};

export const parseSshPublicKey = async (value: string) => {
  const tokens = value.trim().split(/\s+/);
  const keyIndex = tokens.findIndex(token => /^(ssh-|ecdsa-|sk-)/.test(token));
  if (keyIndex < 0 || !tokens[keyIndex + 1]) throw new Error('请输入 OpenSSH 公钥行，例如 ssh-ed25519 AAAA... comment');
  const declaredType = tokens[keyIndex];
  const blob = base64ToBytes(tokens[keyIndex + 1]);
  let offset = 0;
  const typeField = readSshString(blob, offset);
  offset = typeField.next;
  const fields: Record<string, unknown> = {};
  if (typeField.text === 'ssh-rsa') {
    const e = readSshString(blob, offset);
    const n = readSshString(blob, e.next);
    offset = n.next;
    fields.exponent = sshMpintInfo(e.data);
    fields.modulus = sshMpintInfo(n.data);
  } else if (typeField.text === 'ssh-ed25519' || typeField.text === 'sk-ssh-ed25519@openssh.com') {
    const key = readSshString(blob, offset);
    offset = key.next;
    fields.publicKey = { bytes: key.data.length, hex: bytesToHex(key.data) };
  } else if (typeField.text.startsWith('ecdsa-sha2-') || typeField.text === 'sk-ecdsa-sha2-nistp256@openssh.com') {
    const curve = readSshString(blob, offset);
    const point = readSshString(blob, curve.next);
    offset = point.next;
    fields.curve = curve.text;
    fields.publicPoint = { bytes: point.data.length, hexPreview: bytesToHex(point.data.slice(0, 96)) };
  } else {
    const rest: Array<{ bytes: number; textPreview: string; hexPreview: string }> = [];
    while (offset < blob.length) {
      const field = readSshString(blob, offset);
      rest.push({ bytes: field.data.length, textPreview: field.text.replace(/\p{Cc}/gu, '.'), hexPreview: bytesToHex(field.data.slice(0, 64)) });
      offset = field.next;
    }
    fields.remainingFields = rest;
  }
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytesToBuffer(blob)));
  return JSON.stringify({
    declaredType,
    blobType: typeField.text,
    comment: tokens.slice(keyIndex + 2).join(' '),
    fingerprint: `SHA256:${base64ToBase64Url(bytesToBase64(digest))}`,
    blobBytes: blob.length,
    fields,
    trailingBytes: blob.length - offset,
  }, null, 2);
};

export const punycodeAdapt = (delta: number, points: number, firstTime: boolean) => {
  let next = firstTime ? Math.floor(delta / 700) : Math.floor(delta / 2);
  next += Math.floor(next / points);
  let k = 0;
  while (next > 455) {
    next = Math.floor(next / 35);
    k += 36;
  }
  return k + Math.floor((36 * next) / (next + 38));
};

export const punycodeDigitToBasic = (digit: number) => String.fromCharCode(digit + 22 + 75 * Number(digit < 26));
export const punycodeBasicToDigit = (codePoint: number) => {
  if (codePoint >= 48 && codePoint <= 57) return codePoint - 22;
  if (codePoint >= 65 && codePoint <= 90) return codePoint - 65;
  if (codePoint >= 97 && codePoint <= 122) return codePoint - 97;
  return 36;
};

export const punycodeEncodeLabel = (value: string) => {
  const codePoints = Array.from(value).map(char => char.codePointAt(0) || 0);
  const basic = codePoints.filter(point => point < 0x80).map(point => String.fromCodePoint(point)).join('');
  let output = basic;
  let handled = basic.length;
  if (basic.length) output += '-';
  let n = 128;
  let delta = 0;
  let bias = 72;
  while (handled < codePoints.length) {
    const m = Math.min(...codePoints.filter(point => point >= n));
    delta += (m - n) * (handled + 1);
    n = m;
    for (const point of codePoints) {
      if (point < n) delta += 1;
      if (point === n) {
        let q = delta;
        for (let k = 36; ; k += 36) {
          const t = k <= bias ? 1 : k >= bias + 26 ? 26 : k - bias;
          if (q < t) break;
          output += punycodeDigitToBasic(t + ((q - t) % (36 - t)));
          q = Math.floor((q - t) / (36 - t));
        }
        output += punycodeDigitToBasic(q);
        bias = punycodeAdapt(delta, handled + 1, handled === basic.length);
        delta = 0;
        handled += 1;
      }
    }
    delta += 1;
    n += 1;
  }
  return output;
};

export const punycodeDecodeLabel = (value: string) => {
  const output = [];
  const delimiter = value.lastIndexOf('-');
  let index = 0;
  let n = 128;
  let i = 0;
  let bias = 72;
  if (delimiter >= 0) {
    for (const char of value.slice(0, delimiter)) output.push(char.codePointAt(0) || 0);
    index = delimiter + 1;
  }
  while (index < value.length) {
    const oldI = i;
    let weight = 1;
    for (let k = 36; ; k += 36) {
      if (index >= value.length) throw new Error('Punycode 数据不完整');
      const digit = punycodeBasicToDigit(value.charCodeAt(index++));
      i += digit * weight;
      const t = k <= bias ? 1 : k >= bias + 26 ? 26 : k - bias;
      if (digit < t) break;
      weight *= 36 - t;
    }
    bias = punycodeAdapt(i - oldI, output.length + 1, oldI === 0);
    n += Math.floor(i / (output.length + 1));
    i %= output.length + 1;
    output.splice(i, 0, n);
    i += 1;
  }
  return String.fromCodePoint(...output);
};

export const encodePunycode = (value: string) => {
  const trimmed = value.trim();
  if (!trimmed) return '';
  const url = /^https?:\/\//i.test(trimmed) ? new URL(trimmed) : new URL(`http://${trimmed}`);
  const host = url.hostname
    .split('.')
    .map(label => Array.from(label).some(char => char.codePointAt(0)! > 0x7f) ? `xn--${punycodeEncodeLabel(label)}` : label)
    .join('.');
  return /^https?:\/\//i.test(trimmed) ? trimmed.replace(url.hostname, host) : host;
};

export const decodePunycode = (value: string) => {
  const trimmed = value.trim();
  if (!trimmed) return '';
  const url = /^https?:\/\//i.test(trimmed) ? new URL(trimmed) : new URL(`http://${trimmed}`);
  const host = url.hostname
    .split('.')
    .map(label => label.startsWith('xn--') ? punycodeDecodeLabel(label.slice(4)) : label)
    .join('.');
  return /^https?:\/\//i.test(trimmed) ? trimmed.replace(url.hostname, host) : host;
};

export const encodePemBlock = (value: string, blockLabel: string) => {
  const label = (blockLabel || 'PUBLIC KEY').trim().toUpperCase();
  const clean = value.replace(/\s+/g, '');
  const body = /^[A-Za-z0-9+/=]+$/.test(clean) ? clean : textToBase64(value);
  const wrapped = body.match(/.{1,64}/g)?.join('\n') || body;
  return `-----BEGIN ${label}-----\n${wrapped}\n-----END ${label}-----`;
};

export const decodePemBlock = (value: string) => {
  const match = value.trim().match(/-----BEGIN ([^-]+)-----\s*([\s\S]+?)\s*-----END \1-----/);
  if (!match) throw new Error('PEM 块格式不正确');
  const body = match[2].replace(/\s+/g, '');
  return JSON.stringify({
    label: match[1].trim(),
    base64: body,
    textPreview: (() => {
      try { return base64ToText(body); } catch { return ''; }
    })(),
  }, null, 2);
};

export type Asn1Node = {
  offset: number;
  end: number;
  tag: string;
  tagClass: string;
  constructed: boolean;
  type: string;
  length: number | 'indefinite';
  value?: unknown;
  children?: Asn1Node[];
};

export type Asn1ParseState = {
  count: number;
};

export const asn1ClassNames = ['universal', 'application', 'context-specific', 'private'];
export const asn1UniversalTypes: Record<number, string> = {
  0: 'EOC',
  1: 'BOOLEAN',
  2: 'INTEGER',
  3: 'BIT STRING',
  4: 'OCTET STRING',
  5: 'NULL',
  6: 'OBJECT IDENTIFIER',
  10: 'ENUMERATED',
  12: 'UTF8String',
  16: 'SEQUENCE',
  17: 'SET',
  18: 'NumericString',
  19: 'PrintableString',
  20: 'TeletexString',
  22: 'IA5String',
  23: 'UTCTime',
  24: 'GeneralizedTime',
  26: 'VisibleString',
  27: 'GeneralString',
  28: 'UniversalString',
  30: 'BMPString',
};

export const parseAsn1Input = (value: string) => {
  const text = value.trim();
  const pem = text.match(/-----BEGIN ([^-]+)-----\s*([\s\S]+?)\s*-----END \1-----/);
  if (pem) return { encoding: `PEM ${pem[1].trim()}`, bytes: base64ToBytes(pem[2].replace(/\s+/g, '')) };
  const compact = text.replace(/\s+/g, '');
  const hexClean = text.replace(/\\x/gi, '').replace(/0x/gi, '').replace(/[^0-9a-f]/gi, '');
  if (/^[0-9a-fA-Fx\\\s:,-]+$/.test(text) && hexClean.length >= 2 && hexClean.length % 2 === 0) {
    return { encoding: 'hex', bytes: hexToBytes(text) };
  }
  if (/^[A-Za-z0-9+/_=-]+$/.test(compact)) return { encoding: 'base64', bytes: base64ToBytes(compact) };
  throw new Error('ASN.1 输入需要是 PEM、Base64 或 Hex DER/BER 数据');
};

export const asn1BytesToBigInt = (bytes: Uint8Array) => {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
};

export const decodeAsn1Integer = (bytes: Uint8Array) => {
  if (!bytes.length) return { hex: '', decimal: '0' };
  const unsigned = asn1BytesToBigInt(bytes);
  const bits = BigInt(bytes.length * 8);
  const signed = (bytes[0] & 0x80) ? unsigned - (1n << bits) : unsigned;
  return bytes.length <= 8
    ? { hex: bytesToHex(bytes), decimal: signed.toString() }
    : { hex: bytesToHex(bytes), bytes: bytes.length, note: '整数过长，仅显示 hex' };
};

export const decodeAsn1Oid = (bytes: Uint8Array) => {
  const values: number[] = [];
  let current = 0;
  for (const byte of bytes) {
    current = current * 128 + (byte & 0x7f);
    if ((byte & 0x80) === 0) {
      values.push(current);
      current = 0;
    }
  }
  if (!values.length) return '';
  const firstValue = values[0];
  const first = firstValue < 40 ? 0 : firstValue < 80 ? 1 : 2;
  const second = first === 2 ? firstValue - 80 : firstValue - first * 40;
  return [first, second, ...values.slice(1)].join('.');
};

export const decodeAsn1Text = (tagNumber: number, bytes: Uint8Array) => {
  if (tagNumber === 30) {
    const chars: string[] = [];
    for (let index = 0; index + 1 < bytes.length; index += 2) chars.push(String.fromCharCode((bytes[index] << 8) | bytes[index + 1]));
    return chars.join('');
  }
  try {
    return utf8Decoder.decode(bytes);
  } catch {
    return Array.from(bytes, byte => String.fromCharCode(byte)).join('');
  }
};

export const asn1Value = (tagClass: string, tagNumber: number, bytes: Uint8Array) => {
  if (tagClass !== 'universal') return bytes.length ? { hexPreview: bytesToHex(bytes.slice(0, 48)), bytes: bytes.length } : '';
  if (tagNumber === 1) return bytes[0] !== 0;
  if (tagNumber === 2 || tagNumber === 10) return decodeAsn1Integer(bytes);
  if (tagNumber === 3) return { unusedBits: bytes[0] || 0, hex: bytesToHex(bytes.slice(1)), bytes: Math.max(0, bytes.length - 1) };
  if (tagNumber === 4) return { hexPreview: bytesToHex(bytes.slice(0, 80)), bytes: bytes.length };
  if (tagNumber === 5) return null;
  if (tagNumber === 6) return decodeAsn1Oid(bytes);
  if ([12, 18, 19, 20, 22, 23, 24, 26, 27, 30].includes(tagNumber)) return decodeAsn1Text(tagNumber, bytes);
  return bytes.length ? { hexPreview: bytesToHex(bytes.slice(0, 48)), bytes: bytes.length } : '';
};

export const readAsn1Tag = (bytes: Uint8Array, offset: number, limit: number) => {
  if (offset >= limit) throw new Error('ASN.1 tag 超出输入范围');
  const first = bytes[offset];
  let cursor = offset + 1;
  let tagNumber = first & 0x1f;
  if (tagNumber === 0x1f) {
    tagNumber = 0;
    while (cursor < limit) {
      const byte = bytes[cursor];
      tagNumber = tagNumber * 128 + (byte & 0x7f);
      cursor += 1;
      if ((byte & 0x80) === 0) break;
    }
  }
  return {
    cursor,
    tagHex: bytesToHex(bytes.slice(offset, cursor)),
    tagClass: asn1ClassNames[(first >> 6) & 3],
    constructed: (first & 0x20) !== 0,
    tagNumber,
  };
};

export const readAsn1Length = (bytes: Uint8Array, offset: number, limit: number) => {
  if (offset >= limit) throw new Error('ASN.1 length 超出输入范围');
  const first = bytes[offset];
  if (first < 0x80) return { cursor: offset + 1, length: first as number | 'indefinite' };
  if (first === 0x80) return { cursor: offset + 1, length: 'indefinite' as const };
  const count = first & 0x7f;
  if (count > 4) throw new Error('ASN.1 length 字段过长，已拒绝解析');
  if (offset + 1 + count > limit) throw new Error('ASN.1 length 字段不完整');
  let length = 0;
  for (let index = 0; index < count; index += 1) length = length * 256 + bytes[offset + 1 + index];
  return { cursor: offset + 1 + count, length };
};

export const parseAsn1Node = (bytes: Uint8Array, offset: number, limit: number, depth: number, state: Asn1ParseState): Asn1Node => {
  if (depth > 16) throw new Error('ASN.1 嵌套超过 16 层，已停止解');
  state.count += 1;
  if (state.count > 512) throw new Error('ASN.1 节点超过 512 个，已停止解');
  const tag = readAsn1Tag(bytes, offset, limit);
  const length = readAsn1Length(bytes, tag.cursor, limit);
  const valueStart = length.cursor;
  const valueEnd = length.length === 'indefinite' ? limit : valueStart + length.length;
  if (valueEnd > limit) throw new Error('ASN.1 value 长度超出输入范围');
  const type = tag.tagClass === 'universal' ? asn1UniversalTypes[tag.tagNumber] || `Universal ${tag.tagNumber}` : `${tag.tagClass} ${tag.tagNumber}`;
  const node: Asn1Node = {
    offset,
    end: valueEnd,
    tag: tag.tagHex,
    tagClass: tag.tagClass,
    constructed: tag.constructed,
    type,
    length: length.length,
  };
  if (tag.constructed || length.length === 'indefinite') {
    const children: Asn1Node[] = [];
    let cursor = valueStart;
    while (cursor < valueEnd) {
      if (length.length === 'indefinite' && bytes[cursor] === 0 && bytes[cursor + 1] === 0) {
        cursor += 2;
        break;
      }
      const child = parseAsn1Node(bytes, cursor, valueEnd, depth + 1, state);
      if (child.end <= cursor) throw new Error('ASN.1 子节点没有推进游');
      children.push(child);
      cursor = child.end;
    }
    node.children = children;
    node.end = length.length === 'indefinite' ? cursor : valueEnd;
  } else {
    const rawValue = bytes.slice(valueStart, valueEnd);
    node.value = asn1Value(tag.tagClass, tag.tagNumber, rawValue);
    if ((tag.tagNumber === 3 && rawValue[0] === 0 && rawValue.length > 2) || (tag.tagNumber === 4 && rawValue.length > 2)) {
      const nestedBytes = tag.tagNumber === 3 ? rawValue.slice(1) : rawValue;
      try {
        const nestedState = { count: state.count };
        const nested = parseAsn1TopLevel(nestedBytes, depth + 1, nestedState);
        if (nested.length && nestedState.count > state.count) {
          state.count = nestedState.count;
          node.children = nested;
        }
      } catch {
        // Primitive BIT/OCTET STRING often contains arbitrary bytes; nested ASN.1 is best-effort only.
      }
    }
  }
  return node;
};

export const parseAsn1TopLevel = (bytes: Uint8Array, depth: number, state: Asn1ParseState) => {
  const nodes: Asn1Node[] = [];
  let offset = 0;
  while (offset < bytes.length) {
    const node = parseAsn1Node(bytes, offset, bytes.length, depth, state);
    if (node.end <= offset) throw new Error('ASN.1 顶层节点没有推进游标');
    nodes.push(node);
    offset = node.end;
  }
  return nodes;
};

export const parseAsn1Der = (value: string) => {
  const input = parseAsn1Input(value);
  const state = { count: 0 };
  return JSON.stringify({
    encoding: input.encoding,
    bytes: input.bytes.length,
    nodes: parseAsn1TopLevel(input.bytes, 0, state),
  }, null, 2);
};

export const decodeSemiOctetAddress = (bytes: Uint8Array, digitCount?: number, typeOfAddress = 0x81) => {
  const digits: string[] = [];
  const map = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '*', '#', 'a', 'b', 'c'];
  for (const byte of bytes) {
    for (const nibble of [byte & 0x0f, byte >> 4]) {
      if (nibble === 0x0f) continue;
      digits.push(map[nibble] || '?');
      if (digitCount != null && digits.length >= digitCount) break;
    }
    if (digitCount != null && digits.length >= digitCount) break;
  }
  const number = digits.join('');
  const international = (typeOfAddress & 0x70) === 0x10;
  return international && number ? `+${number}` : number;
};

export const decodeSwappedBcd = (byte: number) => `${byte & 0x0f}${(byte >> 4) & 0x0f}`;

export const decodeSmsTimestamp = (bytes: Uint8Array) => {
  if (bytes.length < 7) return { raw: bytesToHex(bytes), text: '' };
  const [yearByte, monthByte, dayByte, hourByte, minuteByte, secondByte, zoneByte] = bytes;
  const year = Number.parseInt(decodeSwappedBcd(yearByte), 10);
  const month = decodeSwappedBcd(monthByte).padStart(2, '0');
  const day = decodeSwappedBcd(dayByte).padStart(2, '0');
  const hour = decodeSwappedBcd(hourByte).padStart(2, '0');
  const minute = decodeSwappedBcd(minuteByte).padStart(2, '0');
  const second = decodeSwappedBcd(secondByte).padStart(2, '0');
  const low = zoneByte & 0x0f;
  const timezoneQuarters = ((low & 0x07) * 10) + ((zoneByte >> 4) & 0x0f);
  const timezoneMinutes = timezoneQuarters * 15;
  const sign = (low & 0x08) ? '-' : '+';
  const timezone = `${sign}${String(Math.floor(timezoneMinutes / 60)).padStart(2, '0')}:${String(timezoneMinutes % 60).padStart(2, '0')}`;
  return {
    raw: bytesToHex(bytes),
    text: `${year < 70 ? 2000 + year : 1900 + year}-${month}-${day} ${hour}:${minute}:${second} ${timezone}`,
  };
};

export const decodeSmsDcs = (dcs: number) => {
  const alphabetBits = dcs & 0x0c;
  const alphabet = alphabetBits === 0x08 ? 'ucs2' : alphabetBits === 0x04 ? '8bit' : 'gsm7';
  return {
    value: `0x${dcs.toString(16).padStart(2, '0')}`,
    alphabet,
    compressed: (dcs & 0x20) !== 0,
    messageClass: (dcs & 0x10) ? dcs & 0x03 : null,
  };
};

export const decodeSmsUserData = (bytes: Uint8Array, dcs: number, userDataLength: number, hasHeader: boolean) => {
  const dcsInfo = decodeSmsDcs(dcs);
  const headerLength = hasHeader && bytes.length ? bytes[0] + 1 : 0;
  const header = headerLength ? bytes.slice(0, headerLength) : new Uint8Array();
  const payload = headerLength ? bytes.slice(headerLength) : bytes;
  if (dcsInfo.alphabet === 'ucs2') {
    const chars: string[] = [];
    for (let index = 0; index + 1 < payload.length; index += 2) chars.push(String.fromCharCode((payload[index] << 8) | payload[index + 1]));
    return { dcs: dcsInfo, udh: headerLength ? bytesToHex(header) : null, text: chars.join('').slice(0, Math.floor(userDataLength / 2)), rawHex: bytesToHex(bytes) };
  }
  if (dcsInfo.alphabet === '8bit') {
    return { dcs: dcsInfo, udh: headerLength ? bytesToHex(header) : null, hex: bytesToHex(payload.slice(0, userDataLength)), asciiPreview: utf8Decoder.decode(payload.slice(0, userDataLength)).replace(/\p{Cc}/gu, '.') };
  }
  const septets = unpackGsm7Septets(bytes);
  const headerSeptets = headerLength ? Math.ceil((headerLength * 8) / 7) : 0;
  const textSeptets = septets.slice(headerSeptets, userDataLength);
  return { dcs: dcsInfo, udh: headerLength ? bytesToHex(header) : null, text: gsm7SeptetsToText(textSeptets), rawHex: bytesToHex(bytes) };
};

export const parseSmsPdu = (value: string) => {
  const bytes = hexToBytes(value);
  if (bytes.length < 2) throw new Error('SMS PDU 太短');
  let offset = 0;
  const smscLength = bytes[offset];
  offset += 1;
  if (offset + smscLength > bytes.length) throw new Error('SMSC 长度超出 PDU 范围');
  const smscType = smscLength ? bytes[offset] : 0;
  const smscAddress = smscLength > 1 ? decodeSemiOctetAddress(bytes.slice(offset + 1, offset + smscLength), undefined, smscType) : '';
  offset += smscLength;
  if (offset >= bytes.length) throw new Error('缺少 TPDU first octet');
  const firstOctet = bytes[offset];
  offset += 1;
  const mti = firstOctet & 0x03;
  const hasUserDataHeader = (firstOctet & 0x40) !== 0;
  const base = {
    smsc: {
      length: smscLength,
      typeOfAddress: smscLength ? `0x${smscType.toString(16).padStart(2, '0')}` : null,
      address: smscAddress,
    },
    firstOctet: `0x${firstOctet.toString(16).padStart(2, '0')}`,
    hasUserDataHeader,
  };

  if (mti === 0) {
    const addressLength = bytes[offset];
    const addressType = bytes[offset + 1];
    const addressBytes = Math.ceil(addressLength / 2);
    offset += 2;
    const sender = decodeSemiOctetAddress(bytes.slice(offset, offset + addressBytes), addressLength, addressType);
    offset += addressBytes;
    const pid = bytes[offset];
    const dcs = bytes[offset + 1];
    const timestamp = decodeSmsTimestamp(bytes.slice(offset + 2, offset + 9));
    offset += 9;
    const userDataLength = bytes[offset];
    offset += 1;
    const userData = decodeSmsUserData(bytes.slice(offset), dcs, userDataLength, hasUserDataHeader);
    return JSON.stringify({ ...base, messageType: 'SMS-DELIVER', sender, pid: `0x${pid.toString(16).padStart(2, '0')}`, timestamp, userData }, null, 2);
  }

  if (mti === 1) {
    const messageReference = bytes[offset];
    const addressLength = bytes[offset + 1];
    const addressType = bytes[offset + 2];
    const addressBytes = Math.ceil(addressLength / 2);
    offset += 3;
    const recipient = decodeSemiOctetAddress(bytes.slice(offset, offset + addressBytes), addressLength, addressType);
    offset += addressBytes;
    const pid = bytes[offset];
    const dcs = bytes[offset + 1];
    offset += 2;
    const validityFormat = (firstOctet >> 3) & 0x03;
    const validityBytes = validityFormat === 0 ? 0 : validityFormat === 2 ? 1 : 7;
    const validityPeriod = validityBytes ? bytesToHex(bytes.slice(offset, offset + validityBytes)) : null;
    offset += validityBytes;
    const userDataLength = bytes[offset];
    offset += 1;
    const userData = decodeSmsUserData(bytes.slice(offset), dcs, userDataLength, hasUserDataHeader);
    return JSON.stringify({ ...base, messageType: 'SMS-SUBMIT', messageReference, recipient, pid: `0x${pid.toString(16).padStart(2, '0')}`, validityPeriod, userData }, null, 2);
  }

  return JSON.stringify({
    ...base,
    messageType: mti === 2 ? 'SMS-STATUS-REPORT' : 'reserved',
    note: '当前解析器重点覆盖 CTF/取证中最常见的 SMS-DELIVER 和 SMS-SUBMIT',
    remainingHex: bytesToHex(bytes.slice(offset)),
  }, null, 2);
};

export const looksLikeSmsPdu = (value: string) => {
  try {
    const bytes = hexToBytes(value);
    if (bytes.length < 16) return false;
    const smscLength = bytes[0];
    if (smscLength + 1 >= bytes.length) return false;
    const firstOctet = bytes[smscLength + 1];
    const mti = firstOctet & 0x03;
    return mti === 0 || mti === 1;
  } catch {
    return false;
  }
};
