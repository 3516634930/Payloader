// CODEC-IMPORTS
import { base64ToBase64Url, base64ToBytes, bytesToBase64, bytesToBuffer, bytesToHex, decodeBase32Bytes, fromBase64Url } from './bases';
import { utf8Decoder, utf8Encoder } from './alphabets';
import type { Direction, ParamKey } from './types';
// CODEC-IMPORTS-END
export const isJsonRecord = (value: unknown): value is Record<string, unknown> => (
  typeof value === 'object' && value !== null && !Array.isArray(value)
);

export const jwtTimestamps = (payload: unknown) => {
  if (!isJsonRecord(payload)) return {};
  return Object.fromEntries(['iat', 'nbf', 'exp']
    .filter(key => typeof payload[key] === 'number')
    .map(key => [key, new Date((payload[key] as number) * 1000).toISOString()]));
};

export const decodeJwt = (value: string) => {
  const token = value.trim().replace(/^Bearer\s+/i, '');
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('JWT 必须包含 Header.Payload.Signature 三段');
  const header = JSON.parse(fromBase64Url(parts[0]));
  const payload = JSON.parse(fromBase64Url(parts[1]));
  const timestamps = jwtTimestamps(payload);
  return JSON.stringify({ header, payload, timestamps, signature: parts[2] }, null, 2);
};

export type JwtHmacSpec = { jwt: 'HS256' | 'HS384' | 'HS512'; subtle: 'SHA-256' | 'SHA-384' | 'SHA-512' };

export const jwtHmacSpecFromHash = (algorithm: string): JwtHmacSpec => {
  if (algorithm === 'sha384') return { jwt: 'HS384', subtle: 'SHA-384' };
  if (algorithm === 'sha512') return { jwt: 'HS512', subtle: 'SHA-512' };
  return { jwt: 'HS256', subtle: 'SHA-256' };
};

export const jwtHmacSpecFromAlg = (alg: unknown) => {
  if (typeof alg !== 'string') return null;
  const upper = alg.toUpperCase();
  if (upper === 'HS256') return { jwt: 'HS256', subtle: 'SHA-256' } as JwtHmacSpec;
  if (upper === 'HS384') return { jwt: 'HS384', subtle: 'SHA-384' } as JwtHmacSpec;
  if (upper === 'HS512') return { jwt: 'HS512', subtle: 'SHA-512' } as JwtHmacSpec;
  return null;
};

export const bytesToBase64Url = (bytes: Uint8Array) => base64ToBase64Url(bytesToBase64(bytes));

export const jwtHmacSignBytes = async (signingInput: string, secret: string, subtleHash: JwtHmacSpec['subtle']) => {
  if (!secret) throw new Error('JWT HMAC 需要填写 secret');
  const key = await crypto.subtle.importKey('raw', bytesToBuffer(utf8Encoder.encode(secret)), { name: 'HMAC', hash: subtleHash }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, bytesToBuffer(utf8Encoder.encode(signingInput))));
};

export const jwtHmacTransform = async (direction: Direction, value: string, params: Record<ParamKey, string>) => {
  if (direction === 'encode') {
    const parsed = JSON.parse(value.trim() || '{}') as unknown;
    if (!isJsonRecord(parsed)) throw new Error('JWT HMAC 签名输入必须是 JSON 对象');
    const hasEnvelopePayload = Object.prototype.hasOwnProperty.call(parsed, 'payload');
    const headerSource = hasEnvelopePayload && isJsonRecord(parsed.header) ? parsed.header : {};
    const payload = hasEnvelopePayload ? parsed.payload : parsed;
    if (payload === undefined) throw new Error('JWT HMAC 签名输入缺少 payload');
    const spec = jwtHmacSpecFromAlg(headerSource.alg) || jwtHmacSpecFromHash(params.hashAlgorithm);
    const header = { alg: spec.jwt, typ: 'JWT', ...headerSource };
    header.alg = spec.jwt;
    const headerPart = bytesToBase64Url(utf8Encoder.encode(JSON.stringify(header)));
    const payloadPart = bytesToBase64Url(utf8Encoder.encode(JSON.stringify(payload)));
    const signingInput = `${headerPart}.${payloadPart}`;
    const signatureBytes = await jwtHmacSignBytes(signingInput, params.secret, spec.subtle);
    const signature = bytesToBase64Url(signatureBytes);
    return JSON.stringify({
      token: `${signingInput}.${signature}`,
      algorithm: spec.jwt,
      header,
      payload,
      signingInput,
      signature: {
        base64url: signature,
        hex: bytesToHex(signatureBytes),
      },
      warning: '仅支持 HS256/HS384/HS512 HMAC。本工具用于本地 CTF、课堂和兼容性分析，不负责生产密钥托管。',
    }, null, 2);
  }

  const trimmed = value.trim();
  let token = trimmed.replace(/^Bearer\s+/i, '');
  if (trimmed.startsWith('{')) {
    try {
      const parsed = JSON.parse(trimmed) as Record<string, unknown>;
      if (typeof parsed.token === 'string' && parsed.token.trim()) token = parsed.token.trim();
    } catch {
      // Keep the original token text path.
    }
  }
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('JWT 必须包含 Header.Payload.Signature 三段');
  const header = JSON.parse(fromBase64Url(parts[0]));
  const payload = JSON.parse(fromBase64Url(parts[1]));
  const headerSpec = isJsonRecord(header) ? jwtHmacSpecFromAlg(header.alg) : null;
  const spec = headerSpec || jwtHmacSpecFromHash(params.hashAlgorithm);
  const signingInput = `${parts[0]}.${parts[1]}`;
  const expectedBytes = await jwtHmacSignBytes(signingInput, params.secret, spec.subtle);
  const providedBytes = base64ToBytes(parts[2]);
  return JSON.stringify({
    valid: constantTimeEqual(providedBytes, expectedBytes),
    algorithm: spec.jwt,
    algorithmSource: headerSpec ? 'jwt-header' : 'selected-option',
    header,
    payload,
    timestamps: jwtTimestamps(payload),
    signingInput,
    signature: {
      providedBase64Url: parts[2],
      expectedBase64Url: bytesToBase64Url(expectedBytes),
      providedHex: bytesToHex(providedBytes),
      expectedHex: bytesToHex(expectedBytes),
    },
    warning: '仅支持 HS256/HS384/HS512 HMAC。本工具用于本地 CTF、课堂和兼容性分析，不负责生产密钥托管。',
  }, null, 2);
};

export const jwtSignatureSummary = (base64Url: string) => {
  const bytes = base64ToBytes(base64Url);
  return {
    base64url: base64Url,
    bytes: bytes.length,
    hex: bytesToHex(bytes),
  };
};

export const jwtPayloadSummary = (bytes: Uint8Array) => {
  const text = utf8Decoder.decode(bytes);
  try {
    const payload = JSON.parse(text);
    return {
      payload,
      payloadText: text,
      payloadHex: bytesToHex(bytes),
      timestamps: jwtTimestamps(payload),
    };
  } catch {
    return {
      payload: text,
      payloadText: text,
      payloadHex: bytesToHex(bytes),
      timestamps: {},
    };
  }
};

export const jwtPublicTransform = async (value: string, params: Record<ParamKey, string>) => {
  const token = value.trim().replace(/^Bearer\s+/i, '');
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('JWT/JWS compact token must have Header.Payload.Signature');
  const keyMaterial = String(params.secret || '').trim();
  if (!keyMaterial) throw new Error('Public verification requires PEM, certificate, JWK, or JWKS input');

  const jose = await import('jose');
  const protectedHeader = jose.decodeProtectedHeader(token);
  const alg = typeof protectedHeader.alg === 'string' ? protectedHeader.alg : '';
  if (!alg || alg.toLowerCase() === 'none') {
    return JSON.stringify({
      valid: false,
      algorithm: alg || null,
      header: protectedHeader,
      signature: jwtSignatureSummary(parts[2]),
      error: 'Unsecured or missing alg is not verifiable with a public key',
    }, null, 2);
  }

  let keyMaterialType = 'unknown';
  try {
    let verification;
    if (/^\s*\{/.test(keyMaterial)) {
      const parsed = JSON.parse(keyMaterial) as Record<string, unknown>;
      if (Array.isArray(parsed.keys)) {
        keyMaterialType = 'JWKS';
        verification = await jose.compactVerify(token, jose.createLocalJWKSet(parsed as never));
      } else if ('kty' in parsed) {
        keyMaterialType = 'JWK';
        const key = await jose.importJWK(parsed as never, alg);
        verification = await jose.compactVerify(token, key);
      } else {
        throw new Error('JSON key material must be a JWK or JWKS object');
      }
    } else if (/-----BEGIN CERTIFICATE-----/.test(keyMaterial)) {
      keyMaterialType = 'X.509 certificate';
      const key = await jose.importX509(keyMaterial, alg);
      verification = await jose.compactVerify(token, key);
    } else if (/-----BEGIN [^-]*PUBLIC KEY-----/.test(keyMaterial)) {
      keyMaterialType = 'PEM public key';
      const key = await jose.importSPKI(keyMaterial, alg);
      verification = await jose.compactVerify(token, key);
    } else {
      throw new Error('Key material must be PEM public key, X.509 certificate, JWK, or JWKS');
    }

    const payloadSummary = jwtPayloadSummary(verification.payload);
    return JSON.stringify({
      valid: true,
      algorithm: alg,
      keyMaterialType,
      header: protectedHeader,
      payload: payloadSummary.payload,
      payloadText: payloadSummary.payloadText,
      payloadHex: payloadSummary.payloadHex,
      timestamps: payloadSummary.timestamps,
      signingInput: `${parts[0]}.${parts[1]}`,
      signature: jwtSignatureSummary(parts[2]),
      warning: 'Signature verification only. Claim validation such as exp, nbf, aud, and iss is shown but not enforced.',
    }, null, 2);
  } catch (error) {
    return JSON.stringify({
      valid: false,
      algorithm: alg || null,
      keyMaterialType,
      header: protectedHeader,
      signingInput: `${parts[0]}.${parts[1]}`,
      signature: jwtSignatureSummary(parts[2]),
      error: error instanceof Error ? error.message : String(error),
      warning: 'The token structure may still parse correctly even when signature verification fails.',
    }, null, 2);
  }
};

export const bytesToBase64UrlPadded = (bytes: Uint8Array) => bytesToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_');

export const fernetKeyParts = (secret: string) => {
  if (!secret.trim()) throw new Error('Fernet 需要填写 URL-safe Base64 32 字节 key');
  const key = base64ToBytes(secret.trim());
  if (key.length !== 32) throw new Error(`Fernet key 解码后必须是 32 字节，当前是 ${key.length} 字节`);
  return {
    signingKey: key.slice(0, 16),
    encryptionKey: key.slice(16),
  };
};

export const uint64Be = (value: bigint) => {
  const bytes = new Uint8Array(8);
  let current = value;
  for (let index = 7; index >= 0; index -= 1) {
    bytes[index] = Number(current & 0xffn);
    current >>= 8n;
  }
  return bytes;
};

export const readUint64Be = (bytes: Uint8Array) => {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
};

export const fernetHmac = async (signingKey: Uint8Array, data: Uint8Array) => {
  const key = await crypto.subtle.importKey('raw', bytesToBuffer(signingKey), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, bytesToBuffer(data)));
};

export const constantTimeEqual = (a: Uint8Array, b: Uint8Array) => {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let index = 0; index < a.length; index += 1) diff |= a[index] ^ b[index];
  return diff === 0;
};

export const importFernetAesKey = (encryptionKey: Uint8Array, usages: KeyUsage[]) => crypto.subtle.importKey(
  'raw',
  bytesToBuffer(encryptionKey),
  { name: 'AES-CBC', length: 128 },
  false,
  usages,
);

export const parseFernetRaw = (value: string) => {
  const raw = base64ToBytes(value.trim().replace(/^Fernet\s+/i, ''));
  if (raw.length < 57) throw new Error('Fernet token 过短，至少需要 version、timestamp、IV、ciphertext、HMAC');
  const version = raw[0];
  const timestamp = readUint64Be(raw.slice(1, 9));
  const iv = raw.slice(9, 25);
  const ciphertext = raw.slice(25, -32);
  const hmacTag = raw.slice(-32);
  if (ciphertext.length === 0 || ciphertext.length % 16 !== 0) throw new Error('Fernet ciphertext 长度必须是 16 字节块的倍数');
  return { raw, version, timestamp, iv, ciphertext, hmacTag, signedData: raw.slice(0, -32) };
};

export const encodeFernet = async (value: string, secret: string) => {
  const { signingKey, encryptionKey } = fernetKeyParts(secret);
  const timestamp = BigInt(Math.floor(Date.now() / 1000));
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const key = await importFernetAesKey(encryptionKey, ['encrypt']);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-CBC', iv: bytesToBuffer(iv) },
    key,
    bytesToBuffer(utf8Encoder.encode(value)),
  ));
  const signedData = new Uint8Array([0x80, ...uint64Be(timestamp), ...iv, ...ciphertext]);
  const hmacTag = await fernetHmac(signingKey, signedData);
  return bytesToBase64UrlPadded(new Uint8Array([...signedData, ...hmacTag]));
};

export const decodeFernet = async (value: string, secret: string) => {
  const parsed = parseFernetRaw(value);
  const result: Record<string, unknown> = {
    versionHex: `0x${parsed.version.toString(16).padStart(2, '0')}`,
    versionValid: parsed.version === 0x80,
    timestamp: parsed.timestamp.toString(),
    timestampIso: new Date(Number(parsed.timestamp) * 1000).toISOString(),
    ivHex: bytesToHex(parsed.iv),
    ciphertextBytes: parsed.ciphertext.length,
    ciphertextHex: bytesToHex(parsed.ciphertext),
    hmacHex: bytesToHex(parsed.hmacTag),
  };

  if (!secret.trim()) {
    result.note = '未填写 Fernet key，仅解析结构；填写 key 后可校验 HMAC 并解密。';
    return JSON.stringify(result, null, 2);
  }

  const { signingKey, encryptionKey } = fernetKeyParts(secret);
  const expected = await fernetHmac(signingKey, parsed.signedData);
  const hmacValid = constantTimeEqual(expected, parsed.hmacTag);
  result.expectedHmacHex = bytesToHex(expected);
  result.hmacValid = hmacValid;
  if (!hmacValid) return JSON.stringify(result, null, 2);

  const key = await importFernetAesKey(encryptionKey, ['decrypt']);
  const plaintext = new Uint8Array(await crypto.subtle.decrypt(
    { name: 'AES-CBC', iv: bytesToBuffer(parsed.iv) },
    key,
    bytesToBuffer(parsed.ciphertext),
  ));
  result.plaintext = utf8Decoder.decode(plaintext);
  result.plaintextHex = bytesToHex(plaintext);
  return JSON.stringify(result, null, 2);
};

export const normalizeOtpAlgorithm = (value: string) => {
  const normalized = String(value || 'sha1').toLowerCase().replace(/[^a-z0-9]/g, '');
  if (normalized === 'sha256') return { subtle: 'SHA-256', label: 'SHA256' };
  if (normalized === 'sha512') return { subtle: 'SHA-512', label: 'SHA512' };
  return { subtle: 'SHA-1', label: 'SHA1' };
};

export const parseOtpDigits = (value: string) => {
  const digits = Number.parseInt(String(value || '6'), 10);
  if (!Number.isFinite(digits) || digits < 4 || digits > 10) throw new Error('OTP 位数必须在 4 到 10 之间');
  return digits;
};

export const parseOtpCounter = (value: string) => {
  const text = String(value ?? '').trim();
  if (!/^\d+$/.test(text)) throw new Error('HOTP counter 必须是非负整数');
  return BigInt(text);
};

export const normalizeOtpSecret = (value: string) => {
  const secret = String(value || '').trim().replace(/\s+/g, '');
  if (!secret) throw new Error('OTP 需要 Base32 secret');
  return secret;
};

export const hotpCode = async (secret: string, counterValue: bigint, algorithm: string, digitsValue: number) => {
  const secretBytes = decodeBase32Bytes(secret, 'special');
  const counterBytes = uint64Be(counterValue);
  const key = await crypto.subtle.importKey(
    'raw',
    bytesToBuffer(secretBytes),
    { name: 'HMAC', hash: normalizeOtpAlgorithm(algorithm).subtle },
    false,
    ['sign'],
  );
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, bytesToBuffer(counterBytes)));
  const offset = mac[mac.length - 1] & 0x0f;
  const binary = ((mac[offset] & 0x7f) << 24)
    | (mac[offset + 1] << 16)
    | (mac[offset + 2] << 8)
    | mac[offset + 3];
  const code = String(binary % (10 ** digitsValue)).padStart(digitsValue, '0');
  return {
    code,
    offset,
    digestHex: bytesToHex(mac),
  };
};

export const generateHotp = async (secret: string, algorithm: string, digitsText: string, counterText: string) => {
  const digitsValue = parseOtpDigits(digitsText);
  const counterValue = parseOtpCounter(counterText);
  const algorithmInfo = normalizeOtpAlgorithm(algorithm);
  const result = await hotpCode(normalizeOtpSecret(secret), counterValue, algorithm, digitsValue);
  return JSON.stringify({
    type: 'HOTP',
    algorithm: algorithmInfo.label,
    digits: digitsValue,
    counter: counterValue.toString(),
    code: result.code,
    digestHex: result.digestHex,
    dynamicTruncationOffset: result.offset,
  }, null, 2);
};

export const generateTotp = async (secret: string, algorithm: string, digitsText: string, stepText: string, timestampText: string) => {
  const digitsValue = parseOtpDigits(digitsText);
  const step = Math.max(1, Number.parseInt(String(stepText || '30'), 10) || 30);
  const timestamp = String(timestampText || '').trim()
    ? Number.parseInt(timestampText, 10)
    : Math.floor(Date.now() / 1000);
  if (!Number.isFinite(timestamp) || timestamp < 0) throw new Error('TOTP 时间戳必须是非负秒数');
  const counterValue = BigInt(Math.floor(timestamp / step));
  const algorithmInfo = normalizeOtpAlgorithm(algorithm);
  const result = await hotpCode(normalizeOtpSecret(secret), counterValue, algorithm, digitsValue);
  return JSON.stringify({
    type: 'TOTP',
    algorithm: algorithmInfo.label,
    digits: digitsValue,
    timeStep: step,
    timestamp,
    timestampIso: new Date(timestamp * 1000).toISOString(),
    counter: counterValue.toString(),
    validForSeconds: step - (timestamp % step),
    code: result.code,
    digestHex: result.digestHex,
    dynamicTruncationOffset: result.offset,
  }, null, 2);
};

export const parseOtpLabel = (value: string) => {
  const decoded = decodeURIComponent(value.replace(/^\/+/, ''));
  const separator = decoded.indexOf(':');
  if (separator < 0) return { label: decoded, issuerFromLabel: '', accountName: decoded };
  return {
    label: decoded,
    issuerFromLabel: decoded.slice(0, separator).trim(),
    accountName: decoded.slice(separator + 1).trim(),
  };
};

export const encodeOtpAuthUri = (label: string, params: Record<ParamKey, string>) => {
  const trimmedLabel = String(label || '').trim();
  if (!trimmedLabel) throw new Error('生成 otpauth URI 需要输入标签，例如 issuer:account');
  const secret = String(params.secret || '').trim().replace(/\s+/g, '');
  if (!secret) throw new Error('生成 otpauth URI 需要填写 Base32 secret');
  const type = params.variant === 'hex' ? 'hotp' : 'totp';
  const algorithm = normalizeOtpAlgorithm(params.hashAlgorithm).label;
  const digitsValue = parseOtpDigits(params.digits);
  const query = new URLSearchParams();
  query.set('secret', secret);
  query.set('algorithm', algorithm);
  query.set('digits', String(digitsValue));
  const labelInfo = parseOtpLabel(encodeURIComponent(trimmedLabel));
  if (labelInfo.issuerFromLabel) query.set('issuer', labelInfo.issuerFromLabel);
  if (type === 'hotp') {
    query.set('counter', parseOtpCounter(params.counter).toString());
  } else {
    query.set('period', String(Math.max(1, Number.parseInt(String(params.timeStep || '30'), 10) || 30)));
  }
  return `otpauth://${type}/${encodeURIComponent(trimmedLabel)}?${query.toString()}`;
};

export const decodeOtpAuthUri = async (value: string) => {
  const uri = new URL(String(value || '').trim());
  if (uri.protocol !== 'otpauth:') throw new Error('输入必须是 otpauth:// URI');
  const type = uri.hostname.toLowerCase();
  if (type !== 'hotp' && type !== 'totp') throw new Error('otpauth URI 仅支持 hotp 或 totp');
  const labelInfo = parseOtpLabel(uri.pathname);
  const secret = String(uri.searchParams.get('secret') || '').trim();
  const algorithmRaw = uri.searchParams.get('algorithm') || 'SHA1';
  const algorithm = normalizeOtpAlgorithm(algorithmRaw).label;
  const digitsValue = parseOtpDigits(uri.searchParams.get('digits') || '6');
  const periodValue = Math.max(1, Number.parseInt(uri.searchParams.get('period') || '30', 10) || 30);
  const counterText = uri.searchParams.get('counter') || '0';
  const issuer = uri.searchParams.get('issuer') || labelInfo.issuerFromLabel || '';

  const result: Record<string, unknown> = {
    type,
    label: labelInfo.label,
    accountName: labelInfo.accountName,
    issuer,
    secret,
    algorithm,
    digits: digitsValue,
    counter: type === 'hotp' ? counterText : undefined,
    period: type === 'totp' ? periodValue : undefined,
  };

  if (!secret) {
    result.note = 'URI 中没有 secret，无法计算验证码';
    return JSON.stringify(result, null, 2);
  }

  if (type === 'hotp') {
    const counterValue = parseOtpCounter(counterText);
    const code = await hotpCode(secret, counterValue, algorithmRaw, digitsValue);
    result.currentCode = code.code;
    result.digestHex = code.digestHex;
    result.dynamicTruncationOffset = code.offset;
  } else {
    const timestamp = Math.floor(Date.now() / 1000);
    const counterValue = BigInt(Math.floor(timestamp / periodValue));
    const code = await hotpCode(secret, counterValue, algorithmRaw, digitsValue);
    result.timestamp = timestamp;
    result.timestampIso = new Date(timestamp * 1000).toISOString();
    result.timeStep = periodValue;
    result.counter = counterValue.toString();
    result.validForSeconds = periodValue - (timestamp % periodValue);
    result.currentCode = code.code;
    result.digestHex = code.digestHex;
    result.dynamicTruncationOffset = code.offset;
  }

  return JSON.stringify(result, null, 2);
};

export const decodeOtpAuthUriCompat = async (value: string) => {
  try {
    return await decodeOtpAuthUri(value);
  } catch {
    // Fall through to the browser-stable parser below.
  }
  const text = String(value || '').trim();
  const match = /^otpauth:\/\/(hotp|totp)\/([^?]+)(?:\?(.*))?$/i.exec(text);
  if (!match) throw new Error('Input must be an otpauth:// URI');
  const [, rawType, rawLabel, rawQuery = ''] = match;
  const type = rawType.toLowerCase();
  if (type !== 'hotp' && type !== 'totp') throw new Error('otpauth URI only supports hotp and totp');
  const labelInfo = parseOtpLabel(rawLabel);
  const searchParams = new URLSearchParams(rawQuery);
  const secret = String(searchParams.get('secret') || '').trim();
  const algorithmRaw = searchParams.get('algorithm') || 'SHA1';
  const algorithm = normalizeOtpAlgorithm(algorithmRaw).label;
  const digitsValue = parseOtpDigits(searchParams.get('digits') || '6');
  const periodValue = Math.max(1, Number.parseInt(searchParams.get('period') || '30', 10) || 30);
  const counterText = searchParams.get('counter') || '0';
  const issuer = searchParams.get('issuer') || labelInfo.issuerFromLabel || '';

  const result: Record<string, unknown> = {
    type,
    label: labelInfo.label,
    accountName: labelInfo.accountName,
    issuer,
    secret,
    algorithm,
    digits: digitsValue,
    counter: type === 'hotp' ? counterText : undefined,
    period: type === 'totp' ? periodValue : undefined,
  };

  if (!secret) {
    result.note = 'URI is missing secret, so no OTP code can be calculated.';
    return JSON.stringify(result, null, 2);
  }

  if (type === 'hotp') {
    const counterValue = parseOtpCounter(counterText);
    const code = await hotpCode(secret, counterValue, algorithmRaw, digitsValue);
    result.currentCode = code.code;
    result.digestHex = code.digestHex;
    result.dynamicTruncationOffset = code.offset;
  } else {
    const timestamp = Math.floor(Date.now() / 1000);
    const counterValue = BigInt(Math.floor(timestamp / periodValue));
    const code = await hotpCode(secret, counterValue, algorithmRaw, digitsValue);
    result.timestamp = timestamp;
    result.timestampIso = new Date(timestamp * 1000).toISOString();
    result.timeStep = periodValue;
    result.counter = counterValue.toString();
    result.validForSeconds = periodValue - (timestamp % periodValue);
    result.currentCode = code.code;
    result.digestHex = code.digestHex;
    result.dynamicTruncationOffset = code.offset;
  }

  return JSON.stringify(result, null, 2);
};
