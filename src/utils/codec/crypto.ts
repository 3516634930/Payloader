// CODEC-IMPORTS
import { base64ToBytes, bytesToBase64, bytesToBuffer, bytesToHex, hexToBytes } from './bases';
import { isNobleAeadOperation, utf8Decoder, utf8Encoder } from './alphabets';
import { adler32, crc16, crc32 } from './textEncodings';
import { parseFunctionLikeCall, parsePythonByteLikeValue, parsePythonTextLikeValue } from './rsa';
import { defaultParams } from './operations';
import type { Direction, OperationId, ParamKey } from './types';
// CODEC-IMPORTS-END

export const md5Bytes = (source: Uint8Array) => {
  const bitLength = source.length * 8;
  const paddedLength = (((source.length + 8) >>> 6) + 1) * 64;
  const bytes = new Uint8Array(paddedLength);
  bytes.set(source);
  bytes[source.length] = 0x80;
  const view = new DataView(bytes.buffer);
  view.setUint32(paddedLength - 8, bitLength >>> 0, true);
  view.setUint32(paddedLength - 4, Math.floor(bitLength / 0x100000000), true);

  let a0 = 0x67452301;
  let b0 = 0xefcdab89;
  let c0 = 0x98badcfe;
  let d0 = 0x10325476;
  const shifts = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];
  const constants = Array.from({ length: 64 }, (_, index) => Math.floor(Math.abs(Math.sin(index + 1)) * 0x100000000) >>> 0);
  const rotate = (number: number, count: number) => ((number << count) | (number >>> (32 - count))) >>> 0;

  for (let offset = 0; offset < paddedLength; offset += 64) {
    const words = Array.from({ length: 16 }, (_, index) => view.getUint32(offset + index * 4, true));
    let a = a0;
    let b = b0;
    let c = c0;
    let d = d0;

    for (let index = 0; index < 64; index += 1) {
      let f = 0;
      let g = 0;
      if (index < 16) {
        f = (b & c) | (~b & d);
        g = index;
      } else if (index < 32) {
        f = (d & b) | (~d & c);
        g = (5 * index + 1) % 16;
      } else if (index < 48) {
        f = b ^ c ^ d;
        g = (3 * index + 5) % 16;
      } else {
        f = c ^ (b | ~d);
        g = (7 * index) % 16;
      }
      const next = d;
      d = c;
      c = b;
      b = (b + rotate((a + f + constants[index] + words[g]) >>> 0, shifts[index])) >>> 0;
      a = next;
    }

    a0 = (a0 + a) >>> 0;
    b0 = (b0 + b) >>> 0;
    c0 = (c0 + c) >>> 0;
    d0 = (d0 + d) >>> 0;
  }

  const digestBytes = new Uint8Array(16);
  [a0, b0, c0, d0].forEach((word, index) => {
    new DataView(digestBytes.buffer).setUint32(index * 4, word, true);
  });
  return digestBytes;
};

export const md5 = (value: string) => bytesToHex(md5Bytes(utf8Encoder.encode(value)));

export const md4Bytes = (source: Uint8Array) => {
  const bitLength = source.length * 8;
  const paddedLength = (((source.length + 8) >>> 6) + 1) * 64;
  const bytes = new Uint8Array(paddedLength);
  bytes.set(source);
  bytes[source.length] = 0x80;
  const view = new DataView(bytes.buffer);
  view.setUint32(paddedLength - 8, bitLength >>> 0, true);
  view.setUint32(paddedLength - 4, Math.floor(bitLength / 0x100000000), true);
  const rotate = (number: number, count: number) => ((number << count) | (number >>> (32 - count))) >>> 0;
  const f = (x: number, y: number, z: number) => (x & y) | (~x & z);
  const g = (x: number, y: number, z: number) => (x & y) | (x & z) | (y & z);
  const h = (x: number, y: number, z: number) => x ^ y ^ z;
  let a0 = 0x67452301;
  let b0 = 0xefcdab89;
  let c0 = 0x98badcfe;
  let d0 = 0x10325476;
  for (let offset = 0; offset < paddedLength; offset += 64) {
    const x = Array.from({ length: 16 }, (_, index) => view.getUint32(offset + index * 4, true));
    let a = a0;
    let b = b0;
    let c = c0;
    let d = d0;
    const round1 = (k: number, s: number) => {
      const next = rotate((a + f(b, c, d) + x[k]) >>> 0, s);
      a = d; d = c; c = b; b = next;
    };
    const round2 = (k: number, s: number) => {
      const next = rotate((a + g(b, c, d) + x[k] + 0x5a827999) >>> 0, s);
      a = d; d = c; c = b; b = next;
    };
    const round3 = (k: number, s: number) => {
      const next = rotate((a + h(b, c, d) + x[k] + 0x6ed9eba1) >>> 0, s);
      a = d; d = c; c = b; b = next;
    };
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15].forEach((k, index) => round1(k, [3, 7, 11, 19][index % 4]));
    [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15].forEach((k, index) => round2(k, [3, 5, 9, 13][index % 4]));
    [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15].forEach((k, index) => round3(k, [3, 9, 11, 15][index % 4]));
    a0 = (a0 + a) >>> 0;
    b0 = (b0 + b) >>> 0;
    c0 = (c0 + c) >>> 0;
    d0 = (d0 + d) >>> 0;
  }
  return [a0, b0, c0, d0].map(word => {
    const out = new Uint8Array(4);
    new DataView(out.buffer).setUint32(0, word, true);
    return bytesToHex(out);
  }).join('');
};

export const md4 = (value: string) => md4Bytes(utf8Encoder.encode(value));

export const utf16leBytes = (value: string) => {
  const bytes: number[] = [];
  for (const char of value) {
    const codePoint = char.codePointAt(0) || 0;
    if (codePoint > 0xffff) {
      const offset = codePoint - 0x10000;
      const high = 0xd800 + (offset >> 10);
      const low = 0xdc00 + (offset & 0x3ff);
      bytes.push(high & 0xff, (high >> 8) & 0xff, low & 0xff, (low >> 8) & 0xff);
    } else {
      bytes.push(codePoint & 0xff, (codePoint >> 8) & 0xff);
    }
  }
  return new Uint8Array(bytes);
};

export const digest = async (value: string, algorithm: string) => {
  if (algorithm === 'md5') return md5(value);
  if (algorithm === 'crc16') return crc16(value);
  if (algorithm === 'crc32') return crc32(value);
  if (algorithm === 'adler32') return adler32(value);
  if (algorithm === 'md4') return md4(value);
  if (algorithm === 'ntlm') return md4Bytes(utf16leBytes(value));
  if (algorithm === 'ripemd160') return bytesToHex((await import('@noble/hashes/legacy.js')).ripemd160(utf8Encoder.encode(value)));
  if (algorithm === 'whirlpool') return (await import('whirlpool-js')).default.encSync(value);
  if (algorithm === 'sm3') return (await import('sm-crypto')).default.sm3(value);
  if (algorithm === 'blake2b-256') return bytesToHex((await import('@noble/hashes/blake2.js')).blake2b(utf8Encoder.encode(value), { dkLen: 32 }));
  if (algorithm === 'blake2b-512') return bytesToHex((await import('@noble/hashes/blake2.js')).blake2b(utf8Encoder.encode(value), { dkLen: 64 }));
  if (algorithm === 'blake2s-256') return bytesToHex((await import('@noble/hashes/blake2.js')).blake2s(utf8Encoder.encode(value), { dkLen: 32 }));
  if (algorithm === 'blake3') return bytesToHex((await import('@noble/hashes/blake3.js')).blake3(utf8Encoder.encode(value)));
  if (algorithm === 'xxhash32') return (await import('xxhashjs')).default.h32(value, 0).toString(16).padStart(8, '0');
  if (algorithm === 'xxhash64') return (await import('xxhashjs')).default.h64(value, 0).toString(16).padStart(16, '0');
  if (algorithm.startsWith('sha3-')) {
    const sha3 = await import('@noble/hashes/sha3.js');
    const map = { 'sha3-224': sha3.sha3_224, 'sha3-256': sha3.sha3_256, 'sha3-384': sha3.sha3_384, 'sha3-512': sha3.sha3_512 };
    return bytesToHex(map[algorithm as keyof typeof map](utf8Encoder.encode(value)));
  }
  if (algorithm.startsWith('keccak-')) {
    const sha3 = await import('@noble/hashes/sha3.js');
    const map = { 'keccak-256': sha3.keccak_256, 'keccak-512': sha3.keccak_512 };
    return bytesToHex(map[algorithm as keyof typeof map](utf8Encoder.encode(value)));
  }
  const map: Record<string, string> = {
    sha1: 'SHA-1',
    sha256: 'SHA-256',
    sha384: 'SHA-384',
    sha512: 'SHA-512',
  };
  const bytes = await crypto.subtle.digest(map[algorithm] || 'SHA-256', bytesToBuffer(utf8Encoder.encode(value)));
  return bytesToHex(new Uint8Array(bytes));
};

export const identifyHash = (value: string) => {
  const text = value.trim();
  if (!text) throw new Error('请输入要识别的 Hash 或摘要字符串');
  type HashEntry = { name: string; hashcatMode?: number; johnFormat?: string };
  const candidates: HashEntry[] = [];
  const hexOnly = /^[0-9a-f]+$/i.test(text);
  if (/^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/.test(text)) candidates.push({ name: 'bcrypt', hashcatMode: 3200, johnFormat: 'bcrypt' });
  if (/^\$argon2(id|i|d)\$/.test(text)) candidates.push({ name: 'Argon2', hashcatMode: 13400 });
  if (/^\$[156]\$/.test(text)) candidates.push({ name: 'Unix crypt / shadow hash', hashcatMode: 1800, johnFormat: 'sha512crypt' });
  if (/^[a-f0-9]{32}:[a-f0-9]+$/i.test(text)) candidates.push({ name: 'Joomla / salted MD5-style hash', hashcatMode: 11 });
  if (hexOnly) {
    if (text.length === 4) candidates.push({ name: 'CRC16 / small checksum' });
    if (text.length === 8) candidates.push({ name: 'CRC32 / Adler32', hashcatMode: 11500, johnFormat: 'CRC32' });
    if (text.length === 32) candidates.push(
      { name: 'MD5', hashcatMode: 0, johnFormat: 'raw-md5' },
      { name: 'NTLM', hashcatMode: 1000, johnFormat: 'nt' },
      { name: 'MD4', hashcatMode: 900, johnFormat: 'raw-md4' },
    );
    if (text.length === 40) candidates.push(
      { name: 'SHA-1', hashcatMode: 100, johnFormat: 'raw-sha1' },
      { name: 'RIPEMD-160', hashcatMode: 6000 },
    );
    if (text.length === 56) candidates.push({ name: 'SHA-224', hashcatMode: 1300 });
    if (text.length === 64) candidates.push(
      { name: 'SHA-256', hashcatMode: 1400, johnFormat: 'raw-sha256' },
      { name: 'SHA3-256', hashcatMode: 17300 },
      { name: 'Keccak-256 (no padding)', hashcatMode: 17800 },
      { name: 'BLAKE2s-256', hashcatMode: 17100 },
    );
    if (text.length === 96) candidates.push({ name: 'SHA-384', hashcatMode: 10800, johnFormat: 'raw-sha384' });
    if (text.length === 128) candidates.push(
      { name: 'SHA-512', hashcatMode: 1700, johnFormat: 'raw-sha512' },
      { name: 'SHA3-512', hashcatMode: 17600 },
      { name: 'BLAKE2b-512', hashcatMode: 600 },
      { name: 'Whirlpool', hashcatMode: 6100 },
    );
  }
  if (/^[A-Za-z0-9+/]+={0,2}$/.test(text) && text.length >= 20) candidates.push({ name: 'Base64-encoded digest or token' });
  const firstCandidate = candidates[0];
  const hashcatCmd = firstCandidate?.hashcatMode !== undefined
    ? `hashcat -m ${firstCandidate.hashcatMode} '${text}' /path/to/wordlist.txt`
    : `hashcat --identify '${text}'`;
  const johnCmd = firstCandidate?.johnFormat
    ? `john --format=${firstCandidate.johnFormat} hash.txt`
    : `john --format=raw-* hash.txt  # try multiple formats`;
  return candidates.length
    ? JSON.stringify({ inputLength: text.length, candidates: candidates.map(c => c.name), hashcatMode: firstCandidate?.hashcatMode ?? null, hashcatCmd, johnCmd, crackingCommands: [`hashcat --identify '${text}'`, hashcatCmd, johnCmd, 'Use crackstation.net or hashes.com for quick lookups'] }, null, 2)
    : JSON.stringify({ inputLength: text.length, candidates: [], hashcatCmd: `hashcat --identify '${text}'`, note: '未匹配常见摘要形态，可尝试 hashid/hashcat --identify' }, null, 2);
};

export const hmac = async (value: string, secret: string, algorithm: string) => {
  if (!secret) throw new Error('HMAC 需要填写密钥');
  const hash = algorithm === 'sha1' ? 'SHA-1' : algorithm === 'sha384' ? 'SHA-384' : algorithm === 'sha512' ? 'SHA-512' : 'SHA-256';
  const key = await crypto.subtle.importKey('raw', bytesToBuffer(utf8Encoder.encode(secret)), { name: 'HMAC', hash }, false, ['sign']);
  const signature = await crypto.subtle.sign('HMAC', key, bytesToBuffer(utf8Encoder.encode(value)));
  return bytesToHex(new Uint8Array(signature));
};

export const bip39Seed = async (value: string, passphrase: string) => {
  const mnemonic = value.trim().toLowerCase().replace(/\s+/g, ' ').normalize('NFKD');
  if (!mnemonic) throw new Error('BIP39 需要输入助记词');
  const words = mnemonic.split(' ');
  const validWordCounts = new Set([12, 15, 18, 21, 24]);
  const salt = `mnemonic${passphrase || ''}`.normalize('NFKD');
  const material = await crypto.subtle.importKey('raw', bytesToBuffer(utf8Encoder.encode(mnemonic)), 'PBKDF2', false, ['deriveBits']);
  const seed = new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: bytesToBuffer(utf8Encoder.encode(salt)), iterations: 2048, hash: 'SHA-512' },
    material,
    512,
  ));
  return JSON.stringify({
    standard: 'BIP39 mnemonic to seed',
    wordCount: words.length,
    expectedWordCount: validWordCounts.has(words.length),
    passphraseUsed: Boolean(passphrase),
    kdf: 'PBKDF2-HMAC-SHA512',
    iterations: 2048,
    seedHex: bytesToHex(seed),
    seedBase64: bytesToBase64(seed),
    note: '未内置完整 wordlist，因此这里只做规范派生，不做助记词校验和验证。',
  }, null, 2);
};

export const deriveAesKey = async (secret: string, salt: Uint8Array, iterations: number) => {
  if (!secret) throw new Error('AES-GCM 需要填写口令');
  const material = await crypto.subtle.importKey('raw', bytesToBuffer(utf8Encoder.encode(secret)), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: bytesToBuffer(salt), iterations, hash: 'SHA-256' },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
};

export const deriveAesKeyForMode = async (secret: string, salt: Uint8Array, iterations: number, mode: 'AES-GCM' | 'AES-CBC' | 'AES-CTR') => {
  if (!secret) throw new Error(`${mode} 需要填写口令`);
  const material = await crypto.subtle.importKey('raw', bytesToBuffer(utf8Encoder.encode(secret)), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: bytesToBuffer(salt), iterations, hash: 'SHA-256' },
    material,
    { name: mode, length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
};

export const aesEncrypt = async (value: string, secret: string, iterations: string) => {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const rounds = Math.max(10000, Number.parseInt(iterations, 10) || 120000);
  const key = await deriveAesKey(secret, salt, rounds);
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: bytesToBuffer(iv) }, key, bytesToBuffer(utf8Encoder.encode(value)));
  return JSON.stringify({
    alg: 'AES-GCM',
    kdf: 'PBKDF2-SHA256',
    iterations: rounds,
    salt: bytesToBase64(salt),
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(new Uint8Array(ciphertext)),
  }, null, 2);
};

export const aesDecrypt = async (value: string, secret: string) => {
  const payload = JSON.parse(value);
  const salt = base64ToBytes(payload.salt);
  const iv = base64ToBytes(payload.iv);
  const ciphertext = base64ToBytes(payload.ciphertext);
  const key = await deriveAesKey(secret, salt, Number(payload.iterations) || 120000);
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytesToBuffer(iv) }, key, bytesToBuffer(ciphertext));
  return utf8Decoder.decode(new Uint8Array(plaintext));
};

export const aesEncryptCbc = async (value: string, secret: string, iterations: string) => {
  if (!secret) throw new Error('AES-CBC 需要填写口令');
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const rounds = Math.max(10000, Number.parseInt(iterations, 10) || 120000);
  const material = await crypto.subtle.importKey('raw', bytesToBuffer(utf8Encoder.encode(secret)), 'PBKDF2', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: bytesToBuffer(salt), iterations: rounds, hash: 'SHA-256' },
    material,
    { name: 'AES-CBC', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-CBC', iv: bytesToBuffer(iv) }, key, bytesToBuffer(utf8Encoder.encode(value)));
  return JSON.stringify({
    alg: 'AES-CBC',
    kdf: 'PBKDF2-SHA256',
    iterations: rounds,
    salt: bytesToBase64(salt),
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(new Uint8Array(ciphertext)),
  }, null, 2);
};

export const aesDecryptCbc = async (value: string, secret: string) => {
  if (!secret) throw new Error('AES-CBC 需要填写口令');
  const payload = JSON.parse(value);
  const salt = base64ToBytes(payload.salt);
  const iv = base64ToBytes(payload.iv);
  const ciphertext = base64ToBytes(payload.ciphertext);
  const material = await crypto.subtle.importKey('raw', bytesToBuffer(utf8Encoder.encode(secret)), 'PBKDF2', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: bytesToBuffer(salt), iterations: Number(payload.iterations) || 120000, hash: 'SHA-256' },
    material,
    { name: 'AES-CBC', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-CBC', iv: bytesToBuffer(iv) }, key, bytesToBuffer(ciphertext));
  return utf8Decoder.decode(new Uint8Array(plaintext));
};

export const concatBytes = (...chunks: Uint8Array[]) => {
  const output = new Uint8Array(chunks.reduce((sum, chunk) => sum + chunk.length, 0));
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.length;
  }
  return output;
};

export const opensslMagic = utf8Encoder.encode('Salted__');

export const opensslEvpBytesToKey = (password: string, salt: Uint8Array) => {
  if (!password) throw new Error('OpenSSL enc 需要填写 passphrase');
  if (salt.length !== 8) throw new Error('OpenSSL Salted__ salt 必须是 8 字节');
  const passwordBytes = utf8Encoder.encode(password);
  const material: number[] = [];
  let previous = new Uint8Array();
  while (material.length < 48) {
    previous = md5Bytes(concatBytes(previous, passwordBytes, salt));
    material.push(...previous);
  }
  const derived = Uint8Array.from(material.slice(0, 48));
  return {
    key: derived.slice(0, 32),
    iv: derived.slice(32, 48),
  };
};

export const parseOpenSslSaltedBlob = (value: string) => {
  let text = value.trim();
  if (text.startsWith('{')) {
    try {
      const parsed = JSON.parse(text) as Record<string, unknown>;
      if (typeof parsed.opensslBase64 === 'string' && parsed.opensslBase64.trim()) text = parsed.opensslBase64.trim();
      else if (typeof parsed.opensslHex === 'string' && parsed.opensslHex.trim()) text = parsed.opensslHex.trim();
    } catch {
      // Fall through to raw text parsing.
    }
  }
  const compact = text.replace(/\s+/g, '');
  const bytes = /^[0-9a-f]+$/i.test(compact) && compact.length % 2 === 0
    ? hexToBytes(compact)
    : base64ToBytes(compact);
  if (bytes.length < 32) throw new Error('OpenSSL Salted__ 数据过短');
  const hasMagic = opensslMagic.every((byte, index) => bytes[index] === byte);
  if (!hasMagic) throw new Error('未找到 OpenSSL Salted__ 头，期望 Base64 以 U2FsdGVkX1 开头，或 hex 以 53616c7465645f5f 开头');
  return {
    salt: bytes.slice(8, 16),
    ciphertext: bytes.slice(16),
    blob: bytes,
  };
};

export const importOpenSslAesCbcKey = (key: Uint8Array, usages: KeyUsage[]) => crypto.subtle.importKey(
  'raw',
  bytesToBuffer(key),
  { name: 'AES-CBC', length: 256 },
  false,
  usages,
);

export const openSslAes256CbcTransform = async (direction: Direction, value: string, secret: string) => {
  if (direction === 'encode') {
    const salt = crypto.getRandomValues(new Uint8Array(8));
    const derived = opensslEvpBytesToKey(secret, salt);
    const key = await importOpenSslAesCbcKey(derived.key, ['encrypt']);
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
      { name: 'AES-CBC', iv: bytesToBuffer(derived.iv) },
      key,
      bytesToBuffer(utf8Encoder.encode(value)),
    ));
    const blob = concatBytes(opensslMagic, salt, ciphertext);
    return JSON.stringify({
      format: 'OpenSSL enc Salted__',
      alg: 'AES-256-CBC',
      kdf: 'EVP_BytesToKey-MD5',
      saltHex: bytesToHex(salt),
      keyHex: bytesToHex(derived.key),
      ivHex: bytesToHex(derived.iv),
      ciphertextHex: bytesToHex(ciphertext),
      opensslBase64: bytesToBase64(blob),
      opensslHex: bytesToHex(blob),
      cliEquivalent: 'openssl enc -aes-256-cbc -salt -md md5 -base64',
      warning: 'EVP_BytesToKey-MD5 是历史兼容格式，适合 CTF/遗留样本分析；新系统应使用现代 KDF 和 AEAD',
    }, null, 2);
  }

  const parsed = parseOpenSslSaltedBlob(value);
  const derived = opensslEvpBytesToKey(secret, parsed.salt);
  const key = await importOpenSslAesCbcKey(derived.key, ['decrypt']);
  const plaintext = new Uint8Array(await crypto.subtle.decrypt(
    { name: 'AES-CBC', iv: bytesToBuffer(derived.iv) },
    key,
    bytesToBuffer(parsed.ciphertext),
  ));
  return JSON.stringify({
    plaintext: utf8Decoder.decode(plaintext),
    plaintextHex: bytesToHex(plaintext),
    format: 'OpenSSL enc Salted__',
    alg: 'AES-256-CBC',
    kdf: 'EVP_BytesToKey-MD5',
    saltHex: bytesToHex(parsed.salt),
    keyHex: bytesToHex(derived.key),
    ivHex: bytesToHex(derived.iv),
    ciphertextHex: bytesToHex(parsed.ciphertext),
    inputBytes: parsed.blob.length,
  }, null, 2);
};

export const aesEncryptCtr = async (value: string, secret: string, iterations: string) => {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const counter = crypto.getRandomValues(new Uint8Array(16));
  const rounds = Math.max(10000, Number.parseInt(iterations, 10) || 120000);
  const key = await deriveAesKeyForMode(secret, salt, rounds, 'AES-CTR');
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-CTR', counter: bytesToBuffer(counter), length: 64 }, key, bytesToBuffer(utf8Encoder.encode(value)));
  return JSON.stringify({
    alg: 'AES-CTR',
    kdf: 'PBKDF2-SHA256',
    iterations: rounds,
    salt: bytesToBase64(salt),
    counter: bytesToBase64(counter),
    length: 64,
    ciphertext: bytesToBase64(new Uint8Array(ciphertext)),
    warning: 'CTR 是流模式，同一 key/counter 复用会泄露明文异或关系',
  }, null, 2);
};

export const aesDecryptCtr = async (value: string, secret: string) => {
  const payload = JSON.parse(value);
  const salt = base64ToBytes(payload.salt);
  const counter = base64ToBytes(payload.counter || payload.iv);
  const ciphertext = base64ToBytes(payload.ciphertext);
  const key = await deriveAesKeyForMode(secret, salt, Number(payload.iterations) || 120000, 'AES-CTR');
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-CTR', counter: bytesToBuffer(counter), length: Number(payload.length) || 64 }, key, bytesToBuffer(ciphertext));
  return utf8Decoder.decode(new Uint8Array(plaintext));
};

export const loadCryptoJs = async () => (await import('crypto-js')).default;
export type CryptoJsRuntime = Awaited<ReturnType<typeof loadCryptoJs>>;
export type CryptoJsWordArray = ReturnType<CryptoJsRuntime['enc']['Utf8']['parse']>;
export type CryptoJsCipherHelper = CryptoJsRuntime['DES'];
export type StreamCipherPayload = { ciphertextHex?: string; ciphertext?: string; nonceHex?: string; nonce?: string };
export type AesRawPayload = { ciphertextHex?: string; ciphertext?: string; wrappedHex?: string; wrapped?: string; ivHex?: string; iv?: string; mode?: string };
export type AeadPayload = StreamCipherPayload & {
  ivHex?: string;
  iv?: string;
  sealedHex?: string;
  sealed?: string;
  tagHex?: string;
  tag?: string;
  aadHex?: string;
  aad?: string;
  associatedDataHex?: string;
  associatedData?: string;
};
export type Sm4Payload = { ciphertextHex?: string; ciphertext?: string; ivHex?: string; iv?: string; mode?: string };

export const parseCryptoJsWordArray = (CryptoJS: CryptoJsRuntime, value: string, labelText: string) => {
  const raw = String(value || '');
  const text = raw.trim();
  if (!text) throw new Error(`${labelText} 不能为空`);
  const compactHex = text.replace(/^0x/i, '').replace(/[\s:_-]/g, '');
  if (compactHex.length % 2 === 0 && /^[0-9a-f]+$/i.test(compactHex)) {
    return { wordArray: CryptoJS.enc.Hex.parse(compactHex), format: 'hex' };
  }
  return { wordArray: CryptoJS.enc.Utf8.parse(raw), format: 'utf8' };
};

export const optionalCryptoJsWordArray = (CryptoJS: CryptoJsRuntime, value: string, labelText: string) => {
  const text = String(value || '').trim();
  return text ? parseCryptoJsWordArray(CryptoJS, text, labelText) : null;
};

export const cryptoJsWordArrayToText = (CryptoJS: CryptoJsRuntime, wordArray: CryptoJsWordArray) => {
  if (!wordArray.sigBytes) throw new Error('解密失败：密钥、IV、模式或密文可能不匹');
  try {
    return CryptoJS.enc.Utf8.stringify(wordArray);
  } catch {
    return JSON.stringify({
      plaintextHex: CryptoJS.enc.Hex.stringify(wordArray),
      note: '明文不是有效 UTF-8，已改为输出 Hex',
    }, null, 2);
  }
};

export const parseCryptoJsCipherInput = (CryptoJS: CryptoJsRuntime, value: string) => {
  const text = String(value || '').trim();
  if (!text) throw new Error('密文不能为空');
  try {
    const payload = JSON.parse(text) as {
      ciphertext?: string;
      ciphertextHex?: string;
      ciphertextEncoding?: string;
      iv?: string;
      ivHex?: string;
      mode?: string;
      alg?: string;
    };
    if (payload && typeof payload === 'object' && (payload.ciphertext || payload.ciphertextHex)) {
      const ciphertextText = String(payload.ciphertextHex || payload.ciphertext).trim();
      const encoding = payload.ciphertextHex ? 'hex' : String(payload.ciphertextEncoding || '').toLowerCase();
      const ciphertext = encoding === 'hex'
        ? CryptoJS.enc.Hex.parse(ciphertextText)
        : CryptoJS.enc.Base64.parse(ciphertextText);
      return { ciphertext, payload };
    }
  } catch {
    // Fall through to raw ciphertext parsing.
  }
  const compactHex = text.replace(/^0x/i, '').replace(/[\s:_-]/g, '');
  const ciphertext = compactHex.length % 2 === 0 && /^[0-9a-f]+$/i.test(compactHex)
    ? CryptoJS.enc.Hex.parse(compactHex)
    : CryptoJS.enc.Base64.parse(text);
  return { ciphertext, payload: null };
};

export const cryptoJsCipherByOperation = (CryptoJS: CryptoJsRuntime, operationId: OperationId): { helper: CryptoJsCipherHelper; alg: string; stream: boolean } => {
  switch (operationId) {
    case 'des':
      return { helper: CryptoJS.DES, alg: 'DES', stream: false };
    case 'triple-des':
      return { helper: CryptoJS.TripleDES, alg: 'TripleDES', stream: false };
    case 'blowfish':
      return { helper: CryptoJS.Blowfish, alg: 'Blowfish', stream: false };
    case 'rabbit':
      return { helper: CryptoJS.Rabbit, alg: 'Rabbit', stream: true };
    default:
      throw new Error('不支持的 crypto-js cipher');
  }
};

export const cryptoJsCipherTransform = async (operationId: OperationId, direction: Direction, value: string, params: Record<ParamKey, string>) => {
  const inferred = prepareSymmetricDecodeInput(operationId, direction, value, params);
  value = inferred.input;
  params = inferred.params;
  const CryptoJS = await loadCryptoJs();
  const { helper, alg, stream } = cryptoJsCipherByOperation(CryptoJS, operationId);
  const variant = operationId === 'rabbit' && params.variant === 'hex' ? 'special' : params.variant;
  if (!params.secret) throw new Error(`${alg} 需要密钥或 passphrase`);

  if (variant === 'decimal') {
    if (direction === 'encode') {
      return helper.encrypt(value, params.secret).toString();
    }
    return cryptoJsWordArrayToText(CryptoJS, helper.decrypt(value.trim(), params.secret));
  }

  const key = parseCryptoJsWordArray(CryptoJS, params.secret, `${alg} key`);
  const parsedInput = direction === 'decode' ? parseCryptoJsCipherInput(CryptoJS, value) : null;
  const payloadIv = parsedInput?.payload?.ivHex || parsedInput?.payload?.iv;
  const iv = optionalCryptoJsWordArray(CryptoJS, payloadIv || params.iv, 'IV');
  const modeName = variant === 'hex' ? 'ECB' : 'CBC';
  if (!stream && modeName === 'CBC' && !iv) throw new Error(`${alg}-CBC 需要填写 IV`);

  const cipherConfig = stream
    ? (iv ? { iv: iv.wordArray } : {})
    : {
      mode: modeName === 'ECB' ? CryptoJS.mode.ECB : CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7,
      ...(modeName === 'CBC' && iv ? { iv: iv.wordArray } : {}),
    };

  if (direction === 'encode') {
    const encrypted = helper.encrypt(CryptoJS.enc.Utf8.parse(value), key.wordArray, cipherConfig);
    return JSON.stringify({
      alg,
      mode: stream ? 'stream' : modeName,
      kdf: 'raw',
      keyFormat: key.format,
      iv: iv ? params.iv.trim() : undefined,
      ivFormat: iv?.format,
      ciphertextEncoding: 'base64',
      ciphertext: CryptoJS.enc.Base64.stringify(encrypted.ciphertext),
    }, null, 2);
  }

  const decrypted = helper.decrypt(CryptoJS.lib.CipherParams.create({ ciphertext: parsedInput?.ciphertext }), key.wordArray, cipherConfig);
  return cryptoJsWordArrayToText(CryptoJS, decrypted);
};

export const normalizeFixedBytes = (value: string, labelText: string, allowedLengths: number[]) => {
  const raw = String(value || '');
  const text = raw.trim();
  if (!text) throw new Error(`${labelText} 不能为空`);
  const compactHex = text.replace(/^0x/i, '').replace(/[\s:_-]/g, '');
  const parsed = compactHex.length % 2 === 0 && /^[0-9a-f]+$/i.test(compactHex)
    ? { bytes: hexToBytes(compactHex), format: 'hex' }
    : { bytes: utf8Encoder.encode(raw), format: 'utf8' };
  if (allowedLengths.includes(parsed.bytes.length)) {
    return { ...parsed, normalized: false, normalizedLength: parsed.bytes.length };
  }
  const targetLength = allowedLengths.find(length => parsed.bytes.length <= length) || allowedLengths[allowedLengths.length - 1];
  const output = new Uint8Array(targetLength);
  output.set(parsed.bytes.slice(0, targetLength));
  return {
    bytes: output,
    format: `${parsed.format}-${parsed.bytes.length < targetLength ? 'zero-padded' : 'truncated'}`,
    normalized: true,
    normalizedLength: targetLength,
  };
};

export const parseHexOrBase64Bytes = (value: string, labelText: string) => {
  const text = String(value || '').trim();
  if (!text) throw new Error(`${labelText} 不能为空`);
  const compactHex = text.replace(/^0x/i, '').replace(/[\s:_-]/g, '');
  if (compactHex.length % 2 === 0 && /^[0-9a-f]+$/i.test(compactHex)) return hexToBytes(compactHex);
  return base64ToBytes(text);
};

export const parseOptionalHexOrUtf8Bytes = (value: string) => {
  const raw = String(value || '');
  const text = raw.trim();
  if (!text) return { bytes: new Uint8Array(), format: 'empty' };
  const compactHex = text.replace(/^0x/i, '').replace(/[\s:_-]/g, '');
  if (compactHex.length % 2 === 0 && /^[0-9a-f]+$/i.test(compactHex)) {
    return { bytes: hexToBytes(compactHex), format: 'hex' };
  }
  return { bytes: utf8Encoder.encode(raw), format: 'utf8' };
};

export const parseHexBase64OrUtf8Bytes = (value: string, labelText: string) => {
  const raw = String(value || '');
  const text = raw.trim();
  if (!text) throw new Error(`${labelText} 不能为空`);
  const compactHex = text.replace(/^0x/i, '').replace(/[\s:_-]/g, '');
  if (compactHex.length % 2 === 0 && /^[0-9a-f]+$/i.test(compactHex)) {
    return { bytes: hexToBytes(compactHex), format: 'hex' };
  }
  try {
    return { bytes: base64ToBytes(text), format: 'base64' };
  } catch {
    return { bytes: utf8Encoder.encode(raw), format: 'utf8' };
  }
};

export type SymmetricInference = {
  operationId: OperationId | null;
  input: string;
  params: Record<ParamKey, string>;
  fields: Record<string, string>;
  confidence: number;
  notes: string[];
};

export const chineseCtfFieldAliases: Array<[RegExp, string]> = [
  [/(?:加密)?算法|算法类型|工作算法/, 'algorithm'],
  [/(?:私钥|私有)指数/, 'privateexponent'],
  [/(?:公钥|公开)指数/, 'publicexponent'],
  [/(?:模数|模)/, 'modulus'],
  [/(?:密钥|秘钥|口令|密码)/, 'key'],
  [/(?:初始(?:化)?向量|初始化向量|向量)/, 'iv'],
  [/(?:一次性)?随机数|随机向量/, 'nonce'],
  [/(?:密文|加密数据|加密后的数据)/, 'ciphertext'],
  [/(?:明文|原文|未加密数据)/, 'plaintext'],
  [/(?:认证|验证)标签|标签/, 'tag'],
  [/(?:附加认证数据|关联数据|附加数据)/, 'associateddata'],
  [/(?:盐值?|加盐)/, 'salt'],
  [/(?:计数器)/, 'counter'],
  [/(?:欧拉函数|欧拉值)/, 'phi'],
  [/(?:生成元|基元|底数)/, 'generator'],
  [/(?:曲线阶|椭圆曲线阶|群阶|子群阶|阶数)/, 'order'],
  [/(?:公钥|公开密钥)/, 'publickey'],
  [/(?:乘数|乘法器|系数)/, 'multiplier'],
  [/(?:增量|增值|常数项)/, 'increment'],
  [/(?:输出序列|状态序列|随机序列|输出值|状态值)/, 'outputs'],
  [/(?:种子)/, 'seed'],
  [/(?:第一|质数一|素数一|质数1|素数1)(?:个)?(?:质数|素数)?/, 'prime1'],
  [/(?:第二|质数二|素数二|质数2|素数2)(?:个)?(?:质数|素数)?/, 'prime2'],
  [/(?:签名)/, 'signature'],
  [/(?:曲线)/, 'curve'],
  [/(?:消息|报文)/, 'message'],
];

export const normalizeCtfFieldName = (value: string) => {
  const normalized = value.normalize('NFKC').toLowerCase();
  const compact = normalized.replace(/[\s_.()-]/g, '');
  for (const [pattern, alias] of chineseCtfFieldAliases) {
    if (pattern.test(compact)) return alias;
  }
  return normalized.replace(/[^a-z0-9]+/g, '');
};

export const symmetricFieldAliases: Record<string, string> = {
  a: 'associatedData',
  ad: 'associatedData',
  aad: 'associatedData',
  additionaldata: 'associatedData',
  alg: 'alg',
  algorithm: 'alg',
  associateddata: 'associatedData',
  associated_data: 'associatedData',
  authtag: 'tag',
  auth_tag: 'tag',
  cipher: 'ciphertext',
  ciphertext: 'ciphertext',
  ciphertexthex: 'ciphertext',
  counter: 'iv',
  ct: 'ciphertext',
  data: 'ciphertext',
  enc: 'ciphertext',
  encrypted: 'ciphertext',
  encrypteddata: 'ciphertext',
  iv: 'iv',
  ivhex: 'iv',
  key: 'key',
  keyhex: 'key',
  keyword: 'key',
  keyword1: 'key',
  keyword2: 'keyword2',
  mac: 'tag',
  mode: 'mode',
  nonce: 'nonce',
  noncehex: 'nonce',
  password: 'key',
  passphrase: 'key',
  plaintext: 'plaintext',
  plain: 'plaintext',
  knownplaintext: 'knownPlaintext',
  known_plaintext: 'knownPlaintext',
  salt: 'salt',
  sealed: 'sealed',
  sealedhex: 'sealed',
  secret: 'key',
  tag: 'tag',
  taghex: 'tag',
};

export const normalizeSymmetricFieldName = (value: string) => symmetricFieldAliases[normalizeCtfFieldName(value)] || null;

export const stripTrailingUnbalancedDelimiter = (value: string, open: string, close: string) => {
  let result = value;
  const countDelimiter = (text: string, delimiter: string) => (
    Array.from(text).reduce((count, char) => count + Number(char === delimiter), 0)
  );

  while (result.endsWith(close) && countDelimiter(result, close) > countDelimiter(result, open)) {
    result = result.slice(0, -1).trimEnd().replace(/[,;]+$/g, '').trimEnd();
  }

  return result;
};

export const cleanLooseFieldValue = (value: unknown) => {
  let result = String(value ?? '')
    .trim()
    .replace(/^b(['"`])([\s\S]*)\1$/i, '$2')
    .replace(/^(['"`])([\s\S]*)\1$/, '$2')
    .trim()
    .replace(/[,;]+$/g, '')
    .trim();

  for (const [open, close] of [['(', ')'], ['[', ']'], ['{', '}']] as const) {
    result = stripTrailingUnbalancedDelimiter(result, open, close);
  }

  return result.trim();
};

export const cleanSymmetricFieldValue = (value: unknown) => cleanLooseFieldValue(value);

export const rememberSymmetricField = (fields: Record<string, string>, rawKey: string, rawValue: unknown) => {
  const key = normalizeSymmetricFieldName(rawKey);
  if (!key) return;
  const value = cleanSymmetricFieldValue(rawValue);
  if (value && !fields[key]) fields[key] = value;
};

export const flattenSymmetricJson = (fields: Record<string, string>, value: unknown, prefix = '') => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return;
  for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
    const fieldName = prefix ? `${prefix}_${key}` : key;
    if (typeof entry === 'string' || typeof entry === 'number' || typeof entry === 'boolean') {
      rememberSymmetricField(fields, fieldName, entry);
      rememberSymmetricField(fields, key, entry);
    } else if (entry && typeof entry === 'object' && !Array.isArray(entry)) {
      flattenSymmetricJson(fields, entry, fieldName);
    }
  }
};

export const parseSymmetricFields = (value: string) => {
  const fields: Record<string, string> = {};
  try {
    flattenSymmetricJson(fields, JSON.parse(value));
  } catch {
    // Fall through to CTF writeup / Python output style parsing.
  }
  const text = value.normalize('NFKC').replace(/\r\n/g, '\n');
  for (const line of text.split('\n')) {
    const lineField = line.match(/^\s*([^:=\r\n]{1,80}?)\s*[:=]\s*(.+?)\s*$/u);
    if (lineField && normalizeSymmetricFieldName(lineField[1])) {
      rememberSymmetricField(fields, lineField[1], lineField[2]);
    }
  }
  for (const match of text.matchAll(/\b([A-Za-z][A-Za-z0-9_. -]{0,40})\s*[:=]\s*b?(['"`])([\s\S]*?)\2/g)) {
    rememberSymmetricField(fields, match[1], match[3]);
  }
  for (const match of text.matchAll(/\b([A-Za-z][A-Za-z0-9_. -]{0,40})\s*[:=]\s*(0x[0-9a-fA-F:_-]+|(?:\\x[0-9a-fA-F]{2})+|[A-Za-z0-9+/_=-]{1,})/g)) {
    rememberSymmetricField(fields, match[1], match[2]);
  }
  return fields;
};

export const normalizeLooseFieldName = (value: string) => normalizeCtfFieldName(value);
export const looseSingleCharTokens = new Set(['a', 'b', 'c', 'd', 'e', 'g', 'h', 'k', 'm', 'n', 'p', 'q', 'r', 's', 'u', 'v', 'x', 'y', 'z']);
export const isArithmeticFieldMatch = (source: string, index: number) => {
  let cursor = index - 1;
  while (cursor >= 0 && /\s/.test(source[cursor])) cursor -= 1;
  return cursor >= 0 && /[+\-*/(]/.test(source[cursor]);
};

export const rememberLooseField = (fields: Record<string, string>, rawKey: string, rawValue: unknown) => {
  const key = normalizeLooseFieldName(rawKey);
  const fieldValue = cleanSymmetricFieldValue(rawValue);
  if (!key || !fieldValue) return;
  const existing = fields[key];
  const existingLooksSelfReferential = Boolean(existing) && normalizeLooseFieldName(existing) === key;
  const nextLooksSelfReferential = normalizeLooseFieldName(fieldValue) === key;
  if (!existing || (existingLooksSelfReferential && !nextLooksSelfReferential)) fields[key] = fieldValue;
  if (/[+*/()]|\s-\s/.test(String(rawKey))) return;

  const tokens = String(rawKey)
    .toLowerCase()
    .match(/[a-z0-9]+/g) || [];
  for (const token of tokens) {
    const normalized = normalizeLooseFieldName(token);
    if (!normalized || normalized === key) continue;
    if (normalized.length > 1 || looseSingleCharTokens.has(normalized)) {
      if (!fields[normalized]) fields[normalized] = fieldValue;
    }
  }
};

export const flattenLooseJson = (fields: Record<string, string>, value: unknown, prefix = '') => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return;
  for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
    const fieldName = prefix ? `${prefix}_${key}` : key;
    if (Array.isArray(entry)) {
      rememberLooseField(fields, fieldName, entry.join(' '));
      rememberLooseField(fields, key, entry.join(' '));
    } else if (typeof entry === 'string' || typeof entry === 'number' || typeof entry === 'boolean') {
      rememberLooseField(fields, fieldName, entry);
      rememberLooseField(fields, key, entry);
    } else if (entry && typeof entry === 'object') {
      flattenLooseJson(fields, entry, fieldName);
    }
  }
};

export const parseLooseCtfFields = (value: string) => {
  const fields: Record<string, string> = {};
  try {
    flattenLooseJson(fields, JSON.parse(value));
  } catch {
    // Plain CTF statements often use prose, Python repr, or one field per line.
  }
  // Normalize backslash line continuations before other parsing
  const text = value.normalize('NFKC')
    .replace(/\r\n/g, '\n')
    .replace(/\\\n\s*/g, '')
    .replace(/`([^`]+)`/g, '$1')   // Strip markdown backticks
    .replace(/^#[^\n]*/gm, '');    // Strip comment lines starting with #
  // Handle int("hex_or_dec", base) expressions: key = int("abc123", 16)
  for (const match of text.matchAll(/\b([A-Za-z][A-Za-z0-9_. -]{0,40})\s*[:=]\s*int\s*\(\s*['"`]([0-9a-fA-F_]+)['"`]\s*,\s*(\d+)\s*\)/g)) {
    try {
      const base = Number(match[3]);
      const num = parseInt(match[2].replace(/_/g, ''), base);
      if (Number.isFinite(num)) rememberLooseField(fields, match[1], String(num));
      else rememberLooseField(fields, match[1], match[2]);
    } catch { /* ignore */ }
  }
  // Handle bytes_to_long(b'...hex...') or bytes_to_long(bytes.fromhex('...'))
  for (const match of text.matchAll(/\b([A-Za-z][A-Za-z0-9_. -]{0,40})\s*[:=]\s*bytes_to_long\s*\(\s*(?:bytes\.fromhex\s*\(\s*)?['"`]([0-9a-fA-F]+)['"`]/g)) {
    rememberLooseField(fields, match[1], `0x${match[2]}`);
  }
  // Handle pow(c, e, n) or pow(c, d, n) patterns — extract the three arguments
  for (const match of text.matchAll(/\bpow\s*\(\s*(0x[0-9a-fA-F_]+|\d[\d_]*)\s*,\s*(0x[0-9a-fA-F_]+|\d[\d_]*)\s*,\s*(0x[0-9a-fA-F_]+|\d[\d_]*)\s*\)/g)) {
    rememberLooseField(fields, 'pow_base', match[1]);
    rememberLooseField(fields, 'pow_exp', match[2]);
    rememberLooseField(fields, 'pow_mod', match[3]);
  }
  // Handle subscript/parenthesis notation: "Cipher (C₁):", "Modulus (N₁):", "C_1 =", "N1 =", "c1:", "n1:"
  for (const match of text.matchAll(/\b([A-Za-z][A-Za-z0-9_]*)\s*\([^)]{0,20}\)\s*[:=]\s*(0x[0-9a-fA-F_]+|\d[\d_]*)/g)) {
    rememberLooseField(fields, match[1], match[2]);
  }
  // Handle zero-width subscript chars like C₁ → c1
  const normalized = text.replace(/[₀₁₂₃₄₅₆₇₈₉]/g, d => String('₀₁₂₃₄₅₆₇₈₉'.indexOf(d)));
  if (normalized !== text) {
    for (const match of normalized.matchAll(/\b([A-Za-z][A-Za-z0-9_]*)\s*[:=]\s*(0x[0-9a-fA-F_]+|\d[\d_]*)/g)) {
      rememberLooseField(fields, match[1], match[2]);
    }
  }
  for (const match of text.matchAll(/['"`]([A-Za-z][A-Za-z0-9_. -]{0,40})['"`]\s*:\s*(\[[^\]]+\]|(?:0x[0-9a-fA-F:_-]+|(?:\\x[0-9a-fA-F]{2})+|[A-Za-z0-9+/_=.^-]{1,}|['"`][\s\S]*?['"`]))/g)) {
    rememberLooseField(fields, match[1], cleanSymmetricFieldValue(match[2]));
  }
  for (const match of text.matchAll(/\b([A-Za-z][A-Za-z0-9_. -]{0,40})\s*[:=]\s*\[([^\]]+)\]/g)) {
    if (isArithmeticFieldMatch(text, match.index || 0)) continue;
    rememberLooseField(fields, match[1], match[2]);
  }
  // Chinese CTF prose: 密钥/秘钥 是/为/：X、密文 是/为/：X（中文题面的字段提取）
  for (const match of text.matchAll(/(?:密钥|秘钥|密匙)\s*(?:是|为)?\s*[:：]?\s*([A-Za-z0-9+/=]{2,64})/g)) {
    rememberLooseField(fields, 'key', match[1]);
  }
  for (const match of text.matchAll(/(?:密文|明文)\s*(?:是|为)?\s*[:：]\s*([^\n]+)/g)) {
    rememberLooseField(fields, 'ciphertext', match[1].trim());
  }
  for (const line of text.split('\n')) {
    const proseField = line.match(/^\s*(?:the\s+)?([A-Za-z][A-Za-z0-9_. -]{0,40}?)\s+(?:is|was|are|equals?)\s*(.+?)\s*$/i);
    if (proseField && /(?:0x[0-9a-f]+|\d|[([{]|[A-Za-z0-9+/_=-]{6,})/i.test(proseField[2])) {
      rememberLooseField(fields, proseField[1], proseField[2]);
    }
    const lineField = line.match(/^\s*([^:=\r\n]{1,80}?)\s*[:=]\s*(.+?)\s*$/u);
    if (lineField) rememberLooseField(fields, lineField[1], lineField[2]);
  }
  for (const match of text.matchAll(/\b([A-Za-z][A-Za-z0-9_. -]{0,40})\s*[:=]\s*b?(['"`])([\s\S]*?)\2/g)) {
    if (isArithmeticFieldMatch(text, match.index || 0)) continue;
    rememberLooseField(fields, match[1], match[3]);
  }
  for (const match of text.matchAll(/\b([A-Za-z][A-Za-z0-9_. -]{0,40})\s*[:=]\s*(0x[0-9a-fA-F:_-]+|(?:\\x[0-9a-fA-F]{2})+|[A-Za-z0-9+/_=.^-]{1,})/g)) {
    if (isArithmeticFieldMatch(text, match.index || 0)) continue;
    rememberLooseField(fields, match[1], match[2]);
  }
  for (const line of text.split('\n')) {
    const listLine = line.match(/\b(outputs?|states?|samples?|values?|leaks?|sequence|keystream|bits)\b\s*[:=]?\s*(.+)$/i);
    if (listLine && /(?:0x[0-9a-f]+|\d|\b[01]{8,}\b)/i.test(listLine[2])) {
      rememberLooseField(fields, listLine[1], listLine[2]);
    }
  }
  return fields;
};

export const looseField = (fields: Record<string, string>, aliases: string[]) => {
  for (const alias of aliases) {
    const value = fields[normalizeLooseFieldName(alias)];
    if (value) return value;
  }
  return '';
};

export const parseLooseIndexedRecords = (
  fields: Record<string, string>,
  aliases: Record<string, string[]>,
  maxRecords = 80,
) => {
  const indexes = new Set<number>();
  for (const key of Object.keys(fields)) {
    for (const aliasList of Object.values(aliases)) {
      for (const alias of aliasList) {
        const normalized = normalizeLooseFieldName(alias);
        const prefix = key.match(new RegExp(`^${normalized}(\\d+)$`));
        const suffix = key.match(new RegExp(`^(\\d+)${normalized}$`));
        const wrapped = key.match(new RegExp(`^(?:sig|signature|sample|record|item)(\\d+)${normalized}$`));
        const match = prefix || suffix || wrapped;
        if (match) indexes.add(Number(match[1]));
      }
    }
  }
  return Array.from(indexes)
    .filter(index => Number.isInteger(index) && index >= 0 && index <= maxRecords)
    .sort((left, right) => left - right)
    .map(index => {
      const record: Record<string, string> = {};
      for (const [field, aliasList] of Object.entries(aliases)) {
        const indexedAliases = aliasList.flatMap(alias => [
          `${alias}${index}`,
          `${index}${alias}`,
          `sig${index}${alias}`,
          `signature${index}${alias}`,
          `sample${index}${alias}`,
          `record${index}${alias}`,
          `item${index}${alias}`,
        ]);
        const value = looseField(fields, indexedAliases);
        if (value) record[field] = value;
      }
      return { index, record };
    })
    .filter(entry => Object.keys(entry.record).length > 0);
};

export const parseLooseObjectBlocks = (value: string, maxBlocks = 80) => {
  const blocks: Array<{ index: string; fields: Record<string, string> }> = [];
  for (const match of value.matchAll(/\{[^{}]{1,4000}\}/g)) {
    if (blocks.length >= maxBlocks) break;
    const fields: Record<string, string> = {};
    const body = match[0].slice(1, -1);
    for (const entry of body.matchAll(/['"`]?([A-Za-z][A-Za-z0-9_. -]{0,40})['"`]?\s*:\s*(\[[^\]]*\]|\([^)]*\)|(?:0x[0-9a-fA-F:_-]+|\d[\d_]*[nNlL]?|[A-Za-z0-9+/_=-]+={0,2}|['"`][\s\S]*?['"`]))/g)) {
      rememberLooseField(fields, entry[1], cleanSymmetricFieldValue(entry[2]));
    }
    if (Object.keys(fields).length) {
      blocks.push({
        index: `dict-${blocks.length}`,
        fields,
      });
    }
  }
  return blocks;
};

export const normalizeLooseBytesLabel = (value: string) => cleanSymmetricFieldValue(value).toLowerCase().replace(/\s+/g, '');

export const parseSymmetricFieldBytes = (value: string, labelText: string) => {
  const text = cleanSymmetricFieldValue(value);
  if (/^(?:\\x[0-9a-fA-F]{2})+$/.test(text)) return hexToBytes(text.replace(/\\x/g, ''));
  return parseHexBase64OrUtf8Bytes(text, labelText).bytes;
};

export const symmetricFieldHex = (value: string | undefined, labelText: string) => (
  value ? bytesToHex(parseSymmetricFieldBytes(value, labelText)) : undefined
);

export const parsePythonAssignmentFields = (value: string) => {
  const fields: Record<string, string> = {};
  for (const line of value.split(/\r?\n/)) {
    const match = line.match(/^\s*([A-Za-z_][A-Za-z0-9_.]*)\s*=\s*(.+?)\s*$/);
    if (!match) continue;
    const key = normalizeLooseFieldName(match[1]);
    if (!key || !match[2]) continue;
    fields[key] = match[2].trim();
  }
  return fields;
};

export const extractNamedPythonCall = (value: string, marker: string) => {
  const start = value.indexOf(marker);
  if (start < 0) return '';
  let depth = 0;
  let quote = '';
  let escaped = false;
  for (let index = start; index < value.length; index += 1) {
    const char = value[index];
    if (quote) {
      if (escaped) {
        escaped = false;
        continue;
      }
      if (char === '\\') {
        escaped = true;
        continue;
      }
      if (char === quote) quote = '';
      continue;
    }
    if (char === '"' || char === '\'') {
      quote = char;
      continue;
    }
    if (char === '(') {
      depth += 1;
      continue;
    }
    if (char === ')') {
      depth -= 1;
      if (depth === 0) return value.slice(start, index + 1);
      continue;
    }
  }
  return '';
};

export const stripPythonKwargPrefix = (value: string, names: string[]) => {
  const text = String(value || '').trim();
  const match = text.match(/^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$/);
  if (!match) return text;
  return names.includes(match[1].toLowerCase()) ? match[2].trim() : text;
};

export const parsePythonCiphertextBytes = (
  value: string,
  fields: Record<string, string> = {},
  seen = new Set<string>(),
): Uint8Array | null => {
  const text = String(value || '').trim();
  if (!text) return null;

  const call = parseFunctionLikeCall(text);
  if (call) {
    const callable = normalizeLooseFieldName(call.name);
    if (callable === 'b64decode' || callable.endsWith('b64decode')) {
      if (!call.args.length) return null;
      const source = parsePythonTextLikeValue(call.args[0], fields, seen);
      if (source == null) return null;
      try {
        return base64ToBytes(source);
      } catch {
        return null;
      }
    }
  }

  const pythonBytes = parsePythonByteLikeValue(text, fields, seen);
  if (pythonBytes) return pythonBytes;

  const source = parsePythonTextLikeValue(text, fields, seen);
  if (source == null) return null;
  try {
    return parseHexOrBase64Bytes(source, 'ciphertext');
  } catch {
    return utf8Encoder.encode(source);
  }
};

export const inferPythonSymmetricSnippet = (
  value: string,
  baseParams: Record<ParamKey, string>,
): SymmetricInference | null => {
  if (!/(?:AES|ChaCha20|ChaCha20_Poly1305|Salsa20)\.new\s*\(/i.test(value)) return null;
  const assignmentFields = parsePythonAssignmentFields(value);
  const newCallMarker = value.match(/[A-Za-z0-9_.]+\.new\s*\(/)?.[0] || '';
  const cipherCallText = newCallMarker ? extractNamedPythonCall(value, newCallMarker.replace(/\s*$/, '')) : '';
  const cipherCall = cipherCallText ? parseFunctionLikeCall(cipherCallText) : null;
  if (!cipherCall) return null;
  const normalizedCall = normalizeLooseFieldName(cipherCall.name);
  const modeArg = cipherCall.args[1]?.toLowerCase() || '';
  const operationId = normalizedCall === 'aesnew'
    ? (/mode[_\s.]*cbc/.test(modeArg)
      ? 'aes-cbc-raw'
      : /mode[_\s.]*ecb/.test(modeArg)
        ? 'aes-ecb'
        : /mode[_\s.]*ctr/.test(modeArg)
          ? 'aes-ctr-raw'
          : /mode[_\s.]*cfb/.test(modeArg)
            ? 'aes-cfb'
            : /mode[_\s.]*ofb/.test(modeArg)
              ? 'aes-ofb'
              : /mode[_\s.]*gcm/.test(modeArg)
                ? 'aes-gcm'
                : null)
    : normalizedCall === 'chacha20new'
      ? 'chacha20-orig'
      : normalizedCall === 'chacha20poly1305new'
        ? 'chacha20-poly1305'
      : normalizedCall === 'salsa20new'
        ? 'salsa20'
      : null;
  if (!operationId) return null;

  const keyArg = stripPythonKwargPrefix(cipherCall.args[0], ['key']);
  const keyBytes = parsePythonByteLikeValue(keyArg, assignmentFields);
  if (!keyBytes) return null;

  const ivArg = cipherCall.args.slice(1).find(arg => /^(?:iv|nonce)\s*=/.test(arg))?.replace(/^(?:iv|nonce)\s*=\s*/, '')
    || cipherCall.args[2]
    || '';
  const ivBytes = ivArg ? parsePythonByteLikeValue(ivArg, assignmentFields) : null;

  const ciphertextExpression = assignmentFields.ct || assignmentFields.ciphertext || assignmentFields.enc || assignmentFields.data || '';
  const ciphertextBytes = ciphertextExpression ? (
    parsePythonCiphertextBytes(ciphertextExpression, assignmentFields)
    || (() => {
      const sourceText = parsePythonTextLikeValue(ciphertextExpression, assignmentFields);
      if (sourceText == null) return null;
      try {
        return parseHexOrBase64Bytes(sourceText, 'ciphertext');
      } catch {
        return utf8Encoder.encode(sourceText);
      }
    })()
  ) : null;
  if (!ciphertextBytes) return null;
  const tagExpression = assignmentFields.tag || assignmentFields.authtag || '';
  const tagBytes = tagExpression ? (
    parsePythonCiphertextBytes(tagExpression, assignmentFields)
    || (() => {
      const sourceText = parsePythonTextLikeValue(tagExpression, assignmentFields);
      if (sourceText == null) return null;
      try {
        return parseHexOrBase64Bytes(sourceText, 'tag');
      } catch {
        return utf8Encoder.encode(sourceText);
      }
    })()
  ) : null;

  const params = { ...baseParams };
  params.secret = bytesToHex(keyBytes);
  if (ivBytes?.length) params.iv = bytesToHex(ivBytes);
  params.variant = 'special';

  const input = JSON.stringify({
    ciphertextHex: bytesToHex(ciphertextBytes),
    ...(ivBytes?.length ? { ivHex: bytesToHex(ivBytes) } : {}),
    ...(tagBytes?.length ? { tagHex: bytesToHex(tagBytes) } : {}),
  });

  return {
    operationId,
    input,
    params,
    fields: {
      key: bytesToHex(keyBytes),
      ...(ivBytes?.length ? { iv: bytesToHex(ivBytes) } : {}),
      ciphertext: bytesToHex(ciphertextBytes),
      ...(tagBytes?.length ? { tag: bytesToHex(tagBytes) } : {}),
      mode: modeArg,
    },
    confidence: 12,
    notes: [
      `python snippet detected: ${operationId}`,
      'parsed key/iv/ciphertext from AES.new(...) style script',
    ],
  };
};

export const detectSymmetricOperationHint = (value: string, fields: Record<string, string>): OperationId | null => {
  const text = `${fields.alg || ''} ${fields.mode || ''} ${value}`.toLowerCase();
  if (/xchacha20[\s_-]*poly1305/.test(text)) return 'xchacha20-poly1305';
  if (/chacha20[\s_-]*poly1305/.test(text)) return 'chacha20-poly1305';
  if (/xsalsa20[\s_-]*poly1305|secretbox/.test(text)) return 'xsalsa20-poly1305';
  if (/aes[\s_-]*gcm[\s_-]*siv|gcmsiv/.test(text)) return 'aes-gcm-siv';
  if (/aes[\s_-]*siv/.test(text)) return 'aes-siv';
  if (/aes[\s_-]*gcm/.test(text)) return 'aes-gcm';
  if (/aes/.test(text) && /\becb\b/.test(text)) return 'aes-ecb';
  if (/aes/.test(text) && /\bcbc\b/.test(text)) return 'aes-cbc-raw';
  if (/aes/.test(text) && /\bctr\b/.test(text)) return 'aes-ctr-raw';
  if (/aes/.test(text) && /\bcfb\b/.test(text)) return 'aes-cfb';
  if (/aes/.test(text) && /\bofb\b/.test(text)) return 'aes-ofb';
  if (/\bxchacha20\b/.test(text)) return 'xchacha20';
  if (/\bchacha20\b/.test(text)) return 'chacha20';
  if (/\bxsalsa20\b/.test(text)) return 'xsalsa20';
  if (/\bsalsa20\b/.test(text)) return 'salsa20';
  if (/\bsm4\b/.test(text)) return 'sm4';
  if (/\b3des\b|triple[\s_-]*des/.test(text)) return 'triple-des';
  if (/\bdes\b/.test(text)) return 'des';
  if (/\bblowfish\b/.test(text)) return 'blowfish';
  if (/\brabbit\b/.test(text)) return 'rabbit';
  return null;
};

export const buildSymmetricPayload = (operationId: OperationId, fields: Record<string, string>, fallbackValue: string) => {
  const payload: Record<string, string> = {};
  const nonceSource = fields.nonce || fields.iv;
  if (fields.mode) payload.mode = fields.mode.toLowerCase();
  if (fields.associatedData) payload.aadHex = symmetricFieldHex(fields.associatedData, 'AAD') || '';

  if (operationId === 'aes-gcm' || isNobleAeadOperation(operationId)) {
    if (nonceSource) payload.nonceHex = symmetricFieldHex(nonceSource, 'nonce') || '';
    if (fields.iv) payload.ivHex = symmetricFieldHex(fields.iv, 'iv') || '';
    if (fields.sealed) payload.sealedHex = symmetricFieldHex(fields.sealed, 'sealed ciphertext') || '';
    if (fields.ciphertext) payload.ciphertextHex = symmetricFieldHex(fields.ciphertext, 'ciphertext') || '';
    if (fields.tag) payload.tagHex = symmetricFieldHex(fields.tag, 'authentication tag') || '';
  } else {
    if (fields.iv || nonceSource) payload.ivHex = symmetricFieldHex(fields.iv || nonceSource, 'iv') || '';
    if (fields.ciphertext) payload.ciphertextHex = symmetricFieldHex(fields.ciphertext, 'ciphertext') || '';
  }

  if (!payload.ciphertextHex && !payload.sealedHex) return fallbackValue;
  return JSON.stringify(payload);
};

export const inferSymmetricCryptoFromText = (
  value: string,
  forcedOperationId: OperationId | null = null,
  baseParams: Record<ParamKey, string> = defaultParams,
): SymmetricInference => {
  if (!forcedOperationId) {
    const pythonSnippet = inferPythonSymmetricSnippet(value, baseParams);
    if (pythonSnippet) return pythonSnippet;
  }
  const fields = parseSymmetricFields(value);
  const operationId = forcedOperationId || detectSymmetricOperationHint(value, fields);
  const params = { ...baseParams };
  const notes: string[] = [];
  let confidence = Object.keys(fields).length;

  if (fields.key) {
    params.secret = fields.key;
    confidence += 2;
    notes.push('parsed key/secret from challenge text');
  }
  if (fields.iv || fields.nonce) {
    params.iv = fields.iv || fields.nonce;
    confidence += 1;
    notes.push(fields.nonce ? 'parsed nonce from challenge text' : 'parsed IV/counter from challenge text');
  }
  if (fields.associatedData) {
    params.associatedData = fields.associatedData;
    confidence += 1;
    notes.push('parsed AAD/associated data from challenge text');
  }
  if (operationId) {
    confidence += 3;
    notes.push(`operation hint: ${operationId}`);
  }
  if (fields.ciphertext || fields.sealed) confidence += 2;
  if (fields.tag) confidence += 1;
  if (operationId === 'sm4' && fields.mode) params.variant = fields.mode.toLowerCase() === 'ecb' ? 'hex' : 'special';

  const input = operationId ? buildSymmetricPayload(operationId, fields, value) : value;
  return { operationId, input, params, fields, confidence, notes };
};

export const prepareSymmetricDecodeInput = (
  operationId: OperationId,
  direction: Direction,
  value: string,
  params: Record<ParamKey, string>,
) => direction === 'decode'
  ? inferSymmetricCryptoFromText(value, operationId, params)
  : { operationId, input: value, params, fields: {}, confidence: 0, notes: [] };

export const bytesToUtf8OrHexJson = (bytes: Uint8Array) => {
  try {
    return utf8Decoder.decode(bytes);
  } catch {
    return JSON.stringify({
      plaintextHex: bytesToHex(bytes),
      note: '明文不是有效 UTF-8，已改为输出 Hex',
    }, null, 2);
  }
};

export const aesGcmTransform = async (direction: Direction, value: string, params: Record<ParamKey, string>) => {
  if (direction === 'encode') return aesEncrypt(value, params.secret, params.iterations);
  const inferred = inferSymmetricCryptoFromText(value, 'aes-gcm', params);
  try {
    const payload = JSON.parse(inferred.input) as AeadPayload & { key?: string; keyHex?: string };
    if (!('salt' in payload) && (payload.ivHex || payload.iv || payload.nonceHex || payload.nonce) && (payload.sealedHex || payload.sealed || payload.ciphertextHex || payload.ciphertext)) {
      const keySource = inferred.params.secret || payload.keyHex || payload.key;
      const key = normalizeFixedBytes(keySource || '', 'AES-GCM key', [16, 24, 32]);
      const ivSource = payload.ivHex || payload.iv || payload.nonceHex || payload.nonce || '';
      const iv = parseSymmetricFieldBytes(ivSource, 'AES-GCM IV');
      const aadSource = payload.aadHex || payload.associatedDataHex || payload.aad || payload.associatedData || inferred.params.associatedData;
      const aad = aadSource ? parseSymmetricFieldBytes(aadSource, 'AES-GCM AAD') : new Uint8Array();
      const sealed = payload.sealedHex || payload.sealed
        ? parseSymmetricFieldBytes(payload.sealedHex || payload.sealed || '', 'AES-GCM sealed ciphertext')
        : concatBytes(
          parseSymmetricFieldBytes(payload.ciphertextHex || payload.ciphertext || '', 'AES-GCM ciphertext'),
          payload.tagHex || payload.tag ? parseSymmetricFieldBytes(payload.tagHex || payload.tag || '', 'AES-GCM tag') : new Uint8Array(),
        );
      const cryptoKey = await crypto.subtle.importKey('raw', bytesToBuffer(key.bytes), { name: 'AES-GCM' }, false, ['decrypt']);
      const options: AesGcmParams = { name: 'AES-GCM', iv: bytesToBuffer(iv) };
      if (aad.length) options.additionalData = bytesToBuffer(aad);
      const plaintext = new Uint8Array(await crypto.subtle.decrypt(options, cryptoKey, bytesToBuffer(sealed)));
      return bytesToUtf8OrHexJson(plaintext);
    }
  } catch {
    // Fall through to the PBKDF2 JSON format used by this tool's AES-GCM operation.
  }
  return aesDecrypt(value, params.secret);
};

export const nobleStreamSpec = (operationId: OperationId) => {
  switch (operationId) {
    case 'chacha20-orig':
      return { alg: 'ChaCha20 (8-byte nonce)', keyLengths: [32], nonceLength: 8 };
    case 'chacha20':
      return { alg: 'ChaCha20', keyLengths: [32], nonceLength: 12 };
    case 'xchacha20':
      return { alg: 'XChaCha20', keyLengths: [32], nonceLength: 24 };
    case 'salsa20':
      return { alg: 'Salsa20', keyLengths: [16, 32], nonceLength: 8 };
    case 'xsalsa20':
      return { alg: 'XSalsa20', keyLengths: [32], nonceLength: 24 };
    default:
      throw new Error('不支持的 noble stream cipher');
  }
};

export const nobleStreamCipherBytes = async (operationId: OperationId, key: Uint8Array, nonce: Uint8Array, data: Uint8Array) => {
  if (operationId === 'chacha20-orig' || operationId === 'chacha20' || operationId === 'xchacha20') {
    const { chacha20orig, chacha20, xchacha20 } = await import('@noble/ciphers/chacha.js');
    if (operationId === 'chacha20-orig') return chacha20orig(key, nonce, data);
    return operationId === 'chacha20' ? chacha20(key, nonce, data) : xchacha20(key, nonce, data);
  }
  const { salsa20, xsalsa20 } = await import('@noble/ciphers/salsa.js');
  return operationId === 'salsa20' ? salsa20(key, nonce, data) : xsalsa20(key, nonce, data);
};

export const nobleStreamTransform = async (operationId: OperationId, direction: Direction, value: string, params: Record<ParamKey, string>) => {
  const inferred = prepareSymmetricDecodeInput(operationId, direction, value, params);
  value = inferred.input;
  params = inferred.params;
  const spec = nobleStreamSpec(operationId);
  const key = normalizeFixedBytes(params.secret, `${spec.alg} key`, spec.keyLengths);
  let payload: StreamCipherPayload | null = null;
  if (direction === 'decode') {
    try {
      payload = JSON.parse(value) as StreamCipherPayload;
    } catch {
      payload = null;
    }
  }
  const nonceSource = direction === 'encode'
    ? params.iv || bytesToHex(crypto.getRandomValues(new Uint8Array(spec.nonceLength)))
    : payload?.nonceHex || payload?.nonce || params.iv;
  const nonce = normalizeFixedBytes(nonceSource || '', `${spec.alg} nonce`, [spec.nonceLength]);
  const inputBytes = direction === 'encode'
    ? utf8Encoder.encode(value)
    : parseHexOrBase64Bytes(payload?.ciphertextHex || payload?.ciphertext || value, '密文');
  const output = await nobleStreamCipherBytes(operationId, key.bytes, nonce.bytes, inputBytes);
  if (direction === 'decode') return bytesToUtf8OrHexJson(output);
  return JSON.stringify({
    alg: spec.alg,
    mode: 'xor-stream',
    keyFormat: key.format,
    keyLength: key.normalizedLength,
    nonceHex: bytesToHex(nonce.bytes),
    nonceFormat: nonce.format,
    ciphertextEncoding: 'hex',
    ciphertextHex: bytesToHex(output),
    warning: 'XOR 流密码在同一 key/nonce 下复用会泄露明文关系',
  }, null, 2);
};

export type NobleAeadSpec = {
  alg: string;
  keyLengths: number[];
  nonceLength: number | null;
  tagLength: number;
  supportsAad: boolean;
};

export const nobleAeadSpec = (operationId: OperationId): NobleAeadSpec => {
  switch (operationId) {
    case 'aes-gcm-siv':
      return { alg: 'AES-GCM-SIV', keyLengths: [16, 24, 32], nonceLength: 12, tagLength: 16, supportsAad: true };
    case 'aes-siv':
      return { alg: 'AES-SIV', keyLengths: [32, 48, 64], nonceLength: null, tagLength: 16, supportsAad: true };
    case 'chacha20-poly1305':
      return { alg: 'ChaCha20-Poly1305', keyLengths: [32], nonceLength: 12, tagLength: 16, supportsAad: true };
    case 'xchacha20-poly1305':
      return { alg: 'XChaCha20-Poly1305', keyLengths: [32], nonceLength: 24, tagLength: 16, supportsAad: true };
    case 'xsalsa20-poly1305':
      return { alg: 'XSalsa20-Poly1305 / secretbox', keyLengths: [32], nonceLength: 24, tagLength: 16, supportsAad: false };
    default:
      throw new Error('不支持的 noble AEAD cipher');
  }
};

export const nobleAeadCipherBytes = async (
  operationId: OperationId,
  direction: Direction,
  key: Uint8Array,
  nonce: Uint8Array | null,
  aad: Uint8Array,
  data: Uint8Array,
) => {
  if (operationId === 'aes-gcm-siv') {
    if (!nonce) throw new Error('AES-GCM-SIV requires a 12-byte nonce');
    const { gcmsiv } = await import('@noble/ciphers/aes.js');
    const cipher = gcmsiv(key, nonce, aad.length ? aad : undefined);
    return direction === 'encode' ? cipher.encrypt(data) : cipher.decrypt(data);
  }
  if (operationId === 'aes-siv') {
    const { aessiv } = await import('@noble/ciphers/aes.js');
    const aadComponents = [
      ...(aad.length ? [aad] : []),
      ...(nonce?.length ? [nonce] : []),
    ];
    const cipher = aessiv(key, ...aadComponents);
    return direction === 'encode' ? cipher.encrypt(data) : cipher.decrypt(data);
  }
  if (!nonce) throw new Error('AEAD nonce is required');
  if (operationId === 'chacha20-poly1305' || operationId === 'xchacha20-poly1305') {
    const { chacha20poly1305, xchacha20poly1305 } = await import('@noble/ciphers/chacha.js');
    const cipher = operationId === 'chacha20-poly1305'
      ? chacha20poly1305(key, nonce, aad.length ? aad : undefined)
      : xchacha20poly1305(key, nonce, aad.length ? aad : undefined);
    return direction === 'encode' ? cipher.encrypt(data) : cipher.decrypt(data);
  }
  if (aad.length) throw new Error('XSalsa20-Poly1305 / secretbox 不支持 AAD');
  const { xsalsa20poly1305 } = await import('@noble/ciphers/salsa.js');
  const cipher = xsalsa20poly1305(key, nonce);
  return direction === 'encode' ? cipher.encrypt(data) : cipher.decrypt(data);
};

export const nobleAeadTransform = async (operationId: OperationId, direction: Direction, value: string, params: Record<ParamKey, string>) => {
  const inferred = prepareSymmetricDecodeInput(operationId, direction, value, params);
  value = inferred.input;
  params = inferred.params;
  const spec = nobleAeadSpec(operationId);
  const key = normalizeFixedBytes(params.secret, `${spec.alg} key`, spec.keyLengths);
  let payload: AeadPayload | null = null;
  if (direction === 'decode') {
    try {
      payload = JSON.parse(value) as AeadPayload;
    } catch {
      payload = null;
    }
  }
  const nonceSource = spec.nonceLength === null
    ? (direction === 'encode' ? params.iv : payload?.nonceHex || payload?.nonce || params.iv)
    : (direction === 'encode'
      ? params.iv || bytesToHex(crypto.getRandomValues(new Uint8Array(spec.nonceLength)))
      : payload?.nonceHex || payload?.nonce || params.iv);
  const nonce = spec.nonceLength === null
    ? parseOptionalHexOrUtf8Bytes(nonceSource || '')
    : normalizeFixedBytes(nonceSource || '', `${spec.alg} nonce`, [spec.nonceLength]);
  const nonceBytes = spec.nonceLength === null && nonce.bytes.length === 0 ? null : nonce.bytes;
  const payloadAadSource = payload?.aadHex || payload?.associatedDataHex || payload?.aad || payload?.associatedData;
  const aadSource = spec.supportsAad
    ? (direction === 'encode' ? params.associatedData : payloadAadSource || params.associatedData)
    : payloadAadSource;
  const aad = parseOptionalHexOrUtf8Bytes(aadSource || '');
  if (!spec.supportsAad && aad.bytes.length) throw new Error(`${spec.alg} 不支持 AAD`);
  const sealedSource = payload?.sealedHex || payload?.sealed || (
    payload?.ciphertextHex && payload?.tagHex
      ? `${payload.ciphertextHex}${payload.tagHex}`
      : payload?.ciphertextHex || payload?.ciphertext || value
  );
  const inputBytes = direction === 'encode'
    ? utf8Encoder.encode(value)
    : parseHexOrBase64Bytes(sealedSource, 'ciphertext+tag');
  if (direction === 'decode' && inputBytes.length < spec.tagLength) {
    throw new Error(`${spec.alg} 密文至少需要包含 ${spec.tagLength} 字节 authentication tag`);
  }
  const output = await nobleAeadCipherBytes(operationId, direction, key.bytes, nonceBytes, aad.bytes, inputBytes);
  if (direction === 'decode') return bytesToUtf8OrHexJson(output);
  const ciphertext = output.slice(0, Math.max(0, output.length - spec.tagLength));
  const tag = output.slice(Math.max(0, output.length - spec.tagLength));
  return JSON.stringify({
    alg: spec.alg,
    mode: 'aead',
    keyFormat: key.format,
    keyLength: key.normalizedLength,
    nonceHex: nonceBytes ? bytesToHex(nonceBytes) : undefined,
    nonceFormat: nonce.format,
    nonceRole: operationId === 'aes-siv' && nonceBytes ? 'final-aad-component' : undefined,
    aadEncoding: aad.format,
    aadHex: aad.bytes.length ? bytesToHex(aad.bytes) : undefined,
    sealedEncoding: 'hex',
    sealedHex: bytesToHex(output),
    ciphertextEncoding: 'hex',
    ciphertextHex: bytesToHex(ciphertext),
    tagHex: bytesToHex(tag),
    tagBytes: spec.tagLength,
    warning: operationId === 'aes-gcm-siv' || operationId === 'aes-siv'
      ? 'SIV AEAD is nonce-misuse resistant, but identical key/input/AAD can still produce linkable output; decrypt failure usually means key, nonce/AAD, or tag mismatch.'
      : 'AEAD 在同一 key/nonce 下复用会破坏认证安全；解密失败通常表示 key、nonce、AAD 或 tag 不匹配',
  }, null, 2);
};

export const aesRawBlockTransform = async (operationId: OperationId, direction: Direction, value: string, params: Record<ParamKey, string>) => {
  const inferred = prepareSymmetricDecodeInput(operationId, direction, value, params);
  value = inferred.input;
  params = inferred.params;
  const { cbc, cfb, ctr, ecb } = await import('@noble/ciphers/aes.js');
  const alg = operationId === 'aes-ecb'
    ? 'AES-ECB'
    : operationId === 'aes-cbc-raw'
      ? 'AES-CBC Raw'
      : operationId === 'aes-ctr-raw'
        ? 'AES-CTR Raw'
        : 'AES-CFB';
  const mode = operationId === 'aes-ecb'
    ? 'ECB'
    : operationId === 'aes-cbc-raw'
      ? 'CBC'
      : operationId === 'aes-ctr-raw'
        ? 'CTR'
        : 'CFB-128';
  const key = normalizeFixedBytes(params.secret, `${alg} key`, [16, 24, 32]);
  const disablePadding = (operationId === 'aes-ecb' || operationId === 'aes-cbc-raw') && params.variant === 'hex';
  let payload: AesRawPayload | null = null;
  if (direction === 'decode') {
    try {
      payload = JSON.parse(value) as AesRawPayload;
    } catch {
      payload = null;
    }
  }
  const ivSource = payload?.ivHex || payload?.iv || params.iv;
  const iv = operationId === 'aes-ecb' ? null : normalizeFixedBytes(ivSource || '', `${alg} IV/counter`, [16]);
  const makeCipher = () => {
    if (operationId === 'aes-ecb') return ecb(key.bytes, { disablePadding });
    if (operationId === 'aes-cbc-raw') return cbc(key.bytes, iv?.bytes || new Uint8Array(16), { disablePadding });
    if (operationId === 'aes-ctr-raw') return ctr(key.bytes, iv?.bytes || new Uint8Array(16));
    return cfb(key.bytes, iv?.bytes || new Uint8Array(16));
  };
  const inputBytes = direction === 'encode'
    ? (disablePadding ? parseHexBase64OrUtf8Bytes(value, 'plaintext').bytes : utf8Encoder.encode(value))
    : parseHexOrBase64Bytes(payload?.ciphertextHex || payload?.ciphertext || value, '密文');
  const output = direction === 'encode' ? makeCipher().encrypt(inputBytes) : makeCipher().decrypt(inputBytes);
  if (direction === 'decode') return bytesToUtf8OrHexJson(output);
  return JSON.stringify({
    alg,
    mode,
    keyFormat: key.format,
    keyLength: key.normalizedLength,
    ivHex: iv ? bytesToHex(iv.bytes) : undefined,
    ivFormat: iv?.format,
    padding: operationId === 'aes-ecb' || operationId === 'aes-cbc-raw' ? (disablePadding ? 'none' : 'pkcs7') : 'none',
    ciphertextEncoding: 'hex',
    ciphertextHex: bytesToHex(output),
    warning: operationId === 'aes-ecb'
      ? 'ECB leaks repeated plaintext block patterns and should only be used for CTF recovery or legacy compatibility.'
      : operationId === 'aes-ctr-raw'
        ? 'CTR is a stream mode; reusing the same key/counter leaks plaintext XOR relationships.'
        : 'This AES mode is unauthenticated; validate recovered plaintext with a MAC, checksum, format marker, or known plaintext.',
  }, null, 2);
};

export const aesOfbTransform = async (direction: Direction, value: string, params: Record<ParamKey, string>) => {
  const inferred = prepareSymmetricDecodeInput('aes-ofb', direction, value, params);
  value = inferred.input;
  params = inferred.params;
  const CryptoJS = await loadCryptoJs();
  const key = normalizeFixedBytes(params.secret, 'AES-OFB key', [16, 24, 32]);
  let payload: AesRawPayload | null = null;
  if (direction === 'decode') {
    try {
      payload = JSON.parse(value) as AesRawPayload;
    } catch {
      payload = null;
    }
  }
  const ivSource = payload?.ivHex || payload?.iv || params.iv;
  const iv = normalizeFixedBytes(ivSource || '', 'AES-OFB IV', [16]);
  const keyWord = CryptoJS.enc.Hex.parse(bytesToHex(key.bytes));
  const ivWord = CryptoJS.enc.Hex.parse(bytesToHex(iv.bytes));
  const cipherConfig = { mode: CryptoJS.mode.OFB, padding: CryptoJS.pad.NoPadding, iv: ivWord };

  if (direction === 'encode') {
    const encrypted = CryptoJS.AES.encrypt(CryptoJS.enc.Utf8.parse(value), keyWord, cipherConfig);
    return JSON.stringify({
      alg: 'AES-OFB',
      mode: 'OFB',
      keyFormat: key.format,
      keyLength: key.normalizedLength,
      ivHex: bytesToHex(iv.bytes),
      ivFormat: iv.format,
      padding: 'none',
      ciphertextEncoding: 'hex',
      ciphertextHex: CryptoJS.enc.Hex.stringify(encrypted.ciphertext),
      warning: 'OFB is a stream mode; reusing the same key/IV leaks plaintext XOR relationships.',
    }, null, 2);
  }

  const ciphertextBytes = parseHexOrBase64Bytes(payload?.ciphertextHex || payload?.ciphertext || value, 'ciphertext');
  const ciphertext = CryptoJS.enc.Hex.parse(bytesToHex(ciphertextBytes));
  const decrypted = CryptoJS.AES.decrypt(CryptoJS.lib.CipherParams.create({ ciphertext }), keyWord, cipherConfig);
  return cryptoJsWordArrayToText(CryptoJS, decrypted);
};

export const aesKeyWrapTransform = async (operationId: OperationId, direction: Direction, value: string, params: Record<ParamKey, string>) => {
  const { aeskw, aeskwp } = await import('@noble/ciphers/aes.js');
  const alg = operationId === 'aes-kw' ? 'AES-KW' : 'AES-KWP';
  const key = normalizeFixedBytes(params.secret, `${alg} KEK`, [16, 24, 32]);
  let payload: AesRawPayload | null = null;
  if (direction === 'decode') {
    try {
      payload = JSON.parse(value) as AesRawPayload;
    } catch {
      payload = null;
    }
  }
  const cipher = operationId === 'aes-kw' ? aeskw(key.bytes) : aeskwp(key.bytes);
  const inputBytes = direction === 'encode'
    ? parseHexBase64OrUtf8Bytes(value, 'key material')
    : { bytes: parseHexOrBase64Bytes(payload?.wrappedHex || payload?.wrapped || payload?.ciphertextHex || payload?.ciphertext || value, 'wrapped key'), format: 'hex/base64' };
  const output = direction === 'encode' ? cipher.encrypt(inputBytes.bytes) : cipher.decrypt(inputBytes.bytes);
  if (direction === 'decode') {
    return JSON.stringify({
      alg,
      keyFormat: key.format,
      unwrappedEncoding: 'hex',
      unwrappedHex: bytesToHex(output),
      unwrappedBase64: bytesToBase64(output),
      unwrappedUtf8: utf8Decoder.decode(output),
    }, null, 2);
  }
  return JSON.stringify({
    alg,
    keyFormat: key.format,
    keyLength: key.normalizedLength,
    inputEncoding: inputBytes.format,
    inputLength: inputBytes.bytes.length,
    wrappedEncoding: 'hex',
    wrappedHex: bytesToHex(output),
    wrappedBase64: bytesToBase64(output),
  }, null, 2);
};

export const aesCmacTransform = async (value: string, params: Record<ParamKey, string>) => {
  const { cmac } = await import('@noble/ciphers/aes.js');
  const key = normalizeFixedBytes(params.secret, 'AES-CMAC key', [16, 24, 32]);
  const input = parseHexBase64OrUtf8Bytes(value, 'message');
  const tag = cmac(input.bytes, key.bytes);
  return JSON.stringify({
    alg: 'AES-CMAC',
    keyFormat: key.format,
    keyLength: key.normalizedLength,
    inputEncoding: input.format,
    inputLength: input.bytes.length,
    tagBytes: 16,
    tagHex: bytesToHex(tag),
    tagBase64: bytesToBase64(tag),
  }, null, 2);
};

export const sm4Transform = async (direction: Direction, value: string, params: Record<ParamKey, string>) => {
  const inferred = prepareSymmetricDecodeInput('sm4', direction, value, params);
  value = inferred.input;
  params = inferred.params;
  const smCrypto = (await import('sm-crypto')).default;
  const mode = params.variant === 'hex' ? 'ecb' : 'cbc';
  const key = normalizeFixedBytes(params.secret, 'SM4 key', [16]);
  let payload: Sm4Payload | null = null;
  if (direction === 'decode') {
    try {
      payload = JSON.parse(value) as Sm4Payload;
    } catch {
      payload = null;
    }
  }
  const payloadMode = String(payload?.mode || mode).toLowerCase();
  const resolvedMode = payloadMode === 'ecb' ? 'ecb' : 'cbc';
  const ivSource = payload?.ivHex || payload?.iv || params.iv;
  const iv = resolvedMode === 'cbc' ? normalizeFixedBytes(ivSource || '', 'SM4 IV', [16]) : null;
  const options: { mode: 'cbc'; iv: string } | undefined = resolvedMode === 'cbc' && iv
    ? { mode: 'cbc', iv: bytesToHex(iv.bytes) }
    : undefined;
  if (direction === 'encode') {
    const ciphertextHex = options
      ? smCrypto.sm4.encrypt(value, bytesToHex(key.bytes), options)
      : smCrypto.sm4.encrypt(value, bytesToHex(key.bytes));
    return JSON.stringify({
      alg: 'SM4',
      mode: resolvedMode.toUpperCase(),
      keyFormat: key.format,
      ivHex: iv ? bytesToHex(iv.bytes) : undefined,
      ivFormat: iv?.format,
      ciphertextEncoding: 'hex',
      ciphertextHex,
    }, null, 2);
  }
  const ciphertextHex = payload?.ciphertextHex || payload?.ciphertext || value;
  return options
    ? smCrypto.sm4.decrypt(ciphertextHex, bytesToHex(key.bytes), options)
    : smCrypto.sm4.decrypt(ciphertextHex, bytesToHex(key.bytes));
};

export const rc4Transform = (value: string, secret: string, decode = false, drop = 0) => {
  if (!secret) throw new Error('RC4 需要填写密钥');
  const inputBytes = decode ? hexToBytes(value) : utf8Encoder.encode(value);
  const keyBytes = utf8Encoder.encode(secret);
  const s = Array.from({ length: 256 }, (_, index) => index);
  let j = 0;
  for (let index = 0; index < 256; index += 1) {
    j = (j + s[index] + keyBytes[index % keyBytes.length]) & 255;
    [s[index], s[j]] = [s[j], s[index]];
  }
  let i = 0;
  j = 0;
  const nextKeyByte = () => {
    i = (i + 1) & 255;
    j = (j + s[i]) & 255;
    [s[i], s[j]] = [s[j], s[i]];
    return s[(s[i] + s[j]) & 255];
  };
  for (let index = 0; index < drop; index += 1) nextKeyByte();
  const output = new Uint8Array(inputBytes.length);
  for (let index = 0; index < inputBytes.length; index += 1) {
    output[index] = inputBytes[index] ^ nextKeyByte();
  }
  return decode ? utf8Decoder.decode(output) : bytesToHex(output);
};

export const blockCipherKeyWords = (secret: string) => {
  if (!secret) throw new Error('TEA/XTEA/XXTEA 需要 16 字节密钥');
  const source = /^[0-9a-f]{32}$/i.test(secret.trim())
    ? hexToBytes(secret)
    : utf8Encoder.encode(secret);
  const key = new Uint8Array(16);
  key.set(source.slice(0, 16));
  const view = new DataView(key.buffer);
  return [0, 4, 8, 12].map(offset => view.getUint32(offset, false));
};

export const pkcs7Pad = (bytes: Uint8Array, blockSize: number) => {
  const remainder = bytes.length % blockSize;
  const pad = remainder === 0 ? blockSize : blockSize - remainder;
  const output = new Uint8Array(bytes.length + pad);
  output.set(bytes);
  output.fill(pad, bytes.length);
  return output;
};

export const pkcs7Unpad = (bytes: Uint8Array) => {
  if (!bytes.length) return bytes;
  const pad = bytes[bytes.length - 1];
  if (pad <= 0 || pad > 8 || pad > bytes.length) throw new Error('PKCS#7 padding 不合法');
  for (let index = bytes.length - pad; index < bytes.length; index += 1) {
    if (bytes[index] !== pad) throw new Error('PKCS#7 padding 不合法');
  }
  return bytes.slice(0, bytes.length - pad);
};

export const readUint32Pair = (bytes: Uint8Array, offset: number) => {
  const view = new DataView(bytes.buffer, bytes.byteOffset + offset, 8);
  return [view.getUint32(0, false), view.getUint32(4, false)] as [number, number];
};

export const writeUint32Pair = (target: Uint8Array, offset: number, left: number, right: number) => {
  const view = new DataView(target.buffer, target.byteOffset + offset, 8);
  view.setUint32(0, left >>> 0, false);
  view.setUint32(4, right >>> 0, false);
};

export const teaBlock = (left: number, right: number, key: number[], decode = false) => {
  const delta = 0x9e3779b9;
  let v0 = left >>> 0;
  let v1 = right >>> 0;
  if (!decode) {
    let sum = 0;
    for (let round = 0; round < 32; round += 1) {
      sum = (sum + delta) >>> 0;
      v0 = (v0 + ((((v1 << 4) >>> 0) + key[0]) ^ (v1 + sum) ^ ((v1 >>> 5) + key[1]))) >>> 0;
      v1 = (v1 + ((((v0 << 4) >>> 0) + key[2]) ^ (v0 + sum) ^ ((v0 >>> 5) + key[3]))) >>> 0;
    }
  } else {
    let sum = (delta * 32) >>> 0;
    for (let round = 0; round < 32; round += 1) {
      v1 = (v1 - (((((v0 << 4) >>> 0) + key[2]) ^ (v0 + sum) ^ ((v0 >>> 5) + key[3])) >>> 0)) >>> 0;
      v0 = (v0 - (((((v1 << 4) >>> 0) + key[0]) ^ (v1 + sum) ^ ((v1 >>> 5) + key[1])) >>> 0)) >>> 0;
      sum = (sum - delta) >>> 0;
    }
  }
  return [v0, v1] as [number, number];
};

export const xteaBlock = (left: number, right: number, key: number[], decode = false) => {
  const delta = 0x9e3779b9;
  let v0 = left >>> 0;
  let v1 = right >>> 0;
  if (!decode) {
    let sum = 0;
    for (let round = 0; round < 32; round += 1) {
      v0 = (v0 + (((((v1 << 4) ^ (v1 >>> 5)) + v1) >>> 0) ^ ((sum + key[sum & 3]) >>> 0))) >>> 0;
      sum = (sum + delta) >>> 0;
      v1 = (v1 + (((((v0 << 4) ^ (v0 >>> 5)) + v0) >>> 0) ^ ((sum + key[(sum >>> 11) & 3]) >>> 0))) >>> 0;
    }
  } else {
    let sum = (delta * 32) >>> 0;
    for (let round = 0; round < 32; round += 1) {
      v1 = (v1 - (((((v0 << 4) ^ (v0 >>> 5)) + v0) >>> 0) ^ ((sum + key[(sum >>> 11) & 3]) >>> 0))) >>> 0;
      sum = (sum - delta) >>> 0;
      v0 = (v0 - (((((v1 << 4) ^ (v1 >>> 5)) + v1) >>> 0) ^ ((sum + key[sum & 3]) >>> 0))) >>> 0;
    }
  }
  return [v0, v1] as [number, number];
};

export const teaTransform = (value: string, secret: string, decode = false, xtea = false) => {
  const key = blockCipherKeyWords(secret);
  const inputBytes = decode ? hexToBytes(value) : pkcs7Pad(utf8Encoder.encode(value), 8);
  if (inputBytes.length % 8 !== 0) throw new Error('TEA/XTEA 解密需要 8 字节对齐的 hex 密文');
  const output = new Uint8Array(inputBytes.length);
  for (let offset = 0; offset < inputBytes.length; offset += 8) {
    const [left, right] = readUint32Pair(inputBytes, offset);
    const [nextLeft, nextRight] = xtea ? xteaBlock(left, right, key, decode) : teaBlock(left, right, key, decode);
    writeUint32Pair(output, offset, nextLeft, nextRight);
  }
  return decode ? utf8Decoder.decode(pkcs7Unpad(output)) : bytesToHex(output);
};

export const bytesToUint32Words = (bytes: Uint8Array, includeLength = false) => {
  const words = Array.from({ length: Math.ceil(bytes.length / 4) || 1 }, () => 0);
  for (let index = 0; index < bytes.length; index += 1) words[index >>> 2] |= bytes[index] << ((index & 3) * 8);
  if (includeLength) words.push(bytes.length);
  return words.map(word => word >>> 0);
};

export const uint32WordsToBytes = (words: number[], includeLength = false) => {
  const data = includeLength ? words.slice(0, -1) : words.slice();
  const length = includeLength ? words[words.length - 1] : data.length * 4;
  if (includeLength && (length < 0 || length > data.length * 4)) throw new Error('XXTEA 明文长度字段不合法');
  const output = new Uint8Array(data.length * 4);
  data.forEach((word, wordIndex) => {
    for (let byteIndex = 0; byteIndex < 4; byteIndex += 1) output[wordIndex * 4 + byteIndex] = (word >>> (byteIndex * 8)) & 255;
  });
  return output.slice(0, length);
};

export const xxteaWords = (input: number[], key: number[], decode = false) => {
  const v = input.slice();
  const n = v.length;
  if (n < 2) return v;
  const delta = 0x9e3779b9;
  if (!decode) {
    let z = v[n - 1];
    let sum = 0;
    for (let q = Math.floor(6 + 52 / n); q > 0; q -= 1) {
      sum = (sum + delta) >>> 0;
      const e = (sum >>> 2) & 3;
      for (let p = 0; p < n - 1; p += 1) {
        const y = v[p + 1];
        const mx = (((z >>> 5) ^ ((y << 2) >>> 0)) + ((y >>> 3) ^ ((z << 4) >>> 0)) ^ ((sum ^ y) + (key[(p & 3) ^ e] ^ z))) >>> 0;
        z = v[p] = (v[p] + mx) >>> 0;
      }
      const y = v[0];
      const mx = (((z >>> 5) ^ ((y << 2) >>> 0)) + ((y >>> 3) ^ ((z << 4) >>> 0)) ^ ((sum ^ y) + (key[((n - 1) & 3) ^ e] ^ z))) >>> 0;
      z = v[n - 1] = (v[n - 1] + mx) >>> 0;
    }
  } else {
    let y = v[0];
    let sum = (Math.floor(6 + 52 / n) * delta) >>> 0;
    while (sum !== 0) {
      const e = (sum >>> 2) & 3;
      for (let p = n - 1; p > 0; p -= 1) {
        const z = v[p - 1];
        const mx = (((z >>> 5) ^ ((y << 2) >>> 0)) + ((y >>> 3) ^ ((z << 4) >>> 0)) ^ ((sum ^ y) + (key[(p & 3) ^ e] ^ z))) >>> 0;
        y = v[p] = (v[p] - mx) >>> 0;
      }
      const z = v[n - 1];
      const mx = (((z >>> 5) ^ ((y << 2) >>> 0)) + ((y >>> 3) ^ ((z << 4) >>> 0)) ^ ((sum ^ y) + (key[e] ^ z))) >>> 0;
      y = v[0] = (v[0] - mx) >>> 0;
      sum = (sum - delta) >>> 0;
    }
  }
  return v;
};

export const xxteaTransform = (value: string, secret: string, decode = false) => {
  const key = blockCipherKeyWords(secret);
  if (!decode) {
    const words = bytesToUint32Words(utf8Encoder.encode(value), true);
    return bytesToHex(uint32WordsToBytes(xxteaWords(words, key), false));
  }
  const words = bytesToUint32Words(hexToBytes(value), false);
  return utf8Decoder.decode(uint32WordsToBytes(xxteaWords(words, key, true), true));
};
