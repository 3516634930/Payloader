// CODEC-IMPORTS
import { bigintFromBytes, bigintModInverse, bigintModPow, bigintToBytes, bitLength, inferRsaParamsFromText, rsaParamNumber } from './rsa';
import { bytesToBase64Url } from './tokens';
import { base64ToBytes, bytesToBase64, bytesToBuffer, bytesToHex, hexToBytes } from './bases';
import { utf8Decoder, utf8Encoder } from './alphabets';
// CODEC-IMPORTS-END
export const bigintNthRoot = (value: bigint, root: bigint): bigint => {
  if (value < 0n) throw new Error('负数没有实数 e 次根');
  if (value < 2n) return value;
  if (root === 1n) return value;
  const bits = bitLength(value);
  let high = 1n << BigInt(Math.ceil(bits / Number(root)) + 1);
  let low = 0n;
  while (low <= high) {
    const mid = (low + high) / 2n;
    const powered = mid ** root;
    if (powered === value) return mid;
    if (powered < value) low = mid + 1n;
    else high = mid - 1n;
  }
  return high;
};

export const bigintToBase64Url = (value: bigint) => bytesToBase64Url(bigintToBytes(value));

export const PGP_PACKET_TAGS: Record<number, string> = {
  1: '公钥加密会话密钥 (PKESK)',
  2: '签名 (Signature)',
  3: '对称密钥会话密钥 (SKESK)',
  5: '私钥 (Secret Key)',
  6: '公钥 (Public Key)',
  7: '保密子钥 (Secret Subkey)',
  8: '压缩数据 (Compressed)',
  9: '对称加密数据 (SEIP)',
  11: '字面数据 (Literal)',
  12: '信任 (Trust)',
  13: '用户 ID (User ID)',
  17: '用户属性 (User Attribute)',
  18: 'AEAD 加密数据',
  19: '完整性计算值 (MDC)',
};

export const PGP_PUBLIC_ALGOS: Record<number, string> = {
  1: 'RSA (加密/签名)', 2: 'RSA-Encrypt', 3: 'RSA-Sign', 9: 'ElGamal', 16: 'ElGamal (加密)',
  17: 'DSA', 18: 'ECDH', 19: 'ECDSA', 22: 'EdDSA',
};

export const PGP_SYMMETRIC_ALGOS: Record<number, string> = {
  0: '无', 1: 'IDEA', 2: '3DES', 3: 'CAST5', 4: 'Blowfish', 7: 'AES-128', 8: 'AES-192', 9: 'AES-256',
  10: 'Twofish', 100: '私有区间',
};

export const PGP_COMPRESSION_ALGOS: Record<number, string> = { 0: '无压缩', 1: 'ZIP (RFC1951)', 2: 'ZLIB (RFC1950)', 3: 'BZip2' };

export const PGP_ARMOR_HEADERS = ['-----BEGIN PGP MESSAGE-----', '-----BEGIN PGP PUBLIC KEY BLOCK-----', '-----BEGIN PGP PRIVATE KEY BLOCK-----', '-----BEGIN PGP SIGNATURE-----'] as const;

export const stripPgpArmor = (text: string): { bytes: Uint8Array; armor: boolean; headers: Record<string, string> } => {
  const trimmed = text.trim();
  const armorHeader = PGP_ARMOR_HEADERS.find(header => trimmed.startsWith(header));
  if (!armorHeader) return { bytes: hexToBytes(text.replace(/0x/gi, '').replace(/[\s,-]/g, '')), armor: false, headers: {} };
  const body = trimmed.slice(trimmed.indexOf('\n'), trimmed.indexOf('-----END')).trim();
  const headers: Record<string, string> = {};
  const lines = body.split('\n');
  let index = 0;
  while (index < lines.length && lines[index].includes(': ')) {
    const [name, ...rest] = lines[index].split(': ');
    headers[name.trim()] = rest.join(': ').trim();
    index += 1;
  }
  const base64 = lines.slice(index).filter(line => !line.startsWith('=')).join('');
  const bytes = base64ToBytes(base64);
  return { bytes, armor: true, headers };
};

export const parsePgpPackets = (data: Uint8Array) => {
  const packets: Array<Record<string, unknown>> = [];
  let offset = 0;
  while (offset < data.length) {
    const start = offset;
    const header = data[offset];
    if ((header & 0x80) === 0) throw new Error(`偏移 ${offset} 处的 packet 头无效（最高位必须为 1，RFC 4880 §4.2）`);
    const newFormat = (header & 0x40) !== 0;
    const tag = newFormat ? header & 0x3f : (header >> 2) & 0x0f;
    let lengthType = '一';
    let length = 0;
    offset += 1;
    if (newFormat) {
      const first = data[offset];
      offset += 1;
      if (first < 192) { length = first; lengthType = '1 字节'; }
      else if (first <= 223) { length = ((first - 192) << 8) + data[offset] + 192; offset += 1; lengthType = '2 字节'; }
      else if (first === 255) { length = Number((BigInt(data[offset]) << 24n) | (BigInt(data[offset + 1]) << 16n) | (BigInt(data[offset + 2]) << 8n) | BigInt(data[offset + 3])); offset += 4; lengthType = '5 字节 (32-bit)'; }
      else { lengthType = '部分长度 (partial)'; length = 1 << (first & 0x1f); }
    } else {
      const lengthTypeBits = header & 0x03;
      if (lengthTypeBits === 0) { length = data[offset]; offset += 1; lengthType = '1 字节'; }
      else if (lengthTypeBits === 1) { length = (data[offset] << 8) | data[offset + 1]; offset += 2; lengthType = '2 字节'; }
      else if (lengthTypeBits === 2) { length = Number((BigInt(data[offset]) << 24n) | (BigInt(data[offset + 1]) << 16n) | (BigInt(data[offset + 2]) << 8n) | BigInt(data[offset + 3])); offset += 4; lengthType = '4 字节'; }
      else { lengthType = '不定长 (indeterminate)'; length = data.length - offset; }
    }
    const content = data.slice(offset, offset + length);
    const info: Record<string, unknown> = {
      index: packets.length,
      offset: start,
      tag,
      name: PGP_PACKET_TAGS[tag] ?? `未知 packet (tag ${tag})`,
      newFormat,
      lengthType,
      length,
      preview: bytesToHex(content.slice(0, 32)) + (content.length > 32 ? '…' : ''),
    };
    if ((tag === 1 || tag === 3) && content.length >= 3) {
      info.version = content[0];
      if (tag === 1) {
        info.keyId = bytesToHex(content.slice(3, 11));
        info.publicAlgo = PGP_PUBLIC_ALGOS[content[2]] ?? `algo ${content[2]}`;
      } else {
        info.symmetricAlgo = PGP_SYMMETRIC_ALGOS[content[2]] ?? `algo ${content[2]}`;
        info.s2k = content[1] === 0 ? '简单 S2K' : content[1] === 3 ? '迭代+盐 S2K' : `S2K 类型 ${content[1]}`;
      }
    }
    if ((tag === 5 || tag === 6 || tag === 7) && content.length >= 3) {
      info.version = content[0];
      const timeHex = bytesToHex(content.slice(1, 5));
      info.createdAt = new Date(parseInt(timeHex, 16) * 1000).toISOString();
      const algo = content[5];
      info.publicAlgo = tag === 6 ? (PGP_PUBLIC_ALGOS[algo] ?? `algo ${algo}`) : undefined;
      if (tag === 6 && algo === 1 && content.length >= 9) {
        info.modulusBits = ((content[6] << 8) | content[7]);
      }
    }
    if (tag === 8 && content.length >= 1) info.compressionAlgo = PGP_COMPRESSION_ALGOS[content[0]] ?? `algo ${content[0]}`;
    if (tag === 2 && content.length >= 3) {
      info.version = content[0];
      info.signatureType = content[1];
      info.publicAlgo = PGP_PUBLIC_ALGOS[content[2]] ?? `algo ${content[2]}`;
    }
    packets.push(info);
    offset += length;
    if (length <= 0 && offset <= start) break;
  }
  return packets;
};

export const parsePgpMessage = (value: string) => {
  const { bytes, armor, headers } = stripPgpArmor(value);
  if (bytes.length === 0) throw new Error('输入为空：需要 PGP 报文（ASCII armor 或二进制 hex）');
  const packets = parsePgpPackets(bytes);
  return `PGP/GPG 报文结构解析（只读展示，不做任何解密）\n\n${JSON.stringify({
    armor,
    armorHeaders: headers,
    packetCount: packets.length,
    packets,
    note: '按 RFC 4880 解析 packet 结构。此工具只读展示结构信息（tag/算法/长度/预览），不实现任何解密。',
  }, null, 2)}`;
};

export const rsaOaepEncryptFromText = async (value: string) => {
  const fieldText = (key: string) => {
    const match = value.match(new RegExp('(^|[^A-Za-z0-9_])' + key + '[ 	]*[=:][ 	]*([A-Za-z0-9+/=_-]{4,})', 'm'));
    return match ? match[2] : null;
  };
  const toBigFromField = (field: string): bigint | null => {
    if (/^0x/i.test(field)) return BigInt(field);
    if (/^[0-9]+$/.test(field)) return BigInt(field);
    try { return bigintFromBytes(base64ToBytes(field.replace(/-/g, '+').replace(/_/g, '/'))); } catch (e) { console.error('TOBIG ERR:', (e as Error).message.slice(0, 80)); return null; }
  };
  const pick = (key: 'n' | 'e'): bigint | null => {
    const raw = fieldText(key);
    return raw ? toBigFromField(raw) : null;
  };
  const n = pick('n');
  const e = pick('e') ?? 65537n;
  const plainMatch = value.match(/(?:plain|明文|message|msg)\s*[:=]\s*['"]?([^'"\n]+)['"]?/i);
  const plaintext = (plainMatch ? plainMatch[1].trim() : value.split('\n').filter(line => !/[:=]/.test(line)).join('').trim()) || value.trim();
  if (!n) throw new Error('RSA-OAEP 加密需要模数 n（支持 n=0x… / n=十进制 / n=base64）');
  const jwk = { kty: 'RSA', n: bigintToBase64Url(n), e: bigintToBase64Url(e) };
  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
  const encrypted = new Uint8Array(await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, key, bytesToBuffer(utf8Encoder.encode(plaintext))));
  return JSON.stringify({ hash: 'SHA-256', plaintext, cipherHex: bytesToHex(encrypted), cipherBase64: bytesToBase64(encrypted), note: 'OAEP 加密使用随机种子，每次输出不同（这是安全特性）。' }, null, 2);
};

export const rsaOaepDecryptFromText = async (value: string) => {
  const fieldText = (key: string) => {
    const match = value.match(new RegExp('(^|[^A-Za-z0-9_])' + key + '[ 	]*[=:][ 	]*([A-Za-z0-9+/=_-]{4,})', 'm'));
    return match ? match[2] : null;
  };
  const toBigFromField = (field: string): bigint | null => {
    if (/^0x/i.test(field)) return BigInt(field);
    if (/^[0-9]+$/.test(field)) return BigInt(field);
    try { return bigintFromBytes(base64ToBytes(field.replace(/-/g, '+').replace(/_/g, '/'))); } catch { return null; }
  };
  const pickBig = (key: 'n' | 'e' | 'd' | 'p' | 'q'): bigint | null => {
    const raw = fieldText(key);
    return raw ? toBigFromField(raw) : null;
  };
  const cipherHexMatch = value.match(/(?:c|ct|cipher)\s*[:=]\s*(?:0x)?([0-9a-fA-F]{64,})/i);
  const cipherB64Match = !cipherHexMatch ? value.match(/(?:c|ct|cipher)\s*[:=]\s*([A-Za-z0-9+/=]{16,})/) : null;
  const cipherBytes = cipherHexMatch
    ? hexToBytes(cipherHexMatch[1])
    : cipherB64Match ? base64ToBytes(cipherB64Match[1]) : new Uint8Array();
  if (!cipherBytes.length) throw new Error('未找到密文：需要 c=<hex 或 base64> 字段');
  const n = pickBig('n');
  const e = pickBig('e') ?? 65537n;
  const d = pickBig('d');
  const p = pickBig('p');
  const q = pickBig('q');
  if (!n || !e || !d || !p || !q) throw new Error('RSA-OAEP 私钥解密需要 n、e、d、p、q 全部参数（WebCrypto JWK 导入要求完整 CRT 参数）');
  const nK = n; const eK = e; const dK = d; const pK = p; const qK = q;
  const dp = dK % (pK - 1n);
  const dq = d % (q - 1n);
  const qi = bigintModInverse(qK, pK)!;
  const jwk = {
    kty: 'RSA',
    n: bigintToBase64Url(nK),
    e: bigintToBase64Url(eK),
    d: bigintToBase64Url(dK),
    p: bigintToBase64Url(pK),
    q: bigintToBase64Url(qK),
    dp: bigintToBase64Url(dp),
    dq: bigintToBase64Url(dq),
    qi: bigintToBase64Url(qi),
  };
  const attempts: string[] = [];
  for (const hash of ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'] as const) {
    try {
      const key = await crypto.subtle.importKey('jwk', { ...jwk, alg: `RSA-OAEP-${hash.slice(4)}` }, { name: 'RSA-OAEP', hash }, false, ['decrypt']);
      const plainBuffer = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, key, bytesToBuffer(cipherBytes));
      const plainBytes = new Uint8Array(plainBuffer);
      const text = utf8Decoder.decode(plainBytes);
      return `智能识别: RSA-OAEP 解密成功 (hash ${hash})\n\n${JSON.stringify({
        hash,
        modulusBits: bitLength(nK),
        plaintextUtf8: text,
        plaintextHex: bytesToHex(plainBytes).slice(0, 256),
        attempted: attempts,
        note: 'WebCrypto RSA-OAEP 原生解密（RFC 8017），hash 逐个尝试后命中。',
      }, null, 2)}`;
    } catch (error) {
      attempts.push(`${hash}: ${(error as Error).message.slice(0, 60)}`);
    }
  }
  throw new Error(`RSA-OAEP 解密失败（尝试 SHA-1/256/384/512）：加密时的 hash 或密钥参数与提供的不一致。尝试记录：${attempts.join('；')}`);
};

export const coppersmithStereotypedSolve = (value: string, prefixParam: string) => {
  const inference = inferRsaParamsFromText(value, 'decode');
  const n = rsaParamNumber(inference.params, 'n');
  const e = rsaParamNumber(inference.params, 'e') ?? 3n;
  const c = rsaParamNumber(inference.params, 'c');
  if (!n || !c) throw new Error('Coppersmith 简化版需要 n 和 c（支持 n=0x…/十进制，c 同）');
  const prefixMatch = value.match(/(?:prefix|前缀|已知)\s*[:=]\s*['"]?([^'"\n]+)['"]?/i);
  const prefix = (prefixMatch ? prefixMatch[1].trim() : prefixParam) || '';
  const notes: string[] = ['简化版边界：只实现整数 e 次开方 + 已知前缀短尾枚举；完整 Coppersmith（Howgrave-Graham + LLL 格基规约）未实现，未知尾部长度受枚举上限约束。'];
  // 路径一：无包装（c = m^e 且 m^e < n 不成立也试——直接对 c 开 e 次根，root^e == c 时即未取模场景）
  const root = bigintNthRoot(c, e);
  if (root ** e === c) {
    const bytes = bigintToBytes(root);
    return JSON.stringify({
      method: '整数 e 次开方（c 未发生模 n 回绕）',
      e: e.toString(),
      recoveredHex: bytesToHex(bytes),
      recoveredUtf8: utf8Decoder.decode(bytes),
      notes,
    }, null, 2);
  }
  if (!prefix) throw new Error('c 无法直接开方时需要已知前缀（prefix=... 参数或 prefix=... 字段）做枚举');
  const suffixLen = Math.min(4, Number((value.match(/(?:suffixLen|尾长)\s*[:=]\s*(\d)/i) || [])[1] || 3));
  const charset = '0123456789abcdefghijklmnopqrstuvwxyz';
  const prefixBytes = utf8Encoder.encode(prefix);
  const base = bigintFromBytes(prefixBytes) * (1n << BigInt(8 * suffixLen));
  const charsetNums = Array.from(charset, char => char.charCodeAt(0));
  let trials = 0;
  const maxTrials = Math.min(500000, Math.pow(charset.length, suffixLen));
  const attemptLimit = Number((value.match(/(?:maxTrials|尝试上限)\s*[:=]\s*(\d+)/i) || [])[1] || 300000);
  for (let mask = 0; mask < maxTrials; mask += 1) {
    let rest = mask;
    const suffix: number[] = [];
    for (let index = 0; index < suffixLen; index += 1) {
      suffix.push(charsetNums[rest % charset.length]);
      rest = Math.floor(rest / charset.length);
    }
    if (suffix.some(byte => byte === undefined)) break;
    const candidate = base + suffix.reduce((acc, byte) => (acc << 8n) | BigInt(byte), 0n);
    trials += 1;
    if (candidate >= n!) break;
    if (bigintModPow(candidate, e, n!) === c) {
      const recovered = prefix + suffix.map(byte => String.fromCharCode(byte)).join('');
      return JSON.stringify({
        method: `已知前缀 + ${suffixLen} 字节尾枚举（简化 Coppersmith）`,
        e: e.toString(),
        trials,
        recovered: recovered,
        recoveredHex: bytesToHex(utf8Encoder.encode(recovered)),
        notes,
      }, null, 2);
    }
    if (trials >= attemptLimit) break;
  }
  throw new Error(`枚举 ${trials} 个候选未命中。该未知部分长度超出简化版枚举能力（真实 Coppersmith 需要 LLL 格基规约，本工具未实现）。可尝试加长已知前缀或减小尾长。`);
};

// CBC padding oracle + bit-flip 教学演示器：本地模拟，全程无网络。
// 演示两个经典 CBC 攻击：
// 1. Bit-flip——攻击者翻转前块密文的位，翻转目标块解密后的对应明文位
// 2. Padding Oracle——利用服务端 padding 校验的差异（成功/失败）逐字节还原明文
export const cbcDemoTransform = async (value: string, keyHex: string) => {
  // CBC padding oracle + bit-flip 教学演示（本地模拟，无网络）
  const demoText = value.trim().slice(0, 48) || 'comments are fun and this is a padding oracle demo';
  const key = keyHex.trim().length >= 64
    ? hexToBytes(keyHex.replace(/0x/gi, '').slice(0, 64))
    : crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const aesKey = await crypto.subtle.importKey('raw', bytesToBuffer(key), 'AES-CBC', false, ['encrypt', 'decrypt']);
  const plainBytes = utf8Encoder.encode(demoText);
  const cipherBytes = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CBC', iv: bytesToBuffer(iv) }, aesKey, bytesToBuffer(plainBytes)));
  const blockCount = Math.ceil(cipherBytes.length / 16);

  // Bit-flip：翻转 IV 使第一块解密变为目标内容（P1 = D(C1) xor IV）
  const flipFrom = 'comments are fun';
  const flipTo = 'PWNED by bitflip';
  const flippedIv = new Uint8Array(iv);
  for (let i = 0; i < 16 && i < flipFrom.length; i += 1) flippedIv[i] ^= flipFrom.charCodeAt(i) ^ flipTo.charCodeAt(i);
  let bitFlipOut = '';
  try { bitFlipOut = new TextDecoder().decode(new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-CBC', iv: bytesToBuffer(flippedIv) }, aesKey, bytesToBuffer(cipherBytes)))).slice(0, 16); } catch { bitFlipOut = '(padding error)'; }

  // Padding oracle 演示：展示逐字节还原原理
  const oracleSteps = [
    'Step 1: Set R[15] = 0x01, scan IV[15] 0..255 for valid padding (P[15]=0x01)',
    'Step 2: Set R[15] = 0x02, scan IV[14] for valid padding (P[14]=P[15]=0x02)',
    'Step 3: Repeat for all 16 positions to recover full intermediate value D(C1)',
    'Step 4: Plaintext = D(C1) xor original IV',
  ];

  return JSON.stringify({
    demo: 'CBC padding oracle + bit-flip 教学演示（本地，无网络）',
    cipherLen: cipherBytes.length,
    blockCount,
    bitFlip: {
      method: '翻转 IV 对应位 → 第一块明文被篡改',
      flippedIvHex: bytesToHex(flippedIv).slice(0, 32),
      originalHead: demoText.slice(0, 16),
      afterFlip: bitFlipOut,
    },
    paddingOracle: {
      method: '逐 position 探测 PKCS#7 padding byte（教学展示攻击原理）',
      steps: oracleSteps,
      note: '完整攻击需要 oracle 区分 padding 错误与其他错误，此处为教学展示。',
    },
    mitigation: '防御：使用 AES-GCM 等 AEAD 模式，或 encrypt-then-MAC。',
  }, null, 2);
};
