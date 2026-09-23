// CODEC-IMPORTS
import { hashLengthExtensionHelper, inferHashLengthExtensionFromText } from './attacks';
import { decodeQuery, decompressText, looksLikeResolvedSmartDecodeText, runSmartDecodeOperation, smartTextScore } from './smartBase';
import { utf8Decoder } from './alphabets';
import { extractClassicCipherSource } from './smartClassical';
import { bigintGcd, bigintMod, bigintModInverse, parseNumericValue } from './rsa';
import { base64ToBytes, hexToBytes } from './bases';
import { cleanLooseFieldValue, looseField, parseLooseCtfFields } from './crypto';
import { defaultParams } from './operations';
import { decodeFernet, decodeJwt, decodeOtpAuthUriCompat, parseFernetRaw } from './tokens';
import { decodePemBlock, parseAsn1Der, parseJwkJwe, parseSshPublicKey } from './binaryFormats';
import { adfgxTransform, bifidTransform, columnarDecode, playfairTransform, trifidTransform } from './classical';
// CODEC-IMPORTS-END
export const trySmartHashLengthExtension = (value: string) => {
  const inference = inferHashLengthExtensionFromText(value, '', '', '');
  const explicit = /(length extension|hashpump|hash_extender|secret\s*\|\||prefix mac|secret-prefix)/i.test(value);
  const hasDigest = /^[a-f0-9]{32,64}$/i.test(inference.digest);
  const hasMaterial = inference.originalMessage !== 'known-message' || inference.appendData !== 'admin=true';
  if (!hasDigest || inference.confidence < 7 || (!explicit && !hasMaterial)) return null;
  return `智能识别: Hash length-extension helper\n\n${hashLengthExtensionHelper(value, inference.algorithm, inference.appendData, inference.originalMessage)}`;
};

export const canSmartHashLengthExtension = (value: string) => Boolean(trySmartHashLengthExtension(value));

export const trySmartSubstitutionBruteforce = (value: string): string | null => {
  const { source: _subSrc } = extractClassicCipherSource(value);
  const text = (_subSrc.trim() || value).trim();
  const letters = text.toUpperCase().replace(/[^A-Z]/g, '');
  if (letters.length < 20) return null;
  const hasHint = /substitut|monoalpha|single.?alpha|cipher.?text|plaintext/i.test(value);
  const icEnglish = 0.0665;
  const freq = new Array(26).fill(0);
  for (const c of letters) freq[c.charCodeAt(0) - 65] += 1;
  const n = letters.length;
  const ic = freq.reduce((s, f) => s + f * (f - 1), 0) / (n * (n - 1));
  if (!hasHint && ic < 0.055) return null; // too low IC → not monoalphabetic
  if (!hasHint && Math.abs(ic - icEnglish) > 0.012) return null;
  // Build substitution from ciphertext freq → English freq (ETAOIN order)
  const etaoin = 'ETAOINSHRDLCUMWFGYPBVKJXQZ';
  const sortedCipher = freq
    .map((f, i) => ({ f, c: String.fromCharCode(65 + i) }))
    .sort((a, b) => b.f - a.f)
    .map(x => x.c);
  const subTable: Record<string, string> = {};
  sortedCipher.forEach((c, i) => { subTable[c] = etaoin[i] ?? c; });
  const scoreText = text.length > 2000 ? text.slice(0, 2000) : text;
  const applySubTable = (t: string, tbl: Record<string, string>) =>
    Array.from(t).map(ch => { const u = ch.toUpperCase(); if (u >= 'A' && u <= 'Z') { const p = tbl[u] ?? ch; return ch === u ? p : p.toLowerCase(); } return ch; }).join('');
  let decoded = applySubTable(scoreText, subTable);
  // Greedy hill-climbing: try all pairwise swaps up to 12 rounds (capped at 2000 chars for perf)
  for (let round = 0; round < 12; round += 1) {
    let improved = false;
    const keys = Object.keys(subTable);
    for (let i = 0; i < keys.length; i += 1) {
      for (let j = i + 1; j < keys.length; j += 1) {
        const [a, b] = [keys[i], keys[j]];
        [subTable[a], subTable[b]] = [subTable[b], subTable[a]];
        const candidate = applySubTable(scoreText, subTable);
        if (smartTextScore(candidate) > smartTextScore(decoded)) { decoded = candidate; improved = true; }
        else [subTable[a], subTable[b]] = [subTable[b], subTable[a]];
      }
    }
    if (!improved) break;
  }
  const finalDecoded = applySubTable(text, subTable);
  const score = smartTextScore(finalDecoded);
  const origScore = smartTextScore(text);
  // 换位嫌疑画像：IC≈英文 + 足够长的密文也可能是换位/分式密码（ETAOIN 映射近似恒等，
  // 容易解出含 "the" 子串的半明文造成误判）。此类输入要求词边界英文或完整 flag 形态才肯认。
  const transpositionSuspect = letters.length >= 80 && Math.abs(ic - icEnglish) <= 0.012;
  const realFlagShape = /(?:flag|ctf|picoctf|htb|thm|ductf|corctf|dice|wctf|utflag|sekai|actf|seccon|ritsec|crypto|lactf|crew|nahamcon|hsctf|justctf|b01lers|wanictf|jerseyctf)\{[a-z0-9_!?.-]{2,}\}/i.test(finalDecoded);
  const wordEvidence = /\b(?:the|and|that|with|from|have|this|which|where|their)\b/i.test(finalDecoded);
  const confident = transpositionSuspect
    ? realFlagShape || (wordEvidence && score - origScore >= 8) || score - origScore >= 20
    : score - origScore >= 8 || realFlagShape || /flag\{|ctf\{|picoctf\{|htb\{|thm\{|ductf\{|corctf\{|dice\{|wctf\{|utflag\{|sekai\{|actf\{|seccon\{|ritsec\{|crypto\{|lactf\{|crew\{|nahamcon\{|hsctf\{|justctf\{|b01lers\{|wanictf\{/i.test(finalDecoded);
  if (!hasHint && !confident) return null;
  return `智能识别: Substitution cipher (frequency-rank mapping)\n\n${JSON.stringify({
    ic: Number(ic.toFixed(4)),
    substitutionTable: subTable,
    decoded: finalDecoded,
    score,
    note: 'Frequency-rank heuristic. Manual refinement via the Substitution tool may be needed.',
  }, null, 2)}`;
};

export const trySmartCrtSolver = (value: string): string | null => {
  // Also handle single linear congruence: ax ≡ b (mod n) or ax = b mod n
  const linMatch = value.match(/(\d+)\s*\*?\s*x\s*[≡=]\s*(\d+)\s*(?:\(mod\b|mod\b)\s*(\d+)/i)
    || value.match(/ax?\s*[≡=]\s*b\s*\(?mod/i) && null; // hint only, no solve
  if (linMatch) {
    const a = BigInt(linMatch[1]);
    const b = BigInt(linMatch[2]);
    const n = BigInt(linMatch[3]);
    const g = bigintGcd(a, n);
    if (b % g === 0n) {
      const a1 = a / g; const b1 = b / g; const n1 = n / g;
      const inv = bigintModInverse(a1, n1);
      if (inv != null) {
        const x0 = bigintMod(b1 * inv, n1);
        const solutions = Array.from({ length: Number(g) }, (_, i) => (x0 + n1 * BigInt(i)).toString());
        return `智能识别: 线性同余方程 ${a}x ≡ ${b} (mod ${n})\n\n${JSON.stringify({ equation: `${a}x ≡ ${b} (mod ${n})`, gcd: g.toString(), solutions, note: `${g} solution(s) mod ${n}` }, null, 2)}`;
      }
    } else {
      return `智能识别: 线性同余方程无解 — gcd(${a},${n})=${g} 不整除 ${b}\n\n${JSON.stringify({ equation: `${a}x ≡ ${b} (mod ${n})`, gcd: g.toString(), hasSolution: false }, null, 2)}`;
    }
  }

  // Parse x ≡ a (mod m) or x = a mod m or a % m = r style lines
  const lines = value.split(/\n|;/).map(l => l.trim()).filter(Boolean);
  type CrtEq = { a: bigint; m: bigint };
  const equations: CrtEq[] = [];
  for (const line of lines) {
    let m = line.match(/(?:x\s*[≡=]\s*)?(0x[0-9a-f]+|\d+)\s*(?:\(mod\b|mod\b)\s*(0x[0-9a-f]+|\d+)\s*\)?/i);
    if (m) {
      const a = parseNumericValue(m[1]);
      const mod = parseNumericValue(m[2]);
      if (typeof a === 'bigint' && typeof mod === 'bigint' && mod > 1n) equations.push({ a, m: mod });
      continue;
    }
    m = line.match(/(0x[0-9a-f]+|\d+)\s*%\s*(0x[0-9a-f]+|\d+)\s*[=≡]+\s*(0x[0-9a-f]+|\d+)/i);
    if (m) {
      const mod = parseNumericValue(m[2]);
      const r = parseNumericValue(m[3]);
      if (typeof r === 'bigint' && typeof mod === 'bigint' && mod > 1n) equations.push({ a: r, m: mod });
    }
  }
  if (equations.length < 2) return null;
  for (let i = 0; i < equations.length; i++) {
    for (let j = i + 1; j < equations.length; j++) {
      if (bigintGcd(equations[i].m, equations[j].m) !== 1n) {
        return `智能识别: CRT 方程组 (模非互质，无法直接用 CRT)\n\n${JSON.stringify({ equations: equations.map(e => ({ a: e.a.toString(), mod: e.m.toString() })), note: 'Moduli are not pairwise coprime. Manual generalized CRT or direct solving required.' }, null, 2)}`;
      }
    }
  }
  const M = equations.reduce((acc, eq) => acc * eq.m, 1n);
  let x = 0n;
  for (const eq of equations) {
    const Mi = M / eq.m;
    const inv = bigintModInverse(Mi, eq.m);
    if (inv == null) return null;
    x = bigintMod(x + eq.a * Mi * inv, M);
  }
  return `智能识别: CRT 方程组求解\n\n${JSON.stringify({
    equations: equations.map(e => ({ a: e.a.toString(), mod: e.m.toString() })),
    M: M.toString(),
    x: x.toString(),
    xHex: '0x' + x.toString(16),
    asText: (() => { try { return utf8Decoder.decode(hexToBytes(x.toString(16).padStart(x.toString(16).length + (x.toString(16).length % 2), '0'))); } catch { return null; } })(),
  }, null, 2)}`;
};

export const trySmartEccHelper = (value: string): string | null => {
  const lower = value.toLowerCase();
  const fields = parseLooseCtfFields(value);
  const getN = (aliases: string[]) => { const r = looseField(fields, aliases); return r ? parseNumericValue(r) : null; };
  const p   = getN(['p', 'prime', 'field', 'mod', 'modulus']);
  const a   = getN(['a', 'coeff_a', 'coeffa', 'curve_a']);
  const b   = getN(['b', 'coeff_b', 'coeffb', 'curve_b']);
  const n   = getN(['n', 'order', 'curve_order', 'group_order', 'grouporder']);
  const priv = getN(['k', 'priv', 'private', 'secret', 'privatekey', 'privkey', 'da', 'dk']);
  const c1Raw = looseField(fields, ['c1', 'r', 'point1', 'cipher1', 'leftcipher']);
  const c2Raw = looseField(fields, ['c2', 's', 'point2', 'cipher2', 'rightcipher']);
  const pub  = looseField(fields, ['q', 'pubkey', 'publickey', 'pub', 'point', 'qa', 'pk']);
  const g    = looseField(fields, ['g', 'generator', 'basepoint', 'base_point']);
  const hasCurveKeyword = /\b(?:ecc|ecdh|elliptic|curve|secp\w*|nist|weierstrass|point|basepoint|base[_ -]?point|ecdlp)\b/.test(lower);
  const hasCoordinateEvidence = /\b(?:g|q|p|r|generator|public(?:\s+key)?|base(?:\s+point)?)\s*[:=]\s*\(\s*(?:0x[0-9a-f]+|\d+)\s*,\s*(?:0x[0-9a-f]+|\d+)\s*\)/i.test(value);
  const hasCurveEquationEvidence = /\by\s*(?:\^|\*\*)\s*2\s*=\s*x\s*(?:\^|\*\*)\s*3\b/i.test(value)
    || /y²\s*=\s*x³/i.test(value);
  if (!hasCurveKeyword && !hasCoordinateEvidence && !hasCurveEquationEvidence) return null;
  let confidence = 0;
  if (p) confidence += 3;
  if (a != null) confidence += 2;
  if (b != null) confidence += 2;
  if (g || pub) confidence += 2;
  if (hasCoordinateEvidence) confidence += 2;
  if (/secp256k1|secp256r1|p-256|p-384|p-521|curve25519|ed25519/i.test(value)) confidence += 4;
  if (confidence < 5) return null;
  const nBits = p ? p.toString(2).length : null;
  const notes: string[] = [];
  if (nBits && nBits <= 64) notes.push('小域（≤64 bit），BSGS/Pohlig-Hellman 可直接在本地计算 ECDLP。');
  if (p && a != null && b != null) {
    const disc = (4n * a ** 3n + 27n * b ** 2n) % p;
    if (disc === 0n) notes.push('判别式 = 0：曲线是奇异曲线（singular），ECDLP 退化为有限域 DLP 或加法群，可用经典方法攻击。');
  }
  if (value.includes('anomalous') || (p && n && p === n)) notes.push('Anomalous 曲线（#E = p），Smart attack 可在 O(log p) 时间内解 ECDLP：使用 SageMath `E.lift(P)` + p-adic lifting。');
  if (value.includes('mov') || value.includes('supersingular')) notes.push('MOV/Frey-Rück attack：将 ECDLP 规约到有限域 DLP，使用 Weil/Tate pairing。');
  const sageTemplate = [
    p && a != null && b != null ? `p=${p}; a=${a}; b=${b}` : '# p, a, b 未完整识别',
    n ? `n=${n}` : '',
    'E = EllipticCurve(GF(p), [a, b])',
    g ? `G = E(${g})` : '# G 未识别，手动指定',
    pub ? `Q = E(${pub})` : '# Q (public key) 未识别',
    'k = discrete_log(Q, G, operation="+")  # ECDLP',
    priv && c1Raw && c2Raw ? `# Private key k=${priv} found — ElGamal decrypt:\nC1=E(${c1Raw}); C2=E(${c2Raw})\nM = C2 - k*C1; print(M)` : '',
  ].filter(Boolean).join('\n');
  return `智能识别: ECC / Elliptic Curve Helper\n\n${JSON.stringify({
    extracted: { p: p?.toString(), a: a?.toString(), b: b?.toString(), n: n?.toString(), generator: g || null, publicKey: pub || null, privateKey: priv?.toString() || null },
    confidence,
    notes,
    sageTemplate,
    commands: [
      p && a != null && b != null ? `sage -c "${sageTemplate.replace(/"/g, "'")}"` : '',
      `python -c "from tinyec import registry; # or manually define curve"`,
    ].filter(Boolean),
  }, null, 2)}`;
};

export const trySmartModDecode = (value: string): string | null => {
  // Detect space-separated integers that map to characters via mod N
  // Common in picoCTF basic-mod1 (mod 37: A-Z/0-9/_) and basic-mod2 (mod 41)
  const tokens = value.trim().split(/[\s,;]+/).filter(Boolean);
  if (tokens.length < 4) return null;
  // Binary/octal-shaped numeric lists belong to the encoding layer (Binary/Octal decoders), not modular decode
  if (tokens.every(token => /^[01]{4,}$/.test(token))) return null;
  if (tokens.every(token => /^0[0-7]+$/.test(token)) || tokens.every(token => /^[0-7]{3}$/.test(token))) return null;
  const nums = tokens.map(Number);
  if (nums.some(n => !Number.isInteger(n) || n < 0)) return null;
  const maxVal = Math.max(...nums);
  if (maxVal <= 127) return null; // Already covered by ASCII codes
  // Try common CTF mod alphabets: mod 37, 41, 40, 47, 97, 26+, ...
  const modAlphabets: Array<{ mod: number; map: (v: number) => string }> = [
    { mod: 37, map: v => v < 26 ? String.fromCharCode(65 + v) : v < 36 ? String(v - 26) : '_' },
    { mod: 41, map: v => v < 26 ? String.fromCharCode(65 + v) : v < 36 ? String(v - 26) : v === 36 ? '_' : v === 37 ? '!' : v === 38 ? '?' : v === 39 ? '@' : '#' },
    { mod: 40, map: v => v < 26 ? String.fromCharCode(65 + v) : v < 36 ? String(v - 26) : '_' },
  ];
  for (const { mod, map } of modAlphabets) {
    const decoded = nums.map(n => map(n % mod)).join('');
    // The loose [A-Z0-9_]{6,} shape alone also matches decode garbage — accept only plausibly textual results
    const modLetters = decoded.replace(/[^A-Za-z]/g, '');
    const textual = /flag\{|ctf\{|picoctf\{|htb\{|thm\{|crypto\{|lactf\{|crew\{/i.test(decoded)
      || looksLikeResolvedSmartDecodeText(decoded)
      || (decoded.length >= 4 && modLetters.length / decoded.length >= 0.6 && /[AEIOU]/.test(modLetters));
    if (textual && /flag\{|ctf\{|picoctf\{|htb\{|thm\{|crypto\{|lactf\{|crew\{|[A-Z0-9_]{6,}/i.test(decoded)) {
      return `智能识别: Modular decode (mod ${mod})\n\n${JSON.stringify({ mod, decoded, note: `Each number taken mod ${mod}, mapped: 0-25→A-Z, 26-35→0-9, 36→_` }, null, 2)}`;
    }
  }
  return null;
};

export const extractSmartRawPayloadCandidate = (value: string) => {
  const fields = parseLooseCtfFields(value);
  const aliases = [
    'hex', 'base64', 'b64', 'base32', 'b32', 'binary', 'octal',
    'ciphertext', 'cipher', 'encoded', 'encoding', 'ct', 'data', 'output', 'result', 'answer',
  ];
  for (const alias of aliases) {
    const candidate = cleanLooseFieldValue(looseField(fields, [alias]));
    const compact = candidate.replace(/\s+/g, '');
    if (compact.length < 4) continue;
    if (/^(?:0x)?[0-9a-f]+$/i.test(compact) || /^[A-Za-z0-9+/_=-]+$/.test(compact)) return candidate;
  }
  return null;
};

export const trySmartStructuredDecode = async (value: string): Promise<string | null> => {
  const text = value.trim();
  if (!text) return null;
  try {
    if (/^data:[^,]*,/is.test(text)) {
      const output = await runSmartDecodeOperation('data-url', text, defaultParams);
      return `智能识别: Data URL\n\n${output}`;
    }
    if (/^Basic\s+[A-Za-z0-9+/=_-]+$/i.test(text)) {
      return `智能识别: HTTP Basic Authorization\n\n${await runSmartDecodeOperation('basic-auth', text, defaultParams)}`;
    }
    if (/^otpauth:\/\//i.test(text)) {
      return `智能识别: otpauth URI\n\n${await decodeOtpAuthUriCompat(text)}`;
    }
    if (/^(?:https?:\/\/)?(?:[\w-]+\.)?xn--[a-z0-9-]+(?:\.[\w.-]+)*\/?$/i.test(text)) {
      return `智能识别: Punycode / IDN\n\n${await runSmartDecodeOperation('punycode', text, defaultParams)}`;
    }
    // Query strings need a key=value assignment after '?'; bare '?' text (e.g. ROT47 ciphertext) is not a query
    if (/^(?:https?:\/\/)?[^\s?]+\?[^=]*=[^\s]+$/.test(text)) {
      return `智能识别: Query String\n\n${decodeQuery(text)}`;
    }
    if (/^[A-Za-z0-9+/_=-\s]+$/.test(text) && text.replace(/\s+/g, '').length >= 12) {
      try {
        const bytes = base64ToBytes(text);
        if (bytes.length >= 3 && bytes[0] === 0x1f && bytes[1] === 0x8b && bytes[2] === 0x08) {
          return `智能识别: Base64 GZip\n\n${await decompressText(text, 'gzip')}`;
        }
        if (bytes.length >= 1 && bytes[0] === 0x78) {
          // zlib header (78 01/9C/DA) — deflate with checksum
          return `智能识别: Base64 Zlib\n\n${await decompressText(text, 'deflate')}`;
        }
        try {
          // raw deflate has no magic bytes; a successful inflate is the signal
          if (bytes.length <= 65536) {
            return `智能识别: Base64 Deflate\n\n${await decompressText(text, 'deflate-raw')}`;
          }
        } catch {
          // Not a raw deflate container.
        }
      } catch {
        // Not a valid Base64-compressed container.
      }
    }
    if (/^[\w-]+\.[\w-]+\.[\w-]*$/i.test(text.replace(/^Bearer\s+/i, ''))) {
      return `智能识别: JWT\n\n${decodeJwt(text)}`;
    }
    if (/^[\w-]+\.[\w-]*\.[\w-]*\.[\w-]*\.[\w-]+$/i.test(text)) {
      return `智能识别: JWE Compact\n\n${parseJwkJwe(text)}`;
    }
    if (/^-----BEGIN [^-]+-----/m.test(text)) {
      try {
        return `智能识别: PEM / ASN.1\n\n${parseAsn1Der(text)}`;
      } catch {
        return `智能识别: PEM Block\n\n${decodePemBlock(text)}`;
      }
    }
    if (/^(?:ssh-|ecdsa-|sk-)/m.test(text) || /\s(?:ssh-|ecdsa-|sk-)[A-Za-z0-9@._-]*\s+[A-Za-z0-9+/=]+/.test(text)) {
      return `智能识别: OpenSSH Public Key\n\n${await parseSshPublicKey(text)}`;
    }
    if (/^\s*\{/.test(text) && /"(?:kty|keys|protected|ciphertext|recipients)"/.test(text)) {
      return `智能识别: JWK / JWE\n\n${parseJwkJwe(text)}`;
    }
    if (/^U2FsdGVkX1/i.test(text.replace(/\s+/g, ''))) {
      return `智能识别: OpenSSL Salted__ AES\n\n${JSON.stringify({
        format: 'OpenSSL enc Salted__',
        note: '识别到 OpenSSL EVP_BytesToKey-MD5 容器；请填写 passphrase 后使用 OpenSSL AES-256-CBC 解密。',
      }, null, 2)}`;
    }
    try {
      const parsed = parseFernetRaw(text);
      if (parsed.version === 0x80) {
        return `智能识别: Fernet\n\n${await decodeFernet(text, '')}`;
      }
    } catch {
      // Not a Fernet token.
    }
  } catch {
    // Keep the generic decoder available when a container is malformed.
  }
  return null;
};

// 评分族已下沉 codec/ngram.ts（T6 解环）：smartClassical 直连 ngram，本模块 re-export 兼容。
export { looksLikeResolvedSmartDecodeText } from './smartBase';

import { classicalNgramMean, classicalNgramMeanPenalized } from './ngram';

export {
  classicalDecodeBase64,
  classicalNgramMean,
  classicalNgramMeanPenalized,
  getClassicalNgramLut,
  injectClassicalNgramTable,
} from './ngram';

export const CLASSICAL_BREAK_TOTAL_BUDGET_MS = 15000;
// 评分参照：真密钥约 -320~-335（视文本长度），随机串约 -630
export const CLASSICAL_ADOPT_PER_LETTER = -560;
export const CLASSICAL_CONFIDENT_PER_LETTER = -530;
export const CLASSICAL_WEAK_ADOPT_PER_LETTER = -600;

// 确定性 PRNG：种子取自密文哈希，同一密文搜索路径一致（回归可复现、防 flaky）
export const classicalFnv1a = (text: string): number => {
  let hash = 0x811c9dc5;
  for (let index = 0; index < text.length; index += 1) {
    hash ^= text.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193);
  }
  return hash >>> 0;
};

export const classicalMulberry32 = (seed: number) => {
  let state = seed >>> 0;
  return (): number => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
};

export const classicalYieldToUi = (): Promise<void> => new Promise(resolve => { setTimeout(resolve, 0); });

export interface ClassicalAnnealResult { key: Int32Array; score: number; steps: number; }

// 通用混合搜索驱动：模拟退火（走平台期）+ 最陡上升精修 + 扰动/重启；mode='ils' 为纯迭代局部搜索
//（对换位类更优），mode='hybrid' 为退火+精修（对替换/分式类更优）。
// key = 若干段排列拼接（联合搜索如 [列排列, 方阵排列]）。
// 预算以评分数为主（同密文轨迹确定，回归可复现），墙钟只作慢机熔断防挂死。
export const classicalIterativeHillClimb = async (options: {
  segmentSizes: number[];
  score: (key: Int32Array) => number;
  stepBudget: number;
  wallDeadline: number;
  rng: () => number;
  mode?: 'hybrid' | 'ils' | 'hc';
  squareSize?: number;
  startKey?: Int32Array;
}): Promise<ClassicalAnnealResult | null> => {
  const { segmentSizes, score, stepBudget, wallDeadline, rng, mode = 'hybrid', squareSize, startKey } = options;
  const size = segmentSizes.reduce((sum, value) => sum + value, 0);
  if (size < 2) return null;
  const segments: Array<{ base: number; length: number }> = [];
  let running = 0;
  for (const segmentSize of segmentSizes) {
    segments.push({ base: running, length: segmentSize });
    running += segmentSize;
  }
  const current = new Int32Array(size);
  const resetRandom = () => {
    // 每段独立做 0..len-1 的身份排列：联合 key 的方阵段值域必须从 0 开始，
    // 否则 key[列数+格位] 的取值整体错位（这正是早期联合搜索不收敛的根因）
    for (const segment of segments) {
      for (let index = 0; index < segment.length; index += 1) current[segment.base + index] = index;
    }
    for (let swap = 0; swap < size * 2; swap += 1) {
      const segment = segments[Math.floor(rng() * segments.length)];
      if (segment.length < 2) continue;
      const first = segment.base + Math.floor(rng() * segment.length);
      const second = segment.base + Math.floor(rng() * segment.length);
      const held = current[first];
      current[first] = current[second];
      current[second] = held;
    }
  };
  const bestRef: { value: ClassicalAnnealResult | null } = { value: null };
  let bestScoreEver = -Infinity;
  let stepsLeft = stepBudget;
  let evalsSinceYield = 0;
  let currentScore = 0;
  const tryRecord = () => {
    if (currentScore > bestScoreEver) {
      bestScoreEver = currentScore;
      bestRef.value = { key: Int32Array.from(current), score: currentScore, steps: stepBudget - stepsLeft };
    }
  };
  const randomSwapScore = () => {
    const segment = segments[Math.floor(rng() * segments.length)];
    if (segment.length < 2) return;
    // 方阵段：行/列整体移动是 Playfair 类逃出平台期的关键路径
    if (squareSize && segment.length === squareSize && rng() < 0.4) {
      const side = Math.round(Math.sqrt(segment.length));
      const first = segment.base + Math.floor(rng() * segment.length);
      const second = segment.base + (rng() < 0.5
        ? Math.floor(first / side) * side + Math.floor(rng() * side)
        : Math.floor(rng() * side) * side + (first % side));
      const held = current[first];
      current[first] = current[second];
      current[second] = held;
      const cand = score(current);
      stepsLeft -= 1;
      const delta = cand - currentScore;
      if (delta >= 0 || rng() < Math.exp(delta / temperature)) currentScore = cand;
      else { current[second] = current[first]; current[first] = held; }
      return;
    }
    const first = segment.base + Math.floor(rng() * segment.length);
    const second = segment.base + Math.floor(rng() * segment.length);
    const held = current[first];
    current[first] = current[second];
    current[second] = held;
    const cand = score(current);
    stepsLeft -= 1;
    const delta = cand - currentScore;
    if (delta >= 0 || rng() < Math.exp(delta / temperature)) currentScore = cand;
    else { current[second] = current[first]; current[first] = held; }
  };
  let temperature = 4.5;
  const temperatureStart = 4.5;
  const temperatureMin = 0.16;
  let stalls = 0;
  let firstCycle = true;
  while (stepsLeft > 0 && Date.now() < wallDeadline) {
    // 首周期可从指定起点出发（两阶段攻击的阶段二继承阶段一结果）
    if (firstCycle && startKey) {
      firstCycle = false;
      current.set(startKey);
      currentScore = score(current);
      stepsLeft -= 1;
      temperature = temperatureStart;
      tryRecord();
      continue;
    }
    // 一半概率从当前最优重启（reheat 开发），一半完全随机（探索）
    if (mode === 'hybrid' && !firstCycle && bestRef.value && rng() < 0.45) {
      current.set(bestRef.value.key);
      currentScore = score(current);
      stepsLeft -= 1;
      temperature = temperatureStart;
    } else if (mode === 'ils' && stalls > 0 && stalls % 6 !== 0) {
      // 扰动逃逸：少量随机交换后在当前状态继续爬
      for (let k = 0; k < 2 + (rng() * 2 | 0); k += 1) {
        const segment = segments[Math.floor(rng() * segments.length)];
        if (segment.length < 2) continue;
        const i = segment.base + Math.floor(rng() * segment.length);
        const j = segment.base + Math.floor(rng() * segment.length);
        const h = current[i];
        current[i] = current[j];
        current[j] = h;
      }
      currentScore = score(current);
      stepsLeft -= 1;
    } else {
      resetRandom();
      currentScore = score(current);
      stepsLeft -= 1;
      temperature = temperatureStart;
    }
    // 退火相
    while (temperature > temperatureMin && stepsLeft > 0 && Date.now() < wallDeadline) {
      for (let step = 0; step < 512 && stepsLeft > 0; step += 1) {
        randomSwapScore();
        // 让出按评估数计（每 4096 次 ≈ 20-60ms），防大预算退火相长时间阻塞主线程
        if (evalsSinceYield >= 4096) { evalsSinceYield = 0; await classicalYieldToUi(); }
        else evalsSinceYield += 1;
      }
      temperature *= 0.955;
    }
    // 精修相：最陡上升直到局部最优；卡住时复合踢（双交换）跳出互锁平台
    let improved = true;
    let kickStalls = 0;
    while (improved && stepsLeft > 0 && Date.now() < wallDeadline) {
      improved = false;
      for (const segment of segments) {
        for (let first = segment.base; first < segment.base + segment.length && stepsLeft > 0; first += 1) {
          for (let second = first + 1; second < segment.base + segment.length && stepsLeft > 0; second += 1) {
            const held = current[first];
            current[first] = current[second];
            current[second] = held;
            const cand = score(current);
            stepsLeft -= 1;
            if (cand > currentScore) { currentScore = cand; improved = true; }
            else { current[second] = current[first]; current[first] = held; }
            if (evalsSinceYield >= 4096) { evalsSinceYield = 0; await classicalYieldToUi(); }
            else evalsSinceYield += 1;
          }
        }
      }
      if (!improved && stepsLeft > 24 && mode !== 'ils' && kickStalls < 3) {
        // 复合踢：两处同时交换（互锁错位需要一次动两格才能跃迁）
        kickStalls += 1;
        const segA = segments[Math.floor(rng() * segments.length)];
        const segB = segments[Math.floor(rng() * segments.length)];
        const a1 = segA.base + Math.floor(rng() * segA.length);
        const b1 = segA.base + Math.floor(rng() * segA.length);
        const a2 = segB.base + Math.floor(rng() * segB.length);
        const b2 = segB.base + Math.floor(rng() * segB.length);
        const h1 = current[a1]; current[a1] = current[b1]; current[b1] = h1;
        const h2 = current[a2]; current[a2] = current[b2]; current[b2] = h2;
        const cand = score(current);
        stepsLeft -= 2;
        if (cand > currentScore) { currentScore = cand; improved = true; }
        else {
          current[b2] = current[a2]; current[a2] = h2;
          current[b1] = current[a1]; current[a1] = h1;
        }
      } else if (improved) {
        kickStalls = 0;
      }
    }
    tryRecord();
    stalls += 1;
    firstCycle = false;
  }
  return bestRef.value;
};

export interface ClassicalKeylessHit {
  method: string;
  perLetter: number;
  decrypted: string;
  key: string;
  keyword2?: string;
  period?: string;
  keySquare: string;
  note: string;
}

// 逐字复刻 columnarDecode 的列长/短板逻辑：order[t] 列的数据在密文 offset 起的连续段，
// 回填到明文 row*k+columnIndex 位置；itemCount 为被换位元素总数。
export const classicalColumnarUnmix = (itemCount: number, order: Int32Array, visit: (sourceIndex: number, targetIndex: number) => void) => {
  const columns = order.length;
  const rows = Math.ceil(itemCount / columns);
  const shortColumns = (columns - (itemCount % columns)) % columns;
  let offset = 0;
  for (let slot = 0; slot < columns; slot += 1) {
    const columnIndex = order[slot];
    const length = rows - (columnIndex >= columns - shortColumns ? 1 : 0);
    for (let row = 0; row < length; row += 1) {
      const target = row * columns + columnIndex;
      if (target < itemCount) visit(offset + row, target);
    }
    offset += length;
  }
};

// 排列 → 关键词（字母互异）：columnOrder(关键词) 恰好还原该排列，供带密钥函数重解
export const classicalOrderKeyword = (order: Int32Array, size: number): string => {
  const chars = new Array<string>(size);
  for (let slot = 0; slot < size; slot += 1) chars[order[slot]] = String.fromCharCode(65 + slot);
  return chars.join('');
};

// 排列 → 密钥字符串：包含全部字符时 keyedSquare/keyedAlphabet/keyedTrifidAlphabet 去重后恰好是该排列
export const classicalSquareKey = (key: Int32Array, offset: number, size: number, alphabet: string): string => {
  let output = '';
  for (let index = 0; index < size; index += 1) output += alphabet[key[offset + index]];
  return output;
};

// 列换位：对每个列数 k 在 k! 空间退火（k ≤ 16），列读序即密钥。
// 输入保留全部字符（空格/标点也是被换位的元素），保证与带密钥函数的网格一致。
export const classicalAttackColumnar = async (text: string, codes: Uint8Array, wallDeadline: number, rng: () => number): Promise<ClassicalKeylessHit | null> => {
  const total = codes.length;
  const maxColumns = Math.min(16, Math.floor(total / 10));
  let bestHit: ClassicalKeylessHit | null = null;
  for (let columns = 2; columns <= maxColumns; columns += 1) {
    if (Date.now() >= wallDeadline) break;
    const plain = new Uint8Array(total);
    const result = await classicalIterativeHillClimb({
      segmentSizes: [columns],
      rng,
      stepBudget: 100000,
      wallDeadline,
      mode: 'ils',
      score: key => {
        classicalColumnarUnmix(total, key, (source, target) => { plain[target] = codes[source]; });
        return classicalNgramMean(plain);
      },
    });
    if (!result) continue;
    if (bestHit && result.score <= bestHit.perLetter) continue;
    const keyword = classicalOrderKeyword(result.key, columns);
    bestHit = {
      method: 'columnar',
      perLetter: result.score,
      decrypted: columnarDecode(text, keyword),
      key: keyword,
      keySquare: '',
      note: 'column width ' + columns + ' recovered by simulated annealing',
    };
    if (result.score >= CLASSICAL_CONFIDENT_PER_LETTER) break;
  }
  return bestHit;
};

// Playfair：25 字母方阵排列退火（I/J 合并，密文偶长）
export const classicalAttackPlayfair = async (text: string, codes: Uint8Array, wallDeadline: number, rng: () => number): Promise<ClassicalKeylessHit | null> => {
  const squareAlphabet = 'ABCDEFGHIKLMNOPQRSTUVWXYZ';
  const charToCell = new Int32Array(26);
  const plain = new Uint8Array(codes.length);
  const result = await classicalIterativeHillClimb({
    segmentSizes: [25],
    rng,
    stepBudget: 700000,
    wallDeadline,
    squareSize: 25,
    score: key => {
      // key[cell] = 方阵字母表位置；字母→格位查表必须与 J-less 字母表一致（ASCII 在 K..Z 错位一格）
      for (let index = 0; index < 25; index += 1) charToCell[squareAlphabet.charCodeAt(key[index]) - 65] = index;
      for (let pair = 0; pair + 1 < codes.length; pair += 2) {
        const a = charToCell[codes[pair]];
        const b = charToCell[codes[pair + 1]];
        const rowA = (a / 5) | 0;
        const colA = a % 5;
        const rowB = (b / 5) | 0;
        const colB = b % 5;
        if (rowA === rowB) {
          plain[pair] = squareAlphabet.charCodeAt(key[rowA * 5 + (colA + 4) % 5]) - 65;
          plain[pair + 1] = squareAlphabet.charCodeAt(key[rowB * 5 + (colB + 4) % 5]) - 65;
        } else if (colA === colB) {
          plain[pair] = squareAlphabet.charCodeAt(key[((rowA + 4) % 5) * 5 + colA]) - 65;
          plain[pair + 1] = squareAlphabet.charCodeAt(key[((rowB + 4) % 5) * 5 + colB]) - 65;
        } else {
          plain[pair] = squareAlphabet.charCodeAt(key[rowA * 5 + colB]) - 65;
          plain[pair + 1] = squareAlphabet.charCodeAt(key[rowB * 5 + colA]) - 65;
        }
      }
      return classicalNgramMean(plain);
    },
  });
  if (!result) return null;
  const keySquare = classicalSquareKey(result.key, 0, 25, squareAlphabet);
  return {
    method: 'playfair',
    perLetter: result.score,
    decrypted: playfairTransform(text, keySquare, true),
    key: keySquare,
    keySquare,
    note: '5x5 key square recovered by simulated annealing (I/J merged)',
  };
};

// Bifid：period 2..10 逐个短促搜参（burst），最优 period 再深挖（dive）
export const classicalAttackBifid = async (text: string, codes: Uint8Array, wallDeadline: number, rng: () => number): Promise<ClassicalKeylessHit | null> => {
  const total = codes.length;
  const maxPeriod = Math.min(10, Math.floor(total / 10));
  const plain = new Uint8Array(total);
  const inverse = new Int32Array(25);
  const squareAlphabetAscii = new Uint8Array(25);
  for (let index = 0; index < 25; index += 1) squareAlphabetAscii[index] = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'.charCodeAt(index) - 65;
  const coordBuf = new Int32Array(32);
  const buildScore = (key: Int32Array, period: number) => {
    for (let index = 0; index < 25; index += 1) inverse[key[index]] = index;
    let outIndex = 0;
    for (let offset = 0; offset < total; offset += period) {
      const blockLength = Math.min(period, total - offset);
      for (let index = 0; index < blockLength; index += 1) {
        const cell = inverse[codes[offset + index]];
        coordBuf[2 * index] = (cell / 5) | 0;
        coordBuf[2 * index + 1] = cell % 5;
      }
      for (let index = 0; index < blockLength; index += 1) {
        plain[outIndex + index] = squareAlphabetAscii[key[coordBuf[index] * 5 + coordBuf[blockLength + index]]];
      }
      outIndex += blockLength;
    }
    return classicalNgramMean(plain);
  };
  let bestPeriod = 0;
  let bestResult: ClassicalAnnealResult | null = null;
  for (let period = 2; period <= maxPeriod; period += 1) {
    if (Date.now() >= wallDeadline) break;
    const result = await classicalIterativeHillClimb({
      segmentSizes: [25],
      rng,
      stepBudget: 30000,
      wallDeadline,
      score: key => buildScore(key, period),
    });
    if (result && (!bestResult || result.score > bestResult.score)) {
      bestResult = result;
      bestPeriod = period;
    }
    if (bestResult && bestResult.score >= CLASSICAL_CONFIDENT_PER_LETTER) break;
  }
  if (!bestResult) return null;
  if (bestResult.score < CLASSICAL_CONFIDENT_PER_LETTER && Date.now() < wallDeadline) {
    const dive = await classicalIterativeHillClimb({
      segmentSizes: [25],
      rng,
      stepBudget: 300000,
      wallDeadline,
      score: key => buildScore(key, bestPeriod),
    });
    if (dive && dive.score > bestResult.score) bestResult = dive;
  }
  const keySquare = classicalSquareKey(bestResult.key, 0, 25, 'ABCDEFGHIKLMNOPQRSTUVWXYZ');
  return {
    method: 'bifid',
    perLetter: bestResult.score,
    decrypted: bifidTransform(text, keySquare, String(bestPeriod), true),
    key: keySquare,
    period: String(bestPeriod),
    keySquare,
    note: `period ${bestPeriod} and key square recovered by simulated annealing`,
  };
};

// Trifid：period 3..8 逐个短促搜参，最优 period 深挖（27 字符排列：A-Z + '.'）
export const classicalAttackTrifid = async (text: string, codes: Uint8Array, wallDeadline: number, rng: () => number): Promise<ClassicalKeylessHit | null> => {
  const total = codes.length;
  const maxPeriod = Math.min(8, Math.floor(total / 10));
  const plain = new Uint8Array(total);
  const inverse = new Int32Array(27);
  const coordBuf = new Int32Array(48);
  const buildScoreOn = (target: Uint8Array, key: Int32Array, period: number) => {
    for (let index = 0; index < 27; index += 1) inverse[key[index]] = index;
    let outIndex = 0;
    for (let offset = 0; offset < target.length; offset += period) {
      const blockLength = Math.min(period, target.length - offset);
      for (let index = 0; index < blockLength; index += 1) {
        const cell = inverse[target[offset + index]];
        coordBuf[3 * index] = (cell / 9) | 0;
        coordBuf[3 * index + 1] = ((cell % 9) / 3) | 0;
        coordBuf[3 * index + 2] = cell % 3;
      }
      for (let index = 0; index < blockLength; index += 1) {
        plain[outIndex + index] = key[coordBuf[index] * 9 + coordBuf[blockLength + index] * 3 + coordBuf[blockLength * 2 + index]];
      }
      outIndex += blockLength;
    }
    return classicalNgramMean(plain);
  };
  const buildScore = (key: Int32Array, period: number) => buildScoreOn(codes, key, period);
  let bestResult: (ClassicalAnnealResult & { period?: number }) | null = null;
  // 周期排名用 inline 单冷却（30k，无 reheat）：hybrid 循环的周期重启在长文本上爬不动
  const periodRanking: Array<{ period: number; result: ClassicalAnnealResult }> = [];
  {
    const burstCur = new Int32Array(27);
    const T0 = 4.5;
    const Tmin = 0.3;
    const burstSteps = 30000;
    const burstCool = Math.pow(Tmin / T0, 1024 / burstSteps);
    for (let period = 3; period <= maxPeriod; period += 1) {
      if (Date.now() >= wallDeadline) break;
      for (let index = 0; index < 27; index += 1) burstCur[index] = index;
      for (let s = 0; s < 54; s += 1) {
        const i = (rng() * 27) | 0;
        const j = (rng() * 27) | 0;
        const h = burstCur[i];
        burstCur[i] = burstCur[j];
        burstCur[j] = h;
      }
      let T = T0;
      let current = buildScore(burstCur, period);
      let bestScore = current;
      const bestKey = Int32Array.from(burstCur);
      let evals = 1;
      while (T > Tmin && evals < burstSteps && Date.now() < wallDeadline) {
        for (let step = 0; step < 512 && evals < burstSteps; step += 1) {
          const i = (rng() * 27) | 0;
          const j = (rng() * 27) | 0;
          const h = burstCur[i];
          burstCur[i] = burstCur[j];
          burstCur[j] = h;
          const cand = buildScore(burstCur, period);
          evals += 1;
          const delta = cand - current;
          if (delta >= 0 || rng() < Math.exp(delta / T)) {
            current = cand;
            if (current > bestScore) { bestScore = current; bestKey.set(burstCur); }
          } else {
            burstCur[j] = burstCur[i];
            burstCur[i] = h;
          }
        }
        T *= burstCool;
      }
      periodRanking.push({ period, result: { key: bestKey, score: bestScore, steps: evals } });
    }
  }
  if (!periodRanking.length) return null;
  periodRanking.sort((left, right) => right.result.score - left.result.score);
  console.error('RANK ' + periodRanking.map(p => p.period + ':' + p.result.score.toFixed(0)).join(' '));
  const topPeriods = periodRanking.slice(0, 2);
  // 单冷却 SA dive：对 burst 排名 top-3 的周期逐个做 150k 长冷却（20k burst 不足以可靠排周期）
  for (const candidate of topPeriods) {
    const bestPeriod = candidate.period;
    if (candidate.result.score >= CLASSICAL_CONFIDENT_PER_LETTER) break;
    if (Date.now() >= wallDeadline) break;
    for (let diveRound = 0; diveRound < 10; diveRound += 1) {
    if (bestResult && bestResult.score >= CLASSICAL_CONFIDENT_PER_LETTER) break;
    if (Date.now() >= wallDeadline) break;
    const cur = new Int32Array(27);
    // 采样加速：SA 爬升用 ≤400 字母子集（统计量充足），收敛后再在全文上精修
    const sampledCodes = codes.length > 400 ? codes.subarray(0, 400) : codes;
    const sampledBuild = (key: Int32Array) => buildScoreOn(sampledCodes, key, bestPeriod);
    const fullBuild = (key: Int32Array) => buildScoreOn(codes, key, bestPeriod);
    for (let index = 0; index < 27; index += 1) cur[index] = index;
    for (let s = 0; s < 54; s += 1) {
      const i = (rng() * 27) | 0;
      const j = (rng() * 27) | 0;
      const h = cur[i];
      cur[i] = cur[j];
      cur[j] = h;
    }
    const T0 = 4.5;
    const Tmin = 0.16;
    const totalSteps = 150000;
    const coolPerBatch = Math.pow(Tmin / T0, 1024 / totalSteps);
    let T = T0;
    let current = sampledBuild(cur);
    let bestDive = current;
    const bestDiveKey = Int32Array.from(cur);
    let evals = 1;
    let evalsSinceYield = 0;
    while (T > Tmin && evals < totalSteps && Date.now() < wallDeadline) {
      for (let step = 0; step < 512 && evals < totalSteps; step += 1) {
        const i = (rng() * 27) | 0;
        const j = (rng() * 27) | 0;
        const h = cur[i];
        cur[i] = cur[j];
        cur[j] = h;
        const cand = sampledBuild(cur);
        evals += 1;
        const delta = cand - current;
        if (delta >= 0 || rng() < Math.exp(delta / T)) {
          current = cand;
          if (current > bestDive) { bestDive = current; bestDiveKey.set(cur); }
        } else {
          cur[j] = cur[i];
          cur[i] = h;
        }
        if (evalsSinceYield >= 4096) { evalsSinceYield = 0; await classicalYieldToUi(); }
        else evalsSinceYield += 1;
      }
      T *= coolPerBatch;
    }
    // 收尾精修
    let improved = true;
    while (improved && Date.now() < wallDeadline) {
      improved = false;
      for (let i = 0; i < 27; i += 1) {
        for (let j = i + 1; j < 27; j += 1) {
          const h = cur[i];
          cur[i] = cur[j];
          cur[j] = h;
          const cand = fullBuild(cur);
          if (cand > current) { current = cand; improved = true; }
          else { cur[j] = cur[i]; cur[i] = h; }
        }
      }
    }
    cur.set(bestDiveKey);
    if (current > bestDive) { bestDive = current; bestDiveKey.set(cur); }
    const fullFinal = fullBuild(cur);
    if (fullFinal > bestDive) { bestDive = fullFinal; bestDiveKey.set(cur); }
    if (bestResult === null || bestDive > bestResult.score) {
      bestResult = { key: Int32Array.from(bestDiveKey), score: bestDive, steps: evals, period: bestPeriod };
    }
    } // diveRound
  }
  if (!bestResult) return null;
  const bestPeriod = bestResult.period ?? topPeriods[0].period;
  const keySquare = classicalSquareKey(bestResult.key, 0, 27, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ.');
  return {
    method: 'trifid',
    perLetter: bestResult.score,
    decrypted: trifidTransform(text, keySquare, String(bestPeriod), true),
    key: keySquare,
    period: String(bestPeriod),
    keySquare,
    note: `period ${bestPeriod} and 27-char alphabet recovered by simulated annealing`,
  };
};


export const classicalAttackAdfgx = async (
  text: string,
  symbols: Uint8Array,
  base: number,
  alphabet: string,
  variant: 'ADFGX' | 'ADFGVX',
  wallDeadline: number,
  rng: () => number,
): Promise<ClassicalKeylessHit | null> => {
  // symbols：每个符号 0..base-1；换位发生在符号流上，还原后相邻两符号组成一个方阵坐标
  const symbolCount = symbols.length;
  if (symbolCount % 2 !== 0) return null;
  const pairCount = symbolCount / 2;
  const minColumns = variant === 'ADFGVX' ? 5 : 5;
  const maxColumns = Math.min(variant === 'ADFGVX' ? 9 : 9, Math.floor(pairCount / 6));
  const unmixTarget = new Uint8Array(symbolCount);
  const plain = new Uint8Array(pairCount);
  // key 值是方阵字母表位置；ADFGX 的 J-less 表在 K..Z 与 ASCII 错位一格，转成 trigram 用的 ASCII 码
  const trigramCode = new Uint8Array(alphabet.length);
  for (let index = 0; index < alphabet.length; index += 1) {
    const charCode = alphabet.charCodeAt(index);
    trigramCode[index] = charCode >= 65 && charCode <= 90 ? charCode - 65 : charCode;
  }
  const buildScore = (key: Int32Array, columns: number) => {
    const order = key.subarray(0, columns);
    for (let slot = 0; slot < columns; slot += 1) {
      if (order[slot] >= columns) return -9999;
    }
    classicalColumnarUnmix(symbolCount, order, (source, target) => { unmixTarget[target] = symbols[source]; });
    for (let pair = 0; pair < pairCount; pair += 1) {
      plain[pair] = trigramCode[key[columns + unmixTarget[pair * 2] * base + unmixTarget[pair * 2 + 1]]];
    }
    return classicalNgramMeanPenalized(plain);
  };
  // 惩罚分：含数字/跳过位的解码按 -9/位计入，防稀疏碎片均值虚高（采纳与跨宽度比较用）
  const penalizedOf = () => classicalNgramMeanPenalized(plain);

  // 每宽度联合搜索（列序+方阵，混合驱动），跨宽度取惩罚分最优者再深度挖掘
  let bestColumns = 0;
  let bestPenalized = -Infinity;
  let bestJoint: Int32Array | null = null;
  let bestJointSearch = -Infinity;
  for (let columns = minColumns; columns <= maxColumns; columns += 1) {
    if (Date.now() >= wallDeadline) break;
    const result = await classicalIterativeHillClimb({
      segmentSizes: [columns, base * base],
      rng,
      stepBudget: 150000,
      wallDeadline,
      score: key => buildScore(key, columns),
    });
    if (!result) continue;
    buildScore(Int32Array.from(result.key), columns);   // 刷新 plain 到该宽度最优状态
    const pen = penalizedOf();
    if (pen > bestPenalized) {
      bestPenalized = pen;
      bestColumns = columns;
      bestJoint = Int32Array.from(result.key);
      bestJointSearch = result.score;
    }
    if (classicalBreakDebug.trace.length < 400) {
      classicalBreakDebug.trace.unshift('w' + columns + ': search=' + result.score.toFixed(1) + ' pen=' + pen.toFixed(1));
    }
    if (bestPenalized >= CLASSICAL_CONFIDENT_PER_LETTER) break;
  }
  if (!bestJoint) return null;

  // 深度挖掘：最优宽度上以阶段一结果为起点再跑 900k
  const startKey = new Int32Array(bestColumns + base * base);
  startKey.set(bestJoint.subarray(0, bestColumns));
  const dive = await classicalIterativeHillClimb({
    segmentSizes: [bestColumns, base * base],
    rng,
    stepBudget: 900000,
    wallDeadline,
    startKey,
    score: key => buildScore(key, bestColumns),
  });
  if (!dive) return null;
  buildScore(Int32Array.from(dive.key), bestColumns);   // 刷新 plain
  const divePen = penalizedOf();
  if (divePen > bestPenalized) {
    bestPenalized = divePen;
    bestJoint = Int32Array.from(dive.key);
    bestJointSearch = dive.score;
  }

  const keyword2 = classicalOrderKeyword(bestJoint.subarray(0, bestColumns), bestColumns);
  const keySquare = classicalSquareKey(bestJoint, bestColumns, base * base, alphabet);
  if (classicalBreakDebug.trace.length < 400) {
    classicalBreakDebug.trace.unshift('width=' + bestColumns + ' pen=' + bestPenalized.toFixed(1) + ' search=' + bestJointSearch.toFixed(1));
  }
  return {
    method: variant.toLowerCase(),
    perLetter: bestJointSearch,
    decrypted: adfgxTransform(text, keySquare, keyword2, true, variant),
    key: keySquare,
    keyword2,
    keySquare,
    note: 'transposition width ' + bestColumns + ' and ' + (base * base) + '-cell square recovered by two-stage simulated annealing',
  };
};


export const classicalBreakDebug = { hits: [] as Array<{ method: string; perLetter: number }>, trace: [] as string[], letters: 0, flags: {} as Record<string, unknown> };

export const ABCDEFGHIKLMNOPQRSTUVWXYZ_SQUARE = 'ABCDEFGHIKLMNOPQRSTUVWXYZ';

// 智能解码无命中时的古典密码破译入口：形状门 → 步数预算退火 → 置信采纳。
// 返回 null 表示统计上没有可置信的英文还原（短文本/垃圾输入允许失败）。
export const trySmartClassicalKeylessBreak = async (value: string): Promise<string | null> => {
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > 20000) return null;
  if (looksLikeResolvedSmartDecodeText(trimmed)) return null;
  const upper = trimmed.toUpperCase();
  const adfgxSymbolsOnly = upper.replace(/[^ADFGX]/g, '');
  const globalDeadline = Date.now() + CLASSICAL_BREAK_TOTAL_BUDGET_MS;
  const rng = classicalMulberry32(classicalFnv1a(trimmed));
  const hits: ClassicalKeylessHit[] = [];

  // ADFGVX（含 V 的六符号流）与 ADFGX（纯五符号流）形状互斥，独占预算
  const adfgvxClean = upper.replace(/[^ADFGVX]/g, '');
  if (adfgvxClean.length >= 240 && /V/.test(adfgvxClean) && adfgvxClean.length / Math.max(1, upper.replace(/\s/g, '').length) > 0.92) {
    const codes = new Uint8Array(adfgvxClean.length);
    for (let index = 0; index < adfgvxClean.length; index += 1) codes[index] = 'ADFGVX'.indexOf(adfgvxClean[index]);
    const hit = await classicalAttackAdfgx(adfgvxClean, codes, 6, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', 'ADFGVX', globalDeadline, rng);
    if (hit) hits.push(hit);
  } else if (adfgxSymbolsOnly.length >= 240 && adfgxSymbolsOnly.length / Math.max(1, upper.replace(/\s/g, '').length) > 0.92) {
    const codes = new Uint8Array(adfgxSymbolsOnly.length);
    for (let index = 0; index < adfgxSymbolsOnly.length; index += 1) codes[index] = 'ADFGX'.indexOf(adfgxSymbolsOnly[index]);
    const hit = await classicalAttackAdfgx(adfgxSymbolsOnly, codes, 5, 'ABCDEFGHIKLMNOPQRSTUVWXYZ', 'ADFGX', globalDeadline, rng);
    if (hit) hits.push(hit);
  } else {
    // 字母流密码：列换位（IC≈英文，与替换/分式形态区分度大）先行；Playfair/Bifid/Trifid
    // 的 ct IC 都在 0.048~0.052 一带、彼此难分，按顺序共享步数预算，命中置信即停。
    const playfairBifidText = upper.replace(/J/g, 'I').replace(/[^A-Z]/g, '');
    const trifidText = upper.replace(/[^A-Z.]/g, '');
    const columnarText = upper;
    const letterCount = playfairBifidText.length;
    if (letterCount < 80) return null;
    const freq = new Array(26).fill(0);
    for (const char of playfairBifidText) freq[char.charCodeAt(0) - 65] += 1;
    const indexOfCoincidence = freq.reduce((sum, count) => sum + count * (count - 1), 0) / (letterCount * (letterCount - 1));
    const runsColumnar = indexOfCoincidence >= 0.06 && columnarText.length >= 100;
    let hasDoublePair = false;
    for (let index = 0; index + 1 < playfairBifidText.length; index += 2) {
      if (playfairBifidText[index] === playfairBifidText[index + 1]) { hasDoublePair = true; break; }
    }
    const runsPlayfair = letterCount >= 160 && playfairBifidText.length % 2 === 0 && !hasDoublePair;
    const runsBifid = letterCount >= 140;
    const runsTrifid = trifidText.length >= 140;

    classicalBreakDebug.letters = letterCount;
    classicalBreakDebug.flags = { runsColumnar, runsPlayfair, runsBifid, runsTrifid, ic: Number(indexOfCoincidence.toFixed(4)) };
    const plan: Array<{ method: 'columnar' | 'playfair' | 'bifid' | 'trifid'; eligible: boolean }> = [
      { method: 'columnar', eligible: runsColumnar },
      { method: 'playfair', eligible: runsPlayfair },
      { method: 'trifid', eligible: runsTrifid },
      { method: 'bifid', eligible: runsBifid },
    ];
    for (const step of plan) {
      if (Date.now() >= globalDeadline) break;
      if (!step.eligible) continue;
      // 每攻击独立墙上限（全局预算的 55%）：防前序攻击（如 trifid 复合收尾）吃光共享预算
      const stepDeadline = Math.min(globalDeadline, Date.now() + 9000);
      if (step.method === 'columnar') {
        const codes = new Uint8Array(columnarText.length);
        for (let index = 0; index < columnarText.length; index += 1) {
          const char = columnarText[index];
          codes[index] = char >= 'A' && char <= 'Z' ? char.charCodeAt(0) - 65 : 26;
        }
        const hit = await classicalAttackColumnar(columnarText, codes, stepDeadline, rng);
        if (hit) hits.push(hit);
      } else if (step.method === 'playfair') {
        const codes = new Uint8Array(playfairBifidText.length);
        for (let index = 0; index < playfairBifidText.length; index += 1) codes[index] = playfairBifidText.charCodeAt(index) - 65;
        const hit = await classicalAttackPlayfair(playfairBifidText, codes, stepDeadline, rng);
        if (hit) hits.push(hit);
      } else if (step.method === 'bifid') {
        const codes = new Uint8Array(playfairBifidText.length);
        for (let index = 0; index < playfairBifidText.length; index += 1) {
          codes[index] = ABCDEFGHIKLMNOPQRSTUVWXYZ_SQUARE.indexOf(playfairBifidText[index]);
        }
        const hit = await classicalAttackBifid(playfairBifidText, codes, stepDeadline, rng);
        if (hit) hits.push(hit);
      } else {
        const codes = new Uint8Array(trifidText.length);
        for (let index = 0; index < trifidText.length; index += 1) {
          codes[index] = trifidText[index] === '.' ? 26 : trifidText.charCodeAt(index) - 65;
        }
        const hit = await classicalAttackTrifid(trifidText, codes, stepDeadline, rng);
        if (hit) hits.push(hit);
      }
      if (hits.some(entry => entry.perLetter >= CLASSICAL_CONFIDENT_PER_LETTER)) break;
    }
  }

  classicalBreakDebug.hits = hits.map(entry => ({ method: entry.method, perLetter: Math.round(entry.perLetter) }));
  hits.sort((left, right) => right.perLetter - left.perLetter);
  const best = hits[0];
  if (!best) return null;
  const decLetters = best.decrypted.replace(/[^A-Za-z]/g, '').toUpperCase();
  const flagish = /(?:FLAG|CTF|PICOCTF|HTB|THM)[A-Z0-9]{4,}/.test(decLetters)
    || /(?:flag|ctf|picoctf|htb|thm|crypto|secret|key)\{[^}]{3,}\}/i.test(best.decrypted);
  // 采纳用密度惩罚评分：稀疏碎片解码（大量数字/杂位）的 quad 均值会虚高，惩罚后才能与真英文区分
  const adoptCodes = new Uint8Array(best.decrypted.length);
  for (let index = 0; index < best.decrypted.length; index += 1) {
    const ch = best.decrypted[index].toUpperCase();
    adoptCodes[index] = ch >= 'A' && ch <= 'Z' ? ch.charCodeAt(0) - 65 : 99;
  }
  const penalizedScore = classicalNgramMeanPenalized(adoptCodes);
  classicalBreakDebug.trace.unshift('adopt: pen=' + penalizedScore.toFixed(1) + ' flagish=' + flagish);
  const adopted = penalizedScore >= CLASSICAL_ADOPT_PER_LETTER
    || (flagish && penalizedScore >= CLASSICAL_WEAK_ADOPT_PER_LETTER);
  if (!adopted) return null;
  const summary: Record<string, unknown> = {
    method: best.method,
    score: Number(best.perLetter.toFixed(1)),
  };
  if (best.period) summary.period = best.period;
  summary.key = best.key;
  if (best.keyword2) summary.keyword2 = best.keyword2;
  summary.decrypted = best.decrypted.slice(0, 4000);
  summary.note = `${best.note}. Verify against the keyed tool if the result reads partially.`;
  return `智能识别: ${best.method} 无密钥破译 (模拟退火)\n\n${JSON.stringify(summary, null, 2)}`;
};

// ---- 现代密码攻击面扩展：RSA-OAEP（WebCrypto）/ Coppersmith stereotyped 简化版 / PGP 报文解析（只读）/ CBC padding oracle & bit-flip 演示器 ----
// 安全边界：OAEP 走 WebCrypto 原生实现；Coppersmith 仅"整数开方 + 已知前缀短尾枚举"简化版（完整格基规约 LLL 未实现，见 note）；
// PGP 解析为只读结构展示，不解密任何载荷；CBC demo 为纯本地教学模拟（oracle 在本地，无网络探测）。
