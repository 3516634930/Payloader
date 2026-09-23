// CODEC-IMPORTS
import { base64ToBytes, bytesToBase64, bytesToHex, hexToBytes } from './bases';
import { utf8Decoder, utf8Encoder } from './alphabets';
import { cleanSymmetricFieldValue, extractNamedPythonCall, inferSymmetricCryptoFromText, normalizeLooseFieldName, parseOptionalHexOrUtf8Bytes, parsePythonAssignmentFields, parsePythonCiphertextBytes, parseSymmetricFields } from './crypto';
import { parseFunctionLikeCall, parsePythonBytesLiteral } from './rsa';
import { guessRepeatingKey, printableScore } from './classical';
import { caesar } from './textEncodings';
import type { OperationId } from './types';
// CODEC-IMPORTS-END
export const encodeQuery = (value: string) => {
  const parsed = JSON.parse(value);
  const params = new URLSearchParams();
  Object.entries(parsed).forEach(([key, entry]) => {
    if (Array.isArray(entry)) entry.forEach(item => params.append(key, String(item)));
    else if (entry != null) params.set(key, String(entry));
  });
  return params.toString();
};

export const decodeQuery = (value: string) => {
  const clean = value.trim().replace(/^[^?]*\?/, '');
  const params = new URLSearchParams(clean);
  const result: Record<string, string | string[]> = {};
  params.forEach((entry, key) => {
    if (Object.prototype.hasOwnProperty.call(result, key)) {
      const current = result[key];
      result[key] = Array.isArray(current) ? [...current, entry] : [current, entry];
    } else {
      result[key] = entry;
    }
  });
  return JSON.stringify(result, null, 2);
};

export const streamToBytes = async (stream: ReadableStream<Uint8Array>) => {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    if (value) {
      chunks.push(value);
      size += value.length;
    }
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  return bytes;
};

export const compressText = async (value: string, format: CompressionFormat) => {
  const CompressionStreamCtor = globalThis.CompressionStream;
  if (!CompressionStreamCtor) throw new Error('当前运行环境不支持 CompressionStream');
  const stream = new Blob([value]).stream().pipeThrough(new CompressionStreamCtor(format));
  return bytesToBase64(await streamToBytes(stream));
};

export const decompressText = async (value: string, format: CompressionFormat) => {
  const DecompressionStreamCtor = globalThis.DecompressionStream;
  if (!DecompressionStreamCtor) throw new Error('当前运行环境不支持 DecompressionStream');
  const stream = new Blob([base64ToBytes(value)]).stream().pipeThrough(new DecompressionStreamCtor(format));
  return utf8Decoder.decode(await streamToBytes(stream));
};

export const tryDecode = (name: string, input: string, decoder: (value: string) => string) => {
  try {
    const output = decoder(input);
    if (output && output !== input) return { name, output };
  } catch {
    return null;
  }
  return null;
};

export const smartSymmetricOperationIds = new Set<OperationId>([
  'aes-gcm',
  'aes-cbc-raw',
  'aes-ctr-raw',
  'aes-ecb',
  'aes-cfb',
  'aes-ofb',
  'aes-gcm-siv',
  'aes-siv',
  'chacha20-orig',
  'chacha20',
  'xchacha20',
  'salsa20',
  'xsalsa20',
  'chacha20-poly1305',
  'xchacha20-poly1305',
  'xsalsa20-poly1305',
  'sm4',
  'des',
  'triple-des',
  'blowfish',
  'rabbit',
]);

// 解码执行器注入点（T6 解环）：smartBase 不再 import transform 全引擎；由 transform 模块
// 加载时注入实现，smartDecode/smartHelpers 经 runSmartDecodeOperation 间接调用。未注入时
// （如脱离 transform 单测 smartBase）解码尝试按不可用处理，返回 null 与原失败路径一致。
export type SmartDecodeExecutor = (operationId: string, input: string, params: Record<string, string>) => Promise<string>;
let smartDecodeExecutor: SmartDecodeExecutor | null = null;
export const setSmartDecodeExecutor = (executor: SmartDecodeExecutor): void => {
  smartDecodeExecutor = executor;
};
export const runSmartDecodeOperation = async (operationId: string, input: string, params: Record<string, string>): Promise<string> => {
  if (!smartDecodeExecutor) throw new Error('smart decode executor 未注入');
  return smartDecodeExecutor(operationId, input, params);
};

export const trySmartSymmetricDecrypt = async (value: string): Promise<string | null> => {
  const inference = inferSymmetricCryptoFromText(value);
  if (!inference.operationId || !smartSymmetricOperationIds.has(inference.operationId)) return null;
  if (inference.confidence < 8 || !inference.fields.key || (!inference.fields.ciphertext && !inference.fields.sealed)) return null;
  try {
    const output: string = await runSmartDecodeOperation(inference.operationId, inference.input, inference.params);
    return `智能识别: ${inference.operationId} 可直接解密\n\n${output}\n\ninference: ${JSON.stringify(inference.notes)}`;
  } catch {
    return null;
  }
};

export const canSmartSymmetricDecryptFromText = (value: string) => {
  const inference = inferSymmetricCryptoFromText(value);
  return Boolean(
    inference.operationId
    && smartSymmetricOperationIds.has(inference.operationId)
    && inference.confidence >= 8
    && inference.fields.key
    && (inference.fields.ciphertext || inference.fields.sealed),
  );
};

export const smartCiphertextSource = (value: string) => {
  const fields = parseSymmetricFields(value);
  return {
    fields,
    source: fields.ciphertext || fields.sealed || value.trim(),
    labelled: Boolean(fields.ciphertext || fields.sealed),
  };
};

export const parseSmartCipherBytes = (source: string, labelled = false) => {
  const text = cleanSymmetricFieldValue(source);
  // Python bytes literal: b'\x1b\x37...' or b"..."
  const pyBytesMatch = text.trim().match(/^(?:br|rb|b)\s*(['"])([\s\S]*)\1$/i);
  if (pyBytesMatch) {
    try { return { bytes: parsePythonBytesLiteral(text.trim()), encoding: 'python-bytes' }; } catch { /* fall through */ }
  }
  // JSON integer array: [91, 241, 101, ...] — common in CTF Python challenge scripts
  const arrayMatch = text.trim().match(/^\[[\d,\s]+\]$/);
  if (arrayMatch) {
    try {
      const nums = JSON.parse(text.trim()) as number[];
      if (Array.isArray(nums) && nums.every(n => Number.isInteger(n) && n >= 0 && n <= 255)) {
        return { bytes: new Uint8Array(nums), encoding: 'decimal-array' };
      }
    } catch { /* fall through */ }
  }
  const compactHex = text.replace(/^0x/i, '').replace(/[\s:_-]/g, '');
  if (compactHex.length >= 8 && compactHex.length % 2 === 0 && /^[0-9a-f]+$/i.test(compactHex)) {
    return { bytes: hexToBytes(compactHex), encoding: 'hex' };
  }
  if (labelled && /^[A-Za-z0-9+/_=-]{8,}$/.test(text.replace(/\s+/g, ''))) {
    try {
      return { bytes: base64ToBytes(text), encoding: 'base64/base64url' };
    } catch {
      return null;
    }
  }
  return null;
};

export const printableRatio = (bytes: Uint8Array) => {
  if (!bytes.length) return 0;
  let printable = 0;
  for (const byte of bytes) {
    if ((byte >= 32 && byte <= 126) || byte === 9 || byte === 10 || byte === 13) printable += 1;
  }
  return printable / bytes.length;
};

export const smartTextScore = (text: string) => {
  let score = 0;
  if (/flag\{|ctf\{|picoctf\{|htb\{|key\{|crypto\{|thm\{|ductf\{|corctf\{|dice\{|wctf\{|utflag\{|sekai\{|actf\{|seccon\{|ritsec\{|lactf\{|nahamcon\{|hsctf\{|justctf\{|b01lers\{|wanictf\{|jerseyctf\{/i.test(text)) score += 50;
  if (/\b(the|and|that|you|this|with|from|have|not|for)\b/i.test(text)) score += 10;
  if (/[{}_-]/.test(text)) score += 2;
  const letters = text.replace(/[^a-z]/gi, '');
  if (letters.length >= Math.max(4, text.length * 0.45)) score += 4;
  score += printableRatio(utf8Encoder.encode(text)) * 10;
  return score;
};

export const SMART_DECODE_ADOPT_FLOOR = 34;

// Quality score (0-100) for a smart-decode candidate output: how likely it is real plaintext.
// Dimensions: readable-char ratio, English similarity, CTF flag bonus, distinctness from the input.
export const smartDecodeOutputScore = (text: string, input?: string) => {
  if (!text) return 0;
  const normalize = (v: string) => v.replace(/\s+/g, '');
  if (input && normalize(text) === normalize(input)) return 0;
  // Sample long outputs — a representative prefix is enough for quality estimation
  const sample = text.length > 20000 ? text.slice(0, 20000) : text;
  const junkAllowed = '0123456789{}[]()_+=.,:;!?\'"-/@&#%$*;\\ \t\n\r';
  let bad = 0;
  let letters = 0;
  let vowels = 0;
  let junk = 0;
  let nonAscii = 0;
  const total = sample.length;
  for (let index = 0; index < total; index += 1) {
    const code = sample.charCodeAt(index);
    if (code >= 0xD800 && code <= 0xDBFF) {
      // High surrogate: a following low surrogate completes a valid pair (emoji, ext. CJK) — count once as text
      const next = index + 1 < total ? sample.charCodeAt(index + 1) : 0;
      if (next >= 0xDC00 && next <= 0xDFFF) {
        letters += 1;
        nonAscii += 1;
        index += 1;
      } else {
        bad += 1;
      }
      continue;
    }
    if (code < 32 || code === 127 || code === 0xFFFD || (code >= 0x80 && code <= 0x9F) || (code >= 0xDC00 && code <= 0xDFFF)) {
      bad += 1;
    } else if ((code >= 0x41 && code <= 0x5A) || (code >= 0x61 && code <= 0x7A)) {
      letters += 1;
      const lower = code | 0x20;
      if (lower === 97 || lower === 101 || lower === 105 || lower === 111 || lower === 117) vowels += 1;
    } else if (code >= 0x80) {
      // Non-ASCII letters (CJK, accented scripts) read as real text, never junk
      letters += 1;
      nonAscii += 1;
    } else if (!junkAllowed.includes(String.fromCharCode(code))) {
      junk += 1;
    }
  }
  const readable = 1 - bad / total;
  let score = readable * 40;
  if (bad / total > 0.1) score -= 25;
  score -= Math.min(24, junk * 4);
  const letterRatio = letters / total;
  if (letterRatio >= 0.45) score += Math.min(12, 6 + (letterRatio - 0.45) * 24);
  if (letters >= 3 && letterRatio >= 0.3) {
    const vowelRatio = vowels / letters;
    if (vowelRatio >= 0.15 && vowelRatio <= 0.6) score += 6;
  }
  const wordHits = text.match(/\b(?:flag|the|and|that|this|you|with|from|have|not|for|key|secret|password|admin|test|hello|world|message|value|data|code|name|user|error|success|welcome|http|https)\b/gi);
  if (wordHits) score += Math.min(18, wordHits.length * 6);
  if (/flag\{|ctf\{|picoctf\{|htb\{|thm\{|key\{|crypto\{|dice\{|wctf\{|utflag\{|ductf\{|corctf\{|sekai\{|actf\{|seccon\{|ritsec\{|lactf\{|crew\{|nahamcon\{|hsctf\{|justctf\{|b01lers\{|wanictf\{|jerseyctf\{|mapna\{/i.test(text)) score += 50;
  else if (/\b[a-z]{2,12}\{[A-Za-z0-9_!@#$%^&*.-]{4,}\}/i.test(text)) score += 40;
  if (nonAscii * 2 >= total && total >= 4) score += 25; // non-Latin real text (CJK etc.) never trips the ASCII resolved-text checks
  if (looksLikeResolvedSmartDecodeText(text)) score += 25;
  if (input) {
    const signature = (v: string) => [
      /[a-z]/.test(v),
      /[A-Z]/.test(v),
      /\d/.test(v),
      /\s/.test(v),
      /[^A-Za-z0-9\s]/.test(v),
    ].map(Boolean).join('');
    if (signature(text) !== signature(input)) score += 4;
  }
  return Math.max(0, Math.min(100, Math.round(score)));
};

export const inferPythonXorSnippet = (value: string) => {
  if (!/\bxor\s*\(/i.test(value)) return null;
  const assignmentFields = parsePythonAssignmentFields(value);
  const xorCallText = extractNamedPythonCall(value, 'xor(');
  const xorCall = xorCallText ? parseFunctionLikeCall(xorCallText) : null;
  if (!xorCall || normalizeLooseFieldName(xorCall.name) !== 'xor' || xorCall.args.length < 2) return null;

  const leftBytes = parsePythonCiphertextBytes(xorCall.args[0], assignmentFields);
  const rightBytes = parsePythonCiphertextBytes(xorCall.args[1], assignmentFields);
  if (!leftBytes || !rightBytes || !rightBytes.length) return null;

  return {
    ciphertextHex: bytesToHex(leftBytes),
    keyHex: bytesToHex(rightBytes),
    notes: ['python snippet detected: xor(...)', 'parsed ciphertext/key from xor(...) style script'],
  };
};

export const xorWithKeyBytes = (bytes: Uint8Array, key: Uint8Array) => {
  if (!key.length) throw new Error('XOR key cannot be empty');
  return bytes.map((byte, index) => byte ^ key[index % key.length]);
};

export const trySmartXorDecrypt = (value: string) => {
  const pythonSnippet = inferPythonXorSnippet(value);
  if (pythonSnippet) {
    try {
      const ciphertext = hexToBytes(pythonSnippet.ciphertextHex);
      const key = hexToBytes(pythonSnippet.keyHex);
      const decoded = xorWithKeyBytes(ciphertext, key);
      const text = utf8Decoder.decode(decoded).replace(/\p{Cc}/gu, '.');
      return `智能识别: XOR 脚本片段\n\n${JSON.stringify({
        method: 'python-xor-call',
        ciphertextHex: pythonSnippet.ciphertextHex,
        keyHex: pythonSnippet.keyHex,
        plaintext: text,
        plaintextHex: bytesToHex(decoded),
        notes: pythonSnippet.notes,
      }, null, 2)}`;
    } catch {
      // Fall through to heuristic XOR recovery.
    }
  }

  const lowered = value.toLowerCase();
  // Binary/octal/decimal-code digit-group payloads are owned by the Binary/Octal/ASCII-code decoders, not XOR-on-hex
  const rawTrimmed = value.trim();
  if (/^[01\s,;|]+$/.test(rawTrimmed) && (rawTrimmed.match(/[01]{8}/g) || []).length > 0) return null;
  const rawTokens = rawTrimmed.split(/[\s,;|]+/);
  if (rawTokens.length >= 4 && rawTokens.every(token => /^0[0-7]{1,3}$/.test(token))) return null;
  if (rawTokens.length >= 4 && rawTokens.every(token => /^\d{1,3}$/.test(token))) return null;
  const { fields, source, labelled } = smartCiphertextSource(value);
  // Also try to extract decimal integer arrays directly from the text (e.g. enc_flag = [91, 241, ...])
  const decimalArrayMatch = value.match(/(?:enc(?:rypted)?[_\s]?(?:flag|msg|message|data|text|ct|cipher|output)?\s*[:=]\s*)?\[(\s*\d+(?:\s*,\s*\d+)+\s*)\]/i)
    || value.match(/\b(?:ciphertext|cipher|ct|enc|output|encrypted)\s*[:=]\s*\[(\s*\d+(?:\s*,\s*\d+)+\s*)\]/i);
  const decimalArrayBytes = decimalArrayMatch ? (() => {
    try {
      const nums = decimalArrayMatch[1].split(',').map(s => Number(s.trim()));
      if (nums.every(n => Number.isInteger(n) && n >= 0 && n <= 255)) return new Uint8Array(nums);
    } catch { /* ignore */ }
    return null;
  })() : null;
  const parsed = parseSmartCipherBytes(decimalArrayBytes ? `[${Array.from(decimalArrayBytes).join(',')}]` : source, labelled || /\bxor\b/.test(lowered) || Boolean(decimalArrayBytes));
  if (!parsed) return null;
  const bytes = parsed.bytes;
  if (!bytes || bytes.length < 4) return null;
  // Interleaved zero bytes are the UTF-16 signature, not XOR ciphertext
  if (bytes.length >= 4 && (bytes.filter((_, index) => index % 2 === 1).every(byte => byte === 0)
    || bytes.filter((_, index) => index % 2 === 0).every(byte => byte === 0))) return null;
  const candidates: Array<{ method: string; key: string; score: number; text: string }> = [];

  if (/\bxor\b/.test(lowered) && fields.key) {
    const key = parseOptionalHexOrUtf8Bytes(fields.key).bytes;
    const decoded = xorWithKeyBytes(bytes, key);
    candidates.push({
      method: 'explicit-key',
      key: bytesToHex(key),
      score: printableScore(decoded) + 20,
      text: utf8Decoder.decode(decoded).replace(/\p{Cc}/gu, '.'),
    });
  }

  for (let key = 1; key < 256; key += 1) {
    const decoded = bytes.map(byte => byte ^ key);
    const text = utf8Decoder.decode(decoded).replace(/\p{Cc}/gu, '.');
    candidates.push({
      method: 'single-byte',
      key: `0x${key.toString(16).padStart(2, '0')}`,
      score: printableScore(decoded),
      text,
    });
  }

  const knownPlaintexts = [
    fields.knownPlaintext,
    fields.plaintext,
    'flag{',
    'FLAG{',
    'ctf{',
    'CTF{',
    'picoCTF{',
    'THM{',
    'HTB{',
    'DUCTF{',
    'corctf{',
    'dice{',
    'wctf{',
    'utflag{',
    'PCTF{',
    'uiuctf{',
    'sekai{',
    'lactf{',
    'crypto{',
    'nahamcon{',
    'hsctf{',
    'sdctf{',
    'dctf{',
    'bcactf{',
    'pbctf{',
    'uoftctf{',
    'openctf{',
    'justctf{',
    'b01lers{',
    'wanictf{',
    'jerseyctf{',
    'squ1rrel{',
    'nitro{',
    'mapna{',
    'cakectf{',
    'dragonctf{',
  ].filter((entry): entry is string => Boolean(entry));
  const knownCandidates = knownPlaintexts.map(known => {
    const plain = utf8Encoder.encode(known);
    const key = plain.map((byte, index) => byte ^ bytes[index]);
    const repeating = guessRepeatingKey(key);
    const keyBytes = repeating ? key.slice(0, repeating.length) : key;
    const decoded = xorWithKeyBytes(bytes, keyBytes);
    return {
      method: 'known-plaintext-prefix',
      knownPlaintext: known,
      keyHexPrefix: bytesToHex(key),
      repeatingKeyGuess: repeating,
      preview: utf8Decoder.decode(decoded.slice(0, 160)).replace(/\p{Cc}/gu, '.'),
      score: printableScore(decoded),
    };
  });

  const ranked = candidates
    .sort((left, right) => right.score - left.score)
    .slice(0, 8);
  const best = ranked[0];
  const second = ranked[1];
  const confident = Boolean(best && (
    /\bxor\b/.test(lowered)
    || /flag\{|ctf\{|picoctf\{|htb\{|thm\{|ductf\{|corctf\{|dice\{|actf\{|seccon\{|ritsec\{|crypto\{|lactf\{|crew\{|nahamcon\{|hsctf\{|sdctf\{|dctf\{|bcactf\{|pbctf\{|uoftctf\{|justctf\{|b01lers\{|wanictf\{|jerseyctf\{|squ1rrel\{|mapna\{|cakectf\{|dragonctf\{/i.test(best.text)
    || (printableRatio(utf8Encoder.encode(best.text)) > 0.9 && (!second || best.score - second.score > 6))
  ));
  if (!confident && !knownCandidates.some(item => /flag\{|ctf\{|picoctf\{|htb\{|thm\{|ductf\{|actf\{|seccon\{|ritsec\{|crypto\{|lactf\{|crew\{|nahamcon\{|hsctf\{|justctf\{|b01lers\{|wanictf\{|jerseyctf\{/i.test(item.preview))) return null;
  return `智能识别: XOR 候选\n\n${JSON.stringify({
    inputEncoding: parsed.encoding,
    ciphertextBytes: bytes.length,
    best,
    ranked,
    knownPlaintextCandidates: knownCandidates,
    repeatingKeyAnalysis: (() => {
      if (bytes.length < 16) return null;
      // IC-based key length detection for repeating-key XOR (Kasiski/IC method adapted for XOR)
      const maxKeyLen = Math.min(32, Math.floor(bytes.length / 3));
      const results: Array<{ keyLength: number; key: string; avgIC: number; preview: string; printable: number }> = [];
      for (let kl = 2; kl <= maxKeyLen; kl++) {
        const cols = Array.from({ length: kl }, (_, i) =>
          Array.from(bytes).filter((_, j) => j % kl === i)
        );
        const avgIC = cols.reduce((sum, col) => {
          const freq = new Array(256).fill(0);
          col.forEach(b => freq[b]++);
          const n = col.length;
          return sum + (n < 2 ? 0 : freq.reduce((s, f) => s + f * (f - 1), 0) / (n * (n - 1)));
        }, 0) / kl;
        // Recover key byte for each column by max score
        const keyBytes = cols.map(col => {
          let best = 0;
          let bestScore = -1;
          for (let k = 0; k < 256; k++) {
            const dec = new Uint8Array(col.map(b => b ^ k));
            const s = printableScore(dec);
            if (s > bestScore) { bestScore = s; best = k; }
          }
          return best;
        });
        const key = new Uint8Array(keyBytes);
        const decoded = xorWithKeyBytes(bytes, key);
        const pRatio = printableRatio(decoded);
        results.push({ keyLength: kl, key: bytesToHex(key), avgIC: Number(avgIC.toFixed(4)), preview: utf8Decoder.decode(decoded.slice(0, 80)).replace(/\p{Cc}/gu, '.'), printable: Number((pRatio * 100).toFixed(1)) });
      }
      results.sort((a, b) => b.printable - a.printable || b.avgIC - a.avgIC);
      const top = results[0];
      return { best: top, candidates: results.slice(0, 6) };
    })(),
    // Chained: try ROT/Caesar on the best XOR plaintext (e.g. Advent of CTF XOR+ROT pattern)
    chainedClassic: (() => {
      if (!best) return null;
      const txt = best.text;
      const letters = txt.replace(/[^a-z]/gi, '');
      if (letters.length < 6 || letters.length / Math.max(1, txt.length) < 0.25) return null;
      const origScore = smartTextScore(txt);
      const rotCandidates = Array.from({ length: 25 }, (_, i) => {
        const d = caesar(txt, i + 1); return { shift: i + 1, text: d, score: smartTextScore(d) };
      }).sort((a, b) => b.score - a.score);
      const bestRot = rotCandidates[0];
      if (/\b[a-z]{2,12}\{[^}]{4,}\}/i.test(bestRot.text) || bestRot.score - origScore > 8)
        return { method: `ROT${bestRot.shift}`, text: bestRot.text, score: bestRot.score };
      return null;
    })(),
    note: 'Single-byte XOR is auto-ranked. Repeating-key XOR uses IC analysis (key lengths 2-32) — check repeatingKeyAnalysis for best candidates.',
  }, null, 2)}`;
};

// 自 smartHelpers 下沉（T6 解环）：纯评分判断，依赖的 printableRatio/smartTextScore 均在本模块。
export const looksLikeResolvedSmartDecodeText = (value: string) => {
  const text = value.trim();
  if (!text) return false;
  if (/flag\{|ctf\{|picoctf\{|htb\{|thm\{|key\{|crypto\{|dice\{|wctf\{|utflag\{|hsctf\{|sdctf\{|dctf\{|nahamcon\{|ductf\{|bcactf\{|uiuctf\{|pbctf\{|corctf\{|sekai\{|idek\{|bi0s\{|glacierctf\{|rgbctf\{|zer0pts\{|watevr\{|darkctf\{|secureflag\{|actf\{|seccon\{|sunshine\{|ritsec\{|magpie\{|crew\{|squ1rrel\{|nitro\{|mapna\{|cakectf\{|dragonctf\{|lactf\{|wanictf\{|jerseyctf\{|b01lers\{|sunshinectf\{/i.test(text)) return true;
  // Generic CTF flag: word{ ... } but exclude common encoding/intermediate prefixes
  if (/\b[a-z]{2,12}\{[A-Za-z0-9_!@#$%^&*.-]{4,}\}/i.test(text) &&
    !/\b(?:b64|hex|url|rot|xor|enc|dec|utf|msg|str|txt|raw|out|res|key|val|data|base|code|text|byte|hash)\{/i.test(text))
    return true;
  if (/^<[a-z!?/][\s\S]*>$/i.test(text) && printableRatio(utf8Encoder.encode(text)) > 0.9) return true;
  if (/^(?:https?|ftp|file|mailto):\/\/\S+/i.test(text)) return true;
  if ((text.startsWith('{') && text.endsWith('}')) || (text.startsWith('[') && text.endsWith(']'))) {
    try {
      JSON.parse(text);
      return true;
    } catch {
      // Keep testing other heuristics.
    }
  }
  if (/%[0-9a-fA-F]{2}/.test(text)) return false;
  if (/&(#\d+|#x[0-9a-f]+|[a-z]+);/i.test(text)) return false;
  if (/\\u\{?[0-9a-fA-F]{2,}|\\x[0-9a-fA-F]{2}/.test(text)) return false;
  if (/\+[A-Za-z0-9/]+-|\+-/.test(text)) return false;
  const score = smartTextScore(text);
  if (text.length <= 12) return score >= 8 && printableRatio(utf8Encoder.encode(text)) > 0.9;
  return score >= 16 && printableRatio(utf8Encoder.encode(text)) > 0.94;
};

