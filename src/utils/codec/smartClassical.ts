// CODEC-IMPORTS
import { looseField, parseLooseCtfFields, parseSymmetricFields } from './crypto';
import { smartTextScore } from './smartBase';
import { affineTransform, atbashTransform, caesar, morseDecode, polluxDecode, trithemiusDecode } from './textEncodings';
import { adfgxTransform, autokeyTransform, baconDecode, beaufortTransform, bifidTransform, columnarDecode, fourSquareTransform, gronsfeldTransform, playfairTransform, polybiusDecode, portaTransform, railFenceDecode, scytaleDecode, tapCodeDecode, trifidTransform, vigenereTransform } from './classical';
import { classicalNgramMean } from './ngram';
// CODEC-IMPORTS-END
export const extractClassicCipherSource = (value: string) => {
  const symmetricFields = parseSymmetricFields(value);
  const looseFields = parseLooseCtfFields(value);
  // Strip labeled field lines (key=X, password=X, etc.) so they don't pollute the cipher source
  const strippedSource = value.trim()
    .split('\n')
    .filter(line => !/^\s*[A-Za-z][A-Za-z0-9_. -]{0,40}\s*[:=]\s*.+$/.test(line) || !/^[A-Za-z]/.test(line.trim()))
    .join('\n')
    .trim();
  // 中文题目提示词（"密文使用栅栏密码加密: XXX"）会把汉字留在 source 里污染解码；
  // 古典密码密文本身是 ASCII，剥掉 CJK 字符/标点即得纯密文
  const cjkStripped = strippedSource
    .replace(/[\u3000-\u303f\uff01-\uffee]/g, ' ')
    .replace(/[\u4e00-\u9fff]+/g, ' ')
    .replace(/\s{2,}/g, ' ')
    .trim()
    // smartDecode 的 NFKC 会把全角冒号转成半角':'残留串首，剥掉密文前的非字母数字前导符号
    .replace(/^[^A-Za-z0-9]+/, '');
  const rawKey = symmetricFields.key || looseField(looseFields, ['key', 'keyword', 'keyword1', 'password']) || '';
  // 中文题面的 key 值常被行尾中文尾巴污染（"LEMON 密文: XXX"），遇到 CJK 直接截断
  const key = /[\u4e00-\u9fff]/.test(rawKey) ? rawKey.split(/[\u4e00-\u9fff]/)[0].trim() : rawKey;
  return {
    source: symmetricFields.ciphertext
      || looseField(looseFields, ['ciphertext', 'cipher', 'ct', 'encoded', 'text', 'message', 'msg'])
      || cjkStripped
      || value.trim(),
    key,
    keyword2: looseField(looseFields, ['keyword2', 'key2', 'transpositionkey', 'columnkey']),
    fields: looseFields,
  };
};

export const rankClassicCandidates = <T extends { text: string; score?: number }>(candidates: T[]) => candidates
  .map(candidate => ({ ...candidate, score: candidate.score ?? smartTextScore(candidate.text) }))
  .sort((left, right) => (right.score || 0) - (left.score || 0));

export const validAffineMultipliers = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25];

export const trySmartStructuredClassicDecrypt = (value: string) => {
  const { source, key, fields } = extractClassicCipherSource(value);
  const text = source.trim();
  // Flag-skeleton chars ({, }, _) embedded in a morse/bacon/polybius/a1z26 token stream mean a mixed-form
  // encoding — the generic encoding loop's token-wise candidates handle those with literal pass-through.
  // Transposition ciphertexts also scatter skeleton chars, so only these token shapes are handed over.
  if (!key) {
    const strippedSkeleton = text.replace(/[{}_"']/g, '');
    const mixedEncoding = /^[-. /\s]+$/.test(strippedSkeleton) && /[.-]{2,}/.test(strippedSkeleton)
      || /^[ABab01\s,]+$/.test(strippedSkeleton)
      || /^[1-5\s,;|-]+$/.test(strippedSkeleton)
      || /^(\d{1,2}[\s,;|/.-]+)*\d{1,2}$/.test(strippedSkeleton.trim());
    if (mixedEncoding) return null;
  }
  const candidates: Array<{ method: string; params?: Record<string, unknown>; score?: number; text: string; noKeyBrute?: boolean }> = [];
  const addCandidate = (method: string, decode: () => string, params?: Record<string, unknown>, noKeyBrute?: boolean) => {
    try {
      const decoded = decode();
      if (decoded && decoded !== text) candidates.push({ method, params, text: decoded, noKeyBrute });
    } catch {
      // Keep ranking other candidates.
    }
  };

  if (/^[-. /\s]+$/.test(text) && /[.-]{2,}/.test(text)) addCandidate('morse', () => morseDecode(text));
  // Binary 8-bit-group digit payloads are owned by the Binary decoder; Pollux/Bacon only misfire on them
  const binaryShapedText = /^[01\s,;|/-]+$/.test(text) && /[01]{8}/.test(text);
  // Pollux cipher: digit-only strings where digits encode Morse dots/dashes
  if (!binaryShapedText && /^[0-9\s]+$/.test(text) && text.replace(/\s/g, '').length >= 8) {
    addCandidate('pollux', () => polluxDecode(text));
  }
  if (!binaryShapedText && ((/\bbacon\b/i.test(value) || /^[ABab01\s,;|/-]+$/.test(text)) && text.replace(/[^ABab01]/gi, '').length >= 10)) {
    addCandidate('bacon', () => baconDecode(text));
  }
  if ((/\bpolybius\b/i.test(value) || /^[1-5\s,;|/-]+$/.test(text)) && (text.match(/[1-5][1-5]/g) || []).length >= 2) {
    addCandidate('polybius', () => polybiusDecode(text));
  }
  if (/\btap\b|敲击|敲擊/i.test(value) || /([.-]{1,5}\s+[.-]{1,5})(\s*\/\s*|\s+)/.test(`${text} `)) {
    addCandidate('tap-code', () => tapCodeDecode(text));
  }

  if (/\baffine\b|仿射/i.test(value)) {
    const aField = looseField(fields, ['a', 'affinea']);
    const bField = looseField(fields, ['b', 'affineb']);
    if (aField && bField) addCandidate('affine-explicit', () => affineTransform(text, aField, bField, true), { a: aField, b: bField });
    for (const a of validAffineMultipliers) {
      for (let b = 0; b < 26; b += 1) addCandidate('affine-bruteforce', () => affineTransform(text, String(a), String(b), true), { a, b });
    }
  }

  const railHint = /\brail\b|fence|栅栏|栏栅|scytale|换位|置换/i.test(value);
  const explicitRails = Number.parseInt(looseField(fields, ['rails', 'rail', 'r', 'columns', 'cols']), 10);
  const hasExplicitRails = Number.isFinite(explicitRails) && explicitRails >= 2;
  if (railHint) {
    const rails = hasExplicitRails
      ? [explicitRails]
      : Array.from({ length: Math.min(10, Math.max(2, Math.floor(text.length / 2))) - 1 }, (_, index) => index + 2);
    for (const rail of rails) addCandidate('rail-fence', () => railFenceDecode(text, String(rail)), { rails: rail });
    if (/scytale|栅栏|column/i.test(value)) {
      for (const columns of rails) addCandidate('scytale', () => scytaleDecode(text, String(columns)), { columns });
    }
  }
  // No-key transposition bruteforce: cheap for short letter-dense texts. Marked noKeyBrute — plain English
  // scores high through any transposition, so these are only trusted on a large score RISE over the input.
  const transpositionLetters = text.replace(/[^a-z]/gi, '');
  if (!railHint && text.length <= 2048 && transpositionLetters.length >= 12 && transpositionLetters.length / Math.max(1, text.length) > 0.6) {
    for (let rail = 2; rail <= 12; rail += 1) {
      addCandidate('rail-fence', () => railFenceDecode(text, String(rail)), { rails: rail }, true);
      addCandidate('scytale', () => scytaleDecode(text, String(rail)), { rails: rail }, true);
    }
  }

  if (key && /\bcolumnar|transposition|列换位|列转位/i.test(value)) {
    addCandidate('columnar-keyed', () => columnarDecode(text, key), { key });
  }

  const ranked = rankClassicCandidates(candidates).slice(0, 16);
  const originalScore = smartTextScore(text);
  // No-key transposition candidates are only trusted when decoding made the text MUCH better than the input
  // (real transposition ciphertext decodes with a large score rise; plain English barely changes).
  // 换位密码字母集不变，smartTextScore 无法区分原文与错序——提示词点名栅栏/scytale 时
  // 用 quadgram 差值裁决：真英文 ≈ -430，换位垃圾 ≈ -630，差 >60 即可信
  const quadDelta = (a: string, b: string) => {
    const toCodes = (t: string) => {
      const letters = t.toUpperCase().replace(/[^A-Z]/g, '');
      const arr = new Uint8Array(letters.length);
      for (let index = 0; index < letters.length; index += 1) arr[index] = letters.charCodeAt(index) - 65;
      return arr;
    };
    return classicalNgramMean(toCodes(a)) - classicalNgramMean(toCodes(b));
  };
  // 提示词点名栅栏/scytale：hint 本身是用户给的强证据。换位候选的 smartTextScore 全部同分
  //（字母集不变），best 会落在插入序第一的垃圾轨上——用 quadgram 差值在 rail 候选中重选最优
  //（真英文 ≈ -430，换位垃圾 ≈ -630，差 >60），并让它优先于 noKeyBrute 的 rise>12 分支
  //（rise 对换位永不成立）
  const hintGated = railHint && /rail|fence|栅栏|栏栅|scytale/i.test(value);
  let best = ranked[0];
  if (hintGated) {
    const railBest = ranked.find(cand => /^(rail-fence|scytale)$/.test(cand.method)
      && (cand.score || 0) >= 14
      && quadDelta(cand.text, text) > 60);
    if (railBest) best = railBest;
  }
  if (!best) return null;
  const confident = (hintGated && best !== ranked[0])
    || (best.noKeyBrute
    ? (best.score || 0) - originalScore > 12
    : /flag\{|ctf\{|picoctf\{|htb\{|thm\{|ductf\{|corctf\{|dice\{|wctf\{|utflag\{|sekai\{|crypto\{|lactf\{|crew\{|nahamcon\{|hsctf\{|justctf\{|b01lers\{|wanictf\{|jerseyctf\{|the|attack|secret|message/i.test(best.text)
    || (best.score || 0) >= 18
    || (best.score || 0) - originalScore > 8
    || (railHint && hasExplicitRails && /^(rail-fence|scytale|columnar-keyed)$/.test(best.method))
    // Trusted method alone is not enough: Bacon/Polybius/tap-code misfires produce '?'-heavy or low-score text
    || (/^(morse|bacon|polybius|tap-code)$/.test(best.method)
      && (best.score || 0) >= 14
      && (best.text.match(/\?/g) || []).length * 20 < best.text.length));
  if (!confident) return null;
  return `智能识别: structured classic cipher candidates\n\n${JSON.stringify({
    best,
    candidates: ranked,
    note: 'Structured formats are decoded directly; transposition and affine families are ranked candidates and should be verified.',
  }, null, 2)}`;
};

export const trySmartClassicWithKey = (value: string) => {
  const { source, key, keyword2, fields } = extractClassicCipherSource(value);
  const lowered = value.toLowerCase();
  if (!source || !key) return null;
  const candidates: Array<{ method: string; key: string; score: number; text: string }> = [];
  if (/vigen[èe猫]re|vigenere|维吉尼亚|维吉涅/.test(lowered)) {
    const text = vigenereTransform(source, key, true);
    candidates.push({ method: 'vigenere', key, score: smartTextScore(text), text });
  }
  if (/beaufort/.test(lowered)) {
    const text = beaufortTransform(source, key);
    candidates.push({ method: 'beaufort', key, score: smartTextScore(text), text });
  }
  if (/autokey/.test(lowered)) {
    const text = autokeyTransform(source, key, true);
    candidates.push({ method: 'autokey-vigenere', key, score: smartTextScore(text), text });
  }
  if (/playfair/.test(lowered)) {
    const text = playfairTransform(source, key, true);
    candidates.push({ method: 'playfair', key, score: smartTextScore(text), text });
  }
  if (/porta/.test(lowered)) {
    const text = portaTransform(source, key);
    candidates.push({ method: 'porta', key, score: smartTextScore(text), text });
  }
  if (/gronsfeld/.test(lowered)) {
    const text = gronsfeldTransform(source, key, true);
    candidates.push({ method: 'gronsfeld', key, score: smartTextScore(text), text });
  }
  if (/bifid/.test(lowered)) {
    const text = bifidTransform(source, key, looseField(fields, ['period']) || '5', true);
    candidates.push({ method: 'bifid', key, score: smartTextScore(text), text });
  }
  if (/trifid/.test(lowered)) {
    const text = trifidTransform(source, key, looseField(fields, ['period']) || '5', true);
    candidates.push({ method: 'trifid', key, score: smartTextScore(text), text });
  }
  if (/four[-\s]?square/.test(lowered)) {
    const text = fourSquareTransform(source, key, keyword2 || key, true);
    candidates.push({ method: 'four-square', key, score: smartTextScore(text), text });
  }
  if (/columnar|transposition/.test(lowered)) {
    const text = columnarDecode(source, key);
    candidates.push({ method: 'columnar', key, score: smartTextScore(text), text });
  }
  if (/adfgvx/.test(lowered)) {
    const text = adfgxTransform(source, key, keyword2 || key, true, 'ADFGVX');
    candidates.push({ method: 'adfgvx', key, score: smartTextScore(text), text });
  } else if (/adfgx/.test(lowered)) {
    const text = adfgxTransform(source, key, keyword2 || key, true, 'ADFGX');
    candidates.push({ method: 'adfgx', key, score: smartTextScore(text), text });
  }
  const ranked = candidates.sort((left, right) => right.score - left.score);
  // Fallback: if key is given but no cipher keyword matched, try Vigenère (most common keyed cipher in CTF)
  if (!ranked.length && key && /^[a-z]{2,}$/i.test(key.trim())) {
    try {
      const text = vigenereTransform(source, key, true);
      const score = smartTextScore(text);
      if (score >= 12) return `智能识别: classic-keyed cipher\n\n${JSON.stringify({ best: { method: 'vigenere', key, score, text }, candidates: [{ method: 'vigenere', key, score, text }] }, null, 2)}`;
    } catch { /* ignore */ }
  }
  if (!ranked.length || ranked[0].score < 12) return null;
  return `智能识别: classic-keyed cipher\n\n${JSON.stringify({ best: ranked[0], candidates: ranked }, null, 2)}`;
};

export const ENGLISH_FREQ = [0.082,0.015,0.028,0.043,0.127,0.022,0.020,0.061,0.070,0.002,0.008,0.040,0.024,0.067,0.075,0.019,0.001,0.060,0.063,0.091,0.028,0.010,0.023,0.001,0.020,0.001];
export const ENGLISH_IC = 0.0665;

export const trySmartVigenereBruteforce = (value: string): string | null => {
  const { source } = extractClassicCipherSource(value);
  const text = source.trim() || value;
  const letters = text.toUpperCase().replace(/[^A-Z]/g, '');
  if (letters.length < 20) return null;
  const hasHint = /vigen[eè]re|polyalpha/i.test(value);
  const colIC = (col: string) => {
    const freq = new Array(26).fill(0);
    for (const c of col) freq[c.charCodeAt(0) - 65] += 1;
    const n = col.length;
    return n < 2 ? 0 : freq.reduce((s, f) => s + f * (f - 1), 0) / (n * (n - 1));
  };
  let bestKeyLen = 2;
  let bestScore = Infinity;
  const maxKeyLen = Math.min(20, Math.floor(letters.length / 3));
  const icCache = new Map<number, number>();
  const getAvgIC = (kl: number) => {
    if (icCache.has(kl)) return icCache.get(kl)!;
    const v = Array.from({ length: kl }, (_, i) => letters.split('').filter((_, j) => j % kl === i).join('')).reduce((s, c) => s + colIC(c), 0) / kl;
    icCache.set(kl, v);
    return v;
  };
  for (let kl = 2; kl <= maxKeyLen; kl += 1) {
    const score = Math.abs(getAvgIC(kl) - ENGLISH_IC) + kl * 0.0008;
    if (score < bestScore) { bestScore = score; bestKeyLen = kl; }
  }
  // Reduce to smallest divisor whose IC is close to English IC (absolute threshold)
  for (let d = 2; d < bestKeyLen; d++) {
    if (bestKeyLen % d === 0 && Math.abs(getAvgIC(d) - ENGLISH_IC) <= 0.01) {
      bestKeyLen = d; break;
    }
  }
  const bestDiff = Math.abs(getAvgIC(bestKeyLen) - ENGLISH_IC);
  if (!hasHint && bestDiff > 0.02) return null;
  const cols = Array.from({ length: bestKeyLen }, (_, i) => letters.split('').filter((_, j) => j % bestKeyLen === i).join(''));
  const key = cols.map(col => {
    let bestShift = 0;
    let bestChi = Infinity;
    for (let shift = 0; shift < 26; shift += 1) {
      const freq = new Array(26).fill(0);
      for (const c of col) freq[(c.charCodeAt(0) - 65 - shift + 26) % 26] += 1;
      const n = col.length;
      const chi2 = freq.reduce((s, f, i) => { const e = n * ENGLISH_FREQ[i]; return s + (e > 0 ? (f - e) ** 2 / e : 0); }, 0);
      if (chi2 < bestChi) { bestChi = chi2; bestShift = shift; }
    }
    return String.fromCharCode(65 + bestShift);
  }).join('');
  const decrypted = vigenereTransform(text, key, true);
  const score = smartTextScore(decrypted);
  const origScore = smartTextScore(text);
  const avgIC = cols.reduce((s, c) => s + colIC(c), 0) / bestKeyLen;
  if (!hasHint && score - origScore < 8 && !/flag\{|ctf\{|picoctf\{|htb\{|thm\{|ductf\{|corctf\{|dice\{|wctf\{|utflag\{|sekai\{|crypto\{|lactf\{|nahamcon\{|hsctf\{|justctf\{|b01lers\{|wanictf\{/i.test(decrypted)) return null;
  return `智能识别: Vigenère bruteforce (key length=${bestKeyLen})\n\n${JSON.stringify({ key, keyLength: bestKeyLen, avgColumnIC: Number(avgIC.toFixed(4)), decrypted, note: 'IC analysis + chi-squared column recovery. Verify manually.' }, null, 2)}`;
};

export const trySmartClassicDecrypt = (value: string) => {
  const keyed = trySmartClassicWithKey(value);
  if (keyed) return keyed;
  const structured = trySmartStructuredClassicDecrypt(value);
  if (structured) return structured;
  // UTF-7 ciphertext (+..- runs) belongs to the UTF-7 decoder, not Caesar-family bruteforce
  if (/\+[A-Za-z0-9/]+-|\+-/.test(value.trim())) return null;
  // Ascii85 framing (<~ .. ~>) belongs to the Ascii85 decoder
  if (/^<~/.test(value.trim()) || /~>$/.test(value.trim())) return null;
  const { source } = extractClassicCipherSource(value);
  const text = source.trim() || value.trim();
  const letters = text.replace(/[^a-z]/gi, '');
  if (letters.length < 6 || letters.length / Math.max(1, text.length) < 0.55) return null;
  const caesarCandidates = Array.from({ length: 25 }, (_, index) => {
    const shift = index + 1;
    const decoded = caesar(text, shift);
    return { method: 'caesar', shift, score: smartTextScore(decoded), text: decoded };
  });
  const atbashText = atbashTransform(text);
  const trithemiusText = trithemiusDecode(text);
  const candidates = [
    ...caesarCandidates,
    { method: 'atbash', shift: null, score: smartTextScore(atbashText), text: atbashText },
    { method: 'trithemius', shift: null, score: smartTextScore(trithemiusText), text: trithemiusText },
  ].sort((left, right) => right.score - left.score);
  const best = candidates[0];
  const originalScore = smartTextScore(text);
  const confident = /flag\{|ctf\{|picoctf\{|htb\{|thm\{|ductf\{|corctf\{|dice\{|wctf\{|utflag\{|sekai\{|crypto\{|lactf\{|nahamcon\{|hsctf\{|justctf\{|b01lers\{|wanictf\{/i.test(best.text) || best.score - originalScore > 8;
  if (!confident) return null;
  return `智能识别: classic cipher candidates\n\n${JSON.stringify({
    best,
    candidates: candidates.slice(0, 10),
    note: 'Caesar/ROT and Atbash are ranked by CTF flag patterns plus English-like scoring.',
  }, null, 2)}`;
};
