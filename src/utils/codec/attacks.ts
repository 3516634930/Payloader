// CODEC-IMPORTS
import { looseField, parseLooseCtfFields, parseSymmetricFieldBytes, parseSymmetricFields } from './crypto';
import { parseIndexedSequence, parseNumericList, parseNumericValue, parseOptionalModulus, parsePowerOrNumeric, stripPrngScalarAssignments } from './textUtils';
import { bigintAbs, bigintGcd, bigintModInverse } from './math';
import { brainfuckToOok, ookToBrainfuck, utf8Decoder, utf8Encoder } from './alphabets';
import { bytesToHex } from './bases';
import { cStringDecode } from './textEncodings';
// CODEC-IMPORTS-END
export type LcgInference = {
  states: bigint[];
  modulus: bigint | null;
  multiplier: bigint | null;
  increment: bigint | null;
  seed: bigint | null;
  confidence: number;
  notes: string[];
  fields: Record<string, string>;
};

export const inferLcgFromText = (value: string, secret = ''): LcgInference => {
  const fields = parseLooseCtfFields(value);
  const modulus = parsePowerOrNumeric(looseField(fields, ['m', 'mod', 'modulus', 'modulo'])) || parseOptionalModulus(secret);
  const multiplier = parsePowerOrNumeric(looseField(fields, ['a', 'multiplier', 'mul']));
  const increment = parsePowerOrNumeric(looseField(fields, ['c', 'increment', 'inc']));
  const seed = parsePowerOrNumeric(looseField(fields, ['seed', 'x0', 'state0']));
  const fieldSequence = looseField(fields, ['outputs', 'output', 'states', 'state', 'samples', 'values', 'leaks', 'sequence', 'randoms']);
  const indexed = parseIndexedSequence(value);
  const states = fieldSequence
    ? parseNumericList(fieldSequence)
    : indexed.length >= 2
      ? indexed
      : parseNumericList(stripPrngScalarAssignments(value));
  const lower = value.toLowerCase();
  let confidence = 0;
  if (/\blcg\b|linear congruential|x\s*\[\s*n\s*\+\s*1\s*\]|x_?n\s*=|线性同余|同余生成器/.test(lower)) confidence += 6;
  if (states.length >= 4) confidence += 5;
  else if (states.length >= 2) confidence += 2;
  if (modulus) confidence += 2;
  if (multiplier != null || increment != null) confidence += 2;
  if (/rand|random|seed|next/.test(lower)) confidence += 1;
  const notes = [
    fieldSequence ? 'state sequence inferred from an outputs/states/samples-style field.' : '',
    indexed.length >= 2 ? 'indexed x0/x1/... assignments were sorted before analysis.' : '',
    modulus ? 'modulus inferred from m/mod/modulus or the helper parameter.' : '',
  ].filter(Boolean);
  return { states, modulus, multiplier, increment, seed, confidence, notes, fields };
};

export const lcgHelper = (value: string, secret: string) => {
  const inference = inferLcgFromText(value, secret);
  const states = inference.states;
  if (states.length < 4 && !(inference.modulus && inference.multiplier != null && inference.increment != null && (states.length || inference.seed != null))) {
    throw new Error('LCG 分析至少需要 4 个连续输出，或提供 m/a/c 与 seed/state');
  }
  const diffs = states.slice(1).map((state, index) => state - states[index]);
  const zeroes: bigint[] = [];
  for (let index = 0; index + 2 < diffs.length; index += 1) {
    zeroes.push(diffs[index + 2] * diffs[index] - diffs[index + 1] * diffs[index + 1]);
  }
  const derivedModulus = zeroes.reduce((current, entry) => current === 0n ? bigintAbs(entry) : bigintGcd(current, entry), 0n);
  const modulus = inference.modulus || (derivedModulus > 1n ? derivedModulus : null);
  const result: Record<string, unknown> = {
    states: states.map(item => item.toString()),
    inferredFields: inference.fields,
    inferenceConfidence: inference.confidence,
    differenceCount: diffs.length,
    derivedModulus: derivedModulus > 1n ? derivedModulus.toString() : null,
    modulus: modulus?.toString() || null,
    parsedMultiplier: inference.multiplier?.toString() || null,
    parsedIncrement: inference.increment?.toString() || null,
    parsedSeed: inference.seed?.toString() || null,
    notes: [
      '输入必须是同一个 LCG 的连续完整输出；截断输出需要 lattice/Z3，前台只做 triage。',
      '如果自动 m 不稳定，请在参数中填写 m=<modulus> 或 m=2^31。',
    ],
  };
  if (!modulus) return JSON.stringify(result, null, 2);
  if (inference.multiplier != null && inference.increment != null) {
    const baseState = states.length ? states[states.length - 1] : inference.seed;
    const next = baseState == null ? null : (inference.multiplier * baseState + inference.increment) % modulus;
    return JSON.stringify({
      ...result,
      a: inference.multiplier.toString(),
      c: inference.increment.toString(),
      next: next?.toString() || null,
      recurrence: `x[n+1] = (${inference.multiplier.toString()} * x[n] + ${inference.increment.toString()}) mod ${modulus.toString()}`,
    }, null, 2);
  }
  const inverse = bigintModInverse(states[1] - states[0], modulus);
  if (inverse == null) {
    result.warning = 'x1-x0 与 modulus 不互素，无法直接求 a；可换一组连续输出，或转 CRT/枚举。';
    return JSON.stringify(result, null, 2);
  }
  const a = (((states[2] - states[1]) * inverse) % modulus + modulus) % modulus;
  const c = ((states[1] - a * states[0]) % modulus + modulus) % modulus;
  const next = (a * states[states.length - 1] + c) % modulus;
  return JSON.stringify({
    ...result,
    a: a.toString(),
    c: c.toString(),
    next: next.toString(),
    recurrence: `x[n+1] = (${a.toString()} * x[n] + ${c.toString()}) mod ${modulus.toString()}`,
  }, null, 2);
};

export const berlekampMassey = (bits: number[]) => {
  let c = [1];
  let b = [1];
  let l = 0;
  let m = 1;
  for (let n = 0; n < bits.length; n += 1) {
    let discrepancy = bits[n];
    for (let index = 1; index <= l; index += 1) discrepancy ^= c[index] & bits[n - index];
    if (discrepancy === 0) {
      m += 1;
      continue;
    }
    const previous = c.slice();
    if (c.length < b.length + m) c = c.concat(Array.from({ length: b.length + m - c.length }, () => 0));
    for (let index = 0; index < b.length; index += 1) c[index + m] ^= b[index];
    if (2 * l <= n) {
      l = n + 1 - l;
      b = previous;
      m = 1;
    } else {
      m += 1;
    }
  }
  return { complexity: l, polynomial: c.slice(0, l + 1) };
};

export const bytesToBitArray = (bytes: Uint8Array) => Array.from(bytes).flatMap(byte => (
  Array.from({ length: 8 }, (_, bit) => (byte >> (7 - bit)) & 1)
));

export type LfsrInference = {
  bits: number[];
  confidence: number;
  notes: string[];
  fields: Record<string, string>;
  masks?: bigint[];
};

export const parseLfsrBitSource = (source: string) => {
  const compact = source.replace(/[^01]/g, '');
  return compact.length >= 4 ? Array.from(compact).map(bit => Number(bit)) : [];
};

export const inferLfsrBitsFromText = (value: string): LfsrInference => {
  const fields = parseLooseCtfFields(value);
  const symmetricFields = parseSymmetricFields(value);
  const notes: string[] = [];
  let bits: number[] = [];
  const fieldSource = looseField(fields, ['keystream', 'key stream', 'bits', 'bitstream', 'stream', 'output', 'outputs', 'state', 'states']);
  if (fieldSource) {
    bits = parseLfsrBitSource(fieldSource);
    if (bits.length) notes.push('keystream bits inferred from a labelled field.');
  }
  if (!bits.length) {
    const binaryRuns = value.match(/[01][01\s,;|/_-]{14,}[01]/g) || [];
    const bestRun = binaryRuns
      .map(run => ({ run, bitCount: run.replace(/[^01]/g, '').length }))
      .sort((left, right) => right.bitCount - left.bitCount)[0];
    if (bestRun) {
      bits = parseLfsrBitSource(bestRun.run);
      notes.push('longest binary-looking run was used as keystream.');
    }
  }
  const knownPlaintext = symmetricFields.knownPlaintext || symmetricFields.plaintext || looseField(fields, ['knownplaintext', 'known plaintext', 'plaintext', 'plain']);
  const cipherSource = symmetricFields.ciphertext || looseField(fields, ['ciphertext', 'cipher', 'ct']);
  if (!bits.length && knownPlaintext && cipherSource) {
    try {
      const ciphertext = parseSymmetricFieldBytes(cipherSource, 'ciphertext');
      const known = utf8Encoder.encode(knownPlaintext);
      const length = Math.min(ciphertext.length, known.length);
      const keystream = ciphertext.slice(0, length).map((byte, index) => byte ^ known[index]);
      bits = bytesToBitArray(keystream);
      notes.push('keystream prefix inferred from ciphertext XOR known plaintext.');
    } catch {
      // Keep falling through to a plain "not enough bits" result.
    }
  }
  const lower = value.toLowerCase();
  let confidence = bits.length >= 32 ? 5 : bits.length >= 16 ? 3 : bits.length >= 4 ? 1 : 0;
  if (/lfsr|berlekamp|feedback|linear complexity|keystream/.test(lower)) confidence += 5;
  if (knownPlaintext && cipherSource) confidence += 2;
  // Extract LFSR mask constants from code (e.g. HITCON: MASK1 = 0x6D6AC812...)
  const maskMatches = Array.from(value.matchAll(/\bMASK\d*\s*=\s*(0x[0-9a-fA-F_]+)/gi));
  const masks = maskMatches.map(m => parseNumericValue(m[1])).filter((m): m is bigint => typeof m === 'bigint');
  if (masks.length) {
    notes.push(`Found ${masks.length} LFSR mask constant(s): ${masks.slice(0,4).map(m=>`0x${m.toString(16)}`).join(', ')}`);
    confidence += masks.length >= 2 ? 6 : 3;
  }
  return { bits, confidence, notes, fields, masks };
};

export const lfsrHelper = (value: string) => {
  const inference = inferLfsrBitsFromText(value);
  const bits = inference.bits;
  if (bits.length < 4) throw new Error('LFSR 分析需要 0/1 keystream');
  const result = berlekampMassey(bits);
  const taps = result.polynomial
    .map((coefficient, index) => coefficient ? index : -1)
    .filter(index => index > 0);
  return JSON.stringify({
    bitCount: bits.length,
    inferredFields: inference.fields,
    inferenceConfidence: inference.confidence,
    inferenceNotes: inference.notes,
    linearComplexity: result.complexity,
    feedbackPolynomial: result.polynomial.map((coefficient, index) => coefficient ? `x^${index}` : '').filter(Boolean).join(' + ').replace('x^0', '1'),
    taps,
    seedHint: `需要前 ${result.complexity} bit 作为状态，按反馈多项式继续生成。`,
    note: '组合 LFSR 或截断/扰动 keystream 需要结合 correlation attack、Z3 或 Sage/GF(2) 矩阵分析。',
  }, null, 2);
};

export const supportedLengthExtensionAlgorithms = new Set(['md5', 'sha1', 'sha256']);

export const inferHashAlgorithmFromDigest = (digest: string) => {
  const clean = digest.replace(/^0x/i, '').toLowerCase();
  if (!/^[a-f0-9]+$/.test(clean)) return '';
  if (clean.length === 32) return 'md5';
  if (clean.length === 40) return 'sha1';
  if (clean.length === 64) return 'sha256';
  return '';
};

export const parseSecretLengthCandidates = (value: string, fields: Record<string, string>) => {
  const source = [
    looseField(fields, ['secretlength', 'secretlen', 'keylength', 'keylen']),
    value,
  ].filter(Boolean).join('\n');
  const range = source.match(/\b(?:secret|key)[-_ ]?(?:len|length)\b\D{0,12}(\d{1,3})\s*(?:\.\.|-|to)\s*(\d{1,3})/i);
  if (range) {
    const start = Number(range[1]);
    const end = Number(range[2]);
    if (Number.isFinite(start) && Number.isFinite(end) && end >= start && end - start <= 64) {
      return Array.from({ length: end - start + 1 }, (_, index) => start + index);
    }
  }
  const single = source.match(/\b(?:secret|key)[-_ ]?(?:len|length)\b\D{0,12}(\d{1,3})/i);
  if (single) return [Number(single[1])].filter(length => length > 0);
  return [8, 12, 16, 20, 24, 32];
};

export type HashLengthExtensionInference = {
  algorithm: string;
  digest: string;
  originalMessage: string;
  appendData: string;
  secretLengths: number[];
  confidence: number;
  notes: string[];
  fields: Record<string, string>;
};

export const inferHashLengthExtensionFromText = (
  value: string,
  algorithm: string,
  appendData: string,
  knownMessage: string,
): HashLengthExtensionInference => {
  const fields = parseLooseCtfFields(value);
  const digestFromField = looseField(fields, ['signature', 'sig', 'mac', 'hash', 'digest', 'hexdigest', 'token']);
  const digest = (digestFromField.match(/[a-f0-9]{32,128}/i)?.[0] || value.match(/[a-f0-9]{32,128}/i)?.[0] || value.trim()).replace(/^0x/i, '');
  const algorithmField = looseField(fields, ['algorithm', 'alg', 'hashalgorithm', 'hash']);
  const textAlgorithm = value.match(/\b(md5|sha1|sha-1|sha256|sha-256)\b/i)?.[1].toLowerCase().replace('-', '') || '';
  const digestAlgorithm = inferHashAlgorithmFromDigest(digest);
  const requestedAlgorithm = supportedLengthExtensionAlgorithms.has(algorithm) ? algorithm : '';
  const inferredAlgorithm = algorithmField.toLowerCase().replace('-', '');
  const alg = supportedLengthExtensionAlgorithms.has(inferredAlgorithm)
    ? inferredAlgorithm
    : textAlgorithm || digestAlgorithm || requestedAlgorithm || 'sha1';
  const original = knownMessage
    || looseField(fields, ['original', 'originalmessage', 'knownmessage', 'message', 'msg', 'data', 'payload'])
    || 'known-message';
  const append = appendData
    || looseField(fields, ['append', 'appenddata', 'extension', 'suffix', 'newdata', 'add'])
    || 'admin=true';
  const secretLengths = parseSecretLengthCandidates(value, fields);
  const lower = value.toLowerCase();
  let confidence = 0;
  if (digest && /^[a-f0-9]{32,64}$/i.test(digest)) confidence += 4;
  if (/(length extension|hashpump|hash_extender|secret\s*\|\||prefix mac|secret-prefix)/i.test(value)) confidence += 5;
  if (original !== 'known-message') confidence += 2;
  if (append !== 'admin=true') confidence += 2;
  if (/\bhmac\b/.test(lower)) confidence -= 4;
  return {
    algorithm: alg,
    digest,
    originalMessage: original,
    appendData: append,
    secretLengths,
    confidence,
    notes: [
      digestAlgorithm ? `digest length suggests ${digestAlgorithm}.` : '',
      /\bhmac\b/.test(lower) ? 'HMAC was mentioned; normal HMAC is not vulnerable to length extension.' : '',
    ].filter(Boolean),
    fields,
  };
};

export const shellSingleQuote = (value: string) => value.replace(/'/g, `'"'"'`);

export const hashLengthExtensionHelper = (value: string, algorithm: string, appendData: string, knownMessage: string) => {
  const inference = inferHashLengthExtensionFromText(value, algorithm, appendData, knownMessage);
  const { algorithm: alg, digest: digestCandidate, appendData: append, originalMessage: original, secretLengths } = inference;
  return JSON.stringify({
    algorithm: alg,
    digest: digestCandidate,
    originalMessage: original,
    appendData: append,
    secretLengthCandidates: secretLengths,
    inferredFields: inference.fields,
    inferenceConfidence: inference.confidence,
    inferenceNotes: inference.notes,
    vulnerableWhen: '服务端 MAC 形如 hash(secret || message)，且使用 MD5/SHA1/SHA256 这类 Merkle-Damgard 摘要',
    notVulnerableWhen: 'HMAC、hash(message || secret)、带 AEAD/MAC 的现代协议通常不适用',
    localCommands: secretLengths.map(length => `hash_extender --data '${shellSingleQuote(original)}' --signature ${digestCandidate} --append '${shellSingleQuote(append)}' --format ${alg} --secret ${length}`),
    pythonTemplate: `import hashpumpy\nfor key_len in ${JSON.stringify(secretLengths)}:\n    new_sig, new_msg = hashpumpy.hashpump('${digestCandidate}', ${JSON.stringify(original)}, ${JSON.stringify(append)}, key_len)\n    print(key_len, new_sig, new_msg)`,
    safetyNote: '仅用于本地 CTF / lab 复现实验；不要对未授权系统发起请求。',
  }, null, 2);
};

export const frequencyAnalysis = (value: string) => {
  const letters = value.toUpperCase().replace(/[^A-Z]/g, '');
  const countMap = (items: string[]) => {
    const counts = new Map<string, number>();
    items.forEach(item => counts.set(item, (counts.get(item) || 0) + 1));
    return Array.from(counts.entries())
      .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]))
      .slice(0, 40)
      .map(([token, count]) => ({ token, count, percent: items.length ? Number(((count / items.length) * 100).toFixed(2)) : 0 }));
  };
  const ngrams = (size: number) => Array.from({ length: Math.max(0, letters.length - size + 1) }, (_, index) => letters.slice(index, index + size));
  const chars = Array.from(value).filter(char => !/\s/.test(char));
  const ic = letters.length > 1
    ? Number((Array.from(new Set(letters)).reduce((sum, char) => {
      const count = letters.split(char).length - 1;
      return sum + count * (count - 1);
    }, 0) / (letters.length * (letters.length - 1))).toFixed(4))
    : 0;
  const cipherHint = ic >= 0.060 ? '单表替换/Caesar（IC≈0.066）——直接用频率对照 ETAOIN 推测替换表' :
    ic >= 0.045 ? '可能是短 key 多表替换（Vigenère）——试用 IC 分析推断 key 长度' :
    ic >= 0.030 ? '多表替换或随机密钥（IC≈0.038）——尝试 Vigenère 暴破或检查 key 重用' :
    ic < 0.030 ? '近似随机（可能是流密码/XOR/强分组密码）——尝试 XOR 工具或查找密文重复块' : '未知';
  return JSON.stringify({
    length: value.length,
    letterCount: letters.length,
    indexOfCoincidence: ic,
    cipherHint,
    letters: countMap(Array.from(letters)),
    characters: countMap(chars),
    bigrams: countMap(ngrams(2)).slice(0, 20),
    trigrams: countMap(ngrams(3)).slice(0, 20),
    hints: ['English ETAOIN 频率可辅助单表替换与 Caesar 分析。', 'IC 接近 0.066 常见于单表英文文本，接近 0.038 更像随机或多表替换。', 'Top bigrams EN: TH HE IN ER AN RE ON EN。'],
  }, null, 2);
};

export const runBrainfuck = (program: string, input: string, maxStepsValue: string) => {
  const code = Array.from(program).filter(char => '<>+-.,[]'.includes(char));
  const bracketStack: number[] = [];
  const jump = new Map<number, number>();
  code.forEach((char, index) => {
    if (char === '[') bracketStack.push(index);
    if (char === ']') {
      const start = bracketStack.pop();
      if (start == null) throw new Error('Brainfuck bracket mismatch');
      jump.set(start, index);
      jump.set(index, start);
    }
  });
  if (bracketStack.length) throw new Error('Brainfuck bracket mismatch');
  const tape = new Uint8Array(30000);
  const inputBytes = utf8Encoder.encode(input);
  const output: number[] = [];
  let pointer = 0;
  let inputIndex = 0;
  let pc = 0;
  let steps = 0;
  const maxSteps = Math.min(5000000, Math.max(1000, Number.parseInt(maxStepsValue, 10) || 120000));
  while (pc < code.length) {
    steps += 1;
    if (steps > maxSteps) throw new Error(`Brainfuck 超过步数限制 ${maxSteps}`);
    const op = code[pc];
    if (op === '>') pointer = (pointer + 1) % tape.length;
    else if (op === '<') pointer = (pointer - 1 + tape.length) % tape.length;
    else if (op === '+') tape[pointer] = (tape[pointer] + 1) & 255;
    else if (op === '-') tape[pointer] = (tape[pointer] - 1) & 255;
    else if (op === '.') output.push(tape[pointer]);
    else if (op === ',') tape[pointer] = inputBytes[inputIndex++] || 0;
    else if (op === '[' && tape[pointer] === 0) pc = jump.get(pc) || pc;
    else if (op === ']' && tape[pointer] !== 0) pc = jump.get(pc) || pc;
    pc += 1;
  }
  return JSON.stringify({
    output: utf8Decoder.decode(new Uint8Array(output)),
    outputHex: bytesToHex(new Uint8Array(output)),
    steps,
    pointer,
  }, null, 2);
};

export const encodeBrainfuckText = (value: string) => {
  let current = 0;
  const chunks: string[] = [];
  for (const byte of utf8Encoder.encode(value)) {
    const up = (byte - current + 256) % 256;
    const down = (current - byte + 256) % 256;
    chunks.push((up <= down ? '+'.repeat(up) : '-'.repeat(down)) + '.');
    current = byte;
  }
  return chunks.join('');
};

export const brainfuckToOokText = (value: string) => Array.from(value)
  .filter(char => Object.prototype.hasOwnProperty.call(brainfuckToOok, char))
  .map(char => brainfuckToOok[char])
  .join(' ');

export const ookToBrainfuckText = (value: string) => {
  const tokens = value.match(/Ook[.!?]/g) || [];
  if (!tokens.length || tokens.length % 2 !== 0) throw new Error('Ook! 解码需要成对的 Ook. / Ook? / Ook! token');
  const output: string[] = [];
  for (let index = 0; index < tokens.length; index += 2) {
    const pair = `${tokens[index]} ${tokens[index + 1]}`;
    const op = ookToBrainfuck[pair];
    if (!op) throw new Error(`未知 Ook! token: ${pair}`);
    output.push(op);
  }
  return output.join('');
};

export const jsfuckInspector = (value: string) => {
  const compact = value.replace(/\s+/g, '');
  const jsfuckChars = compact.replace(/[()[\]{}!+]/g, '').length === 0;
  const symbolRatio = compact.length ? 1 - compact.replace(/[()[\]{}!+]/g, '').length / compact.length : 0;
  const quotedStrings = Array.from(value.matchAll(/(["'`])((?:\\.|(?!\1)[\s\S])*)\1/g)).map(match => {
    try {
      return cStringDecode(match[2]);
    } catch {
      return match[2];
    }
  });
  const escapeStrings = Array.from(value.matchAll(/(?:\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|\\U[0-9a-fA-F]{8})+/g)).map(match => cStringDecode(match[0]));
  const likelyWrappers = [
    ['eval wrapper', /eval|constructor|Function/i.test(value)],
    ['JSFuck alphabet only', jsfuckChars && compact.length > 20],
    ['symbol-heavy JavaScript', symbolRatio > 0.8 && compact.length > 20],
    ['escape-packed payload', escapeStrings.length > 0],
  ].filter(([, enabled]) => enabled).map(([name]) => name);
  return JSON.stringify({
    length: value.length,
    compactLength: compact.length,
    symbolRatio: Number(symbolRatio.toFixed(3)),
    jsfuckAlphabetOnly: jsfuckChars,
    likelyWrappers,
    extractedQuotedStrings: quotedStrings.slice(0, 20),
    extractedEscapeStrings: escapeStrings.slice(0, 20),
    safeNextSteps: [
      '不要直接在当前页面 eval 可疑 JSFuck；先在隔离的 VM 或 DevTools profile 中运行。',
      '如果是纯 JSFuck 字母表，可用 CyberChef JSFuck/Unescape JavaScript 或 de4js 离线还原。',
      '若包含 Function constructor，优先提取字符串常量和 escape 序列，再手工检查网络、DOM、cookie、localStorage 操作。',
    ],
  }, null, 2);
};

export const cryptoAttackHelper = (value: string) => {
  const text = value.trim();
  const lower = text.toLowerCase();
  const checks: Array<{ topic: string; when: boolean; actions: string[] }> = [
    {
      topic: 'RSA weak-key / textbook RSA',
      when: /\bn\s*[:=]/i.test(text) || /\be\s*[:=]/i.test(text) || /\bc\s*[:=]/i.test(text) || /rsa/.test(lower),
      actions: [
        '先用 RSA CTF 辅助解析 n/e/c/p/q/phi，再交给 RsaCtfTool。',
        '检查 small e、Hastad broadcast、common modulus、Fermat、Wiener、p=q、dp/dq/qinv 泄露。',
        '命令方向: python RsaCtfTool.py -n <n> -e <e> --uncipher <c>',
      ],
    },
    {
      topic: 'ECC / DSA nonce issue',
      when: /ecdsa|ed25519|curve|elliptic|dsa|nonce|\br\s*[:=]|\bs\s*[:=]/.test(lower),
      actions: [
        '检查重复 r、低位 nonce、partial nonce、invalid curve、small subgroup、anomalous curve。',
        '重复 nonce 公式: k=(h1-h2)/(s1-s2) mod q, d=(s*k-h)/r mod q',
        '复杂 DLP 或曲线阶分解交给 SageMath / Pohlig-Hellman。',
      ],
    },
    {
      topic: 'LCG / MT19937 / PRNG',
      when: /lcg|mt19937|mersenne|random|seed|rand\(|xorshift|prng/.test(lower),
      actions: [
        'LCG 有连续输出时先求 a/c/m；截断输出时转 lattice/HNP。',
        'MT19937 有 624 个 32-bit 连续输出时可 untemper 恢复状态；少量约束可转 Z3。',
        '命令方向: randcrack, z3-solver, Sage lattice',
      ],
    },
    {
      topic: 'LFSR / stream cipher',
      when: /lfsr|berlekamp|keystream|stream|xor|otp|many.?time/.test(lower),
      actions: [
        '已知明文可先做 XOR / keystream 还原；LFSR 可用 Berlekamp-Massey 恢复反馈多项式。',
        '多次 OTP / CTR / RC4 key reuse 时，可做 crib dragging 与 ciphertext XOR。',
        '本工具可先用 XOR 已知明文和单字节 XOR 爆破做前置分析。',
      ],
    },
    {
      topic: 'AES mode / oracle',
      when: /aes|cbc|ecb|gcm|ctr|padding|oracle|nonce|iv/.test(lower),
      actions: [
        'ECB 看重复块与 cut-and-paste；CBC 看 padding oracle / IV bitflip；CTR/GCM 看 nonce reuse。',
        'CBC IV bitflip: plaintext[i] ^= (original_byte ^ target_byte) 在 IV/前一密文块对应位置。',
        'Padding oracle Python: from paddingoracle import BadPaddingException, PaddingOracle; 或用 padbuster/POET。',
        'GCM nonce reuse 会泄露 CTR keystream，并可能恢复 GHASH key，需要专门脚本。',
        '本工具可复现 AES-GCM/CBC/CTR 正常加解密，攻击链建议写 Python/Sage 脚本',
      ],
    },
    {
      topic: 'Hash length extension / MAC',
      when: /md5|sha1|sha256|mac|hmac|hash|crc|length extension|hashpump/.test(lower),
      actions: [
        '对 hash(secret || msg) 可尝试 length extension；正常 HMAC 不受该攻击影响。',
        '常用工具包括 hashpumpy / hash_extender；CRC 线性问题可转成 GF(2) 方程。',
        '先用 Hash 识别确认摘要形态，再判断是否带 secret-prefix 结构。',
      ],
    },
    {
      topic: 'Lattice / LLL / Coppersmith',
      when: /lll|lattice|coppersmith|small root|partial|knapsack|subset|hidden number|hnp|lwe/.test(lower),
      actions: [
        '部分已知 RSA prime/message、small root、多项式同余优先走 Sage small_roots。',
        'HNP / partial nonce / truncated LCG 先建 lattice，再用 LLL/BKZ/Babai。',
        '前台只做识别和模板提示，实际计算建议 SageMath/fpylll',
      ],
    },
  ];
  const matched = checks.filter(item => item.when);
  const fallback = [
    '没有匹配到明确攻击面。建议先粘贴题目参数名、密文片段、算法名、代码变量名或报错回显。',
    '常见 triage 顺序：编码层 -> 古典密码 -> XOR / 流模式 -> 分组模式 -> RSA / ECC / PRNG / LLL。',
  ];
  return JSON.stringify({
    matched: matched.map(({ topic, actions }) => ({ topic, actions })),
    fallback: matched.length ? [] : fallback,
    localTools: ['RsaCtfTool', 'SageMath', 'PyCryptodome', 'sympy', 'z3-solver', 'fpylll', 'hashpumpy', 'hashcat --identify'],
  }, null, 2);
};

// bigIntSqrt 已下沉 codec/math.ts（T5 解环）；rsa 借用路径改指 math。
import { bigIntSqrt } from './math';
export { bigIntSqrt };

