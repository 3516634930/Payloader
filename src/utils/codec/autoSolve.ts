// 自动破译引擎（CTF 实战高频）：XOR 重叠密钥（xortool 思路）、Vigenère（重合指数 + 卡方拟合）、
// 单表替换（频率对齐 + shotgun 爬山，quipqiup 等价实现）。
// 纯函数、零依赖、零网络、无 eval：评分全部依赖本文件内置的英文频率数据（字母频率 + bigram 表 + 常见词表）。

/** 英文字母频率（a-z，英文语料占比，总和约等于 1）。 */
export const ENGLISH_LETTER_FREQUENCIES: Readonly<Record<string, number>> = {
  a: 0.08167, b: 0.01492, c: 0.02782, d: 0.04253, e: 0.12702, f: 0.02228, g: 0.02015,
  h: 0.06094, i: 0.06966, j: 0.00153, k: 0.00772, l: 0.04025, m: 0.02406, n: 0.06749,
  o: 0.07507, p: 0.01929, q: 0.00095, r: 0.05987, s: 0.06327, t: 0.09056, u: 0.02758,
  v: 0.00978, w: 0.0236, x: 0.0015, y: 0.01974, z: 0.00074,
};

/** 常见 bigram 前 20 及语料占比权重（降序）。 */
export const COMMON_BIGRAM_WEIGHTS: ReadonlyArray<readonly [string, number]> = [
  ['th', 3.56], ['he', 2.51], ['in', 2.31], ['er', 2.22], ['an', 2.09], ['re', 2.06],
  ['on', 1.97], ['at', 1.88], ['en', 1.83], ['nd', 1.78], ['ti', 1.67], ['es', 1.63],
  ['or', 1.55], ['te', 1.53], ['of', 1.47], ['ed', 1.43], ['is', 1.4], ['it', 1.38],
  ['al', 1.33], ['ar', 1.31],
];

/** 常见英文词（通用高频词 + CTF 高频词），替换爬山与 XOR 精修的词命中加分用。 */
export const COMMON_WORDS: ReadonlyArray<string> = [
  'the', 'and', 'for', 'you', 'not', 'that', 'with', 'this', 'have', 'was', 'but', 'from',
  'they', 'will', 'one', 'all', 'would', 'there', 'their', 'what', 'when', 'which', 'who',
  'how', 'its', 'his', 'her', 'she', 'him', 'them', 'then', 'than', 'other', 'people',
  'into', 'time', 'over', 'after', 'also', 'some', 'could', 'these', 'just', 'like',
  'make', 'many', 'more', 'most', 'only', 'such', 'work', 'even', 'good', 'great',
  'little', 'know', 'year', 'see', 'use', 'way', 'well', 'first', 'long', 'get', 'give',
  'back', 'because', 'come', 'day', 'down', 'find', 'go', 'help', 'here', 'new', 'now',
  'old', 'right', 'same', 'take', 'think', 'two', 'want', 'world', 'out', 'about', 'up',
  'so', 'if', 'or', 'my', 'me', 'we', 'be', 'to', 'of', 'in', 'on', 'at', 'it', 'he',
  'as', 'an', 'by', 'do', 'no', 'off', 'enough', 'word', 'text', 'key', 'flag',
  'man', 'woman', 'child', 'hand', 'eye', 'head', 'foot', 'night', 'home', 'house',
  'door', 'room', 'table', 'school', 'life', 'water', 'fire', 'money', 'music', 'city',
  'town', 'road', 'book', 'tree', 'light', 'dark', 'food', 'game', 'name', 'story',
  'dog', 'cat', 'bird', 'fish', 'horse', 'king', 'queen', 'men', 'say', 'said',
  'put', 'let', 'try', 'ask', 'tell', 'found', 'thought', 'look', 'feel', 'become',
];

/** 英文重合指数参考值（随机文本约 0.038，英文约 0.066）。 */
export const ENGLISH_INDEX_OF_COINCIDENCE = 0.066;

/** 英文频率降序字母表（频率对齐初始映射用）。 */
export const ENGLISH_FREQUENCY_ORDER = 'ETAOINSHRDLCUMWFGYPBVKJXQZ';

// 内部扩展 bigram 表（约 80 项，覆盖英文相邻字母对的大头）：短文本单列/单字母评分区分度不足，
// 仅靠前 20 bigram 会被"全常见字母"的伪造解击败，扩展表用于列间/字母间耦合打分。
const EXTENDED_BIGRAMS: ReadonlyArray<readonly [string, number]> = [
  ...COMMON_BIGRAM_WEIGHTS,
  ['st', 1.28], ['to', 1.24], ['nt', 1.17], ['ng', 1.13], ['se', 1.07], ['ha', 1.03],
  ['as', 1.02], ['ou', 1.0], ['io', 0.98], ['le', 0.98], ['ve', 0.95], ['co', 0.94],
  ['me', 0.93], ['de', 0.93], ['hi', 0.91], ['ri', 0.9], ['ro', 0.89], ['ic', 0.86],
  ['ne', 0.85], ['ea', 0.84], ['ra', 0.82], ['ce', 0.76], ['li', 0.73], ['ch', 0.72],
  ['ll', 0.71], ['be', 0.7], ['ma', 0.7], ['si', 0.69], ['om', 0.68], ['ur', 0.66],
  ['ca', 0.65], ['el', 0.64], ['ta', 0.64], ['la', 0.63], ['ns', 0.62], ['di', 0.61],
  ['fo', 0.6], ['ho', 0.59], ['pe', 0.58], ['ec', 0.57], ['pr', 0.56], ['no', 0.55],
  ['ct', 0.54], ['us', 0.53], ['ac', 0.52], ['ot', 0.51], ['il', 0.51], ['tr', 0.51],
  ['ly', 0.5], ['nc', 0.49], ['et', 0.49], ['ut', 0.47], ['ss', 0.46], ['so', 0.46],
  ['rs', 0.46], ['un', 0.45], ['ge', 0.44], ['wo', 0.43], ['em', 0.42], ['ad', 0.41],
  ['wi', 0.36], ['wh', 0.38], ['rt', 0.35], ['ee', 0.33], ['go', 0.31], ['po', 0.3],
  ['br', 0.3], ['ow', 0.3], ['qu', 0.29], ['ck', 0.19], ['gh', 0.2], ['ex', 0.17],
  ['og', 0.16], ['do', 0.31], ['od', 0.15], ['am', 0.34], ['pe', 0.58], ['ap', 0.14],
];

const LETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const LETTER_FREQ = new Float64Array(26);
const LETTER_LOG_FREQ = new Float64Array(26);
for (let index = 0; index < 26; index += 1) {
  const frequency = ENGLISH_LETTER_FREQUENCIES[LETTERS[index].toLowerCase()] ?? 0.0001;
  LETTER_FREQ[index] = frequency;
  LETTER_LOG_FREQ[index] = Math.log(frequency);
}

const EXTENDED_BIGRAM_TABLE = new Float64Array(26 * 26);
for (const [bigram, weight] of EXTENDED_BIGRAMS) {
  EXTENDED_BIGRAM_TABLE[(bigram.charCodeAt(0) - 97) * 26 + (bigram.charCodeAt(1) - 97)] = weight;
}

const COMMON_WORD_PATTERN = new RegExp(`\\b(?:${COMMON_WORDS.join('|')})\\b`, 'g');
const WORD_BONUS = 14;

/** XOR 评分用单字节对数似然表：英文可打印文本先验（1e-6 平滑，字母下限 0.012——
 * 不设下限会让优化器为躲避 q/x/z 的低概率惩罚而"消灭"稀有字母，制造全常见字母的伪造解）。 */
const BYTE_LOG_PROB = (() => {
  const probabilities = new Float64Array(256).fill(1e-6);
  probabilities[0x20] = 0.17;
  for (let index = 0; index < 26; index += 1) {
    probabilities[0x61 + index] = Math.max(LETTER_FREQ[index] * 0.79, 0.012);
    probabilities[0x41 + index] = Math.max(LETTER_FREQ[index] * 0.02, 0.0015);
  }
  probabilities[0x0a] = 0.012;
  probabilities[0x0d] = 0.003;
  probabilities[0x09] = 0.002;
  const punctuation: Array<readonly [number, number]> = [
    [0x2e, 0.008], [0x2c, 0.008], [0x27, 0.005], [0x22, 0.003], [0x2d, 0.003], [0x21, 0.002],
    [0x3f, 0.002], [0x3b, 0.0015], [0x3a, 0.0015], [0x5f, 0.001], [0x28, 0.001], [0x29, 0.001],
    [0x7b, 0.0008], [0x7d, 0.0008],
  ];
  for (const [byte, probability] of punctuation) probabilities[byte] = probability;
  for (let digit = 0; digit < 10; digit += 1) probabilities[0x30 + digit] = 0.0005;
  const table = new Float64Array(256);
  for (let byte = 0; byte < 256; byte += 1) table[byte] = Math.log(probabilities[byte]);
  return table;
})();

/** mulberry32 PRNG（可播种，爬山结果可复现）。 */
const makePrng = (seed: number) => {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) | 0;
    let mixed = Math.imul(state ^ (state >>> 15), 1 | state);
    mixed = (mixed + Math.imul(mixed ^ (mixed >>> 7), 61 | mixed)) ^ mixed;
    return ((mixed ^ (mixed >>> 14)) >>> 0) / 4294967296;
  };
};

const latin1 = (bytes: Uint8Array) => {
  let output = '';
  for (let offset = 0; offset < bytes.length; offset += 4096) {
    output += String.fromCharCode(...bytes.subarray(offset, offset + 4096));
  }
  return output;
};

const letterValueOf = (byte: number) => (byte >= 97 && byte <= 122 ? byte - 97 : byte >= 65 && byte <= 90 ? byte - 65 : -1);

const xorDecrypt = (bytes: Uint8Array, key: Uint8Array) => {
  const plain = new Uint8Array(bytes.length);
  for (let index = 0; index < bytes.length; index += 1) plain[index] = bytes[index] ^ key[index % key.length];
  return plain;
};

/** 明文结构分：字节对数似然 + 相邻字母 bigram ×2（仅紧邻成对，跨空格不算），不含词加分，供精修快速评估。 */
const textStructureScore = (plain: Uint8Array) => {
  let score = 0;
  for (const byte of plain) score += BYTE_LOG_PROB[byte];
  for (let index = 1; index < plain.length; index += 1) {
    const prior = letterValueOf(plain[index - 1]);
    const current = letterValueOf(plain[index]);
    if (prior >= 0 && current >= 0) score += 2 * EXTENDED_BIGRAM_TABLE[prior * 26 + current];
  }
  return score;
};

/** 全文评分：结构分 + 常见词命中，用于候选密钥终选。 */
const fullTextScore = (plain: Uint8Array) => {
  let score = textStructureScore(plain);
  score += WORD_BONUS * (latin1(plain).toLowerCase().match(COMMON_WORD_PATTERN)?.length ?? 0);
  return score;
};

// ---- XOR 自动破译（xortool 算法） ----

export interface XorKeyLenScore {
  len: number;
  score: number;
}

export interface XorAutoSolveOptions {
  /** 猜测的明文最频字节：默认 0x20（空格，适合英文文本）；二进制数据可传 0x00。 */
  frequentPlainByte?: number;
  /** 已知明文片段（如 'flag{'）：在密文上滑动匹配并按周期一致性直接推钥。 */
  knownHint?: string;
  /** 最大候选密钥长度，默认 32。 */
  maxKeyLen?: number;
}

export interface XorAutoSolveResult {
  key: Uint8Array;
  /** 密钥的 latin1 文本形式（ASCII 密钥可直接阅读）。 */
  keyText: string;
  keyLen: number;
  /** 解密结果（latin1 解码）。 */
  plaintext: string;
  /** 各候选密钥长度的重合指数得分（长度升序）。 */
  keyLenScore: XorKeyLenScore[];
  /** 0-1 置信度：密文过短 / 重合指数低 / 解密不可打印都会压低。 */
  confidence: number;
  /** knownHint 是否通过周期一致性验证并命中明文。 */
  hintVerified: boolean;
}

/** 重合指数打分：按长度分列后，列内"等值字节对"占比（正确长度约等于明文重合指数，错误长度约 1/256）。 */
const coincidenceScore = (bytes: Uint8Array, len: number) => {
  let equalPairs = 0;
  let totalPairs = 0;
  for (let column = 0; column < len && column < bytes.length; column += 1) {
    const counts = new Uint32Array(256);
    let size = 0;
    for (let index = column; index < bytes.length; index += len) {
      counts[bytes[index]] += 1;
      size += 1;
    }
    if (size < 2) continue;
    let columnEqual = 0;
    for (let value = 0; value < 256; value += 1) columnEqual += counts[value] * (counts[value] - 1);
    equalPairs += columnEqual;
    totalPairs += size * (size - 1);
  }
  return totalPairs > 0 ? equalPairs / totalPairs : 0;
};

/** 文本模式逐列猜钥：对 256 个候选字节按对数似然打分取最优（"最高频字节 XOR 空格"的推广）。 */
const deriveXorKeyByText = (bytes: Uint8Array, len: number) => {
  const key = new Uint8Array(len);
  const counts = new Uint32Array(256);
  for (let column = 0; column < len; column += 1) {
    counts.fill(0);
    const present: number[] = [];
    for (let index = column; index < bytes.length; index += len) {
      const value = bytes[index];
      if (counts[value] === 0) present.push(value);
      counts[value] += 1;
    }
    let bestByte = 0;
    let bestScore = -Infinity;
    for (let candidate = 0; candidate < 256; candidate += 1) {
      let score = 0;
      for (const value of present) score += counts[value] * BYTE_LOG_PROB[value ^ candidate];
      if (score > bestScore) {
        bestScore = score;
        bestByte = candidate;
      }
    }
    key[column] = bestByte;
  }
  return key;
};

/** 频率模式逐列猜钥：最高频密文字节 XOR 猜测的明文最频字节。 */
const deriveXorKeyByFrequency = (bytes: Uint8Array, len: number, plainByte: number) => {
  const key = new Uint8Array(len);
  for (let column = 0; column < len; column += 1) {
    const counts = new Uint32Array(256);
    for (let index = column; index < bytes.length; index += len) counts[bytes[index]] += 1;
    let topByte = 0;
    for (let value = 1; value < 256; value += 1) if (counts[value] > counts[topByte]) topByte = value;
    key[column] = topByte ^ plainByte;
  }
  return key;
};

/** 单列按对数似然排序的前 topK 个候选字节（坐标上升/双列逃逸的候选集）。 */
const columnTopBytes = (bytes: Uint8Array, column: number, len: number, topK: number) => {
  const counts = new Uint32Array(256);
  const present: number[] = [];
  for (let index = column; index < bytes.length; index += len) {
    const value = bytes[index];
    if (counts[value] === 0) present.push(value);
    counts[value] += 1;
  }
  const scored: Array<{ byte: number; score: number }> = [];
  for (let candidate = 0; candidate < 256; candidate += 1) {
    let score = 0;
    for (const value of present) score += counts[value] * BYTE_LOG_PROB[value ^ candidate];
    scored.push({ byte: candidate, score });
  }
  scored.sort((left, right) => right.score - left.score);
  return scored.slice(0, topK).map(item => item.byte);
};

/** 单列出现频次最高的前 topK 个密文字节（经典猜测候选集：高频密文字节 XOR 常见明文字节）。 */
const columnFrequentBytes = (bytes: Uint8Array, column: number, len: number, topK: number) => {
  const counts = new Uint32Array(256);
  for (let index = column; index < bytes.length; index += len) counts[bytes[index]] += 1;
  const order = Array.from({ length: 256 }, (_, index) => index).sort((left, right) => counts[right] - counts[left] || left - right);
  return order.slice(0, topK);
};

const PLAIN_GUESS_BYTES = [0x20, 0x65, 0x74, 0x61, 0x6f];

/**
 * 坐标上升精修 + 双列联合逃逸：
 * - 单列独立评分会被"全常见字母"的伪造密钥骗过（短文本/周期文本），全文耦合评分能纠正多数列；
 * - 个别错误成对出现（单独翻转任一列都是负收益，如 'th' 被挪进别的词），需要两列联合翻转才能逃逸；
 * - rich 模式（短密钥）把常见词命中并入目标函数，并用"高频密文字节 × 常见明文字节"扩充候选集。
 */
const refineXorKey = (bytes: Uint8Array, key: Uint8Array, rich: boolean) => {
  let currentScore = textStructureScore(xorDecrypt(bytes, key));
  const options: number[][] = Array.from({ length: key.length }, (_, column) => {
    const guesses = rich
      ? columnFrequentBytes(bytes, column, key.length, 3).flatMap(byte => PLAIN_GUESS_BYTES.map(guess => byte ^ guess))
      : [];
    return [...new Set([...columnTopBytes(bytes, column, key.length, 8), ...guesses])];
  });
  const optionScore = rich ? fullTextScore : textStructureScore;

  const ascendFull = () => {
    for (let column = 0; column < key.length; column += 1) {
      const original = key[column];
      let bestByte = original;
      let bestScore = currentScore;
      for (let candidate = 0; candidate < 256; candidate += 1) {
        if (candidate === original) continue;
        key[column] = candidate;
        const score = textStructureScore(xorDecrypt(bytes, key));
        if (score > bestScore) {
          bestScore = score;
          bestByte = candidate;
        }
      }
      key[column] = bestByte;
      if (bestByte !== original) currentScore = bestScore;
    }
  };
  const ascendOptions = () => {
    let bestScore = optionScore(xorDecrypt(bytes, key));
    let improved = true;
    while (improved) {
      improved = false;
      for (let column = 0; column < key.length; column += 1) {
        const original = key[column];
        let bestByte = original;
        let bestScoreColumn = bestScore;
        for (const candidate of options[column]) {
          if (candidate === original) continue;
          key[column] = candidate;
          const score = optionScore(xorDecrypt(bytes, key));
          if (score > bestScoreColumn) {
            bestScoreColumn = score;
            bestByte = candidate;
          }
        }
        key[column] = bestByte;
        if (bestByte !== original) {
          bestScore = bestScoreColumn;
          improved = true;
        }
      }
    }
    currentScore = bestScore;
  };

  ascendFull();
  for (let round = 0; round < 2; round += 1) {
    let escaped = false;
    for (let a = 0; a < key.length; a += 1) {
      for (let b = a + 1; b < key.length; b += 1) {
        const baseA = key[a];
        const baseB = key[b];
        let bestA = baseA;
        let bestB = baseB;
        let bestScore = currentScore;
        for (const candidateA of options[a]) {
          for (const candidateB of options[b]) {
            if (candidateA === baseA && candidateB === baseB) continue;
            key[a] = candidateA;
            key[b] = candidateB;
            const score = optionScore(xorDecrypt(bytes, key));
            if (score > bestScore) {
              bestScore = score;
              bestA = candidateA;
              bestB = candidateB;
            }
          }
        }
        key[a] = bestA;
        key[b] = bestB;
        if (bestA !== baseA || bestB !== baseB) {
          currentScore = bestScore;
          escaped = true;
        }
      }
    }
    if (!escaped) break;
    ascendFull();
    ascendOptions();
  }
  return key;
};

/** 密钥的最小重复周期（'SecretKeySecretKey' → 9），用于把整数倍候选长度归约回真实长度。 */
const bytePeriod = (key: Uint8Array) => {
  for (let period = 1; period < key.length; period += 1) {
    let periodic = true;
    for (let index = period; index < key.length; index += 1) {
      if (key[index] !== key[index % period]) {
        periodic = false;
        break;
      }
    }
    if (periodic) return period;
  }
  return key.length;
};

export const xorAutoSolve = (bytes: Uint8Array, options: XorAutoSolveOptions = {}): XorAutoSolveResult => {
  if (!bytes.length) {
    return { key: new Uint8Array(0), keyText: '', keyLen: 0, plaintext: '', keyLenScore: [], confidence: 0, hintVerified: false };
  }
  const plainByte = options.frequentPlainByte ?? 0x20;
  const hint = options.knownHint ?? '';
  const maxLen = Math.max(1, Math.min(options.maxKeyLen ?? 32, Math.floor(bytes.length / 2)));
  const textMode = plainByte === 0x20;

  const keyLenScore: XorKeyLenScore[] = [];
  for (let len = 1; len <= maxLen; len += 1) keyLenScore.push({ len, score: coincidenceScore(bytes, len) });
  const bestCoincidence = Math.max(...keyLenScore.map(item => item.score));

  interface KeyCandidate {
    key: Uint8Array;
    verified: boolean;
    fromHint: boolean;
  }
  const candidates: KeyCandidate[] = [];
  const pushCandidate = (key: Uint8Array, verified: boolean, fromHint: boolean) => {
    const identity = `${key.length}:${latin1(key)}`;
    const existing = candidates.find(item => `${item.key.length}:${latin1(item.key)}` === identity);
    if (existing) {
      // 同一密钥可能先由重合指数路径（未验证）推出、后由 knownHint 周期验证：合并验证标志
      if (verified && !existing.verified) existing.verified = true;
      return;
    }
    candidates.push({ key, verified, fromHint });
  };

  // 候选一：重合指数显著高于随机水平（1/256≈0.004）且不低于最优值 35% 的长度（覆盖真长度的整数倍）。
  const lens = keyLenScore.filter(item => item.score >= Math.max(0.025, bestCoincidence * 0.35)).map(item => item.len);
  if (!lens.length) {
    const top = keyLenScore.reduce((left, right) => (right.score > left.score ? right : left));
    lens.push(top.len);
  }
  for (const len of lens) {
    pushCandidate(textMode ? deriveXorKeyByText(bytes, len) : deriveXorKeyByFrequency(bytes, len, plainByte), false, false);
  }

  // 候选二：knownHint 滑动推钥——hint 导出的密钥流最小周期小于 hint 长度才算通过一致性验证。
  if (hint.length >= 2 && hint.length <= bytes.length) {
    for (let offset = 0; offset + hint.length <= bytes.length; offset += 1) {
      const stream = new Uint8Array(hint.length);
      for (let index = 0; index < hint.length; index += 1) {
        stream[index] = hint.charCodeAt(index) ^ bytes[offset + index];
      }
      for (let period = 1; period <= Math.min(maxLen, hint.length); period += 1) {
        if (period < hint.length) {
          let periodic = true;
          for (let index = period; index < hint.length; index += 1) {
            if (stream[index] !== stream[index % period]) {
              periodic = false;
              break;
            }
          }
          if (!periodic) continue;
        }
        pushCandidate(stream.slice(0, period), period < hint.length, true);
        break;
      }
    }
  }

  // 终选：全文评分（含词加分）+ 命中 knownHint 的强加成，平分时取更短密钥；频率派生的候选先做全文精修。
  let bestCandidate: KeyCandidate | null = null;
  let bestRank = -Infinity;
  let bestPlain = new Uint8Array(0);
  let bestLenScore = 0;
  for (const candidate of candidates) {
    if (!candidate.verified && textMode) {
      // 重合指数候选做富精修（短密钥才含词加分，控制耗时）；未验证的 hint 候选只做结构精修
      refineXorKey(bytes, candidate.key, !candidate.fromHint && candidate.key.length <= 12);
    }
    const plain = xorDecrypt(bytes, candidate.key);
    const rank = fullTextScore(plain) / plain.length + (hint && latin1(plain).includes(hint) ? 3 : 0) - candidate.key.length * 1e-6;
    const lenScore = keyLenScore.find(item => item.len === candidate.key.length)?.score ?? 0;
    if (rank > bestRank) {
      bestRank = rank;
      bestCandidate = candidate;
      bestPlain = plain;
      bestLenScore = lenScore;
    }
  }
  if (!bestCandidate) {
    return { key: new Uint8Array(0), keyText: '', keyLen: 0, plaintext: latin1(bytes), keyLenScore, confidence: 0, hintVerified: false };
  }

  const period = bytePeriod(bestCandidate.key);
  const key = period < bestCandidate.key.length ? bestCandidate.key.slice(0, period) : bestCandidate.key;
  const plainBytes = period < bestCandidate.key.length ? xorDecrypt(bytes, key) : bestPlain;
  const plaintext = latin1(plainBytes);

  let printable = 0;
  for (const byte of plainBytes) {
    if (byte === 9 || byte === 10 || byte === 13 || (byte >= 32 && byte <= 126)) printable += 1;
  }
  const printableRatio = printable / plainBytes.length;
  let confidence = (0.6 * printableRatio + 0.4 * Math.min(1, bestLenScore / 0.06)) * Math.min(1, bytes.length / 40);
  if (bestCandidate.verified && hint && plaintext.includes(hint)) confidence = Math.max(confidence, 0.8);
  confidence = Math.min(confidence, 0.99);

  return { key, keyText: latin1(key), keyLen: key.length, plaintext, keyLenScore, confidence, hintVerified: bestCandidate.verified };
};

// ---- Vigenère 自动破译（IC 择优 + 列卡方拟合） ----

export interface VigenereAutoSolveResult {
  /** 大写字母密钥。 */
  key: string;
  keyLen: number;
  /** 解密结果：保留大小写与非字母原样。 */
  plaintext: string;
  confidence: number;
  /** 因子族候选（最优长度与最小非平凡因子不同时给出）：字母+bigram 目标下整数倍长度
   *  可过拟合出伪英文，正确解可能是其中较短者，由选手并排识别。 */
  alternate?: { key: string; keyLen: number; plaintext: string };
}

const extractLetters = (text: string) => {
  const positions: number[] = [];
  const values: number[] = [];
  for (let index = 0; index < text.length; index += 1) {
    const code = text.charCodeAt(index);
    if (code >= 65 && code <= 90) {
      positions.push(index);
      values.push(code - 65);
    } else if (code >= 97 && code <= 122) {
      positions.push(index);
      values.push(code - 97);
    }
  }
  // adjacent[i]：第 i 个字母与上一个字母在原文中是否紧邻（跨空格/标点不成 bigram）
  const adjacent = positions.map((position, index) => index > 0 && position === positions[index - 1] + 1);
  return { positions, values, adjacent };
};

/** 各列重合指数的平均值（英文约 0.066，随机约 0.038）。 */
const columnIndexOfCoincidence = (values: number[], len: number) => {
  let icSum = 0;
  let columns = 0;
  for (let column = 0; column < len; column += 1) {
    const counts = new Uint32Array(26);
    let size = 0;
    for (let index = column; index < values.length; index += len) {
      counts[values[index]] += 1;
      size += 1;
    }
    if (size < 2) continue;
    let equal = 0;
    for (const count of counts) equal += count * (count - 1);
    icSum += equal / (size * (size - 1));
    columns += 1;
  }
  return columns > 0 ? icSum / columns : 0;
};

/** 单列卡方拟合：返回使解密列字母分布最贴近英文频率的移位量（即密钥字母）。 */
const chiSquaredShift = (values: number[], start: number, len: number) => {
  const counts = new Float64Array(26);
  let size = 0;
  for (let index = start; index < values.length; index += len) {
    counts[values[index]] += 1;
    size += 1;
  }
  let bestShift = 0;
  let bestChi = Infinity;
  for (let shift = 0; shift < 26; shift += 1) {
    let chi = 0;
    for (let plain = 0; plain < 26; plain += 1) {
      const observed = counts[(plain + shift) % 26];
      const expected = size * LETTER_FREQ[plain];
      chi += (observed - expected) ** 2 / expected;
    }
    if (chi < bestChi) {
      bestChi = chi;
      bestShift = shift;
    }
  }
  return bestShift;
};

const letterStreamScore = (plainValues: number[], adjacent: boolean[]) => {
  let score = 0;
  for (const value of plainValues) score += LETTER_LOG_FREQ[value];
  for (let index = 1; index < plainValues.length; index += 1) {
    if (adjacent[index]) score += 2 * EXTENDED_BIGRAM_TABLE[plainValues[index - 1] * 26 + plainValues[index]];
  }
  return score;
};

export const vigenereAutoSolve = (cipher: string): VigenereAutoSolveResult => {
  const { positions, values, adjacent } = extractLetters(cipher);
  const letterCount = values.length;
  if (!letterCount) return { key: '', keyLen: 0, plaintext: cipher, confidence: 0 };
  const maxLen = Math.max(1, Math.min(20, Math.floor(letterCount / 2)));
  const decryptWithKey = (key: number[]) => values.map((value, index) => (value - key[index % key.length] + 26) % 26);

  // 完整求解单个候选长度（卡方初值 + 列级 bigram 精修），返回 { key, rank }。
  const solveForLength = (len: number): { key: number[]; rank: number } => {
    const key = Array.from({ length: len }, (_, column) => chiSquaredShift(values, column, len));
    // 列级精修：列样本少时卡方会有偏差，用全文 bigram 耦合评分逐列重试 26 个移位。
    // 带 4 分边际门控：评分在列样本上有噪声，微小"改进"不采纳，避免把卡方已正确的列漂移错。
    let currentScore = letterStreamScore(decryptWithKey(key), adjacent);
    for (let round = 0; round < 3; round += 1) {
      let improved = false;
      for (let column = 0; column < len; column += 1) {
        const original = key[column];
        let bestShift = original;
        let bestScore = currentScore + 4;
        for (let shift = 0; shift < 26; shift += 1) {
          if (shift === original) continue;
          key[column] = shift;
          const score = letterStreamScore(decryptWithKey(key), adjacent);
          if (score > bestScore) {
            bestScore = score;
            bestShift = shift;
          }
        }
        key[column] = bestShift;
        if (bestShift !== original) {
          currentScore = bestScore - 4;
          improved = true;
        }
      }
      if (!improved) break;
    }
    return { key, rank: currentScore - len * 1e-6 };
  };

  // 长度选择：先扫描全长度找评分最优，再对其全部真因子重解比较——评分按每字母归一化，
  // 长密钥列精修的过拟合优势摊到每字母后消失（正确解的明文就是最高 bigram 分），
  // 归一化分并列（差 < 0.005/字母）时取更短（奥卡姆）。IC 只做粗筛跳过明显随机的长度以省计算。
  const RANDOM_IC = 0.0385;
  const icByLen: number[] = [];
  let bestIc = 0;
  for (let len = 1; len <= maxLen; len += 1) {
    const ic = columnIndexOfCoincidence(values, len);
    icByLen[len] = ic;
    if (ic > bestIc) bestIc = ic;
  }
  const icFloor = bestIc > RANDOM_IC * 1.3 ? Math.min(RANDOM_IC * 1.3 + (bestIc - RANDOM_IC) * 0.25, bestIc) : bestIc;

  let bestKey: number[] = [];
  let bestPerLetter = -Infinity;
  let bestLen = 1;
  for (let len = 1; len <= maxLen; len += 1) {
    if (len > 1 && icByLen[len] < icFloor) continue;
    const { key, rank } = solveForLength(len);
    const perLetter = (rank + len * 1e-6) / letterCount;
    if (perLetter > bestPerLetter) {
      bestPerLetter = perLetter;
      bestKey = key;
      bestLen = len;
    }
  }
  // 真因子重解归约：bestLen 的全部真因子（含 1）重解，归一化分接近（0.005/字母容差）即取更短。
  for (let d = 1; d < bestLen; d += 1) {
    if (bestLen % d !== 0) continue;
    const { key, rank } = solveForLength(d);
    const perLetter = (rank + d * 1e-6) / letterCount;
    if (perLetter >= bestPerLetter - 0.005) {
      bestKey = key;
      bestLen = d;
      bestPerLetter = perLetter;
      break;
    }
  }

  // 缩减到密钥最小周期（'CRYPTOCRYPTO' → 'CRYPTO'）。
  let keyLen = bestKey.length;
  for (let period = 1; period < keyLen; period += 1) {
    let periodic = true;
    for (let index = period; index < bestKey.length; index += 1) {
      if (bestKey[index] !== bestKey[index % period]) {
        periodic = false;
        break;
      }
    }
    if (periodic) {
      keyLen = period;
      break;
    }
  }

  const plainValues = decryptWithKey(bestKey);
  const output = Array.from(cipher);
  for (let index = 0; index < positions.length; index += 1) {
    const position = positions[index];
    const code = cipher.charCodeAt(position);
    output[position] = String.fromCharCode((code >= 65 && code <= 90 ? 65 : 97) + plainValues[index]);
  }
  const confidence = Math.min(0.99, Math.max(0, (bestIc - 0.038) / (ENGLISH_INDEX_OF_COINCIDENCE - 0.038)) * Math.min(1, letterCount / 60));

  // 因子族多候选（实战需要）：字母+bigram 目标下，真密钥长的整数倍可过拟合出"高频伪英文"超过真解——
  // 把最优长度与其最小非平凡因子（若不同）的解都返回，由选手并排识别正确明文（xortool 同策略）。
  const primary = {
    key: bestKey.slice(0, keyLen).map(shift => LETTERS[shift]).join(''),
    keyLen,
    plaintext: output.join(''),
  };
  let alternate: { key: string; keyLen: number; plaintext: string } | null = null;
  if (bestLen > 2) {
    // 全部真因子（≥2 且 < bestLen）重解，取每字母分最高的作为并排候选——
    // 正确密钥长度的明文分理论上限就是真明文，通常即因子族中的最优短解。
    let altBest: { key: number[]; perLetter: number } | null = null;
    for (let d = 2; d < bestLen; d += 1) {
      if (bestLen % d !== 0) continue;
      const solved = solveForLength(d);
      const perLetter = (solved.rank + d * 1e-6) / letterCount;
      if (!altBest || perLetter > altBest.perLetter) altBest = { key: solved.key, perLetter };
    }
    if (altBest) {
      let altKeyLen = altBest.key.length;
      for (let period = 1; period < altKeyLen; period += 1) {
        let periodic = true;
        for (let index = period; index < altBest.key.length; index += 1) {
          if (altBest.key[index] !== altBest.key[index % period]) { periodic = false; break; }
        }
        if (periodic) { altKeyLen = period; break; }
      }
      const altPlainValues = decryptWithKey(altBest.key);
      const altOutput = Array.from(cipher);
      for (let index = 0; index < positions.length; index += 1) {
        const position = positions[index];
        const code = cipher.charCodeAt(position);
        altOutput[position] = String.fromCharCode((code >= 65 && code <= 90 ? 65 : 97) + altPlainValues[index]);
      }
      alternate = {
        key: altBest.key.slice(0, altKeyLen).map(shift => LETTERS[shift]).join(''),
        keyLen: altKeyLen,
        plaintext: altOutput.join(''),
      };
    }
  }
  return {
    ...primary,
    confidence,
    ...(alternate ? { alternate } : {}),
  };
};

// ---- 单表替换自动破译（频率对齐 + shotgun 爬山） ----

export interface SubstitutionAutoSolveOptions {
  /** 已知词锚点（如 ['flag','the']）：作为硬约束锁定对应密文字母的映射。 */
  cribs?: string[];
  /** 每轮爬山随机交换尝试上限，默认 2000。 */
  maxRounds?: number;
  /** shotgun 重启次数，默认 6。 */
  restarts?: number;
  /** PRNG 种子（默认固定值，结果可复现）。 */
  seed?: number;
}

export interface SubstitutionAutoSolveResult {
  /** 密文字母 → 明文字母（均大写，26 项双射）。 */
  mapping: Record<string, string>;
  /** 26 位字母串：明文字母位 → 密文字母，可直接作为单表替换解码密钥字母表。 */
  mappingKey: string;
  /** 解密结果：保留大小写与非字母原样。 */
  plaintext: string;
  score: number;
  /** 密文字母少于 25 个时可靠性不足，置信度封顶 0.3。 */
  confidence: number;
}

const BIGRAM_SCALE = 2.5;

export const substitutionAutoSolve = (cipher: string, options: SubstitutionAutoSolveOptions = {}): SubstitutionAutoSolveResult => {
  const cribs = (options.cribs ?? [])
    .map(crib => crib.toUpperCase().replace(/[^A-Z]/g, ''))
    .filter(crib => crib.length >= 2);
  const maxRounds = Math.max(200, options.maxRounds ?? 2000);
  const restarts = Math.max(1, options.restarts ?? 6);
  const prng = makePrng(options.seed ?? 0x5eed1234);

  const { positions, values, adjacent } = extractLetters(cipher);
  const letterCount = values.length;

  // 密文字母频率排序 + 英文频率顺序 → 频率对齐初始映射。
  const counts = new Uint32Array(26);
  for (const value of values) counts[value] += 1;
  const frequencyOrder = Array.from({ length: 26 }, (_, index) => index)
    .sort((left, right) => counts[right] - counts[left] || left - right);
  const englishOrder = Array.from(ENGLISH_FREQUENCY_ORDER, char => char.charCodeAt(0) - 65);

  // 评分缓冲区复用：每次交换评估只重算字母流与渲染，不重新分配。
  const plainValues = new Int32Array(letterCount);
  const charCodes = new Uint16Array(cipher.length);
  for (let index = 0; index < cipher.length; index += 1) charCodes[index] = cipher.charCodeAt(index);

  const scoreMapping = (mapping: Uint8Array) => {
    let score = 0;
    for (let index = 0; index < letterCount; index += 1) {
      plainValues[index] = mapping[values[index]];
      score += LETTER_LOG_FREQ[plainValues[index]];
    }
    for (let index = 1; index < letterCount; index += 1) {
      if (adjacent[index]) score += BIGRAM_SCALE * EXTENDED_BIGRAM_TABLE[plainValues[index - 1] * 26 + plainValues[index]];
    }
    for (let index = 0; index < letterCount; index += 1) {
      const position = positions[index];
      const code = cipher.charCodeAt(position);
      charCodes[position] = (code >= 65 && code <= 90 ? 65 : 97) + plainValues[index];
    }
    const text = String.fromCharCode(...charCodes);
    const wordHits = text.toLowerCase().match(COMMON_WORD_PATTERN)?.length ?? 0;
    return score + WORD_BONUS * wordHits;
  };

  interface Seed {
    mapping: Uint8Array;
    locked: Uint8Array;
  }
  const seeds: Seed[] = [];
  const freqSeed = new Uint8Array(26);
  frequencyOrder.forEach((cipherLetter, rank) => {
    freqSeed[cipherLetter] = englishOrder[rank];
  });
  seeds.push({ mapping: freqSeed, locked: new Uint8Array(26) });

  // crib 窗口种子：滑动已知词，找双射一致的位置，锁定锚点后按频率补全其余映射。
  for (const crib of cribs) {
    if (crib.length > letterCount) continue;
    const windows: Seed[] = [];
    for (let start = 0; start + crib.length <= letterCount; start += 1) {
      const mapping = new Uint8Array(26).fill(255);
      const used = new Uint8Array(26);
      let consistent = true;
      for (let index = 0; index < crib.length; index += 1) {
        const cipherLetter = values[start + index];
        const plainLetter = crib.charCodeAt(index) - 65;
        if (mapping[cipherLetter] !== 255) {
          if (mapping[cipherLetter] !== plainLetter) {
            consistent = false;
            break;
          }
        } else if (used[plainLetter]) {
          consistent = false;
          break;
        } else {
          mapping[cipherLetter] = plainLetter;
          used[plainLetter] = 1;
        }
      }
      if (!consistent) continue;
      const locked = new Uint8Array(26);
      for (let letter = 0; letter < 26; letter += 1) if (mapping[letter] !== 255) locked[letter] = 1;
      const remainingPlain = englishOrder.filter(plain => !used[plain]);
      let cursor = 0;
      for (const cipherLetter of frequencyOrder) {
        if (mapping[cipherLetter] === 255) {
          mapping[cipherLetter] = remainingPlain[cursor];
          cursor += 1;
        }
      }
      windows.push({ mapping, locked });
    }
    windows.sort((left, right) => scoreMapping(right.mapping) - scoreMapping(left.mapping));
    for (const window of windows.slice(0, 3)) seeds.push(window);
  }

  // shotgun 爬山：随机交换两个未锁定映射位，接受更优；连续无改进即收敛，打散后重启；
  // 收尾做确定性全对交换扫描，修复随机搜索漏掉的近距离更优解。
  const climb = (seed: Seed) => {
    let current = seed.mapping.slice();
    let currentScore = scoreMapping(current);
    let best = current.slice();
    let bestScore = currentScore;
    const staleLimit = Math.max(200, Math.floor(maxRounds / 5));
    for (let restart = 0; restart < restarts; restart += 1) {
      if (restart > 0) {
        current = best.slice();
        for (let perturb = 0; perturb < 4; perturb += 1) {
          const i = (prng() * 26) | 0;
          const j = (prng() * 26) | 0;
          if (i !== j && !seed.locked[i] && !seed.locked[j]) {
            const temp = current[i];
            current[i] = current[j];
            current[j] = temp;
          }
        }
        currentScore = scoreMapping(current);
      }
      let stale = 0;
      for (let round = 0; round < maxRounds && stale < staleLimit; round += 1) {
        const i = (prng() * 26) | 0;
        const j = (prng() * 26) | 0;
        if (i === j || seed.locked[i] || seed.locked[j]) continue;
        const temp = current[i];
        current[i] = current[j];
        current[j] = temp;
        const score = scoreMapping(current);
        if (score > currentScore) {
          currentScore = score;
          stale = 0;
          if (score > bestScore) {
            bestScore = score;
            best = current.slice();
          }
        } else {
          const back = current[i];
          current[i] = current[j];
          current[j] = back;
          stale += 1;
        }
      }
    }
    let improved = true;
    while (improved) {
      improved = false;
      for (let i = 0; i < 26; i += 1) {
        for (let j = i + 1; j < 26; j += 1) {
          if (seed.locked[i] || seed.locked[j]) continue;
          const temp = best[i];
          best[i] = best[j];
          best[j] = temp;
          const score = scoreMapping(best);
          if (score > bestScore) {
            bestScore = score;
            improved = true;
          } else {
            const back = best[i];
            best[i] = best[j];
            best[j] = back;
          }
        }
      }
    }
    return { mapping: best, score: bestScore };
  };

  let solved = climb(seeds[0]);
  for (const seed of seeds.slice(1)) {
    const candidate = climb(seed);
    if (candidate.score > solved.score) solved = candidate;
  }

  const mappingRecord: Record<string, string> = {};
  const inverse = new Uint8Array(26);
  for (let letter = 0; letter < 26; letter += 1) {
    mappingRecord[LETTERS[letter]] = LETTERS[solved.mapping[letter]];
    inverse[solved.mapping[letter]] = letter;
  }
  const output = Array.from(cipher);
  for (let index = 0; index < letterCount; index += 1) {
    const position = positions[index];
    const code = cipher.charCodeAt(position);
    output[position] = String.fromCharCode((code >= 65 && code <= 90 ? 65 : 97) + solved.mapping[values[index]]);
  }
  let bigramHits = 0;
  for (let index = 1; index < letterCount; index += 1) {
    if (adjacent[index] && EXTENDED_BIGRAM_TABLE[solved.mapping[values[index - 1]] * 26 + solved.mapping[values[index]]] > 0) bigramHits += 1;
  }
  const hitBase = letterCount > 1 ? adjacent.reduce((sum, value) => sum + (value ? 1 : 0), 0) : 1;
  const coverage = hitBase > 0 ? bigramHits / hitBase : 0;
  let confidence = Math.min(0.95, Math.max(0, (coverage - 0.15) / 0.3)) * Math.min(1, letterCount / 40);
  if (letterCount < 25) confidence = Math.min(confidence, 0.3);
  return {
    mapping: mappingRecord,
    mappingKey: Array.from(inverse).map(letter => LETTERS[letter]).join(''),
    plaintext: output.join(''),
    score: solved.score,
    confidence,
  };
};
