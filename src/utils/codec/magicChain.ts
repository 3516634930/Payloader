// CyberChef Magic 等价：洋葱式多层编码链（flag → base64 → hex → base32 …）的 BFS 全链自动
// 解开 + 可读性排名。解码一律复用仓库现有纯文本→文本函数（bases/textEncodings/autoSolve 频率表），
// 本文件只新增门控、评分与 beam 剪枝；不重实现任何编码算法，无 eval、无网络、无副作用。
import {
  base64ToText,
  decodeAscii85,
  decodeBase32,
  decodeBase36,
  decodeBase58,
  decodeBase62,
  decodeUuencode,
  decodeXxencode,
  hexToBytes,
} from './bases';
import { caesar } from './textEncodings';
import { ENGLISH_LETTER_FREQUENCIES } from './autoSolve';
import { utf8Decoder } from './alphabets';

export interface MagicChainCandidate {
  chain: string[];
  result: string;
  score: number;
  printableRatio: number;
  entropy: number;
  flagLike: boolean;
}

export interface MagicChainOptions {
  maxDepth?: number;
  beamWidth?: number;
  topN?: number;
}

interface ChainStep {
  step: number;
  label: string;
  length: number;
  preview: string;
}

interface TextMetrics {
  printableRatio: number;
  controlRatio: number;
  entropy: number;
  cjkRatio: number;
  flagLike: boolean;
  score: number;
}

interface InternalCandidate {
  text: string;
  chain: string[];
  steps: ChainStep[];
  metrics: TextMetrics;
}

// —— 门控/剪枝阈值（改动需同步评估误杀率与分支爆炸）——
const INPUT_CHAR_LIMIT = 65536;        // 超长输入截断到 64KB 再扫描，防 O(n²) bigint 与评分热点
const RESULT_PREVIEW_LIMIT = 512;      // 候选 result 展示截断
const STEP_PREVIEW_LIMIT = 160;        // 报告每步中间形态摘要截断
const MAX_DEPTH_HARD = 4;              // 深度硬上限：白名单 11 步 × beam 16 时全图规模可控
const DEFAULT_MAX_DEPTH = 3;
const DEFAULT_BEAM_WIDTH = 16;         // 每层存活分支上限：真链中间态分数不占优，需保冗余分支
const DEFAULT_TOP_N = 8;
const CONTROL_RATIO_MAX = 0.05;        // 输出控制字符（\n\r\t 外，含 U+FFFD/C1 区）占比 >5% 判失败
const BIGINT_BASE_INPUT_LIMIT = 4096;  // base36/58/62 整数基码解码是 O(n²) bigint 运算，超长直接放弃该分支

const FLAG_LIKE_PATTERN = /(?:flag|ctf|picoctf|htb|thm|ductf|corctf|dice|wctf|utflag|sekai|actf|seccon|ritsec|crypto|lactf|crew|nahamcon|hsctf|justctf|b01lers|wanictf|jerseyctf|key)\{|\{[A-Za-z0-9_]{2,}:/i;

const LETTER_FREQ = Array.from({ length: 26 }, (_, index) => ENGLISH_LETTER_FREQUENCIES[String.fromCharCode(97 + index)] ?? 0.0001);

const stripWhitespace = (text: string) => text.replace(/\s+/g, '');

// 规整串中"落在 allowed 之外"的字符占比（空白已剥离，解码器均容忍空白）
const disallowedRatio = (compact: string, disallowed: RegExp): number => {
  if (!compact.length) return 1;
  const bad = compact.match(disallowed);
  return (bad ? bad.length : 0) / compact.length;
};

const englishness = (text: string): number => {
  const letters = text.toLowerCase().match(/[a-z]/g);
  if (!letters) return 0;
  const total = letters.length;
  // 短样本（卡方自由度噪音）与低字母占比下 chi-squared 无区分度：≥8 字母且占全文 ≥30% 才计分
  if (total < 8 || total < text.length * 0.3) return 0;
  const counts = new Array<number>(26).fill(0);
  for (const char of letters) counts[char.charCodeAt(0) - 97] += 1;
  let chiSquared = 0;
  for (let index = 0; index < 26; index += 1) {
    const expected = total * LETTER_FREQ[index];
    const diff = counts[index] - expected;
    chiSquared += (diff * diff) / expected;
  }
  // 逐字母归一：英文样本 →0（有限样本 ~25/n），均匀随机字母 ≈2.7；1.5 作满分局点
  const perChar = chiSquared / total;
  return Math.max(0, Math.min(1, 1 - perChar / 1.5));
};

const metricsOf = (text: string): TextMetrics => {
  let printable = 0;
  let cjk = 0;
  const frequencies = new Map<string, number>();
  for (let index = 0; index < text.length; index += 1) {
    const code = text.charCodeAt(index);
    const char = text.charAt(index);
    // 可打印 = ASCII 可见 + \t\r\n + ≥0xA0（含 CJK 与全角标点）；C1 控制区(0x7F-0x9F)与 U+FFFD 计为坏字符
    if ((code >= 32 && code <= 126) || code === 9 || code === 10 || code === 13 || code >= 0xa0) printable += 1;
    if (code >= 0x4e00 && code <= 0x9fff) cjk += 1;
    frequencies.set(char, (frequencies.get(char) || 0) + 1);
  }
  const total = Math.max(1, text.length);
  let entropy = 0;
  for (const count of frequencies.values()) {
    const probability = count / total;
    entropy -= probability * Math.log2(probability);
  }
  const printableRatio = printable / total;
  const cjkRatio = cjk / total;
  const flagLike = FLAG_LIKE_PATTERN.test(text);
  const score = englishness(text) * 30
    + printableRatio * 20
    + (cjkRatio >= 0.3 ? 40 : 0)
    + (flagLike ? 1000 : 0);
  return { printableRatio, controlRatio: 1 - printableRatio, entropy, cjkRatio, flagLike, score };
};

interface ChainOp {
  label: string;
  gate: (text: string) => string | null;
  decode: (gated: string) => string;
}

const OPS: ChainOp[] = [
  {
    label: 'hex',
    gate: text => {
      const compact = stripWhitespace(text);
      // hexToBytes 会静默丢弃非 hex 字符导致字节错位，故要求规整后 100% 纯 hex 且偶数长度（严于 90% 总门）
      if (compact.length < 4 || compact.length % 2 !== 0 || /[^0-9a-fA-F]/.test(compact)) return null;
      return compact;
    },
    decode: compact => utf8Decoder.decode(hexToBytes(compact)),
  },
  {
    label: 'base64',
    gate: text => {
      const compact = stripWhitespace(text);
      if (compact.length < 8) return null;
      const body = compact.replace(/=+$/, '');
      // atob 对非法字符在浏览器抛错、在 Node Buffer 实现下静默跳过，两端语义统一为 100% charset 纯净才尝试
      if (body.length < 4 || /=/.test(body) || /[^A-Za-z0-9+/_-]/.test(body)) return null;
      return compact;
    },
    decode: base64ToText,
  },
  {
    label: 'base32',
    gate: text => {
      const compact = stripWhitespace(text);
      if (compact.length < 8) return null;
      const body = compact.replace(/=+$/, '');
      if (body.length < 4 || /=/.test(body) || /[^A-Za-z2-7]/.test(body)) return null;
      return compact;
    },
    decode: compact => decodeBase32(compact),
  },
  {
    label: 'base58',
    gate: text => {
      const compact = stripWhitespace(text);
      if (compact.length < 4 || compact.length > BIGINT_BASE_INPUT_LIMIT || /[^1-9A-HJ-NP-Za-km-z]/.test(compact)) return null;
      return compact;
    },
    decode: decodeBase58,
  },
  {
    label: 'base62',
    gate: text => {
      const compact = stripWhitespace(text);
      if (compact.length < 4 || compact.length > BIGINT_BASE_INPUT_LIMIT || /[^0-9A-Za-z]/.test(compact)) return null;
      return compact;
    },
    decode: decodeBase62,
  },
  {
    label: 'base36',
    gate: text => {
      const compact = stripWhitespace(text);
      // 规格约束：仅当输入是纯字母数字且可数值化（decodeBase36 大写规整后即数值）
      if (compact.length < 4 || compact.length > BIGINT_BASE_INPUT_LIMIT || /[^0-9A-Za-z]/.test(compact)) return null;
      return compact;
    },
    decode: decodeBase36,
  },
  {
    label: 'url-decode',
    gate: text => {
      // 无 %XX 转义不构成 URL 编码输入；其余字符 ≥90% 落在可打印 ASCII 内（规格门限）
      if (!/%[0-9a-fA-F]{2}/.test(text)) return null;
      if (disallowedRatio(stripWhitespace(text), /[^!-~]/g) > 0.1) return null;
      return text;
    },
    decode: decodeURIComponent,
  },
  {
    label: 'base85',
    gate: text => {
      const trimmed = text.trim();
      const wrapped = trimmed.startsWith('<~');
      const compact = trimmed.replace(/^<~/, '').replace(/~>$/, '').replace(/\s+/g, '');
      if (compact.length < 8 || /[^!-uz]/.test(compact)) return null;
      // ASCII85 字符集（!-u）覆盖全部字母数字：无 <~ 包装时要求字母数字占比 ≤75%（真实 Ascii85
      // 输出约 27% 字符落在字母数字之外），防止对任意可打印文本无差别开分支
      if (!wrapped) {
        const alnum = compact.match(/[A-Za-z0-9]/g);
        if (!alnum || alnum.length / compact.length > 0.75) return null;
      }
      return compact;
    },
    decode: decodeAscii85,
  },
  {
    label: 'uuencode',
    gate: text => {
      // 块结构（begin/end 行）是硬形状门；行内字符 ≥90% 可打印 ASCII
      if (!/^begin\s+\d+\s+\S+/m.test(text) || !/^end\s*$/m.test(text)) return null;
      if (disallowedRatio(stripWhitespace(text), /[^!-~]/g) > 0.1) return null;
      return text;
    },
    decode: decodeUuencode,
  },
  {
    label: 'xxencode',
    gate: text => {
      if (!/^begin\s+\S+\s+\S+/m.test(text) || !/^end\s*$/m.test(text)) return null;
      if (disallowedRatio(stripWhitespace(text), /[^!-~]/g) > 0.1) return null;
      return text;
    },
    decode: decodeXxencode,
  },
  {
    label: 'rot13',
    gate: text => {
      const compact = stripWhitespace(text);
      if (compact.length < 4) return null;
      const letters = compact.match(/[A-Za-z]/g);
      // rot13 仅置换字母、其余字符原样保留：字母 ≥4 且占非空白字符 ≥50% + 90% 可打印即可，
      // {}/_ 等 flag 装饰字符不阻断（仅作链中一步，不做 25 种位移暴力）
      if (!letters || letters.length < 4 || letters.length / compact.length < 0.5) return null;
      if (disallowedRatio(compact, /[^!-~]/g) > 0.1) return null;
      return text;
    },
    decode: text => caesar(text, -13),
  },
];

const compareCandidates = (left: InternalCandidate, right: InternalCandidate): number =>
  right.metrics.score - left.metrics.score
  || left.chain.length - right.chain.length
  || left.chain.join('\u0000').localeCompare(right.chain.join('\u0000'));

interface ScanRun {
  text: string;
  truncated: boolean;
  ranked: InternalCandidate[];
}

const runScan = (input: string, options?: MagicChainOptions): ScanRun => {
  const maxDepth = Math.max(1, Math.min(MAX_DEPTH_HARD, Math.floor(options?.maxDepth ?? DEFAULT_MAX_DEPTH)));
  const beamWidth = Math.max(1, Math.floor(options?.beamWidth ?? DEFAULT_BEAM_WIDTH));
  const topN = Math.max(1, Math.floor(options?.topN ?? DEFAULT_TOP_N));
  const source = typeof input === 'string' ? input : '';
  if (!source.trim()) return { text: '', truncated: false, ranked: [] };
  const truncated = source.length > INPUT_CHAR_LIMIT;
  const text = truncated ? source.slice(0, INPUT_CHAR_LIMIT) : source;

  const results = new Map<string, InternalCandidate>();
  const register = (candidate: InternalCandidate) => {
    // 去重：同一 result 字符串只留链最短者；等长保留先注册者（BFS 浅层先到，保证确定性）
    const existing = results.get(candidate.text);
    if (!existing || candidate.chain.length < existing.chain.length) results.set(candidate.text, candidate);
  };

  const rootMetrics = metricsOf(text);
  if (rootMetrics.flagLike) register({ text, chain: [], steps: [], metrics: rootMetrics });

  const seen = new Set<string>([text]);
  let frontier: InternalCandidate[] = [{ text, chain: [], steps: [], metrics: rootMetrics }];
  for (let depth = 0; depth < maxDepth && frontier.length; depth += 1) {
    const next: InternalCandidate[] = [];
    for (const node of frontier) {
      for (const op of OPS) {
        const gated = op.gate(node.text);
        if (gated === null) continue;
        let output: string;
        try {
          output = op.decode(gated);
        } catch {
          continue;
        }
        if (!output || output === gated || output === node.text) continue;
        if (output.length * 100 < gated.length) continue;
        const metrics = metricsOf(output);
        if (metrics.controlRatio > CONTROL_RATIO_MAX) continue;
        if (seen.has(output)) continue;
        seen.add(output);
        const candidate: InternalCandidate = {
          text: output,
          chain: [...node.chain, op.label],
          steps: [...node.steps, { step: node.steps.length + 1, label: op.label, length: output.length, preview: output.slice(0, STEP_PREVIEW_LIMIT) }],
          metrics,
        };
        register(candidate);
        next.push(candidate);
      }
    }
    if (!next.length) break;
    next.sort(compareCandidates);
    frontier = next.slice(0, beamWidth);
  }

  const ranked = Array.from(results.values()).sort(compareCandidates).slice(0, topN);
  return { text, truncated, ranked };
};

const toPublicCandidate = (candidate: InternalCandidate): MagicChainCandidate => ({
  chain: candidate.chain,
  result: candidate.text.length > RESULT_PREVIEW_LIMIT ? candidate.text.slice(0, RESULT_PREVIEW_LIMIT) : candidate.text,
  score: Number(candidate.metrics.score.toFixed(3)),
  printableRatio: Number(candidate.metrics.printableRatio.toFixed(4)),
  entropy: Number(candidate.metrics.entropy.toFixed(4)),
  flagLike: candidate.metrics.flagLike,
});

export const magicChainScan = (input: string, options?: MagicChainOptions): MagicChainCandidate[] =>
  runScan(input, options).ranked.map(toPublicCandidate);

export const magicChainReport = (value: string, options?: MagicChainOptions): string => {
  const run = runScan(value, options);
  const report = {
    tool: 'magic-chain',
    inputLength: typeof value === 'string' ? value.length : 0,
    truncated: run.truncated,
    options: {
      maxDepth: Math.min(options?.maxDepth ?? DEFAULT_MAX_DEPTH, MAX_DEPTH_HARD),
      beamWidth: options?.beamWidth ?? DEFAULT_BEAM_WIDTH,
      topN: options?.topN ?? DEFAULT_TOP_N,
    },
    candidateCount: run.ranked.length,
    candidates: run.ranked.map((candidate, index) => ({
      rank: index + 1,
      ...toPublicCandidate(candidate),
      steps: candidate.steps,
    })),
    notes: [
      '压缩层（gzip/zlib/deflate）未纳入链式候选：解压依赖 CompressionStream 异步流式解压（smart-decode 已能识别 Base64+压缩容器），同步链式引擎接入为长期项。',
      `链式操作白名单：${OPS.map(op => op.label).join('/')}；深度硬上限 ${MAX_DEPTH_HARD}，输入超 ${INPUT_CHAR_LIMIT} 字符截断后扫描。`,
    ],
  };
  return JSON.stringify(report, null, 2);
};
