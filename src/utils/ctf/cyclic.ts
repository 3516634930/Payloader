// Pwn 域 cyclic pattern 工具（Wiremask 双框交互 + pwnlib 语义）：de Bruijn 序列生成与反查，纯计算零依赖。
// 生成：62 字符表（小写+大写+数字）上的字典序 de Bruijn 序列，周期可调 3/4/8（pwnlib cyclic -n 同构），
// 任意 period 长窗口在完整序列中唯一 → 反查 offset 无歧义。
// 反查：支持 0x 十六进制（自动判 16/32/64 位与字节序，LE 优先）与原始子串两种输入。

export const CYCLIC_ALPHABET = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';

export type CyclicPeriod = 3 | 4 | 8;

// 反查搜索上限：62 字符表按字典序生成时前段几乎全是小写区（大写/数字的窗口 offset 深得多），
// 上限取 2,000,000（约 4MB 字符串、生成亚秒级）以覆盖小写全区 + 大写区大部分；周期 3 全量仅 238K。
export const CYCLIC_SEARCH_LIMIT = 2_000_000;

export const CYCLIC_PERIODS: ReadonlyArray<{ value: CyclicPeriod; label: string }> = [
  { value: 4, label: '4（默认，pwnlib 同）' },
  { value: 3, label: '3（metasploit 风格）' },
  { value: 8, label: '8（64 位整窗）' },
];

// de Bruijn 序列生成（Fredricksen–Maiorana / Lyndon words，Wikipedia 标准算法），
// 生成到 maxLen 即提前截断（truncated 标志短路递归），避免为反查一个 offset 生成千万级字符串。
export const buildDeBruijn = (period: number, maxLen: number, alphabet: string = CYCLIC_ALPHABET): string => {
  if (!Number.isInteger(period) || period < 1 || !alphabet.length || maxLen <= 0) return '';
  const k = alphabet.length;
  // a[0] 恒 0（哨兵），序列取 a[1..p]
  const a = new Array<number>(period * k + 1).fill(0);
  const seq: number[] = [];
  let truncated = false;
  const db = (t: number, p: number): void => {
    if (truncated) return;
    if (t > period) {
      if (period % p === 0) {
        for (let index = 1; index <= p; index += 1) {
          seq.push(a[index]);
          if (seq.length >= maxLen) {
            truncated = true;
            return;
          }
        }
      }
      return;
    }
    a[t] = a[t - p];
    db(t + 1, p);
    for (let j = a[t - p] + 1; j < k; j += 1) {
      a[t] = j;
      db(t + 1, t);
    }
  };
  db(1, 1);
  let out = '';
  const limit = Math.min(maxLen, seq.length);
  for (let index = 0; index < limit; index += 1) out += alphabet[seq[index]];
  return out;
};

export type CyclicEndian = 'little' | 'big' | null;

export interface CyclicLookupResult {
  // 序列中的全部命中位置（升序）。完整周期长度的窗口在全序列唯一 → 单命中；
  // 高位零裁剪后 needle 短于周期时可能多处出现（如 RIP 高位为 0、pattern 只覆盖低 6 字节），如实返回多个由选手判断。
  offsets: number[];
  // 便捷首命中 = offsets[0]。
  offset: number;
  // offsets.length > 1 时为真：存在同子串多处命中，UI 应列出全部。
  ambiguous: boolean;
  // 短 needle 命中数超出收集上限被截断（withinBytes 内高频重复），UI 应提示清单不完整。
  truncated: boolean;
  // 用于匹配的子串（hex 输入时为字节序转换后的 ASCII 串）。
  raw: string;
  // hex 输入命中时的字节序；原始子串输入为 null。
  endian: CyclicEndian;
  // hex 输入的位宽（2/4/8 字节 → 16/32/64）；原始子串输入为 null。
  width: 16 | 32 | 64 | null;
  // 高位全零字节被裁掉的数量。
  trimmedZeroBytes: number;
}

export type CyclicLookupFailure = {
  error: 'format' | 'not-found';
  // format 失败时的人类可读说明。
  detail?: string;
};

const isPrintableAscii = (value: string): boolean => {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code < 0x20 || code > 0x7e) return false;
  }
  return true;
};

const hexToString = (hex: string): string => {
  let out = '';
  for (let index = 0; index < hex.length; index += 2) out += String.fromCharCode(Number.parseInt(hex.slice(index, index + 2), 16));
  return out;
};

const trimLeadingZeros = (value: string): { trimmed: string; count: number } => {
  let start = 0;
  while (start < value.length && value.charCodeAt(start) === 0) start += 1;
  return { trimmed: value.slice(start), count: start };
};

const trimTrailingZeros = (value: string): { trimmed: string; count: number } => {
  let end = value.length;
  while (end > 0 && value.charCodeAt(end - 1) === 0) end -= 1;
  return { trimmed: value.slice(0, end), count: value.length - end };
};

const MAX_CANDIDATE_HITS = 16;
// 短 needle（高位零裁剪）的歧义是真实的：答案必然 ≤ 用户实际发送的 pattern 长度，
// 因此在 withinBytes 范围内收集全部命中；该范围有限，不会撞上深处的海量重复。
const DEFAULT_WITHIN_BYTES = 4096;

interface OffsetSearch {
  hits: number[];
  // 命中数达到收集上限被截断时为真（短 needle 高频场景）。
  truncated: boolean;
}

const lookupByHex = (
  hex: string,
  width: 16 | 32 | 64,
  period: CyclicPeriod,
  withinBytes: number,
): CyclicLookupResult | CyclicLookupFailure => {
  const bigEndian = hexToString(hex);
  const littleEndian = Array.from(bigEndian).reverse().join('');
  // 高位零字节裁剪方向随字节序：LE 字节流高位在末尾（0x00007ffd… → …7f fd 00 00），BE 高位在开头。
  const littleTrim = trimTrailingZeros(littleEndian);
  const bigTrim = trimLeadingZeros(bigEndian);
  const candidates: Array<{ raw: string; endian: CyclicEndian; trimmedZeroBytes: number }> = [];
  if (littleTrim.trimmed && isPrintableAscii(littleTrim.trimmed)) {
    candidates.push({ raw: littleTrim.trimmed, endian: 'little', trimmedZeroBytes: littleTrim.count });
  }
  if (bigTrim.trimmed && isPrintableAscii(bigTrim.trimmed)) {
    candidates.push({ raw: bigTrim.trimmed, endian: 'big', trimmedZeroBytes: bigTrim.count });
  }
  for (const candidate of candidates) {
    const search = findCyclicOffsets(candidate.raw, period, withinBytes);
    if (search.hits.length) {
      return { offsets: search.hits, offset: search.hits[0], ambiguous: search.hits.length > 1, truncated: search.truncated, raw: candidate.raw, endian: candidate.endian, width, trimmedZeroBytes: candidate.trimmedZeroBytes };
    }
  }
  if (!candidates.length) return { error: 'not-found', detail: '该十六进制值解出的字节不在 pattern 字母表内（含不可打印字符）。' };
  return { error: 'not-found' };
};

// 序列内查找：needle ≥ 周期长度时窗口在全序列唯一，逐档（20K → 2M）首个命中即答案；
// needle < 周期（高位零裁剪所致）时短窗口多处出现，在 withinBytes 范围内收集全部命中。
const findCyclicOffsets = (needle: string, period: CyclicPeriod, withinBytes: number): OffsetSearch => {
  if (needle.length >= period) {
    for (let limit = 20_000; limit <= CYCLIC_SEARCH_LIMIT; limit *= 100) {
      const sequence = buildDeBruijn(period, limit);
      const found = sequence.indexOf(needle);
      if (found >= 0) return { hits: [found], truncated: false };
      if (sequence.length < limit) break; // 序列已到全量仍未命中
    }
    return { hits: [], truncated: false };
  }
  const limit = Math.min(Math.max(withinBytes, 20_000), CYCLIC_SEARCH_LIMIT);
  const sequence = buildDeBruijn(period, limit);
  const hits: number[] = [];
  let from = 0;
  for (;;) {
    const found = sequence.indexOf(needle, from);
    if (found < 0 || found + needle.length > withinBytes) break;
    hits.push(found);
    if (hits.length >= MAX_CANDIDATE_HITS) return { hits, truncated: true };
    from = found + 1;
  }
  return { hits, truncated: false };
};

// 反查入口：crashInput 支持 0x 前缀十六进制（4/8/16 位 hex = 16/32/64 位寄存器值）与原始 ASCII 子串。
// hex 输入先试 little-endian（pwn 默认），再试 big-endian；任一在序列中命中即返回并标注方向。
// withinBytes = 用户实际生成的 pattern 长度：短 needle 的多命中收集限定在该范围内（答案必然落在其中）。
export const findCyclicOffset = (
  crashInput: string,
  period: CyclicPeriod,
  options?: { withinBytes?: number },
): CyclicLookupResult | CyclicLookupFailure => {
  const withinBytes = options?.withinBytes ?? DEFAULT_WITHIN_BYTES;
  const input = crashInput.trim();
  if (!input) return { error: 'format', detail: '输入为空。' };

  // 0x 开头的输入按用户意图一律走 hex 通道：hex 部分非法（非 4-16 位偶数长）直接报格式错误，不回退子串。
  const looksHex = /^0x/i.test(input);
  const hexMatch = looksHex
    ? /^0x([0-9a-fA-F]{4,16})$/i.exec(input)
    : /^([0-9a-fA-F]{4,16})$/.exec(input);
  if (looksHex) {
    if (!hexMatch || hexMatch[1].length % 2 !== 0) {
      return { error: 'format', detail: '0x 开头的输入需要 4-16 位偶数长十六进制（8 位=32 位寄存器、16 位=64 位寄存器），如 0x61613768。' };
    }
    return lookupByHex(hexMatch[1].toLowerCase(), hexMatch[1].length / 2 * 8 as 16 | 32 | 64, period, withinBytes);
  }
  if (/^[0-9a-fA-F]{4,16}$/.test(input) && input.length % 2 === 0) {
    return lookupByHex(input.toLowerCase(), input.length / 2 * 8 as 16 | 32 | 64, period, withinBytes);
  }

  // 原始子串：至少 2 个可打印 ASCII 字符才有定位意义。
  if (input.length >= 2 && isPrintableAscii(input)) {
    const search = findCyclicOffsets(input, period, withinBytes);
    if (search.hits.length) {
      return { offsets: search.hits, offset: search.hits[0], ambiguous: search.hits.length > 1, truncated: search.truncated, raw: input, endian: null, width: null, trimmedZeroBytes: 0 };
    }
    return { error: 'not-found' };
  }

  return {
    error: 'format',
    detail: '无法识别的输入：请粘贴 0x 开头的寄存器值（如 0x61613768）、4-16 位偶数长十六进制，或 2 个以上可打印 ASCII 字符。',
  };
};
