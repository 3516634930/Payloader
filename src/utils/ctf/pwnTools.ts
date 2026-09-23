// Pwn 域纯计算工具集：payload 字节解析 / 坏字符检查 / 格式化字符串泄漏序号分析。
// 全部纯函数，输入输出均可被 node 回归直接验证；UI 层只做渲染与交互。

// ---- payload 解析 ----

export type PayloadParse =
  | { ok: true; bytes: number[]; source: 'escape' | 'hex' | 'raw' }
  | { ok: false; error: string };

// payload 解析：优先 \xNN 转义串（shellcode 惯例，忽略引号/空白/注释性字符）；
// 无 \xNN 时退化为裸 hex（偶数位 0-9a-f，可夹空白与 0x 前缀）；都不行则按原始 ASCII 字节。
export const parsePayloadBytes = (input: string): PayloadParse => {
  const trimmed = input.trim();
  if (!trimmed) return { ok: false, error: '输入为空。' };

  if (/\\x[0-9a-fA-F]{2}/.test(trimmed)) {
    const bytes: number[] = [];
    for (const match of trimmed.matchAll(/\\x([0-9a-fA-F]{2})/g)) bytes.push(Number.parseInt(match[1], 16));
    return { ok: true, bytes, source: 'escape' };
  }

  const cleaned = trimmed.replace(/^0x|[\s,]+/g, '');
  if (/^[0-9a-fA-F]+$/.test(cleaned) && cleaned.length % 2 === 0) {
    const bytes: number[] = [];
    for (let index = 0; index < cleaned.length; index += 2) bytes.push(Number.parseInt(cleaned.slice(index, index + 2), 16));
    return { ok: true, bytes, source: 'hex' };
  }

  if (isPrintableAscii(trimmed)) {
    return { ok: true, bytes: Array.from(trimmed, char => char.charCodeAt(0)), source: 'raw' };
  }
  return { ok: false, error: '无法解析：支持 \\xNN 转义串、偶数位裸 HEX，或原始 ASCII 文本。' };
};

const isPrintableAscii = (value: string): boolean => {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code < 0x20 || code > 0x7e) return false;
  }
  return true;
};

// ---- 坏字符检查 ----

// 预置坏字符集（CTF 惯例）：NUL / LF / CR / 空格；通过 UI 勾选与自定义输入扩展。
export const COMMON_BAD_CHARS: ReadonlyArray<{ byte: number; label: string }> = [
  { byte: 0x00, label: '\\x00' },
  { byte: 0x0a, label: '\\x0a' },
  { byte: 0x0d, label: '\\x0d' },
  { byte: 0x20, label: '\\x20' },
];

// 坏字符集解析：支持 \xNN、裸 hex 对、单字符字面量（如直接敲一个空格或字母）。
export const parseBadCharSet = (input: string): number[] => {
  const set = new Set<number>();
  for (const match of input.matchAll(/\\x([0-9a-fA-F]{2})/g)) set.add(Number.parseInt(match[1], 16));
  let rest = input.replace(/\\x[0-9a-fA-F]{2}/g, ' ');
  rest = rest.replace(/0x([0-9a-fA-F]{2})/g, (_, hex) => {
    set.add(Number.parseInt(hex, 16));
    return ' ';
  });
  for (const token of rest.split(/[\s,]+/)) {
    if (!token) continue;
    if (/^[0-9a-fA-F]{1,2}$/.test(token)) {
      const value = Number.parseInt(token, 16);
      if (value <= 0xff) set.add(value);
      continue;
    }
    for (const char of token) set.add(char.charCodeAt(0) & 0xff);
  }
  return [...set].sort((left, right) => left - right);
};

export interface BadCharHit {
  offset: number;
  byte: number;
}

export interface BadCharReport {
  total: number;
  hits: BadCharHit[];
  // 命中的坏字节去重清单（便于一眼看出缺哪些字节）。
  uniqueBad: number[];
  badSet: number[];
}

export const checkBadChars = (bytes: number[], badSet: number[]): BadCharReport => {
  const bad = new Set(badSet);
  const hits: BadCharHit[] = [];
  for (let offset = 0; offset < bytes.length; offset += 1) {
    if (bad.has(bytes[offset])) hits.push({ offset, byte: bytes[offset] });
  }
  return { total: bytes.length, hits, uniqueBad: [...new Set(hits.map(hit => hit.byte))].sort((a, b) => a - b), badSet: [...bad].sort((a, b) => a - b) };
};

// ---- 格式化字符串泄漏序号 ----

export interface FormatStringLeak {
  // 泄漏值编号表（1 起，对应 %1$p、%2$p…）。
  values: Array<{ index: number; hex: string }>;
  // 目标值命中的编号（1 起）；未提供目标或未命中为 null。
  matchedIndex: number | null;
  // 目标值说明（未能解析时给出原因，配合 matchedIndex=null 展示）。
  targetNote?: string;
}

// 泄漏输出分析：提取所有 0x 十六进制值按出现顺序编号；
// 目标值做双重解释（hex 数值 + ≤8 字节 ASCII 小端转数值，如 AAAA → 0x41414141），
// 任一解释与某泄漏位相等即命中——"AAAA" 之类既可读作 hex 又是常见 ASCII 填充，两种语义都值得尝试。
export const analyzeFormatStringLeak = (leakOutput: string, target?: string): FormatStringLeak => {
  const matches = [...leakOutput.matchAll(/0x[0-9a-fA-F]{1,16}/g)];
  const values = matches.map((match, position) => ({ index: position + 1, hex: match[0].toLowerCase() }));

  let targetNote: string | undefined;
  let matchedIndex: number | null = null;
  const targetTrimmed = (target ?? '').trim();
  if (targetTrimmed) {
    const candidates: bigint[] = [];
    if (/^(?:0x)?[0-9a-fA-F]+$/.test(targetTrimmed) && /[0-9a-fA-F]/.test(targetTrimmed)) {
      candidates.push(BigInt((targetTrimmed.startsWith('0x') ? '' : '0x') + targetTrimmed.toLowerCase()));
    }
    if (targetTrimmed.length <= 8 && isPrintableAscii(targetTrimmed)) {
      let value = 0n;
      for (let position = targetTrimmed.length - 1; position >= 0; position -= 1) {
        value = (value << 8n) | BigInt(targetTrimmed.charCodeAt(position));
      }
      if (!candidates.some(candidate => candidate === value)) candidates.push(value);
    }
    if (!candidates.length) {
      targetNote = '目标值无法解析：请输入 0x 十六进制，或 ≤8 字节的 ASCII（按小端转数值）。';
    } else {
      const hit = values.find(entry => candidates.some(candidate => BigInt(entry.hex) === candidate));
      if (hit) matchedIndex = hit.index;
      else targetNote = '泄漏输出中没有与目标相等的值：确认已把程序完整输出粘贴进来，且目标值确实被 %p 泄漏。';
    }
  }

  return { values, matchedIndex, targetNote };
};
