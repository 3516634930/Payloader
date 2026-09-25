// Cloakify 词表隐写引擎（文本类隐写批次，对标随波逐流"Cloakify隐写提取"）。
// 格式调研来源（逐行核对过原脚本）：
// - github.com/TryCatchHCF/Cloakify（MIT License, Copyright (c) 2016 TryCatchHCF）
//   cloakify.py / decloakify.py（Python2）：
//   cloak：payload 原始字节 → base64.encodestring（标准 base64 文本）→ 逐字符按固定表查词表行号：
//     array64 = list("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/+=")
//     注意索引 0-25 对应小写 a-z（并非标准 base64 的大写在前），62='/'、63='+'、64='='（填充符）。
//   decloak：逐词 arrayCipher.index(word)（重复行取首次出现位置）→ array64[index] → 拼 base64 →
//     base64.b64decode 还原字节。词表要求"至少 66 行唯一词、无空行"（README 明示需使用者自备，
//   脚本本身不去重——本引擎按相同语义：解码映射取首次出现位置）。
// - 同作者 PacketWhisper/cloakify.py 在 cloak 前多了 gzip 压缩层：解码出的字节以 gzip 魔数
//   (1f 8b) 开头时提示存在该层；本模块是同步纯函数环境（node --test 直跑），仓库内无同步 inflate，
//   故只检测并报告魔数，解压交给 codec 的 gzip 操作（DecompressionStream 异步流在组件层完成）。
// 另支持 CTF 简化克隆语义 mode='byte'：词 → 词表索引 → 直接当字节（无 base64 层，索引 0-255）。
// 纯函数、命名导出、诊断对象；输入上限 20MB。

import { CLOAKIFY_CIPHERS } from './cloakLists';
import { base64ToBytes, bytesToBase64, bytesToHex } from './bases';

export const CLOAKIFY_MAX_TEXT_BYTES = 20 * 1024 * 1024;

// 原工具 cloakify.py 逐字核对的索引表（小写在前）
export const CLOAKIFY_ARRAY64 = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/+=';

export interface CloakifyList {
  name: string;
  source: string;
  words: string[];
}

export type CloakifyMode = 'b64' | 'byte' | 'auto';

export interface CloakifyDecodeResult {
  bytes: Uint8Array;
  text: string; // bytes 的可读文本（UTF-8 优先，含替换符退 latin1）
  mode: 'b64' | 'byte'; // 实际命中的语义
  gzipLayer: boolean; // bytes 是否以 gzip 魔数开头（PacketWhisper 式预压缩层）
  bytesHex: string;
}

export interface CloakifyCandidate {
  list: string; // 词表 key（内置）或 'custom'
  listName: string; // 展示名（中文）
  mode: 'b64' | 'byte';
  text: string;
  printable: number; // 可打印率 0-1
  flagLike: boolean;
  gzipLayer: boolean;
  bytesHex: string;
}

const FLAG_SHAPE = /flag\{|ctf\{|picoctf\{|key[=: ]|pass(word)?[=: ]/i;

// 自定义词表文本 → 词数组：按行切、去行尾空白/空行；不去重（上游语义：重复行由使用者负责，
// 解码按首次出现位置匹配，与 Python list.index 一致）。
export const parseWordList = (raw: string): string[] =>
  raw.split(/\r\n|\r|\n/).map(line => line.trim()).filter(Boolean);

export const getCloakifyCipher = (key: string): CloakifyList | null => {
  const cipher = CLOAKIFY_CIPHERS.find(item => item.key === key);
  return cipher ? { name: cipher.name.zh, source: cipher.source, words: cipher.words } : null;
};

export const cloakifyListNames = (): Array<{ key: string; zh: string; count: number }> =>
  CLOAKIFY_CIPHERS.map(cipher => ({ key: cipher.key, zh: cipher.name.zh, count: cipher.words.length }));

const resolveList = (list: string | string[] | CloakifyList): CloakifyList => {
  if (Array.isArray(list)) {
    if (!list.length) throw new Error('Cloakify 词表为空');
    return { name: 'custom(array)', source: 'user', words: list };
  }
  if (typeof list === 'string') {
    const builtIn = getCloakifyCipher(list);
    if (builtIn) return builtIn;
    const words = parseWordList(list);
    if (!words.length) throw new Error('Cloakify 词表为空或无法按行解析出任何词');
    return { name: 'custom(text)', source: 'user', words };
  }
  return list;
};

// 分词：多行输入按行走（原工具按行匹配，保留含空格的多词条目）；单行输入退化为逗号 → 空白分隔。
const tokenizeCloaked = (text: string): string[] => {
  const trimmed = text.trim();
  if (!trimmed) return [];
  if (/[\r\n]/.test(trimmed)) return trimmed.split(/\r\n|\r|\n/).map(line => line.trim()).filter(Boolean);
  if (trimmed.includes(',')) return trimmed.split(/[,;]+/).map(token => token.trim()).filter(Boolean);
  return trimmed.split(/\s+/).filter(Boolean);
};

const decodeBytesText = (bytes: Uint8Array): string => {
  if (!bytes.length) return '';
  const utf8 = new TextDecoder().decode(bytes);
  return utf8.includes('\uFFFD') ? Array.from(bytes, byte => String.fromCharCode(byte)).join('') : utf8;
};

const printableRatioOf = (bytes: Uint8Array): number => {
  if (!bytes.length) return 0;
  let printable = 0;
  for (const byte of bytes) {
    if ((byte >= 32 && byte <= 126) || byte === 9 || byte === 10 || byte === 13) printable += 1;
  }
  return printable / bytes.length;
};

const isGzip = (bytes: Uint8Array): boolean => bytes.length >= 3 && bytes[0] === 0x1f && bytes[1] === 0x8b && bytes[2] === 0x08;

const decodeWithMode = (text: string, list: CloakifyList, mode: 'b64' | 'byte'): CloakifyDecodeResult | null => {
  const tokens = tokenizeCloaked(text);
  if (!tokens.length) return null;
  const firstIndex = new Map<string, number>();
  list.words.forEach((word, index) => {
    if (!firstIndex.has(word)) firstIndex.set(word, index);
  });
  if (mode === 'b64') {
    // 原工具语义：词 → 行号（<65）→ array64 字符 → base64 → 字节
    let b64 = '';
    for (const token of tokens) {
      const index = firstIndex.get(token);
      if (index === undefined || index >= CLOAKIFY_ARRAY64.length) return null;
      b64 += CLOAKIFY_ARRAY64[index];
    }
    try {
      const bytes = base64ToBytes(b64);
      return { bytes, text: decodeBytesText(bytes), mode, gzipLayer: isGzip(bytes), bytesHex: bytesToHex(bytes) };
    } catch {
      return null;
    }
  }
  // CTF 简化克隆语义：词 → 行号 → 字节
  const bytes = new Uint8Array(tokens.length);
  for (let position = 0; position < tokens.length; position += 1) {
    const index = firstIndex.get(tokens[position]);
    if (index === undefined || index > 255) return null;
    bytes[position] = index;
  }
  return { bytes, text: decodeBytesText(bytes), mode, gzipLayer: isGzip(bytes), bytesHex: bytesToHex(bytes) };
};

export const cloakifyDecode = (text: string, list: string | string[] | CloakifyList, mode: CloakifyMode = 'auto'): CloakifyDecodeResult | null => {
  if (text.length > CLOAKIFY_MAX_TEXT_BYTES) {
    throw new Error(`输入 ${text.length} 字符超过 cloakify 引擎上限 ${CLOAKIFY_MAX_TEXT_BYTES}（20MB）`);
  }
  const resolved = resolveList(list);
  if (mode === 'auto') {
    const b64 = decodeWithMode(text, resolved, 'b64');
    const byte = decodeWithMode(text, resolved, 'byte');
    const scoreOf = (item: CloakifyDecodeResult | null): number =>
      item === null ? -1 : printableRatioOf(item.bytes) + (FLAG_SHAPE.test(item.text) ? 1 : 0);
    // b64 是原工具语义，平分时优先
    return scoreOf(b64) >= scoreOf(byte) ? b64 : byte;
  }
  return decodeWithMode(text, resolved, mode);
};

export const cloakifyEncode = (bytes: Uint8Array, list: string | string[] | CloakifyList, mode: 'b64' | 'byte' = 'b64'): string => {
  const resolved = resolveList(list);
  if (!bytes.length) throw new Error('Cloakify 编码需要非空 payload');
  if (mode === 'b64') {
    if (resolved.words.length < CLOAKIFY_ARRAY64.length) {
      throw new Error(`词表仅 ${resolved.words.length} 词，原工具语义至少需要 65 个唯一词（覆盖 base64 字符 + '='）`);
    }
    const b64 = bytesToBase64(bytes);
    return Array.from(b64, char => {
      const index = CLOAKIFY_ARRAY64.indexOf(char);
      if (index < 0) throw new Error(`字符 "${char}" 不在 cloakify base64 表内`);
      return resolved.words[index];
    }).join('\n');
  }
  for (const byte of bytes) {
    if (byte >= resolved.words.length) {
      throw new Error(`字节 0x${byte.toString(16)} 超出词表范围（${resolved.words.length} 词，byte 模式需 ≤ 词数-1）`);
    }
  }
  return Array.from(bytes, byte => resolved.words[byte]).join('\n');
};

// 全内置词表 × 双语义自动尝试，按 可打印率 + flag 形态 排序返回候选。
export const autoCloakifyDecode = (text: string): CloakifyCandidate[] => {
  if (text.length > CLOAKIFY_MAX_TEXT_BYTES) {
    throw new Error(`输入 ${text.length} 字符超过 cloakify 引擎上限 ${CLOAKIFY_MAX_TEXT_BYTES}（20MB）`);
  }
  const candidates: CloakifyCandidate[] = [];
  for (const cipher of CLOAKIFY_CIPHERS) {
    for (const mode of ['b64', 'byte'] as const) {
      const decoded = decodeWithMode(text, { name: cipher.name.zh, source: cipher.source, words: cipher.words }, mode);
      if (!decoded) continue;
      const ratio = printableRatioOf(decoded.bytes);
      candidates.push({
        list: cipher.key,
        listName: cipher.name.zh,
        mode,
        text: decoded.text,
        printable: ratio,
        flagLike: FLAG_SHAPE.test(decoded.text),
        gzipLayer: decoded.gzipLayer,
        bytesHex: decoded.bytesHex,
      });
    }
  }
  candidates.sort((left, right) => {
    const flagDelta = Number(right.flagLike) - Number(left.flagLike);
    if (flagDelta !== 0) return flagDelta;
    if (right.printable !== left.printable) return right.printable - left.printable;
    return right.bytesHex.length - left.bytesHex.length;
  });
  return candidates;
};

export interface CloakifyAutoReport {
  tool: string;
  candidates: CloakifyCandidate[];
  gzipNote: string;
}

export const cloakifyAutoReport = (value: string): string => {
  const candidates = autoCloakifyDecode(value).slice(0, 8);
  const report: CloakifyAutoReport = {
    tool: 'cloakify-wordlist-stego',
    candidates,
    gzipNote: candidates.some(item => item.gzipLayer)
      ? '命中候选的解码字节以 gzip 魔数 (1f 8b) 开头：PacketWhisper 式链路先 gzip 再 cloak。本引擎为同步纯函数不含 inflate，请复制 bytesHex 到 gzip 操作解压。'
      : '',
  };
  return JSON.stringify(report, null, 2);
};
