// PDF CID/Identity-H 字体 /ToUnicode CMap 映射引擎（真题缺口：攻防世界 pdf 题——flag 在内容流
// (\041) Tj 的 CID 双字节码里，字体是 CID 子集，须解析 /ToUnicode CMap 才能还原字符）。
// 三个入口：parseCmapFromDecoded 吃"已解压"的 CMap 流字节，产出 码→Unicode 映射（纯同步核心）；
// findToUnicodeStreams 在原始 PDF 字节 + inspectPdf 的 streams 里定位被 /ToUnicode 间接引用的流
// （flate 标记该流是否单级 FlateDecode——解压一律由组件层做，引擎禁 zlib）；applyCmapToText 把
// pdfText 输出的 latin1 直读串按双字节（Identity-H：每 2 字节为一个码）或单字节查映射还原。
// CMap 覆盖：beginbfchar <src> <dst>、beginbfrange 连续段 <lo> <hi> <dstStart>（dst 末码元逐项 +1）
// 与数组形式 <lo> <hi> [<d1> …]、UTF-16BE 多字符 dst（连字/CJK/代理对）；% 注释与任意空白穿插；
// 多块并存；块外内容（codespacerange/cidrange 等）一律不映射。坏语法容错：条目畸形即中止当前块
// （保留该块已解析条目）继续找后续块，任何输入不抛错。
// 纯函数、同步、只读输入、无 DOM/eval/网络/依赖。红线：映射总数 65536、单 dst 16 码元、
// 单 bfrange 枚举 65536 条（伪造 CMap 的 4 字节码枚举炸弹按坏块丢弃）。

export type CidToUnicodeMap = Map<number, string>;

export const PDF_CMAP_MAX_ENTRIES = 65536;
export const PDF_CMAP_MAX_DST_UNITS = 16;
export const PDF_CMAP_MAX_RANGE_COUNT = 65536;

export interface CmapStreamRef {
  objectNumber: number;
  offset: number; // stream 数据起始偏移（与 pdfInspect.streams 同口径），组件层按 [offset, offset+length) 取解压输入
  length: number;
  flate: boolean; // /Filter 恰为单级 FlateDecode——组件层单次解压即得 CMap 文本；明文流与多级 filter 链为 false
}

// 结构等同 pdfInspect.PdfStreamInfo（免 import 直接喂 inspectPdf 的 streams）
export interface StreamLocation {
  objectNumber: number;
  offset: number;
  length: number;
  filter: string | null;
}

// 真·latin1 解码（字节↔字符一一对应）：与 pdfInspect/pdfText 同口径——TextDecoder('latin1') 实际按
// windows-1252 映射，字节语义必须精确，故手工分块 fromCharCode。
const latin1ToString = (bytes: Uint8Array): string => {
  let out = '';
  const CHUNK = 8192;
  for (let start = 0; start < bytes.length; start += CHUNK) {
    out += String.fromCharCode(...bytes.subarray(start, Math.min(start + CHUNK, bytes.length)));
  }
  return out;
};

// PDF 空白（\0 \t \n \f \r 空格）。
const skipWhitespace = (source: string, start: number): number => {
  let position = start;
  while (position < source.length) {
    const code = source.charCodeAt(position);
    if (code === 0 || code === 9 || code === 10 || code === 12 || code === 13 || code === 32) {
      position += 1;
      continue;
    }
    break;
  }
  return position;
};

// % 注释（至行尾）整段剥除：CMap 映射块与对象外壳内 % 按词法只可能是注释——剥除后注释里的
// begin/end 关键字与十六进制噪声不再参与定位；字符串内 % 的极端样本最多漏报引用，不产生错报。
const stripComments = (source: string): string => {
  let out = '';
  let position = 0;
  while (position < source.length) {
    const percent = source.indexOf('%', position);
    if (percent < 0) {
      out += source.slice(position);
      break;
    }
    out += source.slice(position, percent);
    let eol = percent + 1;
    while (eol < source.length && source[eol] !== '\n' && source[eol] !== '\r') eol += 1;
    position = eol;
  }
  return out;
};

// 常规字符 = 非空白且非定界符 ()<>[]{}/%：CMap（PostScript 语法）词边界判据。
const isRegularChar = (code: number): boolean => {
  if (code === 0 || code === 9 || code === 10 || code === 12 || code === 13 || code === 32) return false;
  return '()<>[]{}/%'.indexOf(String.fromCharCode(code)) === -1;
};

// 关键字命中：at 起恰为 word 且前后均为非常规字符（或串端）。
const matchKeyword = (source: string, at: number, word: string): boolean => {
  if (!source.startsWith(word, at)) return false;
  if (at > 0 && isRegularChar(source.charCodeAt(at - 1))) return false;
  const after = at + word.length;
  return after >= source.length || !isRegularChar(source.charCodeAt(after));
};

const findKeyword = (source: string, word: string, from: number): number => {
  let position = source.indexOf(word, from);
  while (position !== -1) {
    if (matchKeyword(source, position, word)) return position;
    position = source.indexOf(word, position + 1);
  }
  return -1;
};

interface HexRead {
  value: string; // 去空白后的十六进制数字串
  next: number; // 闭 > 之后的偏移
}

// <hex> 读取：<< 定界、非十六进制字符、未闭合均判畸形返回 null；内部允许空白穿插。
const readHexString = (source: string, start: number): HexRead | null => {
  if (source[start] !== '<' || source[start + 1] === '<') return null;
  let hex = '';
  let position = start + 1;
  while (position < source.length) {
    const ch = source[position];
    if (ch === '>') return hex ? { value: hex, next: position + 1 } : null;
    if (/[0-9A-Fa-f]/.test(ch)) {
      hex += ch;
      position += 1;
      continue;
    }
    const code = ch.charCodeAt(0);
    if (code === 0 || code === 9 || code === 10 || code === 12 || code === 13 || code === 32) {
      position += 1;
      continue;
    }
    return null;
  }
  return null;
};

// dst 十六进制 → Unicode 串：UTF-16BE 每 4 位一个码元（末组不足 4 位右补零），连字/代理对天然
// 支持；空串与超 PDF_CMAP_MAX_DST_UNITS 码元判畸形。
const decodeUtf16BeHex = (hex: string): string | null => {
  if (!hex) return null;
  const digits = hex.length % 4 ? hex.padEnd(Math.ceil(hex.length / 4) * 4, '0') : hex;
  const units = digits.length >> 2;
  if (units < 1 || units > PDF_CMAP_MAX_DST_UNITS) return null;
  let out = '';
  for (let index = 0; index < units; index += 1) {
    out += String.fromCharCode(Number.parseInt(digits.slice(index * 4, index * 4 + 4), 16));
  }
  return out;
};

// 源码：1-8 位十六进制（CMap 码最长 4 字节）；空串与超界判畸形。
const parseCode = (hex: string): number | null => {
  if (hex.length < 1 || hex.length > 8) return null;
  const value = Number.parseInt(hex, 16);
  return Number.isNaN(value) ? null : value;
};

// bfchar 块：条目 <srcCode> <dstUnicode>；畸形条目即中止本块（容错口径：跳过当前块，保留已解析条目）。
const parseBfcharBlock = (target: CidToUnicodeMap, body: string): void => {
  let position = 0;
  while (position < body.length) {
    position = skipWhitespace(body, position);
    if (position >= body.length) break;
    const src = readHexString(body, position);
    if (!src) return;
    position = skipWhitespace(body, src.next);
    const dst = readHexString(body, position);
    if (!dst) return;
    const code = parseCode(src.value);
    if (code === null) return;
    const text = decodeUtf16BeHex(dst.value);
    if (text === null || target.size >= PDF_CMAP_MAX_ENTRIES) return;
    target.set(code, text);
    position = dst.next;
  }
};

// bfrange 块：<lo> <hi> <dstStart>（连续段：dst 末码元逐项 +1）或 <lo> <hi> [<d1> …]（数组形式：
// dst 不足 range 宽度时映射前若干项）。lo>hi、码越界、枚举宽度过大均按坏块中止。
const parseBfrangeBlock = (target: CidToUnicodeMap, body: string): void => {
  let position = 0;
  while (position < body.length) {
    position = skipWhitespace(body, position);
    if (position >= body.length) break;
    const low = readHexString(body, position);
    if (!low) return;
    position = skipWhitespace(body, low.next);
    const high = readHexString(body, position);
    if (!high) return;
    position = skipWhitespace(body, high.next);
    const lowCode = parseCode(low.value);
    const highCode = parseCode(high.value);
    if (lowCode === null || highCode === null || lowCode > highCode) return;
    const count = highCode - lowCode + 1;
    if (count > PDF_CMAP_MAX_RANGE_COUNT) return;

    if (body[position] === '[') {
      const dstTexts: string[] = [];
      position = skipWhitespace(body, position + 1);
      let closed = false;
      while (position < body.length) {
        if (body[position] === ']') {
          closed = true;
          position += 1;
          break;
        }
        const dst = readHexString(body, position);
        if (!dst) return;
        const text = decodeUtf16BeHex(dst.value);
        if (text === null) return;
        dstTexts.push(text);
        position = skipWhitespace(body, dst.next);
      }
      if (!closed) return;
      const limit = Math.min(dstTexts.length, count);
      if (target.size + limit > PDF_CMAP_MAX_ENTRIES) return;
      for (let index = 0; index < limit; index += 1) target.set(lowCode + index, dstTexts[index]);
      continue;
    }

    const start = readHexString(body, position);
    if (!start) return;
    const digits = start.value.length % 4
      ? start.value.padEnd(Math.ceil(start.value.length / 4) * 4, '0')
      : start.value;
    const unitCount = digits.length >> 2;
    if (unitCount < 1 || unitCount > PDF_CMAP_MAX_DST_UNITS) return;
    if (target.size + count > PDF_CMAP_MAX_ENTRIES) return;
    let prefix = '';
    for (let unit = 0; unit < unitCount - 1; unit += 1) {
      prefix += String.fromCharCode(Number.parseInt(digits.slice(unit * 4, unit * 4 + 4), 16));
    }
    const baseLast = Number.parseInt(digits.slice((unitCount - 1) * 4), 16);
    for (let step = 0; step < count; step += 1) {
      const lastUnit = baseLast + step;
      if (lastUnit > 0xffff) break;
      target.set(lowCode + step, prefix + String.fromCharCode(lastUnit));
    }
    position = start.next;
  }
};

export const parseCmapFromDecoded = (decoded: Uint8Array): CidToUnicodeMap => {
  const source = stripComments(latin1ToString(decoded));
  const map: CidToUnicodeMap = new Map();
  let position = 0;
  // 逐块扫描：beginbfchar/beginbfrange 到对应 end 关键字之间为映射体；codespacerange 等其他块不进入
  while (position < source.length && map.size < PDF_CMAP_MAX_ENTRIES) {
    const charAt = findKeyword(source, 'beginbfchar', position);
    const rangeAt = findKeyword(source, 'beginbfrange', position);
    if (charAt < 0 && rangeAt < 0) break;
    const useRange = rangeAt >= 0 && (charAt < 0 || rangeAt < charAt);
    const beginWord = useRange ? 'beginbfrange' : 'beginbfchar';
    const endWord = useRange ? 'endbfrange' : 'endbfchar';
    const bodyStart = (useRange ? rangeAt : charAt) + beginWord.length;
    const endAt = findKeyword(source, endWord, bodyStart);
    const bodyEnd = endAt < 0 ? source.length : endAt;
    if (useRange) parseBfrangeBlock(map, source.slice(bodyStart, bodyEnd));
    else parseBfcharBlock(map, source.slice(bodyStart, bodyEnd));
    position = endAt < 0 ? source.length : endAt + endWord.length;
  }
  return map;
};

export const findToUnicodeStreams = (bytes: Uint8Array, streams: StreamLocation[]): CmapStreamRef[] => {
  const text = latin1ToString(bytes);
  // 引用只在对象外壳（流数据区间之外的文本）里找：压缩流内的随机字节撞 /ToUnicode 不具引用语义
  const ranges = streams
    .map(stream => [stream.offset, Math.min(text.length, stream.offset + stream.length)] as [number, number])
    .filter(([start, end]) => end > start)
    .sort((a, b) => a[0] - b[0] || a[1] - b[1]);
  let shell = '';
  let cursor = 0;
  for (const [start, end] of ranges) {
    if (start > cursor) shell += text.slice(cursor, start);
    cursor = Math.max(cursor, end);
  }
  if (cursor < text.length) shell += text.slice(cursor);

  const referenced = new Set<number>();
  const refPattern = /\/ToUnicode(?![A-Za-z0-9])\s+(\d+)\s+\d+\s+R(?![A-Za-z0-9])/g;
  for (const match of stripComments(shell).matchAll(refPattern)) {
    referenced.add(Number.parseInt(match[1], 10));
  }
  const out: CmapStreamRef[] = [];
  for (const stream of streams) {
    if (!referenced.has(stream.objectNumber)) continue;
    out.push({
      objectNumber: stream.objectNumber,
      offset: stream.offset,
      length: stream.length,
      flate: stream.filter === 'FlateDecode',
    });
  }
  return out;
};

export const applyCmapToText = (rawText: string, map: CidToUnicodeMap, twoByte: boolean): string => {
  let out = '';
  if (!twoByte) {
    for (let index = 0; index < rawText.length; index += 1) {
      const mapped = map.get(rawText.charCodeAt(index));
      out += mapped === undefined ? rawText[index] : mapped;
    }
    return out;
  }
  // 双字节契约：rawText 为内容流字节的 latin1 直读（pdfText 输出口径），每 2 字符一个码；
  // 未命中映射的双字符与奇数尾字符保原样（取证上字节可见优先于丢信息）。
  let index = 0;
  for (; index + 1 < rawText.length; index += 2) {
    const cid = (rawText.charCodeAt(index) << 8) | rawText.charCodeAt(index + 1);
    const mapped = map.get(cid);
    out += mapped === undefined ? rawText[index] + rawText[index + 1] : mapped;
  }
  if (index < rawText.length) out += rawText[index];
  return out;
};
