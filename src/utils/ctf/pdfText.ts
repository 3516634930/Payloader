// PDF 内容流文本提取引擎（真题缺口：攻防世界 pdf 题 flag 藏在被遮挡文本）：对"已解压"的
// 页内容流还原文本显示指令的字符串负载——(..) Tj / [..] TJ / (..) ' / (..) "，正是渲染层被
// 遮挡/盖白时内容流里原样可读的那份文本。
// 编码边界（约束，勿扩）：仅做单字节编码直读——字节按 latin1 一一对应字符（WinAnsi/标准 14 字体
// 简单编码的主流量产 PDF 场景）；UTF-16BE BOM 串手工解码；不做 CMap / 嵌入字体 ToUnicode / CID
// （Identity-H 双字节码）解码——此类字体输出为原始字节 latin1 直读（乱码但字节可见，可十六进制比对）。
// 解压边界（约束，勿扩）：引擎不做解压（浏览器侧禁 node:zlib）——调用方先用
// DecompressionStream('deflate') 解开 FlateDecode 流再喂本函数，流定位用 inspectPdf 的 streams；
// 页文本流的顺序即阅读序，多页由调用方按 streams 顺序拼合。
// 内联图像（BI…ID…EI）按"跳到下一个 EI 词"尽力跳过（不做字典级长度解析，图像二进制内的
// 伪 (…) 不提取）；词边界之外的 Tj 变体（如 Tjx）不认。
// 纯函数、同步、只读输入、无 DOM/eval/网络/依赖。红线：单串收集 8192 字节截断（扫描仍推进到
// 真实闭括号，不破坏后续定位）、单流输出上限 5 万条。

export const PDF_TEXT_MAX_STRING = 8192;
export const PDF_TEXT_MAX_ITEMS = 50000;

// 真·latin1 解码（字节↔字符一一对应）：与 pdfInspect 同口径——TextDecoder('latin1') 实际按
// windows-1252 映射，字符位语义必须精确，故手工分块 fromCharCode。
const latin1ToString = (bytes: Uint8Array): string => {
  let out = '';
  const CHUNK = 8192;
  for (let start = 0; start < bytes.length; start += CHUNK) {
    out += String.fromCharCode(...bytes.subarray(start, Math.min(start + CHUNK, bytes.length)));
  }
  return out;
};

// PDF 字符串字节 → 文本：UTF-16BE BOM（POD 字符串）手工解码，否则 latin1。
const decodePdfStringBytes = (bytes: Uint8Array): string => {
  if (bytes.length >= 2 && bytes[0] === 0xfe && bytes[1] === 0xff) {
    let wide = '';
    for (let index = 2; index + 1 < bytes.length; index += 2) {
      wide += String.fromCharCode((bytes[index] << 8) | bytes[index + 1]);
    }
    return wide;
  }
  return latin1ToString(bytes);
};

const hexToBytes = (hex: string): Uint8Array => {
  const padded = hex.length % 2 ? `${hex}0` : hex;
  const out = new Uint8Array(padded.length >> 1);
  for (let index = 0; index < out.length; index += 1) {
    out[index] = Number.parseInt(padded.slice(index * 2, index * 2 + 2), 16);
  }
  return out;
};

interface ParsedString {
  text: string;
  end: number; // 闭定界符之后的偏移（扫描器推进依据；截断/达上限也须返回真实推进位）
}

// 字面串 (…)：括号配深、\n \r \t \b \f \( \) \\ 转义、八进制 \ddd、反斜杠行续接、未识别转义取字符本身。
// 收集达 PDF_TEXT_MAX_STRING 后停止入列但继续扫描到配深为 0 或 EOF（保证 end 正确）。
const parseLiteralString = (source: string, openIndex: number): ParsedString => {
  const codes: number[] = [];
  const collect = (code: number): void => {
    if (codes.length < PDF_TEXT_MAX_STRING) codes.push(code);
  };
  let depth = 1;
  let position = openIndex + 1;
  while (position < source.length) {
    const ch = source[position];
    if (ch === '\\') {
      const next = position + 1 < source.length ? source[position + 1] : '';
      const nextCode = next.charCodeAt(0);
      if (next === 'n') { collect(10); position += 2; }
      else if (next === 'r') { collect(13); position += 2; }
      else if (next === 't') { collect(9); position += 2; }
      else if (next === 'b') { collect(8); position += 2; }
      else if (next === 'f') { collect(12); position += 2; }
      else if (next === '(') { collect(40); position += 2; }
      else if (next === ')') { collect(41); position += 2; }
      else if (next === '\\') { collect(92); position += 2; }
      else if (next === '\r') { position += source[position + 2] === '\n' ? 3 : 2; } // 行续接（跨 CRLF）
      else if (next === '\n') { position += 2; }
      else if (nextCode >= 0x30 && nextCode <= 0x37) {
        let octal = 0;
        let digits = 0;
        position += 1;
        while (position < source.length && digits < 3) {
          const digit = source.charCodeAt(position);
          if (digit < 0x30 || digit > 0x37) break;
          octal = octal * 8 + (digit - 0x30);
          position += 1;
          digits += 1;
        }
        collect(octal & 0xff);
      } else if (next) {
        collect(nextCode & 0xff);
        position += 2;
      } else {
        position += 1;
      }
      continue;
    }
    if (ch === '(') { depth += 1; collect(40); position += 1; continue; }
    if (ch === ')') {
      depth -= 1;
      if (depth === 0) { position += 1; break; }
      collect(41);
      position += 1;
      continue;
    }
    collect(source.charCodeAt(position) & 0xff);
    position += 1;
  }
  return { text: latin1ToString(Uint8Array.from(codes)), end: Math.min(position, source.length) };
};

// 十六进制串 <…>：内容须全为十六进制（排除 << 字典定界）；奇数长度按规范末位补零；UTF-16BE BOM 感知。
const parseHexStringValue = (source: string, openIndex: number): ParsedString | null => {
  const closeIndex = source.indexOf('>', openIndex);
  if (closeIndex < 0) return null;
  const hex = source.slice(openIndex + 1, closeIndex).replace(/\s+/g, '');
  if (!hex || !/^[0-9A-Fa-f]+$/.test(hex)) return null;
  return { text: decodePdfStringBytes(hexToBytes(hex)), end: closeIndex + 1 };
};

// PDF 空白（\0 \t \n \f \r 空格）与 % 注释（至行尾）——运算符前的操作数间隔允许二者混排。
const skipWhitespaceAndComments = (source: string, start: number): number => {
  let position = start;
  while (position < source.length) {
    const code = source.charCodeAt(position);
    if (code === 0 || code === 9 || code === 10 || code === 12 || code === 13 || code === 32) {
      position += 1;
      continue;
    }
    if (code === 37) {
      while (position < source.length && source.charCodeAt(position) !== 10 && source.charCodeAt(position) !== 13) position += 1;
      continue;
    }
    break;
  }
  return position;
};

// 常规字符 = 非空白且非定界符 ()<>[]{}/%：运算符词边界判据。
const isRegularChar = (code: number): boolean => {
  if (code === 0 || code === 9 || code === 10 || code === 12 || code === 13 || code === 32) return false;
  const ch = String.fromCharCode(code);
  return '()<>[]{}/%'.indexOf(ch) === -1;
};

// 运算符匹配：at 起恰为 word 且词后是非常规字符（或流尾）。
const matchOperator = (source: string, at: number, word: string): boolean => {
  if (!source.startsWith(word, at)) return false;
  const after = at + word.length;
  return after >= source.length || !isRegularChar(source.charCodeAt(after));
};

// 文本显示运算符判定（Tj 恒 2 字符，' 与 " 恒 1 字符）：命中返回消耗长度，未命中返回 0。
const matchShowOperator = (source: string, at: number): number => {
  if (matchOperator(source, at, 'Tj')) return 2;
  if (matchOperator(source, at, "'")) return 1;
  if (matchOperator(source, at, '"')) return 1;
  return 0;
};

export const extractPdfContentText = (decompressed: Uint8Array): string[] => {
  const source = latin1ToString(decompressed);
  const lines: string[] = [];
  const push = (text: string): void => {
    if (!text || lines.length >= PDF_TEXT_MAX_ITEMS) return; // 空串不入场；上限防失控
    lines.push(text.length > PDF_TEXT_MAX_STRING ? text.slice(0, PDF_TEXT_MAX_STRING) : text);
  };

  let position = 0;
  while (position < source.length) {
    const ch = source[position];

    // 内联图像 BI…ID…EI：词边界触发（/BI 之类的名字不触发），尽力跳到下一个 EI 词；
    // 找不到 EI（损坏流）吞到流尾——图像二进制内的伪 (…) / <…> 不应进文本结果。
    if (ch === 'B' && (position === 0 || (!isRegularChar(source.charCodeAt(position - 1)) && source[position - 1] !== '/')) && matchOperator(source, position, 'BI')) {
      let imageEnd = -1;
      for (let scan = position + 2; scan + 1 < source.length; scan += 1) {
        if (!source.startsWith('EI', scan) || isRegularChar(source.charCodeAt(scan - 1))) continue;
        const nextCode = scan + 2 < source.length ? source.charCodeAt(scan + 2) : -1;
        if (nextCode < 0 || !isRegularChar(nextCode)) { imageEnd = scan; break; }
      }
      position = imageEnd === -1 ? source.length : imageEnd + 2;
      continue;
    }

    if (ch === '(') {
      const parsed = parseLiteralString(source, position);
      const after = skipWhitespaceAndComments(source, parsed.end);
      const consumed = matchShowOperator(source, after);
      if (consumed > 0) push(parsed.text);
      position = consumed > 0 ? after + consumed : parsed.end;
      continue;
    }

    if (ch === '<' && source.charCodeAt(position + 1) !== 0x3c) {
      const parsed = parseHexStringValue(source, position);
      if (parsed) {
        const after = skipWhitespaceAndComments(source, parsed.end);
        const consumed = matchShowOperator(source, after);
        if (consumed > 0) push(parsed.text);
        position = consumed > 0 ? after + consumed : parsed.end;
      } else {
        position += 1;
      }
      continue;
    }

    if (ch === '[') {
      // TJ 数组：串与串之间穿插的数值（字距调整）忽略，串按序直接拼接为一个条目；
      // 数组未闭合（截断）或其后不是 TJ（如 dash 数组 [3] 0 d）则不产出。
      const parts: string[] = [];
      let cursor = position + 1;
      let closed = false;
      while (cursor < source.length) {
        const inner = source[cursor];
        if (inner === ']') { closed = true; cursor += 1; break; }
        if (inner === '(') {
          const parsed = parseLiteralString(source, cursor);
          parts.push(parsed.text);
          cursor = parsed.end;
          continue;
        }
        if (inner === '<' && source.charCodeAt(cursor + 1) !== 0x3c) {
          const parsed = parseHexStringValue(source, cursor);
          if (parsed) {
            parts.push(parsed.text);
            cursor = parsed.end;
            continue;
          }
        }
        cursor += 1;
      }
      if (closed) {
        const after = skipWhitespaceAndComments(source, cursor);
        if (matchOperator(source, after, 'TJ')) {
          push(parts.join(''));
          position = after + 2;
        } else {
          position = cursor;
        }
      } else {
        position = cursor;
      }
      continue;
    }

    position += 1;
  }
  return lines;
};
