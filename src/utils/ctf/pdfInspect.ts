// PDF 取证解析引擎（杂项取证域，sweep2 缺口 #23）：PDFiD/peepd 的可移植部分——header 版本、
// 顺序对象扫描、stream 段定位（offset/length/filter 供组件层异步解压）、PDFiD 式风险指标计数、
// /Info 元数据有限解析、% 注释行、对象体内可打印长串（flag 命中排前）。
// 容错口径：CTF 里的 PDF 常被故意搞坏 xref——比 xref 表更可信的是对象本体，引擎按顺序扫描
// `N G obj ... endobj`；stream 定长优先取 /Length（并校验其后确为 endstream），失败回退搜索
// 下一个 endstream；截断流长度按剩余字节计并写 anomalies。
// 纯函数、同步、只读输入、无 DOM/eval/网络、解压不在引擎内做。上限红线 20MB（挂载层已限，引擎内再防一道）。
// 指标/元数据/注释/可疑串只在"对象外壳"（stream 数据之外的文本）上扫描：压缩流内的随机字节命中没有取证价值。

export const PDF_MAX_BYTES = 20 * 1024 * 1024;

export interface PdfStreamInfo {
  objectNumber: number;
  offset: number; // stream 数据起始偏移（stream 关键字 EOL 之后），组件层按 [offset, offset+length) 取解压输入
  length: number; // /Length 校验值或 endstream 回退值（截断时为剩余字节数）
  filter: string | null; // /Filter 名（数组链用 " + " 连接），未声明为 null
}

export interface PdfInspectResult {
  version: string | null;
  objectCount: number;
  trailerId: string | null;
  streams: PdfStreamInfo[];
  indicators: Array<{ key: string; label: string; count: number }>;
  metadata: Record<string, string>;
  comments: string[];
  suspiciousTexts: string[];
  anomalies: string[];
}

// flag 正则镜像 bitPlaneScan.FLAG_PATTERN（常用赛前缀 + 通用"前缀{可打印}"分支），两处需同步维护。
const FLAG_PATTERN = /(flag|ctf|key|ctfshow|NSSCTF|DASCTF|BaseCTF|wanictf)\{|[A-Za-z0-9_]{2,}\{[ -~]{3,}\}/i;

// PDFiD 式风险指标：对象外壳中带斜杠键名/名字值的原始出现次数（与 PDFiD 同为启发式口径，非渲染语义）。
const INDICATOR_DEFS: ReadonlyArray<{ key: string; label: string }> = [
  { key: '/JavaScript', label: '显式 JavaScript 动作' },
  { key: '/JS', label: 'JavaScript 动作（精简键）' },
  { key: '/AA', label: '附加动作 additional-actions' },
  { key: '/OpenAction', label: '文档打开动作' },
  { key: '/Launch', label: '启动外部程序' },
  { key: '/EmbeddedFile', label: '内嵌文件' },
  { key: '/RichMedia', label: '富媒体（Flash 等）' },
  { key: '/URI', label: '外链 URI' },
  { key: '/Annots', label: '注释/交互' },
  { key: '/AcroForm', label: '交互表单' },
];

// /Info 字典常规八键；只取每键首次出现的字符串值。
const INFO_KEYS: readonly string[] = [
  'Title', 'Author', 'Subject', 'Keywords', 'Creator', 'Producer', 'CreationDate', 'ModDate',
];

// 纯 PDF 语法噪声（obj 头/间接引用/xref 行/裸名字/定界符碎片），不进可疑串列表。
const SYNTAX_NOISE = /^(?:[\d\s]*(?:obj|endobj|R|n|f)|xref|trailer|startxref|stream|endstream|\/[A-Za-z0-9+#.-]+|<+|>+)$/;

// 真·latin1 解码（字节↔字符一一对应）：TextDecoder('latin1') 实际按 windows-1252 映射（0x80-0x9F
// 会变成西文标点），本引擎要做字符位→字节回写与偏标定位，必须精确字节语义，故手工分块 fromCharCode。
const latin1ToString = (bytes: Uint8Array): string => {
  let out = '';
  const CHUNK = 8192;
  for (let start = 0; start < bytes.length; start += CHUNK) {
    out += String.fromCharCode(...bytes.subarray(start, Math.min(start + CHUNK, bytes.length)));
  }
  return out;
};

// PDF 字符串字节 → 展示文本：UTF-16BE BOM（POD 字符串）手工解码，否则 latin1。
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

const isPrintableAscii = (bytes: Uint8Array): boolean => {
  if (!bytes.length) return false;
  for (const byte of bytes) {
    if (byte < 0x20 || byte > 0x7e) return false;
  }
  return true;
};

// 字面串 (…)：括号配深、\n \r \t \b \f \( \) \\ 转义、八进制 \ddd、反斜杠行续接；累计上限 256 字节。
const parseLiteralString = (source: string, openIndex: number): string => {
  const codes: number[] = [];
  let depth = 1;
  let position = openIndex + 1;
  while (position < source.length && codes.length < 256) {
    const code = source.charCodeAt(position);
    const ch = source[position];
    if (ch === '\\') {
      const next = position + 1 < source.length ? source[position + 1] : '';
      const nextCode = next.charCodeAt(0);
      if (next === 'n') { codes.push(10); position += 2; }
      else if (next === 'r') { codes.push(13); position += 2; }
      else if (next === 't') { codes.push(9); position += 2; }
      else if (next === 'b') { codes.push(8); position += 2; }
      else if (next === 'f') { codes.push(12); position += 2; }
      else if (next === '(') { codes.push(40); position += 2; }
      else if (next === ')') { codes.push(41); position += 2; }
      else if (next === '\\') { codes.push(92); position += 2; }
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
        codes.push(octal & 0xff);
      } else if (next) {
        codes.push(nextCode & 0xff);
        position += 2;
      } else {
        position += 1;
      }
      continue;
    }
    if (ch === '(') { depth += 1; codes.push(code & 0xff); position += 1; continue; }
    if (ch === ')') {
      depth -= 1;
      if (depth === 0) break;
      codes.push(41);
      position += 1;
      continue;
    }
    codes.push(code & 0xff);
    position += 1;
  }
  return latin1ToString(Uint8Array.from(codes));
};

// 十六进制串 <…>：内容须全为十六进制（排除 << 字典定界）；奇数长度按规范丢弃末位补零处理。
const parseHexStringValue = (source: string, openIndex: number): string | null => {
  const closeIndex = source.indexOf('>', openIndex);
  if (closeIndex < 0) return null;
  const hex = source.slice(openIndex + 1, closeIndex).replace(/\s+/g, '');
  if (!hex || !/^[0-9A-Fa-f]+$/.test(hex)) return null;
  return decodePdfStringBytes(hexToBytes(hex));
};

// /Info 值解析入口：跳空白后按 ( 或 < 起始分派；数字/名字/引用值不属元数据场景，返回 null。
const parsePdfStringValue = (source: string, start: number): string | null => {
  let position = start;
  while (position < source.length && /\s/.test(source[position])) position += 1;
  const opening = source[position];
  if (opening === '(') return parseLiteralString(source, position);
  if (opening === '<' && source[position + 1] !== '<') return parseHexStringValue(source, position);
  return null;
};

// /Filter 提取：单名 /FlateDecode 或数组 [/FlateDecode /ASCIIHexDecode]（链式用 " + " 连接）。
const parseFilter = (dict: string): string | null => {
  const match = /\/Filter(?![A-Za-z0-9])\s*(\/[A-Za-z0-9+#.-]+|\[[^\]]*\])/.exec(dict);
  if (!match) return null;
  const value = match[1];
  if (!value.startsWith('[')) return value.slice(1);
  const names = [...value.matchAll(/\/([A-Za-z0-9+#.-]+)/g)].map(entry => entry[1]);
  return names.length ? names.join(' + ') : null;
};

const countOccurrences = (haystack: string, needle: string): number => {
  let count = 0;
  let position = haystack.indexOf(needle);
  while (position !== -1) {
    count += 1;
    position = haystack.indexOf(needle, position + needle.length);
  }
  return count;
};

// /Length 定长校验：跳过规范允许的空白后必须紧跟 endstream，否则视为声明不可信。
const verifyEndstreamFollows = (text: string, position: number): boolean => {
  let cursor = position;
  while (cursor < text.length && /[\r\n \t]/.test(text[cursor])) cursor += 1;
  return text.startsWith('endstream', cursor);
};

export const inspectPdf = (bytes: Uint8Array): PdfInspectResult => {
  if (bytes.length > PDF_MAX_BYTES) {
    throw new Error(`文件 ${bytes.length} 字节超过 PDF 引擎上限 ${PDF_MAX_BYTES}（20MB）`);
  }
  const text = latin1ToString(bytes);
  const anomalies: string[] = [];

  // —— header：规范要求偏移 0，容错接受前 1024 字节内出现（超窗视为非 PDF）——
  const headerIndex = text.indexOf('%PDF-');
  if (headerIndex < 0 || headerIndex >= 1024) {
    throw new Error(`不是 PDF 文件：前 1024 字节未找到 %PDF- 头（${headerIndex < 0 ? '全文无命中' : `命中偏移 ${headerIndex} 已超窗`}）`);
  }
  const versionMatch = /^%PDF-(\d+\.\d+)/.exec(text.slice(headerIndex, headerIndex + 24));
  if (headerIndex !== 0) {
    anomalies.push(`%PDF 头不在偏移 0（实际偏移 ${headerIndex}）：多数解析器仍接受，头前字节可能是附加/隐藏数据`);
  }

  // —— 顺序对象扫描：比 xref 表更可信的是对象本体 ——
  const objHeaderRe = /(\d+)\s+(\d+)\s+obj(?![A-Za-z0-9])/g;
  const streamKeywordRe = /stream(\r\n|\r|\n)/g;
  const streams: PdfStreamInfo[] = [];
  const shellSpans: Array<[number, number]> = [];
  let shellStart = 0;
  let objectCount = 0;
  let unpairedEndobj = 0;
  let fallbackLengthCount = 0;
  let cursor = 0;

  while (cursor < text.length) {
    objHeaderRe.lastIndex = cursor;
    const headerMatch = objHeaderRe.exec(text);
    if (!headerMatch) break;
    // obj 头须位于行首语义位置（空白或 '>>' 之后），降低二进制内撞名误报
    if (headerMatch.index > 0 && !/[\s>]/.test(text[headerMatch.index - 1])) {
      cursor = headerMatch.index + headerMatch[0].length;
      continue;
    }
    objectCount += 1;
    const objectNumber = Number.parseInt(headerMatch[1], 10);
    const bodyStart = headerMatch.index + headerMatch[0].length;
    const nominalEndobj = text.indexOf('endobj', bodyStart);
    const windowEnd = nominalEndobj === -1 ? text.length : nominalEndobj;

    // 在对象窗口内找 stream 关键字：后随 EOL，且不是 endstream 的一部分
    streamKeywordRe.lastIndex = bodyStart;
    let streamKeyword: RegExpExecArray | null = null;
    for (let candidate = streamKeywordRe.exec(text); candidate !== null; candidate = streamKeywordRe.exec(text)) {
      if (candidate.index >= windowEnd) break;
      if (text.slice(Math.max(0, candidate.index - 3), candidate.index) === 'end') continue;
      streamKeyword = candidate;
      break;
    }

    if (!streamKeyword) {
      // 非流对象：endobj 收口；缺失则计未配对并吞到文件尾（截断容错）
      if (nominalEndobj === -1) unpairedEndobj += 1;
      const objectEnd = nominalEndobj === -1 ? text.length : nominalEndobj + 6;
      cursor = Math.max(objectEnd, headerMatch.index + headerMatch[0].length);
      continue;
    }

    const dataOffset = streamKeyword.index + streamKeyword[0].length;
    const dict = text.slice(bodyStart, streamKeyword.index);
    let length = -1;
    let dataEnd = -1;
    const lengthMatch = /\/Length(?![A-Za-z0-9])\s+(\d+)/.exec(dict);
    if (lengthMatch) {
      const declared = Number.parseInt(lengthMatch[1], 10);
      const candidateEnd = dataOffset + declared;
      if (candidateEnd > text.length) {
        length = text.length - dataOffset;
        dataEnd = text.length;
        anomalies.push(`对象 ${objectNumber} 的 /Length ${declared} 越过文件末尾（流数据中截断），长度按剩余 ${length} 字节计`);
      } else if (verifyEndstreamFollows(text, candidateEnd)) {
        length = declared;
        dataEnd = candidateEnd;
      }
    }
    if (length < 0) {
      // 回退：/Length 缺失 / 间接引用（N 0 R，上面的正则只捕到首个数字）/ 声明与实际不符
      fallbackLengthCount += 1;
      const endstreamIndex = text.indexOf('endstream', dataOffset);
      if (endstreamIndex === -1) {
        length = text.length - dataOffset;
        dataEnd = text.length;
        anomalies.push(`对象 ${objectNumber} 未找到 endstream（流数据被截断），长度按剩余 ${length} 字节计`);
      } else {
        // 数据与 endstream 之间的 EOL 不属于流数据，回退定位时剔除
        let rawEnd = endstreamIndex;
        while (rawEnd > dataOffset && (text[rawEnd - 1] === '\r' || text[rawEnd - 1] === '\n')) rawEnd -= 1;
        length = rawEnd - dataOffset;
        dataEnd = rawEnd;
      }
    }

    streams.push({ objectNumber, offset: dataOffset, length, filter: parseFilter(dict) });
    // 外壳 = 流数据之外的全部文本；流后跳过 endstream/endobj 再继续扫（压缩数据里的伪 obj 头不再过筛）
    if (dataOffset > shellStart) shellSpans.push([shellStart, dataOffset]);
    const endobjIndex = text.indexOf('endobj', dataEnd);
    let objectEnd: number;
    if (endobjIndex === -1) {
      unpairedEndobj += 1;
      const afterStream = text.indexOf('endstream', dataEnd);
      objectEnd = afterStream === -1 ? text.length : afterStream + 9;
    } else {
      objectEnd = endobjIndex + 6;
    }
    shellStart = Math.max(shellStart, objectEnd);
    cursor = Math.max(objectEnd, headerMatch.index + headerMatch[0].length);
  }
  if (shellStart < text.length) shellSpans.push([shellStart, text.length]);
  const shell = shellSpans.map(([start, end]) => text.slice(start, end)).join('');

  // —— trailer /ID（取首个十六进制串）——
  const idMatch = /\/ID\s*\[\s*<([0-9A-Fa-f\s]+)>/.exec(shell);
  const trailerId = idMatch ? idMatch[1].replace(/\s+/g, '') : null;

  // —— PDFiD 式指标（仅对象外壳）——
  const indicators = INDICATOR_DEFS.map(def => ({ key: def.key, label: def.label, count: countOccurrences(shell, def.key) }));

  // —— /Info 元数据（有限解析）——
  const metadata: Record<string, string> = {};
  for (const key of INFO_KEYS) {
    const keyMatch = new RegExp(`/${key}(?![A-Za-z0-9])\\s*`).exec(shell);
    if (!keyMatch) continue;
    const value = parsePdfStringValue(shell, keyMatch.index + keyMatch[0].length);
    if (value !== null && value.trim()) metadata[key] = value.slice(0, 256);
  }

  // —— % 注释行（外壳内）：排除 header 行与 %%EOF 标记；无可打印 ASCII 的二进制注释行跳过 ——
  const comments: string[] = [];
  for (const rawLine of shell.split('\n')) {
    const line = rawLine.endsWith('\r') ? rawLine.slice(0, -1) : rawLine;
    if (!line.startsWith('%') || line.startsWith('%PDF-') || line.startsWith('%%EOF')) continue;
    const content = line.slice(1).trim();
    if (!content || !/[ -~]/.test(content) || comments.length >= 60) continue;
    comments.push(content.length > 256 ? `${content.slice(0, 256)}…` : content);
  }

  // —— 可疑文本：外壳内 ≥6 字符可打印长串 + 十六进制串解码（flag 藏 <666c6177...> 的高发位），
  // 语法噪声过滤，flag 正则命中排前；收集总量上限防止超大文件的列表失控 ——
  const flagHits: string[] = [];
  const plainHits: string[] = [];
  const seenTexts = new Set<string>();
  const consider = (value: string): void => {
    if (flagHits.length + plainHits.length >= 4000) return;
    const compact = value.trim().replace(/\s+/g, ' ');
    if (compact.length < 6 || !/[A-Za-z]/.test(compact)) return;
    if (seenTexts.has(compact) || SYNTAX_NOISE.test(compact)) return;
    seenTexts.add(compact);
    const entry = compact.length > 200 ? `${compact.slice(0, 200)}…` : compact;
    if (FLAG_PATTERN.test(compact)) flagHits.push(entry);
    else plainHits.push(entry);
  };
  for (const match of shell.matchAll(/[ -~]{6,}/g)) consider(match[0]);
  for (const match of shell.matchAll(/<([0-9A-Fa-f\s]{12,})>/g)) {
    const decoded = hexToBytes(match[1].replace(/\s+/g, ''));
    if (!isPrintableAscii(decoded)) continue;
    consider(latin1ToString(decoded));
  }
  const suspiciousTexts: string[] = [];
  for (const entry of flagHits.slice(0, 40)) suspiciousTexts.push(entry);
  for (const entry of plainHits.slice(0, Math.max(0, 120 - suspiciousTexts.length))) suspiciousTexts.push(entry);

  // —— 文件级结构检查（全部不影响顺序扫描的结果，只做标注）——
  if (!/(^|[\r\n])xref[\r\n]/.test(shell)) {
    anomalies.push('未找到 xref 表（被抹除或损坏）；已按顺序扫描对象，解析不受影响');
  }
  const startxrefMatches = [...shell.matchAll(/startxref\s+(\d+)/g)];
  if (startxrefMatches.length === 0) {
    anomalies.push('未找到 startxref（文件尾结构缺失，可能被截断或手工拼接）');
  } else {
    const target = Number.parseInt(startxrefMatches[startxrefMatches.length - 1][1], 10);
    const pointsAtXref = target >= 0 && target < text.length && text.startsWith('xref', target);
    const pointsAtObject = /^\d+\s+\d+\s+obj(?![A-Za-z0-9])/.test(text.slice(target, target + 32));
    if (!pointsAtXref && !pointsAtObject) {
      anomalies.push(`startxref 指向偏移 ${target}，该处既非 xref 也非对象头（xref 表损坏）；顺序扫描不受影响`);
    }
  }
  if (!text.includes('%%EOF')) anomalies.push('未找到 %%EOF（文件被截断或未写完）');
  if (unpairedEndobj > 0) anomalies.push(`${unpairedEndobj} 个 obj 未找到 endobj（截断或手工拼接痕迹）`);
  if (fallbackLengthCount > 0) {
    anomalies.push(`${fallbackLengthCount} 个 stream 的 /Length 缺失/为间接引用/声明不符，已按下一个 endstream 回退定位`);
  }

  return {
    version: versionMatch ? versionMatch[1] : null,
    objectCount,
    trailerId,
    streams,
    indicators,
    metadata,
    comments,
    suspiciousTexts,
    anomalies,
  };
};
