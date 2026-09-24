// PDF ToUnicode CMap 映射引擎测试：bfchar/bfrange 全形态（连续段 + 数组）、UTF-16BE 多字符 dst
// （连字/CJK/代理对）、codespacerange 不入映射、注释与空白穿插、坏 CMap 容错（坏块丢弃不崩）、
// findToUnicodeStreams 定位（嵌 Font 字典间接引用、Flate/明文双形态、内容流不误报）、
// inspectPdf+pdfText+pdfCmap 端到端还原 Identity-H 双字节 flag。向量程序化自造（自带 PDF 工厂，
// FlateDecode 流用 zlib deflate——RFC1950 zlib 格式与 PDF /FlateDecode 同格式），无外部 fixture。
import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import zlib from 'node:zlib';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const srcDir = path.join(projectRoot, 'src');
const { loadModule } = createTsModuleLoader();
const { parseCmapFromDecoded, findToUnicodeStreams, applyCmapToText, PDF_CMAP_MAX_ENTRIES } = loadModule(
  path.join(srcDir, 'utils', 'ctf', 'pdfCmap.ts'),
);
const { inspectPdf } = loadModule(path.join(srcDir, 'utils', 'ctf', 'pdfInspect.ts'));
const { extractPdfContentText } = loadModule(path.join(srcDir, 'utils', 'ctf', 'pdfText.ts'));

// latin1 直造字节（引擎输入即字节流）；CID 序列 → 双字节 latin1 串（高字节在前）
const S = text => Uint8Array.from(Array.from(text, char => char.charCodeAt(0) & 0xff));
const cidString = (...cids) => cids.map(cid => String.fromCharCode((cid >> 8) & 0xff, cid & 0xff)).join('');

// 真实形态 CMap 外壳（Adobe 规范样例结构）：prologue/codespacerange/endcmap 全套
const wrapCmap = body => `/CIDInit /ProcSet findresource begin
12 dict begin
begincmap
/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def
/CMapName /Adobe-Identity-UCS def
/CMapType 2 def
1 begincodespacerange
<0000> <ffff>
endcodespacerange
${body}
endcmap
CMapName currentdict /CMap defineresource pop
end
end
`;

// 造 PDF（无 xref——inspectPdf 顺序扫描口径）：流对象 _truth 记录造料侧 offset/length 真值
const buildPdf = specs => {
  const parts = [];
  // flat(Infinity) 不展开 TypedArray，字节段统一转普通数组（与 pdf-inspect 测试工厂同口径）
  const push = data => parts.push(Array.from(typeof data === 'string' ? S(data) : data));
  const length = () => parts.reduce((sum, part) => sum + part.length, 0);
  push('%PDF-1.7\n%\xe2\xe3\xcf\xd3\n');
  const truths = {};
  for (const spec of specs) {
    if (!spec.stream) {
      push(`${spec.num} 0 obj\n<< ${spec.dict ?? ''} >>\nendobj\n`);
      continue;
    }
    const raw = Buffer.from(spec.stream.content, 'latin1');
    const data = spec.stream.deflate ? zlib.deflateSync(raw) : raw;
    push(`${spec.num} 0 obj\n<< ${spec.dict ?? ''} /Length ${data.length}${spec.stream.deflate ? ' /Filter /FlateDecode' : ''} >>\nstream\n`);
    truths[spec.num] = { offset: length(), length: data.length };
    push(new Uint8Array(data));
    push('\nendstream\nendobj\n');
  }
  const bytes = Uint8Array.from(parts.flat(Infinity));
  return { bytes, truths };
};

const inflateRange = (bytes, ref) =>
  zlib.inflateSync(bytes.subarray(ref.offset, ref.offset + ref.length));

// ---- 用例 1：bfchar 基础映射 + 注释/空白穿插 + codespacerange 不入映射 ----

test('parseCmapFromDecoded bfchar：<041> <0066> → CID 0x041 映射 f；注释内诱饵不生效；codespacerange 不映射', () => {
  const cmap = parseCmapFromDecoded(S(wrapCmap(`2 beginbfchar
% <00ff> <ffff> decoy hex in comment
<041> <0066>
<042>\t<006c> % endbfchar keyword decoy in comment
endbfchar`)));
  assert.equal(cmap.size, 2, `size=${cmap.size}`);
  assert.equal(cmap.get(0x041), 'f');
  assert.equal(cmap.get(0x042), 'l');
  assert.ok(!cmap.has(0x0000) && !cmap.has(0xffff), 'codespacerange 的 <0000> <ffff> 不得入映射');
});

// ---- 用例 2：bfrange 连续段（dst 末码元逐项 +1）与全段身份映射红线 ----

test('parseCmapFromDecoded bfrange 连续段：<lo> <hi> <dstStart> 按末码元 +1 展开；<0000> <ffff> 全段为红线内', () => {
  const cmap = parseCmapFromDecoded(S(wrapCmap(`2 beginbfrange
<0020> <0022> <0061>
% 伪造 4 字节码枚举炸弹（约 43 亿条）必须按坏块丢弃
<00000000> <ffffffff> <0061>
endbfrange`)));
  assert.equal(cmap.get(0x20), 'a');
  assert.equal(cmap.get(0x21), 'b');
  assert.equal(cmap.get(0x22), 'c');
  assert.equal(cmap.size, 3, '枚举炸弹块不得产出任何条目');
  // 全段 <0000>-<ffff> 恰在 65536 红线内：dstStart <0000> 即恒等映射
  const identity = parseCmapFromDecoded(S('beginbfrange\n<0000> <ffff> <0000>\nendbfrange'));
  assert.equal(identity.size, PDF_CMAP_MAX_ENTRIES);
  assert.equal(identity.get(0x0041), 'A');
  assert.equal(identity.get(0x6c4e), String.fromCharCode(0x6c4e));
});

// ---- 用例 3：bfrange 数组形式（含代理对元素与数量不足截断） ----

test('parseCmapFromDecoded bfrange 数组形式：逐项映射、代理对元素、dst 不足宽度截断', () => {
  const cmap = parseCmapFromDecoded(S(wrapCmap(`2 beginbfrange
<0100> <0102> [<0041> <00e9> <0063>]
<0300> <0303> [<d83dde00> <0058>]
endbfrange`)));
  assert.equal(cmap.get(0x100), 'A');
  assert.equal(cmap.get(0x101), '\u00e9');
  assert.equal(cmap.get(0x102), 'c');
  assert.equal(cmap.get(0x300), '\u{1F600}');
  assert.equal(cmap.get(0x301), 'X');
  assert.ok(!cmap.has(0x302) && !cmap.has(0x303), 'dst 数量不足宽度时不得越界映射');
});

// ---- 用例 4：UTF-16BE 多字符 dst（连字/CJK BMP/代理对/奇数位补零） ----

test('parseCmapFromDecoded 多字符 dst：连字 fl、CJK 你好、emoji 代理对与奇数位补零', () => {
  const cmap = parseCmapFromDecoded(S(wrapCmap(`4 beginbfchar
<0044> <0066006c>
<0045> <4f60597d>
<0046> <d83dde00>
<0047> <041>
endbfchar`)));
  assert.equal(cmap.get(0x44), 'fl');
  assert.equal(cmap.get(0x45), '你好');
  assert.equal(cmap.get(0x46), '\u{1F600}');
  assert.equal(cmap.get(0x47), '\u0410', '3 位 dst 末组右补零 → U+0410');
});

// ---- 用例 5：applyCmapToText 双字节整串还原与容错 ----

test('applyCmapToText：Identity-H 双字节码整串还原 flag，未映射/奇数尾保原样；单字节直查', () => {
  const map = new Map([[0x041, 'f'], [0x042, 'l'], [0x043, 'a'], [0x044, 'g']]);
  const raw = cidString(0x041, 0x042, 0x043, 0x044) + '{cid_tj_recovered}';
  assert.equal(applyCmapToText(raw, map, true), 'flag{cid_tj_recovered}');
  // 未映射 CID：双字符原样保留；奇数尾字符原样保留
  const unmapped = cidString(0x0999) + 'x';
  assert.equal(applyCmapToText(unmapped, map, true), '\t\x99x');
  // 单字节模式：1 字节自定义编码字体重集（<41> <0066> 形态）直查
  const single = new Map([[0x41, 'f']]);
  assert.equal(applyCmapToText('A{b}', single, false), 'f{b}');
  // 空映射原样透传
  assert.equal(applyCmapToText(raw, new Map(), true), raw);
});

// ---- 用例 6：findToUnicodeStreams 定位（嵌 Font 字典引用、双形态、共享去重、内容流不误报） ----

test('findToUnicodeStreams：Font 字典内 /ToUnicode 间接引用定位，offset/length 与造料一致，flate 标记正确', () => {
  const flateCmap = wrapCmap('1 beginbfchar\n<041> <0066>\nendbfchar');
  const plainCmap = wrapCmap('1 beginbfchar\n<042> <0062>\nendbfchar');
  const { bytes, truths } = buildPdf([
    { num: 1, dict: '/Type /Catalog /Pages 2 0 R' },
    { num: 2, dict: '/Type /Pages /Kids [3 0 R] /Count 1' },
    { num: 3, dict: '/Type /Page /Parent 2 0 R /Resources << /Font << /F1 5 0 R /F2 8 0 R /F3 10 0 R >> >> /Contents 4 0 R' },
    { num: 4, dict: '', stream: { content: 'BT /F1 12 Tf (\\000A) Tj ET', deflate: true } },
    { num: 5, dict: '/Type /Font /Subtype /Type0 /BaseFont /AAAAAA+Sub /Encoding /Identity-H /DescendantFonts [6 0 R] /ToUnicode 7 0 R' },
    { num: 6, dict: '/Type /Font /Subtype /CIDFontType2 /BaseFont /AAAAAA+Sub /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >>' },
    { num: 7, dict: '', stream: { content: flateCmap, deflate: true } },
    { num: 8, dict: '/Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding /ToUnicode 9 0 R' },
    { num: 9, dict: '', stream: { content: plainCmap, deflate: false } },
    { num: 10, dict: '/Type /Font /Subtype /Type1 /BaseFont /Courier /ToUnicode 7 0 R' },
  ]);
  const inspected = inspectPdf(bytes);
  const found = Array.from(findToUnicodeStreams(bytes, inspected.streams));
  assert.equal(found.length, 2, '共享同一 ToUnicode 对象的两个字体只产出一份流定位');
  const [flateRef, plainRef] = found;
  assert.equal(flateRef.objectNumber, 7);
  assert.equal(flateRef.flate, true);
  assert.equal(flateRef.offset, truths[7].offset);
  assert.equal(flateRef.length, truths[7].length);
  assert.equal(plainRef.objectNumber, 9);
  assert.equal(plainRef.flate, false);
  assert.equal(plainRef.offset, truths[9].offset);
  assert.equal(plainRef.length, truths[9].length);
  assert.ok(!found.some(ref => ref.objectNumber === 4), '页内容流不得被误判为 ToUnicode');
  // flate 流解压回喂核心、明文流直喂核心
  assert.equal(parseCmapFromDecoded(inflateRange(bytes, flateRef)).get(0x41), 'f');
  assert.equal(parseCmapFromDecoded(bytes.subarray(plainRef.offset, plainRef.offset + plainRef.length)).get(0x42), 'b');
});

// ---- 用例 7：坏 CMap 容错不崩（坏块丢弃、好块保留、截断安全） ----

test('parseCmapFromDecoded 容错：坏块跳过不崩、好块保留、截断/未闭合/lo>hi/越界码均安全', () => {
  assert.equal(parseCmapFromDecoded(S('not a cmap, just text with <0041> <0042> pairs')).size, 0);
  assert.equal(parseCmapFromDecoded(new Uint8Array(0)).size, 0);
  // 非 hex 源码块作废，后续好块保留
  const mixed = parseCmapFromDecoded(S('beginbfchar\n<zz> <0041>\nendbfchar\nbeginbfchar\n<0043> <0063>\nendbfchar'));
  assert.equal(mixed.size, 1);
  assert.equal(mixed.get(0x43), 'c');
  // hex 未闭合 → 块作废
  assert.equal(parseCmapFromDecoded(S('beginbfchar\n<0041 <0042>\nendbfchar')).size, 0);
  // lo > hi 与 9 位越界码 → 坏块跳过
  const badRange = parseCmapFromDecoded(S('beginbfrange\n<0045> <0040> <0061>\nendbfrange\nbeginbfrange\n<0000> <fffffff0> <0061>\nendbfrange'));
  assert.equal(badRange.size, 0);
  // 无 end 关键字截断：已完整条目保留
  const truncated = parseCmapFromDecoded(S('beginbfchar\n<0044> <0067>\n<0045'));
  assert.equal(truncated.get(0x44), 'g');
  assert.ok(!truncated.has(0x45));
});

// ---- 用例 8：端到端组合——inspectPdf 定位 → zlib 解压 → pdfText 提取 → CMap 映射还原 flag ----

test('端到端：CID 子集字体内容流双字节码经 ToUnicode CMap 还原 flag{cid_2byte_combo}', () => {
  const flag = 'flag{cid_2byte_combo}';
  const used = new Map();
  let nextCid = 0x41;
  const entries = [];
  for (const ch of flag) {
    let cid = used.get(ch);
    if (cid === undefined) {
      cid = nextCid;
      nextCid += 1;
      used.set(ch, cid);
    }
    entries.push(`<${cid.toString(16).padStart(4, '0')}> <${ch.charCodeAt(0).toString(16).padStart(4, '0')}>`);
  }
  // 内容流字面串：每个 CID 按 高字节八进制转义 + 低字节原字符 编码（高字节全 0x00 → \000）
  const literal = Array.from(flag, ch => {
    const cid = used.get(ch);
    return `\\${(cid >> 8).toString(8).padStart(3, '0')}${String.fromCharCode(cid & 0xff)}`;
  }).join('');
  const { bytes } = buildPdf([
    { num: 1, dict: '/Type /Catalog /Pages 2 0 R' },
    { num: 2, dict: '/Type /Pages /Kids [3 0 R] /Count 1' },
    { num: 3, dict: '/Type /Page /Parent 2 0 R /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R' },
    { num: 4, dict: '', stream: { content: `BT\n/F1 12 Tf\n72 720 Td\n(${literal}) Tj\nET`, deflate: true } },
    { num: 5, dict: '/Type /Font /Subtype /Type0 /BaseFont /BBBBBB+CTFSub /Encoding /Identity-H /DescendantFonts [6 0 R] /ToUnicode 7 0 R' },
    { num: 6, dict: '/Type /Font /Subtype /CIDFontType2 /BaseFont /BBBBBB+CTFSub /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >>' },
    { num: 7, dict: '', stream: { content: wrapCmap(`${entries.length} beginbfchar\n${entries.join('\n')}\nendbfchar`), deflate: true } },
  ]);

  const inspected = inspectPdf(bytes);
  const refs = Array.from(findToUnicodeStreams(bytes, inspected.streams));
  assert.equal(refs.length, 1);
  assert.equal(refs[0].objectNumber, 7);
  assert.equal(refs[0].flate, true);
  const cmap = parseCmapFromDecoded(inflateRange(bytes, refs[0]));

  const contentStream = inspected.streams.find(stream => stream.objectNumber === 4);
  const texts = Array.from(extractPdfContentText(inflateRange(bytes, contentStream)));
  assert.equal(texts.length, 1);
  // 原始提取结果是双字节码的 latin1 直读串（乱码但字节可见），映射后整串还原
  const expectedRaw = Array.from(flag, ch => `\u0000${String.fromCharCode(used.get(ch) & 0xff)}`).join('');
  assert.equal(texts[0], expectedRaw);
  assert.ok(!/flag/.test(texts[0]), '映射前不得出现明文 flag');
  assert.equal(applyCmapToText(texts[0], cmap, true), flag);
});
