// PDF 取证解析引擎测试：inspectPdf 顺序对象扫描、PDFiD 式指标计数（外壳口径）、注释/可疑文本
// flag 命中、stream 偏移长度与造料一致性（node:zlib 回解验证）、/Length 回退、坏 xref/截断容错、
// 非 PDF 抛错。测试向量全部程序化构造（自带 xref/trailer 造 PDF 工厂，FlateDecode 流用 zlib
// deflate——RFC1950 zlib 格式与 PDF /FlateDecode 同格式），无外部 fixture。
import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import zlib from 'node:zlib';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const srcDir = path.join(projectRoot, 'src');
const { loadModule } = createTsModuleLoader();
const { inspectPdf, PDF_MAX_BYTES } = loadModule(path.join(srcDir, 'utils', 'ctf', 'pdfInspect.ts'));

// ---- 测试侧 PDF 造流工厂 ----

const B = text => Array.from(text, char => char.charCodeAt(0) & 0xff);

// 造 PDF：header（+注释行+二进制注释行）+ 对象序列 + xref/trailer。
// 流对象的 _truth 记录造料侧 stream 数据真值（offset/length），供"引擎定位 == 造料真值"断言。
// xrefMode：'good' 正常；'bad-startxref' 把 startxref 值指向 xref 偏移+1（表头错位）；'none' 不写。
const buildPdf = ({ version = '1.7', objects = [], comment = null, binaryComment = true, trailerIdHex = null, infoNum = null, xrefMode = 'good' }) => {
  const parts = [];
  const push = text => parts.push(B(text));
  const pushBytes = data => parts.push(Array.from(data));
  const length = () => parts.reduce((sum, part) => sum + part.length, 0);
  const offsets = [];

  push(`%PDF-${version}\n`);
  if (comment !== null) push(`% ${comment}\n`);
  if (binaryComment) pushBytes([0x25, 0xe2, 0xe3, 0xcf, 0xd3, 0x0a]);

  for (const spec of objects) {
    offsets[spec.num] = length();
    if (spec.stream) {
      const raw = Buffer.from(spec.stream.content, 'latin1');
      const data = spec.stream.deflate ? zlib.deflateSync(raw) : raw;
      const lengthPart = spec.stream.indirectLength ? '/Length 99 0 R' : `/Length ${spec.stream.lengthOverride ?? data.length}`;
      const filterPart = spec.stream.deflate ? '/Filter /FlateDecode' : '';
      push(`${spec.num} 0 obj\n<< ${spec.dict ?? ''} ${lengthPart} ${filterPart} >>\nstream\n`);
      spec._truth = { offset: length(), length: data.length };
      pushBytes(data);
      push('\nendstream\nendobj\n');
    } else {
      push(`${spec.num} 0 obj\n<< ${spec.dict ?? ''} >>\nendobj\n`);
    }
  }

  const maxNum = objects.reduce((max, spec) => Math.max(max, spec.num), 0);
  if (xrefMode !== 'none') {
    const xrefOffset = length();
    push('xref\n');
    push(`0 ${maxNum + 1}\n`);
    push('0000000000 65535 f \n');
    for (let num = 1; num <= maxNum; num += 1) {
      push(`${String(offsets[num] ?? 0).padStart(10, '0')} 00000 n \n`);
    }
    let trailer = `trailer\n<< /Size ${maxNum + 1} /Root 1 0 R`;
    if (infoNum !== null) trailer += ` /Info ${infoNum} 0 R`;
    if (trailerIdHex !== null) trailer += ` /ID [<${trailerIdHex}> <${trailerIdHex}>]`;
    push(`${trailer} >>\n`);
    push(`startxref\n${xrefMode === 'bad-startxref' ? xrefOffset + 1 : xrefOffset}\n%%EOF\n`);
  }
  return Uint8Array.from(parts.flat(Infinity));
};

const inflateRange = (bytes, stream) =>
  zlib.inflateSync(bytes.subarray(stream.offset, stream.offset + stream.length)).toString('latin1');

// ---- 用例 1：基础解析 ----

test('inspectPdf 基础解析：版本/对象数/trailerId/元数据，干净文件零 anomalies', () => {
  const objects = [
    { num: 1, dict: '/Type /Catalog /Pages 2 0 R' },
    { num: 2, dict: '/Type /Pages /Kids [3 0 R] /Count 1' },
    { num: 3, dict: '/Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]' },
    { num: 4, dict: '/Type /Font /Subtype /Type1 /BaseFont /Helvetica' },
    { num: 5, dict: "/Title (Payloader PDF Test) /Author (hezihao) /Producer (pdfInspect-fixture) /CreationDate (D:20260924120000+08'00)" },
  ];
  const result = inspectPdf(buildPdf({ version: '1.7', objects, trailerIdHex: 'a1b2c3d4e5f60718a1b2c3d4e5f60718', infoNum: 5 }));
  assert.equal(result.version, '1.7');
  assert.equal(result.objectCount, 5);
  assert.equal(result.trailerId, 'a1b2c3d4e5f60718a1b2c3d4e5f60718');
  assert.equal(result.streams.length, 0);
  assert.equal(result.metadata.Title, 'Payloader PDF Test');
  assert.equal(result.metadata.Author, 'hezihao');
  assert.equal(result.metadata.Producer, 'pdfInspect-fixture');
  assert.ok(result.metadata.CreationDate.startsWith('D:20260924120000'), `CreationDate=${result.metadata.CreationDate}`);
  // 沙箱返回数组勿用 deepStrictEqual（AGENTS.md 跨 realm 踩坑），逐项断言
  assert.equal(result.anomalies.length, 0, `anomalies=${JSON.stringify(result.anomalies)}`);
});

// ---- 用例 2：PDFiD 式风险指标计数 ----

test('inspectPdf 指标计数：各键精确计数，压缩流内的键名不计（对象外壳口径）', () => {
  const objects = [
    { num: 1, dict: '/Type /Catalog /OpenAction 4 0 R /AcroForm 6 0 R' },
    { num: 2, dict: '/Type /Pages /Kids [3 0 R] /Count 1' },
    { num: 3, dict: '/Type /Page /Parent 2 0 R /Annots [7 0 R] /AA << /O 4 0 R >>' },
    { num: 4, dict: '/Type /Action /S /JavaScript /JS (app.alert\\("pwn"\\))' },
    { num: 5, dict: '/Type /Font' },
    { num: 6, dict: '/DA (/Helv 0 Tf 0 g) /NeedAppearances true' },
    { num: 7, dict: '/Type /Annot /Subtype /Link /A << /S /URI /URI (https://ctf.example/flag) >>' },
    { num: 8, dict: '/Type /EmbeddedFile' },
    { num: 9, dict: '/Type /RichMedia' },
    { num: 10, dict: '/Type /Action /S /Launch /Win << /F (cmd.exe) >>' },
    { num: 11, dict: '', stream: { content: '/JavaScript /OpenAction /JS /AA /Launch /EmbeddedFile /RichMedia /URI /Annots /AcroForm buried in compressed data', deflate: true } },
  ];
  const result = inspectPdf(buildPdf({ objects }));
  const countOf = key => result.indicators.find(item => item.key === key).count;
  assert.equal(result.indicators.length, 10);
  assert.equal(countOf('/JavaScript'), 1);
  assert.equal(countOf('/JS'), 1);
  assert.equal(countOf('/OpenAction'), 1);
  assert.equal(countOf('/AA'), 1);
  assert.equal(countOf('/Launch'), 1);
  assert.equal(countOf('/EmbeddedFile'), 1);
  assert.equal(countOf('/RichMedia'), 1);
  assert.equal(countOf('/URI'), 2);
  assert.equal(countOf('/Annots'), 1);
  assert.equal(countOf('/AcroForm'), 1);
});

// ---- 用例 3：注释行命中 flag ----

test('inspectPdf 注释行：flag 命中，header/%%EOF/二进制注释行不进列表', () => {
  const objects = [{ num: 1, dict: '/Type /Catalog' }];
  const result = inspectPdf(buildPdf({ objects, comment: 'flag{pdf_comment_hit}' }));
  assert.equal(result.comments.length, 1, `comments=${JSON.stringify(result.comments)}`);
  assert.equal(result.comments[0], 'flag{pdf_comment_hit}');
});

// ---- 用例 4：可疑文本命中对象体内 flag ----

test('inspectPdf 可疑文本：对象体 flag 排前 + 字典十六进制串解码命中', () => {
  const hexFlag = Buffer.from('flag{hex_hit}', 'latin1').toString('hex');
  const objects = [
    { num: 1, dict: '/Type /Catalog /Pages 2 0 R' },
    { num: 2, dict: '/Type /Page /Parent 1 0 R' },
    { num: 3, dict: `/JS (flag{pdf_object_flag}) /Contents <${hexFlag}>` },
  ];
  const texts = inspectPdf(buildPdf({ objects })).suspiciousTexts;
  const objectFlagIndex = texts.findIndex(text => text.includes('flag{pdf_object_flag}'));
  const hexFlagIndex = texts.indexOf('flag{hex_hit}');
  const plainIndex = texts.findIndex(text => text.includes('/Type /Catalog') && !text.includes('flag{'));
  assert.ok(objectFlagIndex >= 0, `texts=${JSON.stringify(texts)}`);
  assert.ok(hexFlagIndex >= 0, `texts=${JSON.stringify(texts)}`);
  assert.ok(plainIndex >= 0, `texts=${JSON.stringify(texts)}`);
  assert.ok(objectFlagIndex < plainIndex, 'flag 命中应排在普通串之前');
  assert.ok(hexFlagIndex < plainIndex, '十六进制解码命中应排在普通串之前');
});

// ---- 用例 5：stream 偏移/长度与造料一致（组件层解压依赖此） ----

test('inspectPdf stream 定位：offset/length 与造料真值一致，FlateDecode 流 zlib 回解还原', () => {
  const content = 'flag{flate_stream_hit} hidden payload 0123456789 abcdefgh';
  const objects = [
    { num: 1, dict: '/Type /Catalog' },
    { num: 8, dict: '', stream: { content, deflate: true } },
    { num: 9, dict: '', stream: { content: 'plain-stream-data-no-filter', deflate: false } },
  ];
  const bytes = buildPdf({ objects });
  const result = inspectPdf(bytes);
  assert.equal(result.streams.length, 2);
  const flate = result.streams[0];
  const plain = result.streams[1];
  assert.equal(flate.objectNumber, 8);
  assert.equal(flate.offset, objects[1]._truth.offset);
  assert.equal(flate.length, objects[1]._truth.length);
  assert.equal(flate.filter, 'FlateDecode');
  assert.equal(inflateRange(bytes, flate), content);
  assert.equal(plain.objectNumber, 9);
  assert.equal(plain.offset, objects[2]._truth.offset);
  assert.equal(plain.length, objects[2]._truth.length);
  assert.equal(plain.filter, null);
  assert.equal(Buffer.from(bytes.subarray(plain.offset, plain.offset + plain.length)).toString('latin1'), 'plain-stream-data-no-filter');
});

// ---- 用例 6：坏 xref 仍可解析 + anomaly ----

test('inspectPdf 坏 xref：startxref 指向错位偏移仍完整解析并标注', () => {
  const objects = [
    { num: 1, dict: '/Type /Catalog' },
    { num: 2, dict: '/Title (Broken Xref Doc)' },
  ];
  const result = inspectPdf(buildPdf({ objects, xrefMode: 'bad-startxref' }));
  assert.equal(result.objectCount, 2);
  assert.equal(result.metadata.Title, 'Broken Xref Doc');
  assert.ok(result.anomalies.some(note => note.includes('startxref') && note.includes('损坏')), `anomalies=${JSON.stringify(result.anomalies)}`);
});

// ---- 用例 7：非 PDF 抛错 ----

test('inspectPdf 非 PDF 输入：PNG/纯文本/头超 1024 窗均抛中文错误', () => {
  const png = Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, ...new Array(40).fill(0)]);
  assert.throws(() => inspectPdf(png), /不是 PDF/);
  assert.throws(() => inspectPdf(Uint8Array.from(B('hello world, definitely not a pdf'))), /不是 PDF/);
  const farHeader = Uint8Array.from([...new Array(1030).fill(0x41), ...B('%PDF-1.4\n')]);
  assert.throws(() => inspectPdf(farHeader), /不是 PDF/);
});

// ---- 用例 8：截断容错 ----

test('inspectPdf 截断容错：流数据中截断按剩余长度计，后续对象不再计并标注', () => {
  const objects = [
    { num: 1, dict: '/Type /Catalog' },
    { num: 2, dict: '/Type /Pages' },
    { num: 3, dict: '', stream: { content: 'X'.repeat(300), deflate: false } },
    { num: 4, dict: '/Type /NeverReached' },
  ];
  const bytes = buildPdf({ objects });
  const cut = objects[2]._truth.offset + 37;
  const result = inspectPdf(bytes.slice(0, cut));
  assert.equal(result.objectCount, 3);
  assert.equal(result.streams.length, 1);
  assert.equal(result.streams[0].objectNumber, 3);
  assert.equal(result.streams[0].length, 37);
  assert.ok(result.anomalies.some(note => note.includes('截断')), `anomalies=${JSON.stringify(result.anomalies)}`);
  assert.ok(result.anomalies.some(note => note.includes('%%EOF')));
  assert.ok(result.anomalies.some(note => note.includes('endobj')));
});

// ---- 用例 9：/Length 声明错误与间接引用回退 ----

test('inspectPdf /Length 异常回退：声明值错误与间接引用均按 endstream 定位，回解一致', () => {
  const wrongLength = 'flag{wrong_length_hit} ' + 'x'.repeat(150);
  const indirect = 'flag{indirect_length_hit} ' + 'y'.repeat(150);
  const objects = [
    { num: 1, dict: '/Type /Catalog' },
    { num: 2, dict: '', stream: { content: wrongLength, deflate: true, lengthOverride: 5 } },
    { num: 3, dict: '', stream: { content: indirect, deflate: true, indirectLength: true } },
  ];
  const bytes = buildPdf({ objects });
  const result = inspectPdf(bytes);
  assert.equal(result.streams.length, 2);
  assert.equal(result.streams[0].length, objects[1]._truth.length);
  assert.equal(result.streams[1].length, objects[2]._truth.length);
  assert.ok(result.anomalies.some(note => note.includes('回退')), `anomalies=${JSON.stringify(result.anomalies)}`);
  assert.equal(inflateRange(bytes, result.streams[0]), wrongLength);
  assert.equal(inflateRange(bytes, result.streams[1]), indirect);
});

// ---- 用例 10：头不在 0 偏移 ----

test('inspectPdf 头不在偏移 0：仍解析版本并标注附加前缀', () => {
  const pdfBytes = buildPdf({ version: '1.4', objects: [{ num: 1, dict: '/Type /Catalog' }] });
  const prefixed = Uint8Array.from([...B('JUNK-PREFIX-BYTES '), ...pdfBytes]);
  const result = inspectPdf(prefixed);
  assert.equal(result.version, '1.4');
  assert.equal(result.objectCount, 1);
  assert.ok(result.anomalies.some(note => note.includes('不在偏移 0')), `anomalies=${JSON.stringify(result.anomalies)}`);
});

// ---- 用例 11：红线与指标形状 ----

test('PDF_MAX_BYTES 红线为 20MB；indicators 固定十条且干净文件全为 0', () => {
  assert.equal(PDF_MAX_BYTES, 20 * 1024 * 1024);
  const result = inspectPdf(buildPdf({ objects: [{ num: 1, dict: '/Type /Catalog' }] }));
  assert.equal(result.indicators.length, 10);
  for (const item of result.indicators) {
    assert.equal(typeof item.count, 'number');
    assert.ok(item.label.length > 0 && item.key.startsWith('/'));
    assert.equal(item.count, 0);
  }
});
