// PDF 内容流文本提取引擎测试：extractPdfContentText 纯函数核心——Tj 单串/TJ 数组多串拼接
// （字距数值忽略）/字面串转义（括号/反斜杠/八进制/行续接）/十六进制串/' 与 " 运算符/无文本流
// 空返回/内联图像 BI…EI 跳过/注释与词边界。测试向量直接以 latin1 构造"已解压"内容流
// （引擎契约：解压由组件层 DecompressionStream 完成，测试不引入 zlib 路径），无外部 fixture。
import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const srcDir = path.join(projectRoot, 'src');
const { loadModule } = createTsModuleLoader();
const { extractPdfContentText } = loadModule(path.join(srcDir, 'utils', 'ctf', 'pdfText.ts'));

// latin1 直造字节（引擎输入即解压后字节流）
const S = text => Uint8Array.from(Array.from(text, char => char.charCodeAt(0) & 0xff));

// 沙箱返回数组勿用 deepStrictEqual（AGENTS.md 跨 realm 踩坑）：先 Array.from 转主 realm 再断言。
const asArray = value => Array.from(value);

// ---- 用例 1：Tj 单串与多操作顺序保持 ----

test('extractPdfContentText Tj：单串提取，多操作按流顺序逐条返回', () => {
  const out = extractPdfContentText(
    S('BT /F1 12 Tf 1 0 0 1 72 720 Tm (Hello flag{Tj_hit}) Tj (second show) Tj ET'),
  );
  assert.deepStrictEqual(asArray(out), ['Hello flag{Tj_hit}', 'second show']);
});

// ---- 用例 2：TJ 数组多串拼接（字距数值忽略）与十六进制串混排 ----

test('extractPdfContentText TJ：数组内字符串与 <hex> 按序拼接为一个条目，数值忽略', () => {
  const out = extractPdfContentText(S('[(Hel)-250(lo )<576f726c64>(2!)] TJ (plain) Tj'));
  assert.deepStrictEqual(asArray(out), ['Hello World2!', 'plain']);
});

// ---- 用例 3：字面串转义（括号/反斜杠/八进制/嵌套括号） ----

test('extractPdfContentText 转义：\\( \\) \\\\ 与八进制 \\ddd 还原，未转义嵌套括号按配深计入', () => {
  const out = extractPdfContentText(S('BT (a\\(b\\)c\\\\d\\101\\ne) Tj (deep (nested) text) Tj ET'));
  assert.deepStrictEqual(asArray(out), ['a(b)c\\dA\ne', 'deep (nested) text']);
});

// ---- 用例 4：十六进制串独立显示与 ' / " 运算符 ----

test('extractPdfContentText hex 与换行算子：<hex> Tj、<hex> \' 与 (..) " 均各成一条', () => {
  const out = extractPdfContentText(S('<48656c6c6f> Tj <666c6167> \' 6.5 3 (dq op) "'));
  assert.deepStrictEqual(asArray(out), ['Hello', 'flag', 'dq op']);
});

// ---- 用例 5：无文本流空返回 ----

test('extractPdfContentText 纯图形流：无文本显示指令返回空数组', () => {
  const out = extractPdfContentText(S('1 0 0 1 5 5 cm 0 0 100 100 re f BT /F1 1 Tf ET'));
  assert.equal(out.length, 0);
});

// ---- 用例 6：内联图像 BI…ID…EI 跳过 ----

test('extractPdfContentText 内联图像：BI…EI 二进制内的伪字符串不产出，其后文本正常提取', () => {
  const out = extractPdfContentText(
    S('q BI /W 8 /H 8 /BPC 8 /CS /G ID x(y)z(( EI (after_image) Tj Q'),
  );
  assert.deepStrictEqual(asArray(out), ['after_image']);
});

// ---- 用例 7：注释穿透与运算符词边界 ----

test('extractPdfContentText 边界：% 注释可穿插在 ] 与 TJ 之间；空串不入场；Tjx 非运算符', () => {
  const out = extractPdfContentText(S('[(a) % kern\n(b)] % c2\nTJ () Tj (c) Tjx'));
  assert.deepStrictEqual(asArray(out), ['ab']);
});
