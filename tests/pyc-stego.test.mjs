// pyc 解析器 + Stegosaurus 隐写提取测试。
// 向量策略（双保险，离线可跑）：
// 1) 内嵌 base64 真实向量——本机 CPython 3.10.11 / 3.11.16 / 3.12.14（python-build-standalone）
//    py_compile 现编的 pyc；stego 载体由 AngelKitty/stegosaurus 的 stegosaurus.py 原版
//    `_embedPayload`/`_extractPayload`（8271 字节源码逐行核对）真实嵌入产出，
//    交叉验证闭环：工具自己的 -x 提取结果 = "flag{r34l_st3g0saurus}"，容量报告 23。
// 2) 运行时若发现可用 python（PYTHON_BIN > python > python3 > py -3.10 > py），现场在系统
//    临时目录重编 3.10 向量断言（临时文件不落项目目录）；无 python 时跳过该组。
// marshal ref（TYPE_REF/FLAG_REF 同对象复用）用真实编译器去重产物 + 手工合成流双重覆盖。
// 注意：被测模块经 vm 沙箱加载，其返回数组是沙箱 realm 的 Array——deepEqual 前必须
// Array.from 转主 realm（项目已知坑，见 AGENTS.md node:vm 条目）。
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const srcDir = path.join(projectRoot, 'src');
const { loadModule } = createTsModuleLoader();
const {
  parsePyc,
  unmarshalPython,
  extractPycInfo,
  walkCodeObjects,
  PYC_MAX_BYTES,
} = loadModule(path.join(srcDir, 'utils', 'ctf', 'pycParse.ts'));
const {
  extractStegosaurus,
  detectPycAnomaly,
  iterateStegoSlots,
  STEGO_HAVE_ARGUMENT,
} = loadModule(path.join(srcDir, 'utils', 'ctf', 'pycStego.ts'));

const arr = value => Array.from(value); // 沙箱数组 → 主 realm（deepEqual 前置转换）

// ---- 内嵌真实向量（生成环境：CPython 3.10.11/3.11.16/3.12.14 + stegosaurus.py 原版嵌入）----
const vec = b64 => Uint8Array.from(Buffer.from(b64, 'base64'));

// t.py：flag_str = "flag{pyc_test}" / b"\x89PNGflag{bytes_level}" / def f(a,/,c=1,*,d=2) 内
// "flag{nested_func}" / class K: v="flag{class_attr}"；由三个版本各自 py_compile 产出。
const V_T310 = vec(
  'bw0NCgAAAAD46LVquwAAAOMAAAAAAAAAAAAAAAAAAAAABAAAAEAAAABzMgAAAGQAWgBkAVoBZApkA2QEnAFkBWQGhANaAkcAZAdkCIQAZAiDAloDZQRlAIMBAQBkCVMAKQt6DmZsYWd7cHljX3Rlc3R9cxUAAACJUE5HZmxhZ3tieXRlc19sZXZlbH3pAQAAAOkCAAAAKQHaAWRjAgAAAAEAAAABAAAABAAAAAIAAABDAAAAcxAAAABkAX0DfAB8ARcAfAIXAFMAKQJOehFmbGFne25lc3RlZF9mdW5jfakAKQTaAWHaAWNyAwAAANoBc3IEAAAAcgQAAAD6BHQucHnaAWYDAAAAcwQAAAAEAQwBcgkAAABjAAAAAAAAAAAAAAAAAAAAAAEAAABAAAAAcxAAAABlAFoBZABaAmQBWgNkAlMAKQPaAUt6EGZsYWd7Y2xhc3NfYXR0cn1OKQTaCF9fbmFtZV9f2gpfX21vZHVsZV9f2gxfX3F1YWxuYW1lX1/aAXZyBAAAAHIEAAAAcgQAAAByCAAAAHIKAAAABgAAAHMEAAAACAAIAXIKAAAATikBcgEAAAApBVoIZmxhZ19zdHLaAWJyCQAAAHIKAAAA2gVwcmludHIEAAAAcgQAAAByBAAAAHIIAAAA2gg8bW9kdWxlPgEAAABzCgAAAAQABAEQAQ4DDAI=',
);
const V_T311 = vec(
  'pw0NCgAAAAD46LVquwAAAOMAAAAAAAAAAAAAAAAEAAAAAAAAAPNMAAAAlwBkAFoAZAFaAWQJZANkBJwBZAWEA1oCAgBHAGQGhABkB6YCAACrAgAAAAAAAAAAWgMCAGUEZQCmAQAAqwEAAAAAAAAAAAEAZAhTACkKeg5mbGFne3B5Y190ZXN0fXMVAAAAiVBOR2ZsYWd7Ynl0ZXNfbGV2ZWx96QEAAADpAgAAACkB2gFkYwIAAAABAAAAAQAAAAIAAAADAAAA8xYAAACXAGQBfQN8AHwBegAAAHwCegAAAFMAKQJOehFmbGFne25lc3RlZF9mdW5jfakAKQTaAWHaAWNyBAAAANoBc3MEAAAAICAgIPoEdC5wedoBZnILAAAAAwAAAHMVAAAAgADYCBuAQdgLDIhxiTWQMYk50AQU8wAAAABjAAAAAAAAAAAAAAAAAQAAAAAAAADzEgAAAJcAZQBaAWQAWgJkAVoDZAJTACkD2gFLehBmbGFne2NsYXNzX2F0dHJ9TikE2ghfX25hbWVfX9oKX19tb2R1bGVfX9oMX19xdWFsbmFtZV9f2gF2cgYAAAByDAAAAHIKAAAAcg4AAAByDgAAAAYAAABzEwAAAIAAgACAAIAAgADYCBqAQYBBgEFyDAAAAHIOAAAATikBcgIAAAApBdoIZmxhZ19zdHLaAWJyCwAAAHIOAAAA2gVwcmludHIGAAAAcgwAAAByCgAAAPoIPG1vZHVsZT5yFgAAAAEAAABzaAAAAPADAQEB2AsbgAjYBB+AAfACAgEVkGHwAAIBFfAAAgEV8AACARXwAAIBFfAAAgEV8AYBARvwAAEBG/AAAQEb8AABARvwAAEBG/EAAQEb9AABARvwAAEBG+AABYAFgGiBD4QPgA+AD4APcgwAAAA=',
);
const V_T312 = vec(
  'yw0NCgAAAAD46LVquwAAAOMAAAAAAAAAAAAAAAAEAAAAAAAAAPM+AAAAlwBkAFoAZAFaAWQIZAJkA5wBZASEA1oCAgBHAGQFhABkBqsCAAAAAAAAWgMCAGUEZQCrAQAAAAAAAAEAeQcpCXoOZmxhZ3tweWNfdGVzdH1zFQAAAIlQTkdmbGFne2J5dGVzX2xldmVsfekCAAAAKQHaAWRjAgAAAAEAAAABAAAAAgAAAAMAAADzFgAAAJcAZAF9A3wAfAF6AAAAfAJ6AAAAUwApAk56EWZsYWd7bmVzdGVkX2Z1bmN9qQApBNoBYdoBY3IDAAAA2gFzcwQAAAAgICAg+gR0LnB52gFmcgoAAAADAAAAcxUAAACAANgIG4BB2AsMiHGJNZAxiTnQBBTzAAAAAGMAAAAAAAAAAAAAAAABAAAAAAAAAPMQAAAAlwBlAFoBZABaAmQBWgN5AikD2gFLehBmbGFne2NsYXNzX2F0dHJ9TikE2ghfX25hbWVfX9oKX19tb2R1bGVfX9oMX19xdWFsbmFtZV9f2gF2cgUAAAByCwAAAHIJAAAAcg0AAAByDQAAAAYAAABzBwAAAIQA2AgagUFyCwAAAHINAAAATikB6QEAAAApBdoIZmxhZ19zdHLaAWJyCgAAAHINAAAA2gVwcmludHIFAAAAcgsAAAByCQAAANoIPG1vZHVsZT5yFgAAAAEAAABzLAAAAPADAQEB2AsbgAjYBB+AAfACAgEVkGH0AAIBFfcGAQEb8QABARvhAAWAaIUPcgsAAAA=',
);
// dup.py：同字面量 "flag{dup_ref}" 重复 4 次（编译器去重 → marshal 发 TYPE_REF）+ 大整数常量。
const V_DUP310 = vec(
  'bw0NCgAAAADt6bVqcgAAAOMAAAAAAAAAAAAAAAAAAAAAAQAAAEAAAABzFAAAAGQAWgBkAVoBZAFaAmQCWgNkA1MAKQT6DWZsYWd7ZHVwX3JlZn0pAnIBAAAAcgEAAABsBwAAANIKfhy5A58bbH8hXWMATikE2gFh2gFi2gFj2gFuqQByBgAAAHIGAAAA+gZkdXAucHnaCDxtb2R1bGU+AQAAAHMIAAAABAAEAQQBCAE=',
);
// carrier310.pyc：t.py + dead() 函数（大量无参指令造死槽），容量 23（工具 -r 实测）。
const V_CARRIER310 = vec(
  'bw0NCgAAAACS67Vq8QEAAOMAAAAAAAAAAAAAAAAAAAAABAAAAEAAAABzOgAAAGQAWgBkAVoBZAxkA2QEnAFkBWQGhANaAkcAZAdkCIQAZAiDAloDZAlkCoQAWgRlBWUAgwEBAGQLUwApDXoOZmxhZ3tweWNfdGVzdH1zFQAAAIlQTkdmbGFne2J5dGVzX2xldmVsfekBAAAA6QIAAAApAdoBZGMCAAAAAQAAAAEAAAAEAAAAAgAAAEMAAABzEAAAAGQBfQN8AHwBFwB8AhcAUwApAk56EWZsYWd7bmVzdGVkX2Z1bmN9qQApBNoBYdoBY3IDAAAA2gFzcgQAAAByBAAAAPoKY2Fycmllci5wedoBZgMAAABzBAAAAAQBDAFyCQAAAGMAAAAAAAAAAAAAAAAAAAAAAQAAAEAAAABzEAAAAGUAWgFkAFoCZAFaA2QCUwApA9oBS3oQZmxhZ3tjbGFzc19hdHRyfU4pBNoIX19uYW1lX1/aCl9fbW9kdWxlX1/aDF9fcXVhbG5hbWVfX9oBdnIEAAAAcgQAAAByBAAAAHIIAAAAcgoAAAAGAAAAcwQAAAAIAAgBcgoAAABjAQAAAAAAAAAAAAAABAAAAAIAAABDAAAAc44AAAB8AGQBFwB9AHwAZAIYAH0AfABkAxQAfQB8AGQEGgB9AHwAZAUWAH0AfABkBhMAfQB8AGQHQAB9AHwAZAhCAH0AfABkCUEAfQB8AGQBPgB9AHwAZAI/AH0AfAALAH0AfAAKAH0AfAAPAH0AfAB8AGYCfQF8AGcBfQJ+AmQKRABdBX0DfANyRHE/cT98AFMAKQtOcgEAAAByAgAAAOkDAAAA6QQAAADpBQAAAOkGAAAA6QcAAADpCAAAAOkJAAAAKQJyAQAAAHICAAAAcgQAAAApBNoBeNoBedoBetoBaXIEAAAAcgQAAAByCAAAANoEZGVhZAgAAABzLAAAAAgBCAEIAQgBCAEIAQgBCAEIAQgBCAEGAQYBBgEIAQYBAgEIAQQBAgEC/wQCchoAAABOKQFyAQAAACkGWghmbGFnX3N0ctoBYnIJAAAAcgoAAAByGgAAANoFcHJpbnRyBAAAAHIEAAAAcgQAAAByCAAAANoIPG1vZHVsZT4BAAAAcwwAAAAEAAQBEAEOAwgCDBY=',
);
// stego310.pyc：stegosaurus.py 原版 _embedPayload 写入 "flag{r34l_st3g0saurus}"（872→872 字节不变）。
const V_STEGO310 = vec(
  'bw0NCgAAAACS67Vq8QEAAGMAAAAAAAAAAAAAAAAAAAAABAAAAEAAAABzOgAAAGQAWgBkAVoBZAxkA2QEnAFkBWQGhANaAkdzZAdkCIQAZAiDAloDZAlkCoQAWgRlBWUAgwEBfWQLUwApDfoOZmxhZ3tweWNfdGVzdH3zFQAAAIlQTkdmbGFne2J5dGVzX2xldmVsfekBAAAA6QIAAACpAdoBZGMCAAAAAQAAAAEAAAAEAAAAAgAAAEMAAABzEAAAAGQBfQN8AHwBF3V8AhdyU3UpAk76EWZsYWd7bmVzdGVkX2Z1bmN9qQCpBNoBYdoBY3IFAAAA2gFzcgcAAAByBwAAAPoKY2Fycmllci5wedoBZgMAAADzBAAAAAQBDAFyDQAAAGMAAAAAAAAAAAAAAAAAAAAAAQAAAEAAAABzEAAAAGUAWgFkAFoCZAFaA2QCU2EpA9oBS/oQZmxhZ3tjbGFzc19hdHRyfU6pBNoIX19uYW1lX1/aCl9fbW9kdWxlX1/aDF9fcXVhbG5hbWVfX9oBdnIHAAAAcgcAAAByBwAAAHIMAAAAcg8AAAAGAAAA8wQAAAAIAAgBcg8AAABjAQAAAAAAAAAAAAAABAAAAAIAAABDAAAAc44AAAB8AGQBF2Z9AHwAZAIYbH0AfABkAxRhfQB8AGQEGmd9AHwAZAUWe30AfABkBhNyfQB8AGQHQDN9AHwAZAhCNH0AfABkCUFsfQB8AGQBPl99AHwAZAI/c30AfAALdH0AfAAKM30AfAAPZ30AfAB8AGYCfQF8AGcBfQJ+AmQKRDBdBX0DfANyRHE/cT98AFNzKQtOcgIAAAByAwAAAOkDAAAA6QQAAADpBQAAAOkGAAAA6QcAAADpCAAAAOkJAAAAqQJyAgAAAHIDAAAAcgcAAACpBNoBeNoBedoBetoBaXIHAAAAcgcAAAByDAAAANoEZGVhZAgAAADzLAAAAAgBCAEIAQgBCAEIAQgBCAEIAQgBCAEGAQYBBgEIAQYBAgEIAQQBAgEC/wQCciQAAABOqQFyAgAAAKkGWghmbGFnX3N0ctoBYnINAAAAcg8AAAByJAAAANoFcHJpbnRyBwAAAHIHAAAAcgcAAAByDAAAANoIPG1vZHVsZT4BAAAA8wwAAAAEAAQBEAEOAwgCDBY=',
);

// ---- 运行时 python 发现（仅用于现场再生成 3.10 向量，找不到则跳过）----
const findPython = () => {
  const candidates = [process.env.PYTHON_BIN, 'python', 'python3', 'py -3.10', 'py -3', 'py'].filter(Boolean);
  for (const candidate of candidates) {
    const parts = candidate.split(' ');
    const probe = spawnSync(parts[0], [...parts.slice(1), '-c', 'import sys;print(sys.version.split()[0])'], {
      encoding: 'utf8',
      timeout: 15000,
    });
    if (probe.status === 0) return { command: candidate, version: probe.stdout.trim() };
  }
  return null;
};

const T_PY_SOURCE = [
  'flag_str = "flag{pyc_test}"',
  'b = b"\\x89PNGflag{bytes_level}"',
  'def f(a, /, c=1, *, d=2):',
  '    s = "flag{nested_func}"',
  '    return a + c + d',
  'class K:',
  '    v = "flag{class_attr}"',
  'print(flag_str)',
  '',
].join('\n');

test('parsePyc：3.10/3.11/3.12 真实向量——版本、头、尾零附、布局字段', () => {
  const cases = [
    [V_T310, '3.10', 3439, 'posonly'],
    [V_T311, '3.11', 3495, 'modern'],
    [V_T312, '3.12', 3531, 'modern'],
  ];
  for (const [bytes, version, magic, layout] of cases) {
    const parsed = parsePyc(bytes);
    assert.equal(parsed.header.version, version);
    assert.equal(parsed.header.magic, magic);
    assert.equal(parsed.header.layout, layout);
    assert.equal(parsed.header.headerSize, 16); // PEP 552（magic ≥ 3392）
    assert.equal(parsed.header.hashBased, false);
    assert.ok(parsed.header.timestamp !== null && parsed.header.timestamp > 0);
    assert.equal(parsed.trailingBytes, 0, `${version} 向量不应有尾附数据`);
    assert.equal(parsed.endOffset, bytes.length);
  }
  // 3.11+ 现代布局：nlocals 删除、qualname/localsplus/exceptiontable 就位（函数 f 的局部 a）
  const modernCodes = walkCodeObjects(parsePyc(V_T311).root);
  assert.equal(parsePyc(V_T311).root.nlocals, null);
  assert.ok(parsePyc(V_T311).root.qualname !== null);
  assert.ok(parsePyc(V_T311).root.exceptiontable !== null);
  const funcF = modernCodes.find(code => code.name === 'f');
  assert.ok(funcF, '应解析出函数 f 的 code object');
  assert.ok(funcF.localsplusnames !== null && arr(funcF.localsplusnames).includes('a'), 'f 的 localsplusnames 应含参数 a');
  // 3.8-3.10 posonly 布局：nlocals 仍在、qualname/localsplus 为 null
  const posonlyRoot = parsePyc(V_T310).root;
  assert.ok(posonlyRoot.nlocals !== null);
  assert.equal(posonlyRoot.qualname, null);
  assert.equal(posonlyRoot.localsplusnames, null);
  const posonlyF = walkCodeObjects(posonlyRoot).find(code => code.name === 'f');
  assert.ok(posonlyF && arr(posonlyF.varnames).includes('s'), '3.10 的 f.varnames 应含局部 s');
  assert.equal(posonlyF.posonlyargcount, 1, 'f 有 1 个仅位置参数（PEP 570）');
});

test('extractPycInfo：挖出全部嵌套 code object 的字符串/bytes 常量与 flag 候选', () => {
  for (const bytes of [V_T310, V_T311, V_T312]) {
    const info = extractPycInfo(bytes);
    const stringValues = arr(info.strings).map(item => item.value);
    for (const expected of ['flag{pyc_test}', 'flag{nested_func}', 'flag{class_attr}']) {
      assert.ok(stringValues.includes(expected), `应挖出字符串常量 ${expected}`);
    }
    assert.ok(arr(info.names).includes('print'), 'co_names 应含全局名 print');
    assert.ok(arr(info.varnames).includes('s'), 'f 的局部变量 s 应在 varnames/localsplusnames');
    assert.ok(info.codeCount >= 3, '模块 + f + K 至少 3 个 code object');
    assert.ok(info.totalCodeBytes > 0);
    const candidateValues = arr(info.flagCandidates).map(item => item.value);
    assert.ok(candidateValues.includes('flag{pyc_test}'), 'flag 候选应命中花括号型');
    // bytes 常量 b"\x89PNGflag{bytes_level}"：hex 前缀 89504e47，latin1 面可读出 flag
    const pngConst = arr(info.bytesConsts).find(item => item.hex.startsWith('89504e47'));
    assert.ok(pngConst, '应识别 PNG 头 bytes 常量');
    assert.ok(pngConst.latin1.includes('flag{bytes_level}'));
  }
});

test('运行时 python 现场向量（本机 3.10.11；无 python 则跳过）', { timeout: 60000 }, t => {
  const found = findPython();
  if (!found) {
    t.skip('本机未发现可用 python，回落内嵌向量（已由其他用例覆盖）');
    return;
  }
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'payloader-pyc-'));
  const pyFile = path.join(dir, 't.py');
  const pycFile = path.join(dir, 't.pyc');
  fs.writeFileSync(pyFile, T_PY_SOURCE);
  const parts = found.command.split(' ');
  const run = spawnSync(
    parts[0],
    [...parts.slice(1), '-c', `import py_compile;py_compile.compile(${JSON.stringify(pyFile)}, ${JSON.stringify(pycFile)}, doraise=True)`],
    { encoding: 'utf8', timeout: 45000 },
  );
  assert.equal(run.status, 0, `py_compile 失败：${run.stderr}`);
  const bytes = Uint8Array.from(fs.readFileSync(pycFile));
  const parsed = parsePyc(bytes);
  assert.ok(parsed.header.version.startsWith('3.'), `现场向量版本异常：${parsed.header.version}（python ${found.version}）`);
  assert.equal(parsed.endOffset, bytes.length);
  const info = extractPycInfo(bytes);
  const stringValues = arr(info.strings).map(item => item.value);
  for (const expected of ['flag{pyc_test}', 'flag{nested_func}']) {
    assert.ok(stringValues.includes(expected));
  }
});

test('marshal ref 复用：真实编译器去重产物（TYPE_REF）+ 大整数 TYPE_LONG', () => {
  const parsed = parsePyc(V_DUP310);
  const occurrences = arr(parsed.root.consts).filter(item => item.kind === 'str' && item.value === 'flag{dup_ref}');
  // 源码 4 处字面量 → 编译器去重为 1 个对象，consts 里直接出现 1 次 + 元组内 2 次 ref 复用
  assert.equal(occurrences.length, 1);
  const tupleConst = arr(parsed.root.consts).find(item => item.kind === 'tuple');
  assert.ok(tupleConst, '应解析出元组常量 (flag, flag)');
  assert.equal(tupleConst.items.length, 2);
  assert.ok(arr(tupleConst.items).every(item => item.kind === 'str' && item.value === 'flag{dup_ref}'), '元组内两次 TYPE_REF 均应解析回同一字符串');
  // 123456789012345678901234567890 → TYPE_LONG 7 位块 → bigint
  const big = arr(parsed.root.consts).find(item => item.kind === 'bigint');
  assert.ok(big, '大整数应走 TYPE_LONG→bigint 分支');
  assert.equal(big.value, 123456789012345678901234567890n);
});

test('marshal 合成流：ref 链、悬挂 ref、集合/字典/浮点/遗留文本浮点', () => {
  // [FLAG_REF 小元组(3): FLAG_REF Z"abc"(idx1), TYPE_REF 1, FLAG_REF None] —— 先序保留索引语义
  const refChain = Uint8Array.from([
    0xa9, 0x03, // ) +FLAG_REF，count 3 → 预留 idx0
    0xda, 0x03, 0x61, 0x62, 0x63, // Z +FLAG_REF，len 3 "abc" → idx1
    0x72, 0x01, 0x00, 0x00, 0x00, // r idx1 → 复用 "abc"
    0xce, // N +FLAG_REF
  ]);
  const refResult = unmarshalPython(refChain, { offset: 0, magic: 3439 });
  assert.equal(refResult.endOffset, refChain.length);
  assert.equal(refResult.value.kind, 'tuple');
  assert.deepEqual(arr(refResult.value.items).map(item => (item.kind === 'str' ? item.value : item.kind)), ['abc', 'abc', 'none']);

  // 悬挂 ref（索引 5 超出已登记数）必须报错而非静默错读
  assert.throws(() => unmarshalPython(Uint8Array.from([0x72, 0x05, 0x00, 0x00, 0x00]), { magic: 3439 }), /TYPE_REF 索引越界/);

  // set / frozenset / dict(NULL 终止) / 二进制浮点 / 遗留文本浮点 / Ellipsis / 负 TYPE_LONG
  //（list/set 的元素数是 i32，非单字节——与 marshal.c r_long 一致）
  const blob = Uint8Array.from([
    0x5b, 0x07, 0x00, 0x00, 0x00, // [ list count 7（i32）
    0x3c, 0x02, 0x00, 0x00, 0x00, 0x69, 0x01, 0x00, 0x00, 0x00, 0x69, 0x02, 0x00, 0x00, 0x00, // < set{1,2}
    0x3e, 0x01, 0x00, 0x00, 0x00, 0x69, 0x03, 0x00, 0x00, 0x00, // > frozenset{3}
    0x7b, 0x7a, 0x01, 0x6b, 0x69, 0x2a, 0x00, 0x00, 0x00, 0x30, // { z"k": 42, NULL 结束
    0x67, ...doubleBytes(1.5), // g 二进制浮点
    0x66, 0x03, 0x00, 0x00, 0x00, 0x32, 0x2e, 0x35, // f 遗留文本浮点，i32 长度 + "2.5"
    0x2e, // . Ellipsis
    0x6c, 0xff, 0xff, 0xff, 0xff, 0x01, 0x00, // l -1 个 2^15 位块 → -1
    // TYPE_LIST 长度前缀制，无闭合标记（7 个元素到此为止）
  ]);
  const blobResult = unmarshalPython(blob, { offset: 0, magic: 3439 });
  assert.equal(blobResult.endOffset, blob.length);
  const items = arr(blobResult.value.items);
  assert.deepEqual(arr(items[0].items).map(item => item.value), [1, 2]);
  assert.deepEqual(arr(items[1].items).map(item => item.value), [3]);
  assert.deepEqual(arr(items[2].entries).map(entry => [entry.key.value, entry.value.value]), [['k', 42]]);
  assert.equal(items[3].value, 1.5);
  assert.equal(items[4].value, 2.5);
  assert.equal(items[5].kind, 'ellipsis');
  assert.equal(items[6].value, -1);
});

const doubleBytes = value => {
  const buffer = new ArrayBuffer(8);
  new DataView(buffer).setFloat64(0, value, true);
  return [...new Uint8Array(buffer)];
};

test('头变体与错误路径：PEP 552 哈希头、未知 magic、截断、20MB 红线', () => {
  // 哈希校验头：flags bit0=1，8 字节 SipHash，marshal 流同样从 16 起
  const hashed = V_T310.slice();
  new DataView(hashed.buffer).setUint32(4, 1, true);
  const hashedParsed = parsePyc(hashed);
  assert.equal(hashedParsed.header.hashBased, true);
  assert.equal(hashedParsed.header.hash.length, 8);
  assert.equal(hashedParsed.header.timestamp, null);
  assert.equal(hashedParsed.trailingBytes, 0);

  assert.throws(() => parsePyc(Uint8Array.from([0x99, 0x99, 0x0d, 0x0a, 0, 0, 0, 0, 0, 0, 0, 0])), /未知 pyc magic/);
  assert.throws(() => parsePyc(Uint8Array.from([0x6f, 0x0d, 0x0d, 0x0a, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x63])), /截断/);
  const oversized = new Uint8Array(PYC_MAX_BYTES + 1);
  oversized.set(V_T310.subarray(0, 16));
  assert.throws(() => parsePyc(oversized), /20MB 上限/);
});

test('Stegosaurus 提取：真实工具嵌入向量（与原版 -x 输出逐字节一致）', () => {
  const result = extractStegosaurus(V_STEGO310);
  assert.deepEqual(arr(result.payloads), ['flag{r34l_st3g0saurus}']);
  assert.equal(result.slotCount, 23, '死槽总数应等于工具 -r 报告的容量 23');
  const clean = extractStegosaurus(V_CARRIER310);
  assert.deepEqual(arr(clean.payloads), [], '干净载体应无 payload');
  assert.equal(clean.slotCount, 23);
  const report = detectPycAnomaly(V_STEGO310);
  assert.equal(report.stegoSuspect, true);
  assert.ok(report.slotNonzero >= 'flag{r34l_st3g0saurus}'.length);
});

test('干净载体跨版本零误报 + explodeAfter 槽位裁剪（合成 printable-opcode 载体）', () => {
  for (const bytes of [V_T310, V_T311, V_T312, V_CARRIER310, V_DUP310]) {
    const report = detectPycAnomaly(bytes);
    assert.equal(report.stegoSuspect, false, '干净 pyc 的死槽应全零（CPython 汇编器恒写 0）');
    assert.equal(report.nonzeroHex, '');
  }
  const carrierCodes = walkCodeObjects(parsePyc(V_CARRIER310).root);
  assert.equal(iterateStegoSlots(carrierCodes, Infinity).length, 23);
  assert.equal(STEGO_HAVE_ARGUMENT, 90);
  // explodeAfter 只在"槽前连续可打印字节 ≥ N"时跳槽（防 strings 泄漏）。CPython 真实指令的
  // opcode 字节几乎都 < 0x20（不可打印），计数每 2 字节归零 → 真实载体上永不触发，与工具同义。
  // 用 opcode 字节可打印（0x30='0'<90）的合成载体验证跳槽分支确实生效。
  const printableOps = makeSyntheticPyc([0x30, 0x41, 0x30, 0x42, 0x30, 0x43, 0x30, 0x44]);
  const printableCodes = walkCodeObjects(parsePyc(printableOps).root);
  assert.equal(iterateStegoSlots(printableCodes, Infinity).length, 4, '不设阈值应得 4 槽');
  assert.ok(iterateStegoSlots(printableCodes, 2).length < 4, 'explodeAfter=2 应跳过部分槽');
});

test('字节级手写嵌入器：按协议 patch 载体 co_code 后提取/检测闭环', () => {
  // 独立复刻 stegosaurus 槽位规则（从其源码翻译，不复用被测实现）：先序建栈 → 逆序遍历 →
  // 偶偏移且 opcode<90 的指令 arg 字节为槽；payload 写满后剩余槽清零。
  const payload = 'flag{t3st_h4ndm4de}';
  const patched = V_CARRIER310.slice();
  const parsed = parsePyc(patched);
  const stack = [];
  const buildStack = code => {
    stack.push(code);
    for (const item of code.consts) if (item.kind === 'code') buildStack(item.code);
  };
  buildStack(parsed.root);
  let payloadIndex = 0;
  const payloadBytes = [...payload].map(char => char.charCodeAt(0));
  let patchedCount = 0;
  for (let stackIndex = stack.length - 1; stackIndex >= 0; stackIndex -= 1) {
    const code = stack[stackIndex];
    for (let i = 0; i < code.code.length; i += 2) {
      if (code.code[i] < 90 && i + 1 < code.code.length) {
        const byte = payloadIndex < payloadBytes.length ? payloadBytes[payloadIndex] : 0;
        if (patched[code.codeOffset + i + 1] !== byte) patchedCount += 1;
        patched[code.codeOffset + i + 1] = byte;
        payloadIndex += 1;
      }
    }
  }
  assert.ok(payloadIndex >= payloadBytes.length, `槽容量应足够（${payloadIndex} 槽）`);
  assert.ok(patchedCount > 0, '嵌入应实际改动死槽字节');
  // 仅死槽字节差异：其余字节与原载体一致（隐写不改变文件其余部分）
  let diffBytes = 0;
  for (let i = 0; i < patched.length; i += 1) if (patched[i] !== V_CARRIER310[i]) diffBytes += 1;
  assert.ok(diffBytes <= patchedCount, '只允许死槽字节变化');

  const extracted = extractStegosaurus(patched);
  assert.deepEqual(arr(extracted.payloads), [payload]);
  const report = detectPycAnomaly(patched);
  assert.equal(report.stegoSuspect, true);
  assert.equal(report.slotNonzero, payload.length, '非零槽数应恰为 payload 长度');
});

// 合成 pyc 工厂：3.10 布局（posonly，16B 头），单 code object，co_code/调用方可定制
const makeSyntheticPyc = codeBytes => {
  const i32bytes = value => [value & 0xff, (value >> 8) & 0xff, (value >> 16) & 0xff, (value >> 24) & 0xff];
  return Uint8Array.from([
    0x6f, 0x0d, 0x0d, 0x0a, // magic 3439（3.10）+ \r\n
    ...i32bytes(0), ...i32bytes(0), ...i32bytes(0), // flags + mtime + size
    0x63, // TYPE_CODE
    ...i32bytes(0), ...i32bytes(0), ...i32bytes(0), ...i32bytes(0), ...i32bytes(2), ...i32bytes(0),
    0x73, ...i32bytes(codeBytes.length), ...codeBytes, // co_code
    0x29, 0x00, // consts ()
    0x29, 0x00, // names ()
    0x29, 0x00, // varnames ()
    0x29, 0x00, // freevars ()
    0x29, 0x00, // cellvars ()
    0x7a, 0x01, 0x78, // filename z"x"
    0x7a, 0x01, 0x6d, // name z"m"
    ...i32bytes(1), // firstlineno
    0x73, ...i32bytes(2), 0, 1, // lnotab
  ]);
};

test('detectPycAnomaly：尾附数据、3.6 合成载体的跳转/lnotab 越界（legacy 布局覆盖）', () => {
  // 尾附数据
  const tailed = Uint8Array.from([...V_T310, ...['G', 'A', 'R', 'B', 'A', 'G', 'E'].map(c => c.charCodeAt(0))]);
  const tailedReport = detectPycAnomaly(tailed);
  assert.ok(arr(tailedReport.anomalies).some(line => line.includes('尾附数据')), '应报告尾附数据');

  // 3.6（magic 3379，legacy 布局 + 12 字节头）合成 code object：
  // co_code = JUMP_ABSOLUTE(113) arg=200（越界）+ NOP(9)；lnotab 地址累计 100 > co_code 长度 4
  const i32bytes = value => [value & 0xff, (value >> 8) & 0xff, (value >> 16) & 0xff, (value >> 24) & 0xff];
  const synthetic = Uint8Array.from([
    0x33, 0x0d, 0x0d, 0x0a, // magic 3379（3.6 定稿）+ \r\n
    ...i32bytes(0), ...i32bytes(0), // mtime + size（12 字节头）
    0x63, // TYPE_CODE
    ...i32bytes(0), ...i32bytes(0), ...i32bytes(0), ...i32bytes(2), ...i32bytes(0), // argcount/kwonly/nlocals/stacksize/flags（legacy 五连）
    0x73, ...i32bytes(4), 113, 200, 9, 0, // co_code：JUMP_ABSOLUTE arg=200 + NOP
    0x29, 0x00, // consts ()
    0x29, 0x00, // names ()
    0x29, 0x00, // varnames ()
    0x29, 0x00, // freevars ()
    0x29, 0x00, // cellvars ()
    0x7a, 0x01, 0x78, // filename z"x"
    0x7a, 0x01, 0x6d, // name z"m"
    ...i32bytes(1), // firstlineno
    0x73, ...i32bytes(2), 100, 1, // lnotab：地址累计 100
  ]);
  const legacyParsed = parsePyc(synthetic);
  assert.equal(legacyParsed.header.version, '3.6');
  assert.equal(legacyParsed.header.headerSize, 12);
  assert.equal(legacyParsed.endOffset, synthetic.length);
  assert.equal(legacyParsed.root.nlocals, 0);
  const legacyReport = detectPycAnomaly(synthetic);
  assert.ok(arr(legacyReport.anomalies).some(line => line.includes('跳转目标')), '应报告跳转越界');
  assert.ok(arr(legacyReport.anomalies).some(line => line.includes('lnotab 地址累计')), '应报告 lnotab 越界');

  // 3.5（magic 3350，指令变长时代）：无 wordcode 死槽语义，extractStegosaurus 应拒绝提取并说明原因
  const synthetic35 = Uint8Array.from(synthetic);
  synthetic35[0] = 0x16; // magic 3350 = 0x0D16 → LE 低字节
  synthetic35[1] = 0x0d;
  assert.equal(parsePyc(synthetic35).header.version, '3.5');
  const stego35 = extractStegosaurus(synthetic35);
  assert.deepEqual(arr(stego35.payloads), []);
  assert.ok(arr(stego35.detail).some(line => line.includes('3.6 之前')), '应说明 3.5 无死槽语义');
});
