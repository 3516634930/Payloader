// Magic 编码链引擎测试：BFS 全链解开 + 评分排名。洋葱层数据全部程序化构造（无外部 fixture），
// 加载统一走 tests/helpers/compileTsModule.mjs。跨 realm 断言遵循仓库约定：候选 chain 先 Array.from
// 转主 realm 数组再 deepEqual（沙箱数组原型与主 realm 不同）。
import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const srcDir = path.join(projectRoot, 'src');
const { loadModule } = createTsModuleLoader();
const { magicChainScan, magicChainReport } = loadModule(path.join(srcDir, 'utils', 'codec', 'magicChain.ts'));
const {
  textToBase64,
  encodeBase32,
  encodeBase58,
  encodeAscii85,
  encodeUuencode,
  bytesToHex,
} = loadModule(path.join(srcDir, 'utils', 'codec', 'bases.ts'));

// ---- 编码工厂（复用仓库编码函数造洋葱，与被测解码互为镜像） ----

const hexEncode = value => bytesToHex(Buffer.from(value, 'utf8'));
const rot13 = value => Array.from(value).map(char => {
  const code = char.charCodeAt(0);
  const base = code >= 65 && code <= 90 ? 65 : code >= 97 && code <= 122 ? 97 : null;
  return base === null ? char : String.fromCharCode(base + ((code - base + 13) % 26));
}).join('');

// 固定种子 PRNG：随机向量可复现（防 flaky）
const makePrng = seed => {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) | 0;
    let mixed = Math.imul(state ^ (state >>> 15), 1 | state);
    mixed = (mixed + Math.imul(mixed ^ (mixed >>> 7), 61 | mixed)) ^ mixed;
    return ((mixed ^ (mixed >>> 14)) >>> 0) / 4294967296;
  };
};

test('深度 3 洋葱：base64(hex(base32(flag))) 全链自动解开', () => {
  const flag = 'flag{magic_chain_depth3}';
  const onion = textToBase64(hexEncode(encodeBase32(flag)));
  const candidates = magicChainScan(onion);
  assert.ok(candidates.length >= 1);
  const top = candidates[0];
  assert.deepEqual(Array.from(top.chain), ['base64', 'hex', 'base32']);
  assert.ok(top.result.includes('magic_chain_depth3'));
  assert.equal(top.flagLike, true);
  assert.ok(top.score >= 1000);
  assert.ok(top.printableRatio > 0.99);
});

test('深度 2 组合 A：base64(hex(flag))', () => {
  const flag = 'flag{b64_hex_two_layers}';
  const candidates = magicChainScan(textToBase64(hexEncode(flag)));
  assert.ok(candidates.length >= 1);
  assert.deepEqual(Array.from(candidates[0].chain), ['base64', 'hex']);
  assert.ok(candidates[0].result.includes('b64_hex_two_layers'));
  assert.equal(candidates[0].flagLike, true);
});

test('深度 2 组合 B：base32(url(flag))', () => {
  const flag = 'flag{url_b32_two_layer}';
  const candidates = magicChainScan(encodeBase32(encodeURIComponent(flag)));
  assert.ok(candidates.length >= 1);
  assert.deepEqual(Array.from(candidates[0].chain), ['base32', 'url-decode']);
  assert.ok(candidates[0].result.includes('url_b32_two_layer'));
  assert.equal(candidates[0].flagLike, true);
});

test('深度 2 组合 C：base64(rot13(flag))', () => {
  const flag = 'flag{rot13_b64_combo}';
  const candidates = magicChainScan(textToBase64(rot13(flag)));
  assert.ok(candidates.length >= 1);
  assert.deepEqual(Array.from(candidates[0].chain), ['base64', 'rot13']);
  assert.ok(candidates[0].result.includes('rot13_b64_combo'));
  assert.equal(candidates[0].flagLike, true);
});

test('hex → base58 组合链', () => {
  const flag = 'flag{hex_base58_combo}';
  const candidates = magicChainScan(encodeBase58(hexEncode(flag)));
  assert.ok(candidates.length >= 1);
  assert.deepEqual(Array.from(candidates[0].chain), ['base58', 'hex']);
  assert.ok(candidates[0].result.includes('hex_base58_combo'));
  assert.equal(candidates[0].flagLike, true);
});

test('中文明文双层 base64：CJK 加分生效', () => {
  const plain = '洋葱层攻击：flag 藏于东郊古堡的密室之中';
  const candidates = magicChainScan(textToBase64(textToBase64(plain)));
  assert.ok(candidates.length >= 1);
  const top = candidates[0];
  assert.deepEqual(Array.from(top.chain), ['base64', 'base64']);
  assert.ok(top.result.includes('藏于东郊古堡的密室'));
  assert.equal(top.flagLike, false);
  // 无 CJK 加分时纯中文文本上限 = 可打印 20 分（字母 <30% 英文分为 0）；≥60 即证明 +40 中文项生效
  assert.ok(top.score >= 60, `score=${top.score}`);
});

test('纯随机 hex 垃圾输入：无 flag 命中且低分', () => {
  const prng = makePrng(0x20260924);
  const alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let junk = '';
  for (let index = 0; index < 120; index += 1) junk += alphabet[Math.floor(prng() * alphabet.length)];
  const garbageHex = hexEncode(junk);
  assert.ok(/^[0-9a-f]+$/.test(garbageHex) && garbageHex.length % 2 === 0);
  const candidates = magicChainScan(garbageHex);
  assert.ok(candidates.length >= 1, 'hex 解码候选应存活（可打印垃圾）');
  for (const candidate of candidates) {
    assert.equal(candidate.flagLike, false);
    assert.ok(candidate.score < 60, `score=${candidate.score}`);
  }
});

test('输入本身 flagLike：作为深度 0 候选返回', () => {
  const candidates = magicChainScan('flag{already_plain_input}');
  assert.ok(candidates.length >= 1);
  const top = candidates[0];
  assert.deepEqual(Array.from(top.chain), []);
  assert.equal(top.flagLike, true);
  assert.equal(top.result, 'flag{already_plain_input}');
  assert.ok(top.score >= 1000);
});

test('base85（Ascii85）单层', () => {
  const flag = 'flag{a85_wrapped_layer}';
  const candidates = magicChainScan(encodeAscii85(flag));
  assert.ok(candidates.length >= 1);
  const top = candidates[0];
  assert.deepEqual(Array.from(top.chain), ['base85']);
  assert.ok(top.result.includes('a85_wrapped_layer'));
  assert.equal(top.flagLike, true);
});

test('uuencode 单层', () => {
  const flag = 'flag{uu_single_layer}';
  const candidates = magicChainScan(encodeUuencode(flag, ''));
  assert.ok(candidates.length >= 1);
  const top = candidates[0];
  assert.deepEqual(Array.from(top.chain), ['uuencode']);
  assert.ok(top.result.includes('uu_single_layer'));
  assert.equal(top.flagLike, true);
});

test('深度硬上限 4：5 层洋葱不可全解且无链条越界，4 层可解', () => {
  const flag = 'flag{depth_layer_probe}';
  let fourLayers = flag;
  for (let round = 0; round < 4; round += 1) fourLayers = textToBase64(fourLayers);
  const solved = magicChainScan(fourLayers, { maxDepth: 4 });
  assert.ok(solved.length >= 1);
  assert.equal(solved[0].flagLike, true);
  assert.equal(solved[0].chain.length, 4);

  const fiveLayers = textToBase64(fourLayers);
  const capped = magicChainScan(fiveLayers, { maxDepth: 99 });
  assert.ok(capped.length >= 1);
  for (const candidate of capped) {
    assert.ok(candidate.chain.length <= 4, `chain=${candidate.chain.join('>')}`);
    assert.equal(candidate.flagLike, false);
  }
  // 默认深度 3 下 5 层洋葱同样只能剥到 3 层
  const defaultDepth = magicChainScan(fiveLayers);
  for (const candidate of defaultDepth) assert.ok(candidate.chain.length <= 3);
});

test('报告 JSON：结构、每步中间形态、topN 去重与截断标注', () => {
  const plain = '洋葱层攻击：flag 藏于东郊古堡的密室之中';
  const onion = textToBase64(textToBase64(plain));
  const report = JSON.parse(magicChainReport(onion));
  assert.equal(report.tool, 'magic-chain');
  assert.equal(report.truncated, false);
  assert.equal(report.inputLength, onion.length);
  assert.ok(Array.isArray(report.candidates) && report.candidates.length >= 1);
  assert.ok(report.candidates.length <= report.options.topN);
  const top = report.candidates[0];
  assert.equal(top.rank, 1);
  assert.deepEqual(Array.from(top.chain), ['base64', 'base64']);
  assert.equal(top.steps.length, top.chain.length);
  assert.equal(top.steps[0].label, 'base64');
  assert.ok(top.steps[0].preview.length > 0);
  assert.ok(top.result.includes('密室'));
  // 同一 result 字符串只保留链最短的一条（候选结果唯一）
  const results = report.candidates.map(candidate => candidate.result);
  assert.equal(new Set(results).size, results.length);
  assert.ok(Array.isArray(report.notes) && report.notes.length >= 1);

  // >64KB 输入截断到前 65536 字符并标注；明文 flag 头仍作为深度 0 候选
  const bigInput = 'flag{big_input_marker}' + 'A'.repeat(70000);
  const bigReport = JSON.parse(magicChainReport(bigInput));
  assert.equal(bigReport.truncated, true);
  assert.equal(bigReport.inputLength, 70022);
  assert.deepEqual(Array.from(bigReport.candidates[0].chain), []);
  assert.equal(bigReport.candidates[0].flagLike, true);
});
