// 位平面全组合扫描引擎测试：R/LSB flag、B/LSB zlib 魔数、列序可打印、rgb 打包序、
// lsbFirst 位序变体、与 extractLsbBytes 语义一致性、排序/maxHits、退化输入。
// 测试向量全部程序化构造（无外部 fixture），加载统一走 tests/helpers/compileTsModule.mjs。
import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const srcDir = path.join(projectRoot, 'src');
const { loadModule } = createTsModuleLoader();
const { scanBitPlanes } = loadModule(path.join(srcDir, 'utils', 'ctf', 'bitPlaneScan.ts'));
const { extractLsbBytes, bytesToPreviewText } = loadModule(path.join(srcDir, 'utils', 'ctf', 'imagePlanes.ts'));

// ---- 测试工厂 ----

const makePrng = seed => {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) | 0;
    let mixed = Math.imul(state ^ (state >>> 15), 1 | state);
    mixed = (mixed + Math.imul(mixed ^ (mixed >>> 7), 61 | mixed)) ^ mixed;
    return ((mixed ^ (mixed >>> 14)) >>> 0) / 4294967296;
  };
};

const makeRgba = (width, height, prng) => {
  const rgba = new Uint8Array(width * height * 4);
  for (let index = 0; index < rgba.length; index += 1) rgba[index] = Math.floor(prng() * 256);
  for (let pixel = 0; pixel < width * height; pixel += 1) rgba[pixel * 4 + 3] = 255;
  return rgba;
};

// 嵌入是扫描提取的写侧镜像：按 通道组序 × 像素序 展开采样位，写进指定位平面（LSB）。
const embedBits = (rgba, width, height, channels, messageBytes, { lsbFirst = false, column = false } = {}) => {
  const bits = [];
  for (const byte of messageBytes) {
    for (let shift = 0; shift < 8; shift += 1) bits.push((byte >> (lsbFirst ? shift : 7 - shift)) & 1);
  }
  for (let sample = 0; sample < bits.length; sample += 1) {
    const ordinal = Math.floor(sample / channels.length);
    const channel = channels[sample % channels.length];
    const pixel = column
      ? Math.floor(ordinal / height) + (ordinal % height) * width
      : ordinal;
    const index = pixel * 4 + channel;
    rgba[index] = (rgba[index] & 0xfe) | bits[sample];
  }
  return rgba;
};

const textBytes = text => Array.from(Buffer.from(text, 'latin1'));
const repeatTo = (text, length) => text.repeat(Math.ceil(length / text.length)).slice(0, length);

const SIZE = 64;

// ---- 用例 1：R 通道 LSB 行序 MSB-first 藏 flag，应排 #1 ----

test('scanBitPlanes R/LSB/行序/MSB-first 藏 flag：#1 命中且 reasons 含 flag 格式', () => {
  const rgba = makeRgba(SIZE, SIZE, makePrng(0x5eed0001));
  embedBits(rgba, SIZE, SIZE, [0], textBytes('flag{zsteg_scan_hit}'));
  const hits = scanBitPlanes(rgba, SIZE, SIZE);
  assert.ok(hits.length >= 1, `应有命中，实际 ${hits.length}`);
  const top = hits[0];
  assert.equal(top.channel, 'r');
  assert.equal(top.bit, 1);
  assert.equal(top.lsbFirst, false);
  assert.equal(top.pixelOrder, 'row');
  assert.ok(top.reasons.includes('flag 格式'), `reasons=${JSON.stringify(top.reasons)}`);
  assert.equal(top.score, 100);
  assert.ok(top.preview.includes('flag{zsteg_scan_hit}'), `preview=${top.preview.slice(0, 40)}`);
  assert.equal(top.byteCount, 256, '64x64 单通道可提取 512 字节，默认窗口截 256');
});

// ---- 用例 2：B 通道 LSB 藏 zlib 头 ----

test('scanBitPlanes B/LSB 藏 78 9C：zlib 魔数命中', () => {
  const prng = makePrng(0x5eed0002);
  const payload = [0x78, 0x9c];
  for (let index = 0; index < 254; index += 1) payload.push(Math.floor(prng() * 256));
  const rgba = makeRgba(SIZE, SIZE, makePrng(0x5eed0003));
  embedBits(rgba, SIZE, SIZE, [2], payload);
  const hits = scanBitPlanes(rgba, SIZE, SIZE);
  const zlibHit = hits.find(hit =>
    hit.channel === 'b' && hit.bit === 1 && !hit.lsbFirst && hit.pixelOrder === 'row');
  assert.ok(zlibHit, `应命中 b/1/msb/row，实际 hits=${JSON.stringify(hits.map(h => `${h.channel}/${h.bit}/${h.pixelOrder}`))}`);
  assert.ok(zlibHit.reasons.includes('zlib/gzip 魔数'));
  assert.equal(zlibHit.score, 100);
  assert.ok(zlibHit.preview.startsWith('x\\x9c'), `preview=${zlibHit.preview.slice(0, 12)}`);
});

// ---- 用例 3：列序藏长可打印文本 ----

test('scanBitPlanes R/LSB 列序藏 256 字节文本：column 组合高可打印命中', () => {
  const secret = repeatTo('column order walks pixels top to bottom before shifting right. ', 256);
  const rgba = makeRgba(SIZE, SIZE, makePrng(0x5eed0004));
  embedBits(rgba, SIZE, SIZE, [0], textBytes(secret), { column: true });
  const hits = scanBitPlanes(rgba, SIZE, SIZE);
  const columnHit = hits.find(hit =>
    hit.channel === 'r' && hit.bit === 1 && hit.pixelOrder === 'column' && !hit.lsbFirst);
  assert.ok(columnHit, `应命中 r/1/msb/column，实际 ${JSON.stringify(hits.map(h => `${h.channel}/${h.pixelOrder}`))}`);
  assert.ok(columnHit.reasons.includes('高可打印率'));
  assert.ok(columnHit.preview.includes('column order walks'), `preview=${columnHit.preview.slice(0, 40)}`);
});

// ---- 用例 4：全随机图无强命中 ----

test('scanBitPlanes 全随机图：无 zlib/flag 强命中', () => {
  for (const seed of [0x5eed0005, 0xfeedbeef, 0xc0ffee42]) {
    const rgba = makeRgba(SIZE, SIZE, makePrng(seed));
    const hits = scanBitPlanes(rgba, SIZE, SIZE);
    for (const hit of hits) {
      assert.ok(!hit.reasons.includes('zlib/gzip 魔数'), `误报 zlib: ${hit.channel}/${hit.bit} seed=${seed}`);
      assert.ok(!hit.reasons.includes('flag 格式'), `误报 flag: ${hit.channel}/${hit.bit} seed=${seed}`);
      assert.ok(hit.score <= 90, `随机图不应出现强命中: ${hit.channel}/${hit.bit} score=${hit.score}`);
    }
  }
});

// ---- 用例 5：rgb 打包序（每像素 r,g,b 连续）藏文本 ----

test('scanBitPlanes rgb 打包序藏文本：rgb 组合命中且 bgr 读不出', () => {
  const secret = repeatTo('rgb packing hides three chars per pixel in a row. ', 256);
  const rgba = makeRgba(SIZE, SIZE, makePrng(0x5eed0006));
  embedBits(rgba, SIZE, SIZE, [0, 1, 2], textBytes(secret));
  const hits = scanBitPlanes(rgba, SIZE, SIZE);
  const rgbHit = hits.find(hit =>
    hit.channel === 'rgb' && hit.bit === 1 && hit.pixelOrder === 'row' && !hit.lsbFirst);
  assert.ok(rgbHit, `应命中 rgb/1/msb/row，实际 ${JSON.stringify(hits.map(h => h.channel))}`);
  assert.ok(rgbHit.reasons.includes('高可打印率'));
  assert.ok(rgbHit.preview.includes('rgb packing hides'), `preview=${rgbHit.preview.slice(0, 40)}`);
  const bgrLeak = hits.find(hit => hit.channel === 'bgr' && hit.preview.includes('rgb packing hides'));
  assert.equal(bgrLeak, undefined, 'bgr 反序读取不应还原出明文');
});

// ---- 用例 6：lsbFirst 字节内位序变体 ----

test('scanBitPlanes R/LSB lsbFirst 位序藏文本：lsbFirst=true 组合命中', () => {
  const secret = repeatTo('lsb first packs bits from b0 within each byte. ', 256);
  const rgba = makeRgba(SIZE, SIZE, makePrng(0x5eed0007));
  embedBits(rgba, SIZE, SIZE, [0], textBytes(secret), { lsbFirst: true });
  const hits = scanBitPlanes(rgba, SIZE, SIZE);
  const lsbHit = hits.find(hit =>
    hit.channel === 'r' && hit.bit === 1 && hit.lsbFirst && hit.pixelOrder === 'row');
  assert.ok(lsbHit, `应命中 r/1/lsb/row，实际 ${JSON.stringify(hits.map(h => `${h.channel}/${h.lsbFirst}`))}`);
  assert.ok(lsbHit.reasons.includes('高可打印率'));
  assert.ok(lsbHit.preview.includes('lsb first packs'), `preview=${lsbHit.preview.slice(0, 40)}`);
});

// ---- 用例 7：与 extractLsbBytes 语义一致性 ----

test('scanBitPlanes 基准组合输出与 extractLsbBytes 语义一致', () => {
  const secret = repeatTo('baseline semantics must stay aligned. ', 256);
  const rgba = makeRgba(SIZE, SIZE, makePrng(0x5eed0008));
  embedBits(rgba, SIZE, SIZE, [0], textBytes(secret));
  const hits = scanBitPlanes(rgba, SIZE, SIZE);
  const baseline = hits.find(hit =>
    hit.channel === 'r' && hit.bit === 1 && !hit.lsbFirst && hit.pixelOrder === 'row');
  assert.ok(baseline);
  const reference = bytesToPreviewText(extractLsbBytes(rgba, { channel: 0, bit: 0, maxBytes: 256 }));
  assert.equal(baseline.preview, reference);
});

// ---- 用例 8：同分排序（通道序 tie-break）与 maxHits 截断、字段域 ----
// 注：flag 正则的通用分支（word{3+}）会对文本位平面的串扰噪声产生同分误报，
// 全局前三名因此不稳定；同分 tie-break 的可判定形式是 r(0) 与 g(1) 之间无通道可插队。

test('scanBitPlanes 同分通道序 tie-break + maxHits 截断 + 字段域校验', () => {
  const secret = 'flag{tie_break_order_check}';
  const rgba = makeRgba(SIZE, SIZE, makePrng(0x5eed0009));
  embedBits(rgba, SIZE, SIZE, [0], textBytes(secret));
  embedBits(rgba, SIZE, SIZE, [1], textBytes(secret));
  const full = scanBitPlanes(rgba, SIZE, SIZE);
  assert.ok(full.length >= 2);
  const channelNames = new Set(['r', 'g', 'b', 'a', 'rgb', 'bgr', 'rgba', 'bgra', 'all']);
  for (const hit of full) {
    assert.ok(channelNames.has(hit.channel), `未知通道名 ${hit.channel}`);
    assert.ok(hit.bit >= 1 && hit.bit <= 8);
    assert.ok(hit.pixelOrder === 'row' || hit.pixelOrder === 'column');
    assert.ok(typeof hit.lsbFirst === 'boolean');
    assert.ok(Array.isArray(hit.reasons) && hit.reasons.length >= 1);
    assert.ok(hit.preview.length > 0);
    assert.ok(hit.byteCount >= 1 && hit.byteCount <= 256);
  }
  for (let index = 1; index < full.length; index += 1) {
    assert.ok(full[index - 1].score >= full[index].score, 'score 应降序');
  }
  const rHit = full.find(hit =>
    hit.channel === 'r' && hit.bit === 1 && !hit.lsbFirst && hit.pixelOrder === 'row');
  const gHit = full.find(hit =>
    hit.channel === 'g' && hit.bit === 1 && !hit.lsbFirst && hit.pixelOrder === 'row');
  assert.ok(rHit && gHit, 'r/g 同藏 flag 文本均应命中');
  assert.equal(rHit.score, 100);
  assert.equal(gHit.score, 100);
  // 同分 100 时按通道序 tie-break：r(0) 必为全局第一，且排在 g(1) 之前
  // （其余 r 变体的通用分支误报同属 rank 0，只可能插在 r 与 g 之间，不影响两条断言）
  assert.ok(full[0] === rHit, `全局第一应为 r，实际 ${full[0].channel}/${full[0].score}`);
  assert.ok(full.indexOf(rHit) < full.indexOf(gHit), '同分时 r 应排在 g 前');
  const capped = scanBitPlanes(rgba, SIZE, SIZE, { maxHits: 1 });
  assert.equal(capped.length, 1);
  assert.equal(capped[0].channel, 'r');
});

// ---- 用例 9：退化输入不崩溃（沙箱数组勿用 deepStrictEqual，见 AGENTS.md 踩坑） ----

test('scanBitPlanes 退化输入：空图/越界尺寸返回空数组不崩溃', () => {
  assert.equal(scanBitPlanes(new Uint8Array(0), 0, 0).length, 0);
  assert.equal(scanBitPlanes(new Uint8Array(16), 2, 2).length, 0);
  assert.equal(scanBitPlanes(new Uint8Array(16), 0, 8).length, 0);
});
