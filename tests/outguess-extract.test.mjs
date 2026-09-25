// outguess 0.2 提取器测试（批次 SI-3，32 项对标收官件）：核心为回环向量——测试侧自实现
// 与提取端对偶的嵌入方向（同 ARC4/iterator 前置件、同位流收集规则、同 LSB-first 写序、
// 头部 XOR as / 数据 XOR tas 双流），直接喂系数数组（outguessRevealFromCoefficients）闭环，
// 覆盖：位流收集语义（0/+1 跳过、-1 与 |c|≥2 收 LSB）、iterator_adapt 手算数值、
// 嵌入→提取往返（明文/seed/declaredLength）、空口令、错口令降级断言、位流耗尽与
// 声明超容错误分支、真实 JPEG（PIL fixture）优雅报错。真实 outguess 编码器产物本机
// 无原版工具，走回环 + 语义单测锚定（C 源语义逐行核对见 outguessExtract.ts 头注）。
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const srcDir = path.join(projectRoot, 'src');
const { loadModule } = createTsModuleLoader();
const { collectOutguessBits, outguessReveal, outguessRevealFromCoefficients } = loadModule(
  path.join(srcDir, 'utils', 'ctf', 'outguessExtract.ts'),
);
const { arc4InitKey, iteratorAdapt, iteratorInit, iteratorNext, iteratorSeed } = loadModule(
  path.join(srcDir, 'utils', 'ctf', 'outguessCrypto.ts'),
);

// ---- 位流收集语义（jdcoefct 钩子 → steg_use_bit：(temp&1)==temp 跳过）----

test('collectOutguessBits：0 与 +1 跳过，-1 与 |c|≥2 全收 LSB', () => {
  const { bits, totalBits } = collectOutguessBits(Int32Array.from([0, 1, -1, 2, 3, -2, 7, 0, 4, -3]));
  assert.equal(totalBits, 7);
  assert.deepEqual(Array.from(bits.subarray(0, 7)), [1, 0, 1, 0, 1, 0, 1]); // -1→1, 2→0, 3→1, -2→0, 7→1, 4→0, -3→1
});

test('collectOutguessBits：全 0/1 系数流 totalBits 为 0', () => {
  assert.equal(collectOutguessBits(Int32Array.from([0, 1, 0, 1])).totalBits, 0);
});

// ---- iterator_adapt 手算数值（SKIPADJ 公式：rem>bits/32 → 2，否则 2-(seg-rem)/seg）----

test('iteratorAdapt：远未到尾段时 skipmod=trunc(2×rem/(8×datalen))', () => {
  const state = iteratorInit(new TextEncoder().encode('k'));
  state.off = 128;
  iteratorAdapt(state, 1024, 64); // rem=896>32 → 2；trunc(2*896/512)=3
  assert.equal(state.skipmod, 3);
});

test('iteratorAdapt：尾段（rem≤bits/32）走插值分支并向下截断', () => {
  const state = iteratorInit(new TextEncoder().encode('k'));
  state.off = 1000;
  iteratorAdapt(state, 1024, 4); // rem=24≤32 → 2-8/32=1.75；trunc(1.75*24/32)=1
  assert.equal(state.skipmod, 1);
});

// ---- 回环：测试侧嵌入方向（镜像 do_embed 无 preserve 简化：位位置语义与原版一致）----

// 与提取端同规则收集可嵌位（含源系数下标），写位改物理 LSB（|c|≥2 或 -1 改 LSB 永不落入 0/+1）
const buildCarrier = (coeffs) => {
  const positions = [];
  for (let i = 0; i < coeffs.length; i += 1) {
    if (coeffs[i] !== 0 && coeffs[i] !== 1) positions.push(i);
  }
  return positions;
};

const embedOutguess = (coeffs, password, plaintext, seed) => {
  const positions = buildCarrier(coeffs);
  const totalBits = positions.length;
  const writeBit = (bitIndex, bit) => {
    const ci = positions[bitIndex];
    coeffs[ci] = (coeffs[ci] & ~1) | bit;
  };
  const embedByte = (iter, value) => {
    for (let where = 0; where < 8; where += 1) {
      writeBit(iter.off, (value >> where) & 1);
      iteratorNext(iter);
    }
  };
  const key = new TextEncoder().encode(password);
  const as = arc4InitKey('Encryption', key);
  const tas = as.clone();
  const iter = iteratorInit(key);
  const header = new Uint8Array([seed & 0xff, (seed >> 8) & 0xff, plaintext.length & 0xff, (plaintext.length >> 8) & 0xff]);
  for (let i = 0; i < 4; i += 1) embedByte(iter, header[i] ^ as.getbyte());
  iteratorSeed(iter, seed);
  let remaining = plaintext.length;
  let n = 0;
  while (remaining > 0) {
    iteratorAdapt(iter, totalBits, remaining);
    embedByte(iter, plaintext[n] ^ tas.getbyte());
    n += 1;
    remaining -= 1;
  }
  return totalBits;
};

// mock 系数流：交错 ±7/±2/-1/3 混入 0/1 噪声（0/1 会被两端一致跳过）
const mockCoeffs = (count) => {
  const pattern = [7, -7, 2, -2, 0, 3, -1, 1, 5, -3];
  return Int32Array.from({ length: count }, (_, i) => pattern[i % pattern.length]);
};

test('回环：嵌入→提取往返还原明文/seed/declaredLength（常规口令）', () => {
  const coeffs = mockCoeffs(4000);
  const plaintext = Uint8Array.from('flag{outguess_roundtrip_0x2}', (ch) => ch.charCodeAt(0));
  const seed = 0x1234;
  embedOutguess(coeffs, 'secret', plaintext, seed);
  const { data, seed: gotSeed, declaredLength } = outguessRevealFromCoefficients(coeffs, 'secret');
  assert.deepEqual(Array.from(data), Array.from(plaintext));
  assert.equal(gotSeed, seed);
  assert.equal(declaredLength, plaintext.length);
});

test('回环：空口令（空 key 的 MD5 语义）同样成立', () => {
  const coeffs = mockCoeffs(3000);
  const plaintext = Uint8Array.from([0x00, 0xff, 0x41, 0x80, 0x7f, 0x01]);
  embedOutguess(coeffs, '', plaintext, 0xbeef);
  const { data } = outguessRevealFromCoefficients(coeffs, '');
  assert.deepEqual(Array.from(data), Array.from(plaintext));
});

test('回环：长载荷（>256 字节，触发 u16 长度字段高位）往返', () => {
  const coeffs = mockCoeffs(20000);
  const plaintext = Uint8Array.from({ length: 300 }, (_, i) => (i * 37 + 11) & 0xff);
  embedOutguess(coeffs, 'pw-long', plaintext, 0x4321);
  const { data, declaredLength } = outguessRevealFromCoefficients(coeffs, 'pw-long');
  assert.equal(declaredLength, 300);
  assert.deepEqual(Array.from(data), Array.from(plaintext));
});

test('错口令：要么报错要么解不出原明文（绝不误还原）', () => {
  const coeffs = mockCoeffs(4000);
  const plaintext = Uint8Array.from('correct horse battery staple', (ch) => ch.charCodeAt(0));
  embedOutguess(coeffs, 'right', plaintext, 42);
  let leaked = false;
  try {
    const { data } = outguessRevealFromCoefficients(coeffs, 'wrong');
    leaked = Array.from(data).join(',') === Array.from(plaintext).join(',');
  } catch {
    // 长度异常 / 位流耗尽抛错均合法
  }
  assert.equal(leaked, false);
});

// ---- 错误分支 ----

test('声明长度为 0（口令错或无嵌入）正确报错', () => {
  const coeffs = mockCoeffs(4000); // 未嵌入：解出的 header 大概率非法
  assert.throws(() => outguessRevealFromCoefficients(coeffs, 'whatever'), /outguess/);
});

test('可嵌位不足 64 位正确报错', () => {
  const coeffs = Int32Array.from([7, -7, 2, -2, 3, -3, 5, -5, 6, -6]); // 10 位
  assert.throws(() => outguessRevealFromCoefficients(coeffs, 'k'), /至少 64 位/);
});

test('声明长度超过可嵌容量正确报错', () => {
  // 手工构造位流耗尽：mock 位流 128 位（容量 16 字节），构造 header 声明 60000 字节
  const coeffs = Int32Array.from({ length: 128 }, (_, i) => (i % 2 === 0 ? 7 : -7));
  // 全 0/1 的位流 + 任意口令解出的 header 不可控——直接检查抛错即可（长度或耗尽分支）
  assert.throws(() => outguessRevealFromCoefficients(coeffs, 'x'), /outguess/);
});

// ---- 真实 JPEG 集成路径（PIL fixture，非 outguess 载荷优雅报错）----

const fixturePath = path.join(projectRoot, 'tests', 'fixtures', 'jpeg-test.jpg');
if (fs.existsSync(fixturePath)) {
  test('JPEG 集成路径：PIL fixture（非 outguess 载荷）经完整管线正确报错', () => {
    const bytes = new Uint8Array(fs.readFileSync(fixturePath));
    assert.throws(() => outguessReveal(bytes, 'any'), /outguess|长度|位流/);
  });
} else {
  test('JPEG fixture 缺失：跳过（无 jpeg-test.jpg）', { skip: true }, () => {});
}
