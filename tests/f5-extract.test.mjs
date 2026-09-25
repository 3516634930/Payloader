// F5 提取器测试（批次 SI·A 线收尾件）：全部向量程序化构造——测试侧自实现 F5 嵌入
// 方向镜像（同一 F5Random/F5Permutation、同一可用系数流、同一 PRNG 消耗序），直接喂
// 系数数组（f5ExtractFromCoefficients）做闭环，覆盖矩阵解码（k=1/2/3）、收缩重嵌、
// 直嵌（k=0）、空口令、头部去白噪小端序、错口令与 JPEG 入口错误透传；真实编码器
// 产物（PIL fixture）走"非 F5 载荷正确报错"。沙箱跨 realm 断言一律主 realm
// Array.from 转换后再 deepEqual（AGENTS.md 踩坑记录）。
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const srcDir = path.join(projectRoot, 'src');
const { loadModule } = createTsModuleLoader();
const { f5Extract, f5ExtractFromCoefficients } = loadModule(
  path.join(srcDir, 'utils', 'ctf', 'f5Extract.ts'),
);
const { F5Random, F5Permutation } = loadModule(path.join(srcDir, 'utils', 'ctf', 'f5Crypto.ts'));

const latin1 = (text) => Uint8Array.from(text, (ch) => ch.charCodeAt(0) & 0xff);
const flagBytes = (text) => Uint8Array.from(text, (ch) => ch.charCodeAt(0));
const bitOf = (value) => (value > 0 ? value & 1 : 1 - (value & 1));

// 与提取端对偶的写位：正系数物理 LSB=bit、负系数物理 LSB=1-bit（读位取反的对偶）。
// ±1 载体凑 LSB=0 时改写 ±2——纯 setBit 会造出 0 系数，而提取端跳 0、嵌入端已消费
// 该位，头/块边界会整体错位
const setBit = (value, bit) => {
  const next = value > 0 ? (value & ~1) | bit : -(((-value) & ~1) | (1 - bit));
  return next === 0 ? (value > 0 ? 2 : -2) : next;
};

// 测试侧 F5 嵌入镜像：PRNG 消耗序 = Permutation 构造 → 头部 4 字节 → 每载荷字节
// 1 字节，与 f5Extract 逐拍一致。矩阵编码：块内至多改一个系数（位置 = hash^segment，
// F5 语义），改法 |c|-1 保符号；减到 0 即收缩——0 系数被双端跳过，故从块首重收块
// （窗口越过置 0 位自然前滑）重嵌同一段。
const embed = (coeff, password, payload, k) => {
  const out = Int32Array.from(coeff);
  const message = Uint8Array.from(payload);
  const random = new F5Random(latin1(password));
  const permutation = new F5Permutation(out.length, random);
  const field = ((((k << 24) | (message.length & 0x7fffff)) >>> 0)
    ^ random.getNextByte()
    ^ (random.getNextByte() << 8)
    ^ (random.getNextByte() << 16)
    ^ (random.getNextByte() << 24)) >>> 0;
  let cursor = 0;
  const nextUsable = () => {
    for (;;) {
      assert.ok(cursor < out.length, '测试向量系数容量不足');
      const index = permutation.getShuffled(cursor);
      cursor += 1;
      if (index % 64 === 0 || out[index] === 0) continue;
      return index;
    }
  };
  // 头 32 位 LSB-first 写入前 32 个可用系数
  for (let bitPosition = 0; bitPosition < 32; bitPosition += 1) {
    const index = nextUsable();
    out[index] = setBit(out[index], (field >>> bitPosition) & 1);
  }
  // 载荷去白噪在拆位前完成（提取端是拼完字节后去白噪，两侧 PRNG 字节序相同）
  const bits = [];
  for (const byte of Array.from(message, (b) => b ^ random.getNextByte())) {
    for (let b = 7; b >= 0; b -= 1) bits.push((byte >> b) & 1);
  }
  if (k === 0) {
    for (const bit of bits) {
      const index = nextUsable();
      out[index] = setBit(out[index], bit);
    }
    return { coeff: out, shrinks: 0 };
  }
  const n = (1 << k) - 1;
  let shrinks = 0;
  let bitCursor = 0;
  while (bitCursor < bits.length) {
    let segment = 0;
    for (let j = 0; j < k; j += 1) {
      segment = (segment << 1) | (bitCursor < bits.length ? bits[bitCursor] : 0);
      bitCursor += 1;
    }
    for (;;) {
      const blockStart = cursor;
      const block = [];
      while (block.length < n) {
        assert.ok(cursor < out.length, '测试向量系数容量不足');
        const index = permutation.getShuffled(cursor);
        cursor += 1;
        if (index % 64 === 0 || out[index] === 0) continue;
        block.push(index);
      }
      let hash = 0;
      block.forEach((index, position) => {
        if (bitOf(out[index]) === 1) hash ^= position + 1;
      });
      if (hash === segment) break;
      const target = block[(hash ^ segment) - 1];
      if (out[target] > 0) out[target] -= 1;
      else out[target] += 1;
      if (out[target] === 0) {
        shrinks += 1;
        cursor = blockStart; // 收缩：块作废，从块首重收（置 0 位被自然跳过）
      } else {
        break;
      }
    }
  }
  return { coeff: out, shrinks };
};

// 20 块灰度系数向量：DC 放块号（双端都不触 DC），AC 用 ±2..±5 混合符号——普通翻转
// 不会无谓制造 0；forceOnes 变体把部分 AC 压成 ±1 以强制触发收缩重嵌分支
const makeCoefficients = (forceOnes = false) => {
  const coeff = new Int32Array(20 * 64);
  for (let i = 0; i < coeff.length; i += 1) {
    if (i % 64 === 0) {
      coeff[i] = Math.floor(i / 64) + 1;
    } else if (forceOnes && i % 9 === 0) {
      coeff[i] = i % 18 < 9 ? 1 : -1;
    } else {
      coeff[i] = ((i >> 3) % 2 === 0 ? 1 : -1) * (2 + (i % 4));
    }
  }
  return coeff;
};

const countUsable = (coeff) => {
  let usable = 0;
  for (let i = 0; i < coeff.length; i += 1) {
    if (i % 64 !== 0 && coeff[i] !== 0) usable += 1;
  }
  return usable;
};

const assertRoundtrip = ({ password, payload, k, forceOnes = false, requireShrinks = false }) => {
  const { coeff, shrinks } = embed(makeCoefficients(forceOnes), password, payload, k);
  if (requireShrinks) {
    assert.ok(shrinks >= 1, `收缩重嵌分支未被触发（shrinks=${shrinks}），需调整测试向量`);
  }
  const result = f5ExtractFromCoefficients(coeff, password);
  assert.equal(result.k, k, '头部 k 字段还原');
  assert.equal(result.declaredLength, payload.length, '头部声明长度还原');
  assert.deepEqual(Array.from(result.data), Array.from(payload), '载荷逐字节还原');
  assert.equal(result.usableCoefficients, countUsable(coeff), '可用系数计数（收缩产生的 0 已剔除）');
  return { coeff, shrinks, result };
};

const flagPayload = flagBytes('flag{f5_matrix_roundtrip_ok}');
const mixedPayload = Uint8Array.from({ length: 48 }, (_, i) => (i * 37 + 11) & 0xff);

// ---- 端到端闭环 ----

test('闭环：k=1（n=1）与 k=2（n=3）矩阵解码往返（flag 文本 + 混合字节载荷）', () => {
  assertRoundtrip({ password: 'Steg0F5', payload: flagPayload, k: 1 });
  assertRoundtrip({ password: 'Steg0F5', payload: mixedPayload, k: 2 });
});

test('闭环：空口令（""）同样走满 PRNG 消耗序', () => {
  assertRoundtrip({ password: '', payload: mixedPayload, k: 2 });
});

test('闭环：k=3（n=7）段跨字节（8%3≠0）的 MSB-first 位流拼装', () => {
  assertRoundtrip({ password: 'cross-byte', payload: mixedPayload, k: 3 });
});

test('闭环：收缩重嵌——±1 系数被减到 0 后块前滑重嵌，提取端跳 0 仍完整还原', () => {
  assertRoundtrip({
    password: 'shrink-me',
    payload: mixedPayload,
    k: 2,
    forceOnes: true,
    requireShrinks: true,
  });
});

test('闭环：k=0 直嵌分支（每可用系数 1 bit 直接拼字节）', () => {
  assertRoundtrip({ password: 'direct-lsb', payload: flagPayload, k: 0 });
});

// ---- 头部去白噪序 ----

test('头部去白噪序：Permutation 构造后的前 4 个 getNextByte 按小端异或进长度头', () => {
  const password = 'f5-header-order';
  const payload = flagBytes('flag{f5_header_pad}');
  const { coeff } = embed(makeCoefficients(), password, payload, 2);
  const result = f5ExtractFromCoefficients(coeff, password);
  assert.equal(result.declaredLength, payload.length, '前置：闭环本身成立');
  // 独立复算 pad：同源 F5Random 在 Permutation 构造（消耗 length 次 getNextValue）后的 4 字节
  const padRandom = new F5Random(latin1(password));
  new F5Permutation(coeff.length, padRandom);
  const pad = [0, 1, 2, 3].map(() => padRandom.getNextByte());
  // 从嵌入产物按可用系数流直接读回原始 32 位头（LSB-first）
  const readRandom = new F5Random(latin1(password));
  const perm = new F5Permutation(coeff.length, readRandom);
  let raw = 0;
  let collected = 0;
  for (let i = 0; collected < 32; i += 1) {
    const index = perm.getShuffled(i);
    if (index % 64 === 0 || coeff[index] === 0) continue;
    raw |= bitOf(coeff[index]) << collected;
    collected += 1;
  }
  const field = (result.k << 24) | result.declaredLength;
  assert.equal(
    (raw ^ field ^ pad[0] ^ (pad[1] << 8) ^ (pad[2] << 16) ^ (pad[3] << 24)) >>> 0,
    0,
    'raw 头应恰为 field 逐位异或小端 pad',
  );
});

// ---- 防呆 ----

test('错口令 / 非 F5 载荷：头部解码出荒谬长度 → 中文报错', () => {
  const { coeff } = embed(makeCoefficients(), 'right-password', flagPayload, 2);
  assert.throws(() => f5ExtractFromCoefficients(coeff, 'wrong-password'), /口令错误或非 F5 载荷/);
  // 干净系数（未嵌任何载荷）同样在头部校验被拒——真实场景的"非 F5 载荷"路径
  assert.throws(() => f5ExtractFromCoefficients(makeCoefficients(), 'any'), /口令错误或非 F5 载荷/);
});

test('f5Extract 入口：非 JPEG / 渐进式透传 jpegCoeffs 的中文错误', () => {
  const pngMagic = Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  assert.throws(() => f5Extract(pngMagic, 'x'), /不是有效的 JPEG/);
  assert.throws(() => f5Extract(new Uint8Array(0), 'x'), /不是有效的 JPEG/);
  // 仅 SOI + SOF2 帧头：解码器在帧解析即抛渐进式
  const progressive = Uint8Array.from([
    0xff, 0xd8,
    0xff, 0xc2, 0x00, 0x0b, 0x08, 0x00, 0x08, 0x00, 0x08, 0x01, 0x01, 0x11, 0x00,
  ]);
  assert.throws(() => f5Extract(progressive, 'x'), /渐进式/);
});

// ---- JPEG 集成路径（真实编码器产物） ----

const fixturePath = path.join(projectRoot, 'tests', 'fixtures', 'jpeg-test.jpg');
if (fs.existsSync(fixturePath)) {
  test('JPEG 集成路径：PIL fixture（非 F5 载荷）经完整 readJpegCoefficients 管线正确报错', () => {
    const bytes = new Uint8Array(fs.readFileSync(fixturePath));
    // 该 8×8 梯度图可用 AC 不足 32 个 → 触发头部容量防线；可用系数够多的图则落在
    // 长度校验防线，两者都是"非 F5 载荷"的正确拒绝
    assert.throws(() => f5Extract(bytes, 'whatever'), /口令错误或非 F5 载荷|系数容量不足/);
  });
}
