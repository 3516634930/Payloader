// stegpy / OpenStego LSB 隐写引擎测试（批次 SI·B 线）：全部向量程序化构造（字节数组直建），
// 不依赖图片编解码。加密闭环（Fernet / PBE AES128）走 WebCrypto，gzip 走 CompressionStream 家族。
// node:vm 沙箱数组跨 realm：notes 等断言前先 Array.from（AGENTS.md 踩坑记录）。
import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const srcDir = path.join(projectRoot, 'src');
const { loadModule } = createTsModuleLoader();
const stegpy = loadModule(path.join(srcDir, 'utils', 'ctf', 'stegpy.ts'));
const openstego = loadModule(path.join(srcDir, 'utils', 'ctf', 'openstego.ts'));

const randomBytes = length => {
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i += 1) out[i] = Math.floor(Math.random() * 256);
  return out;
};

const solid = (width, height, [r, g, b]) => ({
  data: (() => {
    const out = new Uint8ClampedArray(width * height * 4);
    for (let i = 0; i < width * height; i += 1) {
      out[i * 4] = r;
      out[i * 4 + 1] = g;
      out[i * 4 + 2] = b;
      out[i * 4 + 3] = 255;
    }
    return out;
  })(),
  width,
  height,
});

const assertBytesEqual = (actual, expected, label) => {
  assert.ok(actual.length === expected.length, `${label} 长度 ${actual.length} ≠ ${expected.length}`);
  for (let i = 0; i < expected.length; i += 1) {
    assert.equal(actual[i], expected[i], `${label} 第 ${i} 字节：${actual[i]} ≠ ${expected[i]}`);
  }
};

const toHex = bytes => Array.from(bytes, value => value.toString(16).padStart(2, '0')).join('');

// ---- stegpy：位深标记与 LSB 位序 ----

test('stegpy 位深标记三态：bits=1/2/4 分别写 operand 0/16/32 且三态闭环', async () => {
  for (const [bits, operand] of [[1, 0], [2, 16], [4, 32]]) {
    const host = randomBytes(256);
    const stego = await stegpy.stegpyEncode(host, { data: 'x', bits });
    assert.equal((stego[0] & 48) >> 4, operand >> 4, `bits=${bits} 时宿主[0] bit4-5 标记`);
    const decoded = await stegpy.stegpyDecodeFromPixels(stego);
    assert.equal(decoded.text, 'x', `bits=${bits} 闭环`);
    assert.equal(decoded.magic, 'stegv3');
  }
});

test('stegpy 低位组在前锚点：帧首字节 "s"=0x73=01110011 拆 4 组（bits=2）落在宿主[0..3] 低 2 位 = 3,0,3,1', async () => {
  const host = randomBytes(128);
  const stego = await stegpy.stegpyEncode(host, { data: 'flag', fileName: 'f', bits: 2 });
  assert.equal(stego[0] & 48, 16, 'bits=2 标记占用 bit4');
  assert.equal(stego[0] & 3, 3, '组 0（最低 2 位）= 11');
  assert.equal(stego[1] & 3, 0, '组 1 = 00');
  assert.equal(stego[2] & 3, 3, '组 2 = 11');
  assert.equal(stego[3] & 3, 1, '组 3 = 01');
});

// ---- stegpy：无口令闭环 ----

test('stegpy 无口令闭环：文本与 0-255 全域二进制往返、文件名保留', async () => {
  const flag = 'flag{stegpy_lsb_order}';
  const stego = await stegpy.stegpyEncode(randomBytes(4096), { data: flag, fileName: 'flag.txt', bits: 2 });
  const result = await stegpy.stegpyDecodeFromPixels(stego);
  assert.equal(result.magic, 'stegv3');
  assert.equal(result.fileName, 'flag.txt');
  assert.equal(result.text, flag);
  const binary = new Uint8Array(512);
  for (let i = 0; i < 512; i += 1) binary[i] = (i * 7 + 3) & 0xff;
  const stegoBinary = await stegpy.stegpyEncode(randomBytes(8192), { data: binary, fileName: 'blob.bin', bits: 4 });
  const resultBinary = await stegpy.stegpyDecodeFromPixels(stegoBinary);
  assert.equal(resultBinary.fileName, 'blob.bin');
  assertBytesEqual(resultBinary.data, binary, '二进制载荷');
  assert.equal(resultBinary.text, undefined, '含非 UTF-8 字节时 text 不置值');
});

// ---- stegpy：Fernet 口令模式 ----

test('stegpy 口令模式闭环：Fernet 令牌双层 stegv3 头往返、错口令拒绝', async () => {
  const secret = 'flag{fernet_double_layer}';
  const stego = await stegpy.stegpyEncode(randomBytes(20000), { data: secret, fileName: 'secret.txt', password: 'S3cret!' });
  // 无口令读外层：数据应是 base64url 文本（Fernet 令牌形态）、外层文件名为空
  const outer = await stegpy.stegpyDecodeFromPixels(stego);
  assert.equal(outer.fileName, '');
  assert.match(outer.text, /^[A-Za-z0-9\-_]+=*$/, '外层数据是 base64url 文本');
  // 正确口令剥两层
  const inner = await stegpy.stegpyDecodeFromPixels(stego, 'S3cret!');
  assert.equal(inner.fileName, 'secret.txt');
  assert.equal(inner.text, secret);
  // 错口令：HMAC 校验失败（两种盐定位均拒绝）
  await assert.rejects(() => stegpy.stegpyDecodeFromPixels(stego, 'wrong-password'), /Fernet 口令解密失败/);
});

// ---- stegpy：WAV 载体语义 ----

test('stegpy WAV 载体：原始字节跳过前 10000 后闭环、不足阈值报中文错误', async () => {
  const raw = randomBytes(10000 + 512);
  const tail = await stegpy.stegpyEncode(raw.subarray(10000), { data: 'wav-flag', bits: 2 });
  raw.set(tail, 10000);
  const result = await stegpy.stegpyDecodeFromBytes(raw);
  assert.equal(result.text, 'wav-flag');
  await assert.rejects(() => stegpy.stegpyDecodeFromBytes(randomBytes(9999)), /10000/);
});

// ---- stegpy：载体识别 ----

test('stegpy 魔数与位深标记校验：非 stegpy 载体抛中文错误', async () => {
  const garbage = randomBytes(256);
  garbage[0] = 0;
  await assert.rejects(() => stegpy.stegpyDecodeFromPixels(garbage), /stegv3|不是 stegpy/);
  const badMarker = randomBytes(64);
  badMarker[0] = 0x30; // bit4+bit5 同置 → bits=8
  await assert.rejects(() => stegpy.stegpyDecodeFromPixels(badMarker), /位深标记/);
});

// ---- OpenStego：MD5 与 java.util.Random 复刻标准性 ----

test('MD5 纯 JS 复刻：RFC 1321 标准向量（空串 / abc / message digest）', () => {
  const encode = value => new TextEncoder().encode(value);
  assert.equal(toHex(openstego.md5(encode(''))), 'd41d8cd98f00b204e9800998ecf8427e');
  assert.equal(toHex(openstego.md5(encode('abc'))), '900150983cd24fb0d6963f7d28e17f72');
  assert.equal(toHex(openstego.md5(encode('message digest'))), 'f96b697d7cb7938d525a2f31aaf161d0');
});

test('java.util.Random 复刻：经典向量互证 + nextInt(100) 序列 + 2 的幂快速路径 + nextInt(1) 恒 0', () => {
  // 教材级经典向量（独立于任务规格，交叉锁定 LCG 公式正确性）
  assert.equal(new openstego.JavaRandom(42).nextInt(), -1170105035, 'new Random(42).nextInt()');
  assert.equal(new openstego.JavaRandom(0).nextInt(), -1155484576, 'new Random(0).nextInt()');
  assert.equal(new openstego.JavaRandom(1).nextInt(), -1155869325, 'new Random(1).nextInt()');
  // nextInt(100) 首序列：前 3 个与规格给定向量前缀 60/48/29 吻合，后 2 个由上述经典向量锁定的公式推得 47/15
  const sequence = new openstego.JavaRandom(0);
  assert.deepEqual(
    [sequence.nextInt(100), sequence.nextInt(100), sequence.nextInt(100), sequence.nextInt(100), sequence.nextInt(100)],
    [60, 48, 29, 47, 15],
  );
  // 2 的幂快速路径 (bound*next(31))>>31
  const power = new openstego.JavaRandom(0);
  assert.deepEqual([power.nextInt(16), power.nextInt(16), power.nextInt(16)], [11, 13, 3]);
  // channelBits=1 的 randlsb 头部路径：nextInt(1) 恒 0
  assert.equal(new openstego.JavaRandom(0).nextInt(1), 0);
});

// ---- OpenStego：顺序 LSB 位序手工向量 ----

test('OpenStego 顺序 LSB 位序手工向量：8×9 图 1bit/通道装 26B 头 + 1B 数据（x 先增、R→G→B、MSB-first）', async () => {
  // 独立手工构造期望位流："OPENSTEGO" + 0x02 + len=1(小端) + chBits=1 + fnLen=0 + comp=0 + enc=0 + 8 空格 + 0xA5
  const frame = Buffer.concat([
    Buffer.from('OPENSTEGO', 'latin1'),
    Buffer.from([0x02, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]),
    Buffer.alloc(8, 0x20),
    Buffer.from([0xa5]),
  ]);
  assert.equal(frame.length, 27, '8×9 图 3 通道 ×1bit = 216 bit 恰装 27 字节');
  const manual = solid(8, 9, [0, 0, 0]);
  let slot = 0;
  for (const byte of frame) {
    for (let b = 7; b >= 0; b -= 1) {
      manual.data[Math.floor(slot / 3) * 4 + (slot % 3)] = (byte >> b) & 1;
      slot += 1;
    }
  }
  // 手工锚点（'O'=0x4F=01001111）：位序 0,1,0,0,1,1,1,1 依次填 (0,0)R/G/B、(1,0)R/G/B、(2,0)R/G
  assert.deepEqual([manual.data[0], manual.data[1], manual.data[2]], [0, 1, 0], '(0,0) R/G/B 低 1 位');
  assert.deepEqual([manual.data[4], manual.data[5], manual.data[6]], [0, 1, 1], '(1,0) R/G/B 低 1 位');
  assert.deepEqual([manual.data[8], manual.data[9]], [1, 1], '(2,0) R/G 低 1 位');
  // 读方向：手工位填充图直接解出头字段与数据
  const decoded = await openstego.openstegoDecodeFromPixels(manual);
  assert.equal(decoded.fileName, '');
  assertBytesEqual(decoded.data, new Uint8Array([0xa5]), '手工向量数据段');
  assert.ok(Array.from(decoded.notes).some(note => /顺序 lsb/.test(note)), 'notes 标注顺序 lsb 插件');
  // 写方向互证：引擎 encode 产物与手工图逐像素一致
  const engine = await openstego.openstegoEncode(solid(8, 9, [0, 0, 0]), {
    data: new Uint8Array([0xa5]),
    compress: false,
    channelBits: 1,
    plugin: 'lsb',
  });
  assertBytesEqual(engine.data, manual.data, 'encode 产物与手工位填充一致');
});

// ---- OpenStego：无口令闭环 ----

test('OpenStego 无口令闭环：大内容触发 gzip 压缩并还原、文件名保留', async () => {
  const flag = `flag{openstego_lsb_order}${'A'.repeat(3000)}`;
  const stego = await openstego.openstegoEncode(solid(64, 64, [12, 34, 56]), { data: flag, fileName: 'flag.txt' });
  const result = await openstego.openstegoDecodeFromPixels(stego);
  assert.equal(result.fileName, 'flag.txt');
  assert.equal(new TextDecoder().decode(result.data), flag);
  const notes = Array.from(result.notes).join('；');
  assert.match(notes, /useCompression=1：gzip 解压/);
  assert.match(notes, /顺序 lsb/);
});

test('OpenStego channelBits=2 无压缩闭环：头部按 1bit 写、数据段按 2bit 读', async () => {
  const stego = await openstego.openstegoEncode(solid(16, 16, [200, 100, 50]), {
    data: 'cb2-data',
    fileName: 'n.txt',
    compress: false,
    channelBits: 2,
  });
  const result = await openstego.openstegoDecodeFromPixels(stego);
  assert.equal(result.fileName, 'n.txt');
  assert.equal(new TextDecoder().decode(result.data), 'cb2-data');
});

// ---- OpenStego：口令闭环（randlsb + PBE + gzip） ----

test('OpenStego 口令闭环：randlsb 插件 + PBEWithHmacSHA256AndAES_128 + gzip，IV 定位模式入 notes', async () => {
  const flag = `flag{randlsb_pbe_aes}${'B'.repeat(2000)}`;
  const stego = await openstego.openstegoEncode(solid(64, 64, [7, 77, 177]), {
    data: flag,
    fileName: 'rand.bin',
    password: 'pw-测试',
  });
  const result = await openstego.openstegoDecodeFromPixels(stego, 'pw-测试');
  assert.equal(result.fileName, 'rand.bin');
  assert.equal(new TextDecoder().decode(result.data), flag);
  const notes = Array.from(result.notes).join('；');
  assert.match(notes, /randlsb/);
  assert.match(notes, /IV 定位：params 尾部 16 字节/, '编码方向 params=IV 命中 paramsTail 模式');
  await assert.rejects(() => openstego.openstegoDecodeFromPixels(stego, 'bad-pw'), /OpenStego 提取失败/);
});

test('OpenStego 双试兜底：给了口令但数据实际是顺序 lsb（未加密）仍可解出', async () => {
  const stego = await openstego.openstegoEncode(solid(32, 32, [1, 2, 3]), {
    data: 'plain-lsb',
    compress: false,
    plugin: 'lsb',
  });
  const result = await openstego.openstegoDecodeFromPixels(stego, 'whatever');
  assert.equal(new TextDecoder().decode(result.data), 'plain-lsb');
  assert.match(Array.from(result.notes).join('；'), /顺序 lsb/);
});

// ---- OpenStego：错误路径 ----

test('OpenStego 容量不足与非 OpenStego 载体抛中文错误', async () => {
  await assert.rejects(
    () => openstego.openstegoEncode(solid(4, 4, [0, 0, 0]), { data: 'x'.repeat(64), compress: false }),
    /槽位耗尽|容量不足/,
  );
  await assert.rejects(() => openstego.openstegoDecodeFromPixels(solid(16, 16, [1, 2, 3])), /OPENSTEGO|魔数/);
});
