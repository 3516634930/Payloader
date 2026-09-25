// steghide 0.5.1 提取方向测试（批次 SI·B 线）：
// 1) Selector 置换：m=16 手算对照（推导表见各断言处）+ 确定性 + {0..m-1} 双射
// 2) LCG：种子已知的 Value 序列首值断言（A/C 常量与 32 位回绕）
// 3) 位流状态机：Magic/版本一元码/算法索引经 NAry 数字流 roundtrip
// 4) 端到端闭环 24bpp BMP：测试侧自实现嵌入方向镜像（同 Selector/EmbData 正向 + AES-256-CBC +
//    zlib 压缩）写入 flag{steghide_roundtrip}，提取还原 + CRC 通过
// 5) 端到端闭环 16bit PCM WAV：同理
// 6) 错口令 → 魔数失败中文报错；非 steghide 载体 / 未支持 bpp、bit 数、加密组合中文报错
// 说明：无本地 steghide 二进制，本批为闭环验证（镜像嵌入 ↔ 提取），真产物对拍待真题阶段。
// 加载统一走 tests/helpers/compileTsModule.mjs；沙箱数组断言用主 realm 的 Array.from 转换。
import assert from 'node:assert/strict';
import { deflateSync } from 'node:zlib';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const { loadModule } = createTsModuleLoader();
const {
  PseudoRandomSource, SteghideSelector, steghideSelectorSeed, LsbBits, NaryDigitReader,
  steghideKeygen, steghideExtractBmp, steghideExtractWav, parseBmpCarrier, parseWavCarrier,
  steghideCrc32, STEGHIDE_MAGIC,
} = loadModule(path.join(projectRoot, 'src', 'utils', 'ctf', 'steghideExtract.ts'));

// mhash MHASH_CRC32 语义：非反射 0x04C11DB7、MSB 先行、初值/终值取反（独立实现，交叉核对）
const stegCrc32 = data => {
  const table = Array.from({ length: 256 }, (_, n) => {
    let c = (n << 24) >>> 0;
    for (let k = 0; k < 8; k += 1) c = c & 0x80000000 ? ((c << 1) ^ 0x04c11db7) >>> 0 : (c << 1) >>> 0;
    return c >>> 0;
  });
  let crc = 0xffffffff;
  for (const byte of data) crc = (((crc << 8) >>> 0) ^ table[(crc >>> 24) ^ byte]) >>> 0;
  return (crc ^ 0xffffffff) >>> 0;
};

const makePrng = seed => {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) | 0;
    let mixed = Math.imul(state ^ (state >>> 15), 1 | state);
    mixed = (mixed + Math.imul(mixed ^ (mixed >>> 7), 61 | mixed)) ^ mixed;
    return ((mixed ^ (mixed >>> 14)) >>> 0) / 4294967296;
  };
};

// ---- 1) Selector 置换 ----

// 手算推导（passphrase='a'，md5=0cc175b9c0f1b6a831c399e269772661）：
//   4 个小端字 0xb975c10c ^ 0xa8b6f1c0 ^ 0xe299c331 ^ 0x61267769 = seed 0x927c8494。
//   LCG 推进 k 序列（k = j + getValue(16-j)）：1,4,11,14,4,10,10,11,11,9,10,15,13,13,14,15
//   分支（m=miss 直写，H=hit 用 Y[i] 替代）：m m m m H m H H H m H m m H H H
//   逐步（Y[i] 链回填按 Selector.cc 分支顺序）：
//   j=0..3 miss → X=1,4,11,14；j=4 命中 4(i=1)，X[4]=Y[1]=0（Y[1] 在尾部检查中被改为 Y[0]=0）
//   j=5 miss → X[5]=10；j=6 命中 10(i=5) → X[6]=Y[5]=5，随后 Y[5]=6
//   j=7 命中 11(i=2) → X[7]=Y[2]=2；j=8 命中 11(i=2) → X[8]=Y[2]=7（Y[2] 已被 j=7 改为 7）
//   j=9 miss → X[9]=9；j=10 命中 10(i=5) → X[10]=Y[5]=6；j=11 miss → X[11]=15
//   j=12 miss → X[12]=13；j=13 命中 13(i=12) → X[13]=Y[12]=12
//   j=14 命中 14(i=3) → X[14]=Y[3]=3；j=15 命中 15(i=11) → X[15]=Y[11]=8（Y[11] 链到 Y[2]=8）
//   得 X = [1,4,11,14,0,10,5,2,7,9,6,15,13,12,3,8]
test('Selector 置换：m=16 手算对照（分支顺序逐行对齐 Selector.cc）', () => {
  const seed = steghideSelectorSeed(new TextEncoder().encode('a'));
  assert.equal(seed, 0x927c8494, '种子 = 4 个小端字异或');
  const selector = new SteghideSelector(16, seed);
  const produced = Array.from({ length: 16 }, (_, i) => selector.at(i));
  assert.deepEqual(produced, [1, 4, 11, 14, 0, 10, 5, 2, 7, 9, 6, 15, 13, 12, 3, 8]);
  // 懒计算语义：at(5) 只推进到 5；先深后浅重复读取结果一致（确定性）
  const again = new SteghideSelector(16, seed);
  again.at(9);
  assert.equal(again.at(3), produced[3]);
  assert.equal(again.at(9), produced[9]);
});

test('Selector 置换：是 {0..m-1} 的双射且随口令改变', () => {
  for (const passphrase of ['a', 'ctf2026', '口令中文', 'x']) {
    const seed = steghideSelectorSeed(new TextEncoder().encode(passphrase));
    const selector = new SteghideSelector(64, seed);
    const produced = Array.from({ length: 64 }, (_, i) => selector.at(i));
    assert.equal(new Set(produced).size, 64, `${passphrase}：无双射`);
    for (const value of produced) assert.ok(value >= 0 && value < 64);
  }
  const seedA = steghideSelectorSeed(new TextEncoder().encode('a'));
  const seedB = steghideSelectorSeed(new TextEncoder().encode('ctf2026'));
  assert.equal(seedB, 0xe50b1104, '第二组种子手算对照');
  const second = Array.from({ length: 16 }, (_, i) => new SteghideSelector(16, seedB).at(i));
  assert.deepEqual(second, [6, 3, 0, 14, 13, 11, 15, 8, 2, 12, 5, 10, 7, 1, 9, 4]);
  assert.notEqual(seedA, seedB);
});

// ---- 2) LCG ----

test('CRC32（mhash MHASH_CRC32 语义）：已知向量 + 测试侧独立实现互证', () => {
  // "123456789"：CRC-32/MPEG-2 无终值取反时为 0x0376E6E7，本变体终值取反 → 0xFC891918
  assert.equal(steghideCrc32(new TextEncoder().encode('123456789')), 0xfc891918);
  assert.equal(steghideCrc32(new Uint8Array(0)), 0x00000000);
  assert.equal(steghideCrc32(new TextEncoder().encode('flag{steghide_roundtrip}')), 0x65d94a22);
  const prng = makePrng(1234);
  const blob = new Uint8Array(1024).map(() => Math.floor(prng() * 256));
  assert.equal(steghideCrc32(blob), stegCrc32(blob), '模块与测试侧独立实现一致');
});

test('LCG：A/C 常量与 32 位回绕的首值序列（种子 0x927c8494 手算对照）', () => {
  const prng = new PseudoRandomSource(0x927c8494);
  assert.equal(prng.peek(), 0x927c8494);
  // 首步手算：V1 = (1367208549 × 0x927c8494 + 1) mod 2^32 = 0x10b83665；
  // getValue(2^20) = ⌊2^20 × V1/2^32⌋ = V1 >>> 12
  const values = [];
  for (let i = 0; i < 5; i += 1) {
    prng.getValue(1 << 20);
    values.push(prng.peek());
  }
  assert.deepEqual(values, [0x10b83665, 0x4069efda, 0xa5f9b503, 0xde184030, 0x13aeb2f1].map(v => v >>> 0));
  // 值域与单调推进：getValue(n) ∈ [0, n)
  const bounded = new PseudoRandomSource(7);
  for (let i = 0; i < 1000; i += 1) {
    const draw = bounded.getValue(10);
    assert.ok(draw >= 0 && draw < 10);
  }
  // Math.imul 回绕与 BigInt 参考一致
  const bigRef = seed => {
    let v = BigInt(seed);
    return () => {
      v = (1367208549n * v + 1n) & 0xffffffffn;
      return v;
    };
  };
  const big = bigRef(0xdeadbeef);
  const imul = new PseudoRandomSource(0xdeadbeef);
  for (let i = 0; i < 50; i += 1) {
    imul.getValue(1);
    assert.equal(imul.peek(), Number(big()));
  }
});

// ---- 3) 位流状态机 ----

test('位流状态机：Magic/版本一元码/算法索引经 NAry 数字流 roundtrip（modulus=4 与 2）', async () => {
  const header = new LsbBits();
  header.appendValue(STEGHIDE_MAGIC, 24); // Magic
  header.appendValue(0, 1); // 版本一元码：CodeVersion=0 → 单个 0 位
  header.appendValue(2, 5); // EncAlgo = rijndael-128
  header.appendValue(1, 3); // EncMode = cbc
  header.appendValue(0x1234abcd, 32); // NPlainBits
  assert.equal(header.length, 24 + 1 + 5 + 3 + 32);

  for (const modulus of [4, 2]) {
    const arityNBits = Math.round(Math.log2(modulus));
    // 镜像嵌入：整条位流按 appendNAry 展开为 base-modulus 数字流（尾部零填充到数字边界）
    const padded = new LsbBits();
    padded.appendBits(header);
    while (padded.length % arityNBits !== 0) padded.appendBit(0);
    const digits = [];
    for (let p = 0; p * arityNBits < padded.length; p += 1) {
      digits.push(padded.getValue(p * arityNBits, arityNBits));
    }
    const reader = new NaryDigitReader(() => digits.shift(), arityNBits);
    assert.equal(reader.readBits(24), STEGHIDE_MAGIC);
    assert.equal(reader.readBit(), 0, '版本一元码终止位');
    assert.equal(reader.readBits(5), 2, 'EncAlgo 索引');
    assert.equal(reader.readBits(3), 1, 'EncMode 索引');
    assert.equal(reader.readBits(32), 0x1234abcd);
  }

  // 非对齐字节读：NAry 流中按位偏移取字节仍保持 LSB-first 打包
  const bytes = new LsbBits();
  bytes.appendValue(0b1, 1); // 先错开 1 位
  bytes.appendValue(0xab, 8);
  bytes.appendValue(0xcd, 8);
  let cursor = 0;
  const shifted = new NaryDigitReader(() => bytes.getValue(cursor++, 1), 1);
  shifted.readBit();
  assert.deepEqual(Array.from(shifted.readBytes(2)), [0xab, 0xcd]);
});

// ---- 4) 端到端闭环：嵌入方向镜像（测试侧正向实现） ----

// 构造 EmbData::getBitString 同形位流（压缩 + CRC + 文件名），再做 AES-256-CBC 加密与 NAry 展开
const buildEmbeddedStream = async (fileName, data, passphrase, { compress = true, encrypt = true } = {}) => {
  // compr = 校验标志(1) + CRC32(32) + 文件名 + NUL + 数据
  const compr = new LsbBits();
  compr.appendValue(1, 1);
  compr.appendValue(stegCrc32(data), 32);
  for (const byte of Buffer.from(fileName, 'latin1')) compr.appendValue(byte, 8);
  compr.appendValue(0, 8);
  compr.appendBytes(new Uint8Array(data));

  const plain = new LsbBits();
  if (compress) {
    // C++ 语义：先记录未 pad 的 compr 位长，再 pad(8,0) 到字节边界后 deflate
    const unpaddedBits = compr.length;
    while (compr.length % 8 !== 0) compr.appendBit(0);
    const zipped = new Uint8Array(deflateSync(Buffer.from(compr.toBytes()), { level: 9 }));
    plain.appendValue(1, 1);
    plain.appendValue(unpaddedBits, 32);
    plain.appendBytes(zipped);
  } else {
    plain.appendValue(0, 1);
    plain.appendBits(compr);
  }

  // main = Magic + 版本 + EncAlgo/EncMode + NPlainBits + 密文
  const main = new LsbBits();
  main.appendValue(STEGHIDE_MAGIC, 24);
  main.appendValue(0, 1);
  if (encrypt) {
    main.appendValue(2, 5);
    main.appendValue(1, 3);
    main.appendValue(plain.length, 32);
    // padRandom 镜像：随机位补齐到 16 字节倍数，随机 IV 前置
    const prng = makePrng(0xc0ffee);
    const paddedBitCount = Math.ceil(plain.length / 128) * 128;
    const padded = new Uint8Array(paddedBitCount / 8);
    for (let i = 0; i < plain.length; i += 1) {
      if (plain.getBit(i)) padded[i >> 3] |= 1 << (i & 7);
    }
    for (let i = plain.length; i < paddedBitCount; i += 1) {
      if (prng() < 0.5) padded[i >> 3] |= 1 << (i & 7);
    }
    const iv = new Uint8Array(16);
    for (let i = 0; i < 16; i += 1) iv[i] = Math.floor(prng() * 256);
    const key = await crypto.subtle.importKey('raw', steghideKeygen(new TextEncoder().encode(passphrase), 32), { name: 'AES-CBC' }, false, ['encrypt']);
    const encrypted = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CBC', iv }, key, padded));
    // WebCrypto 加密对齐输入会追加整块 PKCS#7，取前 padded.length 字节即真实 CBC 密文
    main.appendBytes(iv);
    main.appendBytes(encrypted.subarray(0, padded.length));
  } else {
    main.appendValue(0, 5); // none
    main.appendValue(0, 3); // ecb（none 时忽略）
    main.appendValue(plain.length, 32);
    main.appendBits(plain);
  }
  return main;
};

const streamToDigits = (stream, modulus) => {
  const arityNBits = Math.round(Math.log2(modulus));
  // 尾部零填充到数字边界（对齐 BitString::getNAry 的部分末数字语义）
  const padded = new LsbBits();
  padded.appendBits(stream);
  while (padded.length % arityNBits !== 0) padded.appendBit(0);
  const digits = [];
  for (let p = 0; p * arityNBits < padded.length; p += 1) {
    digits.push(padded.getValue(p * arityNBits, arityNBits));
  }
  return digits;
};

// 24bpp BMP 构造器：WIN 头 + 随机像素（含奇宽度行 pad 分支）
const buildBmp24 = (width, height, prng) => {
  const lineBytes = width * 3;
  const padding = (4 - (lineBytes % 4)) % 4;
  const rowStride = lineBytes + padding;
  const offBits = 54;
  const buf = Buffer.alloc(offBits + rowStride * height);
  buf.write('BM', 0, 'latin1');
  buf.writeUInt32LE(buf.length, 2);
  buf.writeUInt32LE(offBits, 10);
  buf.writeUInt32LE(40, 14);
  buf.writeInt32LE(width, 18);
  buf.writeInt32LE(height, 22);
  buf.writeUInt16LE(1, 26);
  buf.writeUInt16LE(24, 28);
  buf.writeUInt32LE(0, 30);
  for (let row = 0; row < height; row += 1) {
    for (let i = 0; i < lineBytes; i += 1) {
      buf[offBits + row * rowStride + i] = Math.floor(prng() * 256);
    }
  }
  return { bytes: new Uint8Array(buf), lineBytes, padding, rowStride, offBits };
};

const bmpEValue = (bytes, offBits, rowStride, pos, width) => {
  const row = Math.floor(pos / width);
  const column = pos % width;
  const index = offBits + row * rowStride + column * 3;
  const r = bytes[index + 2] & 1;
  const g = bytes[index + 1] & 1;
  const b = bytes[index] & 1;
  return ((r ^ g) << 1) | (r ^ b);
};

// 嵌入镜像：每数字 2 个被选样本；只改第二个样本所在像素，翻转单通道 ±1 即可覆盖 E ⊕ {01,10,11}
const embedBmp = (bmp, width, digits, passphrase) => {
  const out = Uint8Array.from(bmp.bytes);
  const numSamples = width * width;
  const selector = new SteghideSelector(numSamples, steghideSelectorSeed(new TextEncoder().encode(passphrase)));
  let sampleIndex = 0;
  for (const digit of digits) {
    const p1 = selector.at(sampleIndex++);
    const p2 = selector.at(sampleIndex++);
    const e1 = bmpEValue(out, bmp.offBits, bmp.rowStride, p1, width);
    const e2 = bmpEValue(out, bmp.offBits, bmp.rowStride, p2, width);
    const flip = ((digit - e1) % 4 + 4) % 4 ^ e2;
    if (flip === 0) continue;
    const row = Math.floor(p2 / width);
    const column = p2 % width;
    const index = bmp.offBits + row * bmp.rowStride + column * 3;
    const channel = flip === 0b01 ? 0 : flip === 0b10 ? 1 : 2; // B=LSB 位、G=高位、R=双位
    const current = out[index + channel];
    out[index + channel] = current === 0xff ? current - 1 : current + 1;
  }
  return out;
};

// 16bit PCM WAV 构造器（立体声交织，中间夹一个 LIST 块验证跳块）
const buildWav16 = (numSamples, prng) => {
  const dataLen = numSamples * 2;
  const buf = Buffer.alloc(12 + 8 + 16 + 8 + 4 + 8 + dataLen);
  buf.write('RIFF', 0, 'latin1');
  buf.writeUInt32LE(buf.length - 8, 4);
  buf.write('WAVE', 8, 'latin1');
  buf.write('fmt ', 12, 'latin1');
  buf.writeUInt32LE(16, 16);
  buf.writeUInt16LE(1, 20);
  buf.writeUInt16LE(2, 22);
  buf.writeUInt32LE(44100, 24);
  buf.writeUInt32LE(44100 * 4, 28);
  buf.writeUInt16LE(4, 32);
  buf.writeUInt16LE(16, 34);
  buf.write('LIST', 36, 'latin1');
  buf.writeUInt32LE(4, 40);
  buf.write('INFO', 44, 'latin1');
  const dataStart = 48;
  buf.write('data', dataStart, 'latin1');
  buf.writeUInt32LE(dataLen, dataStart + 4);
  for (let i = 0; i < numSamples; i += 1) {
    const value = Math.floor(prng() * 65536);
    buf[dataStart + 8 + i * 2] = value & 0xff;
    buf[dataStart + 8 + i * 2 + 1] = (value >> 8) & 0xff;
  }
  return { bytes: new Uint8Array(buf), dataStart: dataStart + 8 };
};

const embedWav = (wav, digits, passphrase) => {
  const out = Uint8Array.from(wav.bytes);
  const selector = new SteghideSelector(8000, steghideSelectorSeed(new TextEncoder().encode(passphrase)));
  let sampleIndex = 0;
  for (const digit of digits) {
    const p1 = selector.at(sampleIndex++);
    const p2 = selector.at(sampleIndex++);
    const offset = wav.dataStart + p2 * 2;
    const low = out[offset];
    const high = out[offset + 1];
    const e1 = (out[wav.dataStart + p1 * 2] & 1);
    const e2 = low & 1;
    if ((e1 ^ e2) === digit) continue;
    const word = (low | (high << 8)) + 1 & 0xffff; // 回绕加一翻转 LSB
    out[offset] = word & 0xff;
    out[offset + 1] = word >> 8;
  }
  return out;
};

test('端到端闭环 24bpp BMP：嵌入镜像 → 提取还原 flag + CRC 通过', async () => {
  const passphrase = 'S3cr3t!';
  const flag = Buffer.from('flag{steghide_roundtrip}', 'latin1');
  const stream = await buildEmbeddedStream('flag.txt', flag, passphrase);
  const digits = streamToDigits(stream, 4);
  assert.ok(digits.length * 2 <= 64 * 64, '容量检查：4096 样本装下全部数字');
  const bmp = buildBmp24(64, 64, makePrng(42));
  const stego = embedBmp(bmp, 64, digits, passphrase);
  assert.notDeepEqual(Array.from(stego), Array.from(bmp.bytes), '像素区确有改动');

  const result = await steghideExtractBmp(stego, passphrase);
  assert.equal(result.fileName, 'flag.txt');
  assert.deepEqual(Array.from(result.data), Array.from(flag));
  assert.equal(result.crcOk, true);
  assert.ok(result.notes.some(note => note.includes('rijndael-128')));
  assert.ok(result.notes.some(note => note.includes('CRC32：校验通过')));
  // 同一口令重复提取确定性
  const again = await steghideExtractBmp(stego, passphrase);
  assert.deepEqual(Array.from(again.data), Array.from(flag));
});

test('端到端闭环 24bpp BMP：无压缩 + 无加密（none）路径', async () => {
  const passphrase = 'plain';
  const payload = Buffer.from('steghide-none-nocompress-明文数据', 'utf8');
  const stream = await buildEmbeddedStream('note.bin', payload, passphrase, { compress: false, encrypt: false });
  const digits = streamToDigits(stream, 4);
  const bmp = buildBmp24(64, 64, makePrng(7));
  const stego = embedBmp(bmp, 64, digits, passphrase);
  const result = await steghideExtractBmp(stego, passphrase);
  assert.equal(result.fileName, 'note.bin');
  assert.deepEqual(Array.from(result.data), Array.from(payload));
  assert.equal(result.crcOk, true);
  assert.ok(result.notes.some(note => note.includes('none（明文透传）')));
  assert.ok(result.notes.some(note => note.includes('压缩：无')));
});

test('端到端闭环 16bit PCM WAV：嵌入镜像 → 提取还原 flag + CRC 通过', async () => {
  const passphrase = 'wav-口令-2026';
  const flag = Buffer.from('flag{steghide_roundtrip}', 'latin1');
  const stream = await buildEmbeddedStream('secret.txt', flag, passphrase);
  const digits = streamToDigits(stream, 2);
  assert.ok(digits.length * 2 <= 8000, '容量检查：8000 样本装下全部数字');
  const wav = buildWav16(8000, makePrng(0x5eed));
  const stego = embedWav(wav, digits, passphrase);
  const result = await steghideExtractWav(stego, passphrase);
  assert.equal(result.fileName, 'secret.txt');
  assert.deepEqual(Array.from(result.data), Array.from(flag));
  assert.equal(result.crcOk, true);
  assert.ok(result.notes.some(note => note.includes('16bit PCM WAV')));
});

test('端到端闭环：奇宽度 24bpp BMP（行尾 3 字节 pad 分支）', async () => {
  const passphrase = 'odd-width';
  const payload = Buffer.from('flag{bmp_row_padding}', 'latin1');
  const stream = await buildEmbeddedStream('odd.txt', payload, passphrase);
  const digits = streamToDigits(stream, 4);
  const bmp = buildBmp24(63, 63, makePrng(77)); // lineBytes=189 → pad=3
  assert.equal(bmp.padding, 3);
  const stego = embedBmp(bmp, 63, digits, passphrase);
  const result = await steghideExtractBmp(stego, passphrase);
  assert.deepEqual(Array.from(result.data), Array.from(payload));
  assert.equal(result.crcOk, true);
});

test('端到端闭环：20KB 载荷触发位流缓冲压缩路径（读取超 128Kbit）', async () => {
  const passphrase = 'big-payload';
  const prng = makePrng(2026);
  const payload = new Uint8Array(20 * 1024).map(() => Math.floor(prng() * 256));
  const stream = await buildEmbeddedStream('blob.bin', payload, passphrase);
  assert.ok(stream.length > 1 << 17, `流位长 ${stream.length} 应超压缩阈值 131072`);
  const digits = streamToDigits(stream, 4);
  assert.ok(digits.length * 2 <= 512 * 512, '容量检查：512×512 样本装下全部数字');
  const bmp = buildBmp24(512, 512, makePrng(555));
  const stego = embedBmp(bmp, 512, digits, passphrase);
  const result = await steghideExtractBmp(stego, passphrase);
  assert.equal(result.fileName, 'blob.bin');
  assert.deepEqual(Array.from(result.data), Array.from(payload));
  assert.equal(result.crcOk, true);
});

// ---- 6) 错误路径 ----

test('错口令：魔数失败中文报错', async () => {
  const passphrase = 'right-one';
  const stream = await buildEmbeddedStream('f', Buffer.from('payload-data-123'), passphrase);
  const digits = streamToDigits(stream, 4);
  const bmp = buildBmp24(64, 64, makePrng(1));
  const stego = embedBmp(bmp, 64, digits, passphrase);
  await assert.rejects(
    steghideExtractBmp(stego, 'wrong-one'),
    /魔数不匹配/,
  );
});

test('非 steghide 载体：随机 BMP/WAV 提取抛中文错误', async () => {
  const bmp = buildBmp24(64, 64, makePrng(99));
  await assert.rejects(steghideExtractBmp(bmp.bytes, 'whatever'), /魔数不匹配/);
  const wav = buildWav16(1000, makePrng(98));
  await assert.rejects(steghideExtractWav(wav.bytes, 'whatever'), /魔数不匹配/);
});

test('未支持格式：8bpp BMP / 8bit WAV / 非 PCM WAV / 非 BMP 非 WAV 中文记账', async () => {
  // 8bpp BMP 头
  const bmp8 = Buffer.alloc(54 + 1024 + 64 * 8);
  bmp8.write('BM', 0, 'latin1');
  bmp8.writeUInt32LE(bmp8.length, 2);
  bmp8.writeUInt32LE(54 + 1024, 10);
  bmp8.writeUInt32LE(40, 14);
  bmp8.writeInt32LE(64, 18);
  bmp8.writeInt32LE(8, 22);
  bmp8.writeUInt16LE(1, 26);
  bmp8.writeUInt16LE(8, 28);
  await assert.rejects(steghideExtractBmp(new Uint8Array(bmp8), 'pw'), /暂不支持.*8bpp BMP/);
  await assert.rejects(async () => parseBmpCarrier(new Uint8Array(bmp8)), /暂不支持/);

  // 8bit PCM WAV
  const wav8 = Buffer.alloc(44 + 100);
  wav8.write('RIFF', 0, 'latin1');
  wav8.writeUInt32LE(wav8.length - 8, 4);
  wav8.write('WAVE', 8, 'latin1');
  wav8.write('fmt ', 12, 'latin1');
  wav8.writeUInt32LE(16, 16);
  wav8.writeUInt16LE(1, 20);
  wav8.writeUInt16LE(1, 22);
  wav8.writeUInt32LE(8000, 24);
  wav8.writeUInt32LE(8000, 28);
  wav8.writeUInt16LE(1, 32);
  wav8.writeUInt16LE(8, 34);
  wav8.write('data', 36, 'latin1');
  wav8.writeUInt32LE(100, 40);
  await assert.rejects(steghideExtractWav(new Uint8Array(wav8), 'pw'), /暂不支持.*8bit PCM WAV/);

  // 非 PCM（FormatTag=3 IEEE float）
  const wavFloat = Buffer.from(buildWav16(100, makePrng(3)).bytes);
  wavFloat.writeUInt16LE(3, 20);
  await assert.rejects(steghideExtractWav(wavFloat, 'pw'), /暂不支持.*非 PCM WAV/);

  // 非 BMP / 非 WAV
  await assert.rejects(steghideExtractBmp(new Uint8Array([0x89, 0x50, 0x4e, 0x47]), 'pw'), /不是 BMP 文件/);
  await assert.rejects(steghideExtractWav(new Uint8Array(64).fill(0x20), 'pw'), /不是 WAV 文件/);
});

test('载体解析语义：24bpp EValue 与 16bit WAV EValue 按位核对', () => {
  // 构造已知像素：R=0b00000011,G=0,B=0 → E=((1^0)<<1)|(1^0)=3
  const width = 2;
  const height = 1;
  const offBits = 54;
  const buf = Buffer.alloc(offBits + width * 3);
  buf.write('BM', 0, 'latin1');
  buf.writeUInt32LE(offBits, 10);
  buf.writeUInt32LE(40, 14);
  buf.writeInt32LE(width, 18);
  buf.writeInt32LE(height, 22);
  buf.writeUInt16LE(1, 26);
  buf.writeUInt16LE(24, 28);
  buf[offBits] = 0; // B
  buf[offBits + 1] = 0; // G
  buf[offBits + 2] = 3; // R
  buf[offBits + 3] = 1; // 第二像素 B
  buf[offBits + 4] = 1; // G
  buf[offBits + 5] = 1; // R → E=((1^1)<<1)|(1^1)=0
  const carrier = parseBmpCarrier(new Uint8Array(buf));
  assert.equal(carrier.modulus, 4);
  assert.equal(carrier.samplesPerVertex, 2);
  assert.equal(carrier.numSamples, 2);
  assert.equal(carrier.embeddedValue(0), 3);
  assert.equal(carrier.embeddedValue(1), 0);

  // 16bit WAV：奇偶 LSB；含负值补码（两通道交织下按顺序取样）
  const wav = buildWav16(16, makePrng(11));
  const wavCarrier = parseWavCarrier(wav.bytes);
  const s = i => (wav.bytes[wav.dataStart + i * 2] | (wav.bytes[wav.dataStart + i * 2 + 1] << 8));
  assert.equal(wavCarrier.modulus, 2);
  assert.equal(wavCarrier.samplesPerVertex, 2);
  assert.equal(wavCarrier.numSamples, 16);
  for (let i = 0; i < 16; i += 1) assert.equal(wavCarrier.embeddedValue(i), s(i) & 1);
});
