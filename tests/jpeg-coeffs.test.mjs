// JPEG DCT 系数层 + jsteg 提取器测试（批次 SI·A 线）：全部向量程序化构造——手写最小
// baseline JPEG（SOI / DQT 全 1 表 / SOF0 / 自造 2-4 码字 Huffman / SOS + MSB-first
// 位流 + 0xFF 字节填充 / EOI），不依赖外部样本；真实编码器锚由 PIL 生成的 fixture 覆盖。
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const srcDir = path.join(projectRoot, 'src');
const { loadModule } = createTsModuleLoader();
const coeffs = loadModule(path.join(srcDir, 'utils', 'ctf', 'jpegCoeffs.ts'));
const jsteg = loadModule(path.join(srcDir, 'utils', 'ctf', 'jsteg.ts'));
const { JPEG_ZIGZAG } = coeffs;

// ---- 最小 baseline JPEG 构造器（灰度 1 分量，量化表全 1） ----

// 自造 Huffman（码字需为规范前缀码且不完全填满码空间——jpeg-js 的建表器
// 对满/超订表会在收尾时抛 Could not recreate Huffman Table）：
// DC 表 BITS=[1,1,0×14] VALS=[0,3] → '0'=cat0，'10'=cat3（Kraft 0.75）
// AC 表 BITS=[0,3,1,0×13] VALS=[(0,0),(0,1),(0,2),(0,3)]
//      → '00'=EOB，'01'=cat1，'10'=cat2，'110'=cat3（Kraft 0.875）
const DC_BITS = [1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
const DC_VALS = [0x00, 0x03];
const AC_BITS = [0, 3, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
const AC_VALS = [0x00, 0x01, 0x02, 0x03];

const bitLength = (value) => (value === 0 ? 0 : Math.abs(value).toString(2).length);

// JPEG receiveAndExtend 语义：正数取 s 位原码，负数取 v + 2^s - 1 的补码偏移
const valueBits = (value, size) => {
  const encoded = value > 0 ? value : value + (1 << size) - 1;
  return encoded.toString(2).padStart(size, '0');
};

const makeBitWriter = () => {
  const bytes = [];
  let current = 0;
  let count = 0;
  const emit = () => {
    bytes.push(current);
    if (current === 0xFF) bytes.push(0x00); // 熵位流字节填充（0xFF 后必须填 0x00）
    current = 0;
    count = 0;
  };
  return {
    pushBits(text) {
      for (const ch of text) {
        current = (current << 1) | (ch === '1' ? 1 : 0);
        count += 1;
        if (count === 8) emit();
      }
    },
    finish() {
      while (count !== 0) {
        current = (current << 1) | 1; // 尾部按规范补 1
        count += 1;
        if (count === 8) emit();
      }
    },
    bytes,
  };
};

// zigzag：64 元素数组，[0]=DC，[1..63]=zigzag 序 AC。约束：AC 全非零直到块尾（无 EOB），
// 或非零后只跟块尾零游程（单个 EOB）；AC |值| ∈ 1..7，DC 差值类别 ∈ {0,3}
const encodeBlock = (writer, zigzag, prevDc) => {
  const diff = zigzag[0] - prevDc;
  const dcCategory = bitLength(diff);
  if (dcCategory !== 0 && dcCategory !== 3) {
    throw new Error(`测试向量 DC 差值类别 ${dcCategory} 超出自造 DC 表`);
  }
  writer.pushBits(dcCategory === 0 ? '0' : '10');
  if (dcCategory === 3) writer.pushBits(valueBits(diff, 3));
  let k = 1;
  while (k < 64) {
    if (zigzag[k] === 0) {
      while (k < 64 && zigzag[k] === 0) k += 1;
      if (k < 64) throw new Error('测试向量含非块尾零游程，超出自造 AC 表');
      writer.pushBits('00'); // EOB
      break;
    }
    const size = bitLength(zigzag[k]);
    if (size > 3) throw new Error(`测试向量 AC |${zigzag[k]}| 超出自造 AC 表`);
    writer.pushBits(size === 1 ? '01' : size === 2 ? '10' : '110');
    writer.pushBits(valueBits(zigzag[k], size));
    k += 1;
  }
  return zigzag[0];
};

const segment = (marker, payload) => [
  0xFF, marker,
  ((payload.length + 2) >> 8) & 0xFF, (payload.length + 2) & 0xFF,
  ...payload,
];

const buildJpeg = (widthBlocks, heightBlocks, blocks, sofMarker = 0xC0) => {
  const writer = makeBitWriter();
  let prevDc = 0;
  for (const zigzag of blocks) prevDc = encodeBlock(writer, zigzag, prevDc);
  writer.finish();
  const width = widthBlocks * 8;
  const height = heightBlocks * 8;
  return Uint8Array.from([
    0xFF, 0xD8, // SOI
    ...segment(0xDB, [0x00, ...Array(64).fill(0x01)]), // DQT：8bit 全 1 量化表
    ...segment(sofMarker, [
      0x08, (height >> 8) & 0xFF, height & 0xFF, (width >> 8) & 0xFF, width & 0xFF,
      1, 1, 0x11, 0x00, // 精度 8 / 单分量 id=1 h=v=1 / 量化表 0
    ]),
    ...segment(0xC4, [0x00, ...DC_BITS, ...DC_VALS]),
    ...segment(0xC4, [0x10, ...AC_BITS, ...AC_VALS]),
    ...segment(0xDA, [1, 1, 0x00, 0, 63, 0]), // SOS：1 分量 / DC0+AC0 表 / 全谱 baseline
    ...writer.bytes,
    0xFF, 0xD9, // EOI
  ]);
};

const sparseBlock = (dc, acEntries) => {
  const zigzag = new Array(64).fill(0);
  zigzag[0] = dc;
  for (const [k, value] of acEntries) zigzag[k] = value;
  return zigzag;
};

// 全 63 个 AC 非零：bitSource(j) 决定第 j 个 AC 是 2（LSB 0）还是 3（LSB 1），比特可控
const denseBlock = (bitSource, dc = 0) => {
  const zigzag = new Array(64).fill(0);
  zigzag[0] = dc;
  for (let k = 1; k < 64; k += 1) zigzag[k] = bitSource(k - 1) ? 3 : 2;
  return zigzag;
};

const asciiBytes = (text) => Array.from(text, (ch) => ch.charCodeAt(0));
const latin1Of = (bytes, start, end) =>
  String.fromCharCode(...Array.from(bytes.subarray(start, end)));

// ---- 系数还原 ----

test('readJpegCoefficients：8×8 手造 JPEG 逐系数还原（natural order 存储验证）', () => {
  const jpeg = buildJpeg(1, 1, [sparseBlock(5, [[1, 2], [2, -3], [3, 1]])]);
  const data = coeffs.readJpegCoefficients(jpeg);
  assert.equal(data.width, 8);
  assert.equal(data.height, 8);
  assert.equal(data.components.length, 1);
  const c0 = data.components[0];
  assert.equal(c0.widthInBlocks, 1);
  assert.equal(c0.heightInBlocks, 1);
  assert.equal(c0.h, 1);
  assert.equal(c0.v, 1);
  assert.equal(c0.blocks.length, 64);
  // 块内 natural order：DC=5；zigzag1/2/3 → natural 1/8/16
  const expected = new Array(64).fill(0);
  expected[0] = 5;
  expected[JPEG_ZIGZAG[1]] = 2;
  expected[JPEG_ZIGZAG[2]] = -3;
  expected[JPEG_ZIGZAG[3]] = 1;
  assert.deepEqual(Array.from(c0.blocks), expected);
  assert.equal(data.mcuOrderComponentIndex, null); // 单分量图像为 null
  assert.deepEqual(Array.from(data.mcuOrderCoefficients), expected);
  // jsteg 基本语义在最小向量上：z1(2)→LSB0、z2(-3)→LSB1，z3=1 与 DC/0 全部跳过
  const reveal = jsteg.jstegReveal(jpeg);
  assert.equal(reveal.coefficientCount, 2);
  assert.equal(reveal.rawBits[0], 0b10);
});

test('readJpegCoefficients：16×16（4 块）验证 MCU 顺序（灰度无交织 = 块光栅序）', () => {
  const dcs = [5, 10, 15, 20];
  const jpeg = buildJpeg(2, 2, dcs.map((dc) => sparseBlock(dc, [[1, 2], [2, -3], [3, 1]])));
  const data = coeffs.readJpegCoefficients(jpeg);
  assert.equal(data.width, 16);
  assert.equal(data.height, 16);
  const c0 = data.components[0];
  assert.equal(c0.widthInBlocks, 2);
  assert.equal(c0.heightInBlocks, 2);
  assert.equal(c0.blocks.length, 4 * 64);
  assert.equal(data.mcuOrderCoefficients.length, 4 * 64);
  dcs.forEach((dc, blockIndex) => {
    assert.equal(c0.blocks[blockIndex * 64], dc, `块 ${blockIndex} DC 光栅落位`);
    assert.equal(data.mcuOrderCoefficients[blockIndex * 64], dc, `块 ${blockIndex} MCU 序落位`);
  });
  assert.deepEqual(Array.from(data.mcuOrderCoefficients), Array.from(c0.blocks));
  // 每块可用 AC 都是 z1(0)、z2(1)：8 bit 序列 0,1,0,1,… LSB-first 装配 → 0b10101010
  const reveal = jsteg.jstegReveal(jpeg);
  assert.equal(reveal.coefficientCount, 8);
  assert.equal(reveal.rawBits[0], 0b10101010);
});

// ---- jsteg 提取 ----

test('jstegReveal：系数 LSB 序列装配出 "jsteg"+le32+载荷 的 CLI 封装格式并命中 findings', () => {
  const cliPayload = [...asciiBytes('jsteg'), 11, 0, 0, 0, ...asciiBytes('flag{jsteg}')];
  const totalBits = cliPayload.length * 8; // 160 bit ≤ 4 块 × 63 AC = 252
  const bitAt = (i) => (cliPayload[i >> 3] >> (i & 7)) & 1;
  const jpeg = buildJpeg(
    2,
    2,
    Array.from({ length: 4 }, (_, b) =>
      denseBlock((j) => {
        const global = b * 63 + j;
        return global < totalBits ? bitAt(global) : 0; // 尾部补 LSB 0
      }),
    ),
  );
  const result = jsteg.jstegReveal(jpeg);
  assert.equal(result.coefficientCount, 252); // 全部 63×4 个 AC 均可用（2/3 非 0/±1）
  assert.equal(latin1Of(result.rawBits, 0, 5), 'jsteg');
  assert.equal(result.rawBits[5], 11); // le32 长度（小端首字节）
  assert.equal(latin1Of(result.rawBits, 9, 20), 'flag{jsteg}');
  assert.ok(
    result.findings.some((f) => f.kind === 'jsteg' && f.offset === 0 && f.preview.includes('flag{jsteg}')),
    `应命中 jsteg CLI 封装 finding（实际 ${JSON.stringify(Array.from(result.findings, (f) => f.kind))}）`,
  );
  // 载荷内可打印 flag 文本也会独立报告（位偏移 9 字节 × 8）
  assert.ok(result.findings.some((f) => f.kind === 'flag' && f.preview.includes('flag{jsteg}')));
});

test('jstegReveal：includeMinusOne 开关的跳过集差异（-1 系数默认跳过、开启后计入）', () => {
  const jpeg = buildJpeg(1, 1, [sparseBlock(5, [[1, 2], [2, -1], [3, 3]])]);
  // lukechampine 默认 {0,1,-1} 跳过：z1(2)→0、z3(3)→1 → 0b10
  const standard = jsteg.jstegReveal(jpeg);
  assert.equal(standard.coefficientCount, 2);
  assert.equal(standard.rawBits[0], 0b10);
  // 原版 C jsteg {0,+1} 跳过集：-1 计入，LSB=1 落在 bit1 → 0b110
  const legacy = jsteg.jstegReveal(jpeg, { includeMinusOne: true });
  assert.equal(legacy.coefficientCount, 3);
  assert.equal(legacy.rawBits[0], 0b110);
});

// ---- 防呆 ----

test('readJpegCoefficients/jstegReveal：非 JPEG / 空 / 渐进式 / 截断 / 20MB 均抛中文错误', () => {
  const pngMagic = Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  assert.throws(() => coeffs.readJpegCoefficients(pngMagic), /不是有效的 JPEG/);
  assert.throws(() => coeffs.readJpegCoefficients(new Uint8Array(0)), /不是有效的 JPEG/);
  assert.throws(() => jsteg.jstegReveal(pngMagic), /不是有效的 JPEG/);
  // SOF2（渐进式）：改造后的解码器在帧头即拒绝
  const progressive = buildJpeg(1, 1, [sparseBlock(5, [[1, 2]])], 0xC2);
  assert.throws(() => coeffs.readJpegCoefficients(progressive), /渐进式 JPEG 暂不支持系数提取/);
  // 截断：掐掉 EOI 与熵字节 → 尾部找不到 marker
  const full = buildJpeg(1, 1, [sparseBlock(5, [[1, 2], [2, -3], [3, 1]])]);
  assert.throws(() => coeffs.readJpegCoefficients(full.subarray(0, full.length - 4)), /截断|损坏/);
  assert.throws(
    () => coeffs.readJpegCoefficients(new Uint8Array(20 * 1024 * 1024 + 1)),
    /20MB/,
  );
});

// ---- PIL 交叉验证锚 ----

const fixturePath = path.join(projectRoot, 'tests', 'fixtures', 'jpeg-test.jpg');
const sidecarPath = path.join(projectRoot, 'tests', 'fixtures', 'jpeg-test.json');
const hasFixture = fs.existsSync(fixturePath) && fs.existsSync(sidecarPath);

// 从文件 DQT 段读 8bit 量化表（zigzag 序 → natural order）
const readQuantizationTable = (bytes) => {
  let offset = 2;
  while (offset + 3 < bytes.length) {
    if (bytes[offset] !== 0xFF) {
      offset += 1;
      continue;
    }
    const marker = bytes[offset + 1];
    if (marker === 0x00 || marker === 0xFF || (marker >= 0xD0 && marker <= 0xD7)) {
      offset += 1;
      continue;
    }
    const length = (bytes[offset + 2] << 8) | bytes[offset + 3];
    if (marker === 0xDB && (bytes[offset + 4] >> 4) === 0) {
      const table = new Uint8Array(64);
      for (let j = 0; j < 64; j += 1) table[JPEG_ZIGZAG[j]] = bytes[offset + 5 + j];
      return table;
    }
    offset += 2 + length;
  }
  throw new Error('fixture 中未找到 8bit DQT 段');
};

// 朴素 2D IDCT（公式直算）：逆量化 + 电平回归 +128，返回 8×8 块像素均值
const idctMean = (block, quant) => {
  const dequantized = new Float64Array(64);
  for (let i = 0; i < 64; i += 1) dequantized[i] = block[i] * quant[i];
  const scale = (u) => (u === 0 ? Math.SQRT1_2 : 1);
  let sum = 0;
  for (let y = 0; y < 8; y += 1) {
    for (let x = 0; x < 8; x += 1) {
      let accumulator = 0;
      for (let v = 0; v < 8; v += 1) {
        for (let u = 0; u < 8; u += 1) {
          accumulator +=
            scale(u) * scale(v) * dequantized[v * 8 + u] *
            Math.cos(((2 * x + 1) * u * Math.PI) / 16) *
            Math.cos(((2 * y + 1) * v * Math.PI) / 16);
        }
      }
      sum += accumulator / 4 + 128;
    }
  }
  return sum / 64;
};

test('PIL 锚：真实 baseline JPEG 的块数/尺寸正确，逆量化+IDCT 块均值与 PIL 像素均值粗对齐 ±30',
  { skip: !hasFixture && 'PIL fixture 未生成（生成机无 PIL 时跳过此锚）' },
  () => {
    const bytes = new Uint8Array(fs.readFileSync(fixturePath));
    const data = coeffs.readJpegCoefficients(bytes);
    assert.equal(data.width, 8);
    assert.equal(data.height, 8);
    assert.equal(data.components.length, 1);
    const c0 = data.components[0];
    assert.equal(c0.widthInBlocks, 1);
    assert.equal(c0.heightInBlocks, 1);
    assert.equal(c0.blocks.length, 64);
    assert.notEqual(c0.blocks[0], 0, '梯度图的 DC 必然非零');
    const pixelMean = idctMean(c0.blocks, readQuantizationTable(bytes));
    const expected = JSON.parse(fs.readFileSync(sidecarPath, 'utf8')).pixelMean;
    assert.ok(
      Math.abs(pixelMean - expected) <= 30,
      `IDCT 块均值 ${pixelMean.toFixed(2)} 与 PIL 像素均值 ${expected.toFixed(2)} 偏差超过 30`,
    );
    // jsteg 在真实编码器产物上不抛错、有可用系数、无误报 jsteg 封装
    const reveal = jsteg.jstegReveal(bytes);
    assert.ok(reveal.coefficientCount > 0);
    assert.ok(!reveal.findings.some((f) => f.kind === 'jsteg'));
  });
