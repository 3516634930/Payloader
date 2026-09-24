// 二维码解码引擎测试：测试侧自带一个最小 QR 编码器（仅 Version 1-L / byte 模式 /
// 掩码 0），按 QR 规范独立实现（BCH(15,5) 格式信息、GF(256) Reed-Solomon 纠错码字、
// 之字数据摆放）——与被测解码器（jsQR 移植）互为独立实现：编码器铺出的模块矩阵经
// RGBA 渲染后必须被解码器完整还原，任何一侧的规范理解偏差都会打断对拍。
// 覆盖：自编码还原 / 反色 / 平移缩放 / 非 QR 图返回空 / 一图多码 / 大画布干扰 /
// RS 纠错（翻转数据模块）。加载统一走 tests/helpers/compileTsModule.mjs；
// 断言只用标量字段（vm 沙箱跨 realm 对象不做 deepStrictEqual，见 AGENTS.md 踩坑记录）。
import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const srcDir = path.join(projectRoot, 'src');
const { loadModule } = createTsModuleLoader();
const { decodeQrCodes } = loadModule(path.join(srcDir, 'utils', 'ctf', 'qrDecode.ts'));

// ---------- 测试侧最小 QR 编码器（独立实现，仅 Version 1-L byte 模式 + 掩码 0） ----------

const QR_SIZE = 21; // Version 1
const DATA_CODEWORDS = 19; // 1-L 数据码字
const EC_CODEWORDS = 7; // 1-L 纠错码字

// GF(256)，本原多项式 0x11D（QR 规范），生成子基 0。
const GF_EXP = new Uint8Array(512);
const GF_LOG = new Uint8Array(256);
{
  let x = 1;
  for (let i = 0; i < 255; i += 1) {
    GF_EXP[i] = x;
    GF_LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i += 1) GF_EXP[i] = GF_EXP[i - 255];
}
const gfMul = (a, b) => (a && b ? GF_EXP[GF_LOG[a] + GF_LOG[b]] : 0);

// RS 纠错码字：消息多项式（最高次在前）除以生成多项式取余。
const reedSolomonEc = (dataCodewords, ecCount) => {
  let generator = [1]; // 最高次在前，首一
  for (let i = 0; i < ecCount; i += 1) {
    const next = new Array(generator.length + 1).fill(0);
    for (let j = 0; j < generator.length; j += 1) {
      next[j] ^= generator[j]; // × x
      next[j + 1] ^= gfMul(generator[j], GF_EXP[i]); // × α^i
    }
    generator = next;
  }
  const poly = [...dataCodewords, ...new Array(ecCount).fill(0)];
  for (let i = 0; i < dataCodewords.length; i += 1) {
    const coef = poly[i];
    if (coef === 0) continue;
    for (let j = 1; j < generator.length; j += 1) poly[i + j] ^= gfMul(generator[j], coef);
  }
  return poly.slice(dataCodewords.length);
};

// BCH(15,5) 格式信息：5 位数据（纠错档 2 位 + 掩码 3 位）+ 10 位 BCH 余数，再异或 0x5412。
const formatInfoBits = (ecBits, maskBits) => {
  const data = (ecBits << 3) | maskBits;
  let v = data << 10;
  for (let bit = 14; bit >= 10; bit -= 1) {
    if ((v >>> bit) & 1) v ^= 0x537 << (bit - 10);
  }
  return ((data << 10) | v) ^ 0x5412;
};

// Version 1 功能图案判定（与解码器 buildFunctionPatternMask 的 v1 投影一致，但独立推导）。
const isFunctionModule = (col, row) =>
  (col < 9 && row < 9) || // 左上 9×9（定位 + 分隔 + 格式）
  (col >= 13 && row < 9) || // 右上 8×9
  (col < 9 && row >= 13) || // 左下 9×8
  (col === 6 && row >= 9 && row <= 12) || // 垂直定时
  (row === 6 && col >= 9 && col <= 12); // 水平定时

const drawFinder = (matrix, centerX, centerY) => {
  for (let dy = -3; dy <= 3; dy += 1) {
    for (let dx = -3; dx <= 3; dx += 1) {
      const chebyshev = Math.max(Math.abs(dx), Math.abs(dy));
      matrix[centerY + dy][centerX + dx] = chebyshev !== 2; // 外环/核心黑，中环白
    }
  }
};

// 格式信息两个副本的 15 个落点（下标 = 位序号 b0..b14，值为 [row, col]）。
const FORMAT_POS_COPY1 = [
  [0, 8], [1, 8], [2, 8], [3, 8], [4, 8], [5, 8], [7, 8], [8, 8],
  [8, 7], [8, 5], [8, 4], [8, 3], [8, 2], [8, 1], [8, 0],
];
const FORMAT_POS_COPY2 = [
  [8, 20], [8, 19], [8, 18], [8, 17], [8, 16], [8, 15], [8, 14], [8, 13],
  [14, 8], [15, 8], [16, 8], [17, 8], [18, 8], [19, 8], [20, 8],
];

const buildQrV1LMatrix = text => {
  const bytes = Array.from(Buffer.from(text, 'utf8'));
  assert.ok(bytes.length <= 17, 'Version 1-L byte 模式容量 17 字节');

  // 位流：模式 0100（byte）+ 8 位长度 + 数据 + 终止符 + 填充。
  const bits = [];
  const pushBits = (value, count) => {
    for (let i = count - 1; i >= 0; i -= 1) bits.push((value >> i) & 1);
  };
  pushBits(0b0100, 4);
  pushBits(bytes.length, 8);
  for (const byte of bytes) pushBits(byte, 8);
  const capacityBits = DATA_CODEWORDS * 8;
  for (let i = 0; i < 4 && bits.length < capacityBits; i += 1) bits.push(0);
  while (bits.length % 8 !== 0) bits.push(0);
  const dataCodewords = [];
  for (let i = 0; i < bits.length; i += 8) {
    let value = 0;
    for (let j = 0; j < 8; j += 1) value = (value << 1) | bits[i + j];
    dataCodewords.push(value);
  }
  let padHigh = true;
  while (dataCodewords.length < DATA_CODEWORDS) {
    dataCodewords.push(padHigh ? 0xec : 0x11);
    padHigh = !padHigh;
  }
  const codewords = [...dataCodewords, ...reedSolomonEc(dataCodewords, EC_CODEWORDS)];
  assert.equal(codewords.length, DATA_CODEWORDS + EC_CODEWORDS);

  const matrix = Array.from({ length: QR_SIZE }, () => new Array(QR_SIZE).fill(false));

  // 定位图案 + 分隔带（9×9 区域先全部铺白再画 7×7 定位）。
  for (let row = 0; row <= 7; row += 1) {
    for (let col = 0; col <= 7; col += 1) matrix[row][col] = false;
    for (let col = 13; col <= 20; col += 1) matrix[row][col] = false;
  }
  for (let row = 13; row <= 20; row += 1) {
    for (let col = 0; col <= 7; col += 1) matrix[row][col] = false;
  }
  drawFinder(matrix, 3, 3);
  drawFinder(matrix, 17, 3);
  drawFinder(matrix, 3, 17);

  // 定时图案（col/row 6，偶数坐标黑）。
  for (let row = 8; row <= 12; row += 1) matrix[row][6] = row % 2 === 0;
  for (let col = 8; col <= 12; col += 1) matrix[6][col] = col % 2 === 0;

  // 暗模块 + 格式信息（L=01，掩码 000）。
  matrix[13][8] = true;
  const format = formatInfoBits(0b01, 0b000);
  for (let i = 0; i <= 14; i += 1) {
    const bit = Boolean((format >> i) & 1);
    matrix[FORMAT_POS_COPY1[i][0]][FORMAT_POS_COPY1[i][1]] = bit;
    matrix[FORMAT_POS_COPY2[i][0]][FORMAT_POS_COPY2[i][1]] = bit;
  }

  // 数据 + 纠错码字之字摆放，掩码 0：((row + col) % 2) === 0 时取反。
  const maskFn = (row, col) => (row + col) % 2 === 0;
  let bitIndex = 0;
  let upward = true;
  for (let colPair = QR_SIZE - 1; colPair > 0; colPair -= 2) {
    if (colPair === 6) colPair -= 1; // 跳过垂直定时整列
    for (let i = 0; i < QR_SIZE; i += 1) {
      const row = upward ? QR_SIZE - 1 - i : i;
      for (let offset = 0; offset < 2; offset += 1) {
        const col = colPair - offset;
        if (isFunctionModule(col, row)) continue;
        const dataBit = Boolean((codewords[bitIndex >> 3] >> (7 - (bitIndex & 7))) & 1);
        bitIndex += 1;
        matrix[row][col] = maskFn(row, col) ? !dataBit : dataBit;
      }
    }
    upward = !upward;
  }
  assert.equal(bitIndex, codewords.length * 8, 'Version 1 数据区恰为 26 码字 208 位');

  return matrix;
};

// ---------- 渲染工具 ----------

const makePrng = seed => {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) | 0;
    let mixed = Math.imul(state ^ (state >>> 15), 1 | state);
    mixed = (mixed + Math.imul(mixed ^ (mixed >>> 7), 61 | mixed)) ^ mixed;
    return ((mixed ^ (mixed >>> 14)) >>> 0) / 4294967296;
  };
};

// 模块矩阵 → RGBA。modulePx 每模块像素数；quiet 静区模块数；offsetX/Y 画布内偏移像素；
// width/height 画布尺寸（缺省按码尺寸收边）；invert 反转 RGB（保留 alpha）。
const rasterizeQr = (matrix, options = {}) => {
  const { modulePx = 4, quiet = 4, offsetX = 0, offsetY = 0, invert = false } = options;
  const size = matrix.length;
  const width = options.width ?? (size + quiet * 2) * modulePx;
  const height = options.height ?? (size + quiet * 2) * modulePx;
  const rgba = new Uint8Array(width * height * 4);
  for (let pixel = 0; pixel < width * height; pixel += 1) {
    rgba[pixel * 4] = 255;
    rgba[pixel * 4 + 1] = 255;
    rgba[pixel * 4 + 2] = 255;
    rgba[pixel * 4 + 3] = 255;
  }
  const baseX = quiet * modulePx + offsetX;
  const baseY = quiet * modulePx + offsetY;
  for (let row = 0; row < size; row += 1) {
    for (let col = 0; col < size; col += 1) {
      if (!matrix[row][col]) continue;
      for (let dy = 0; dy < modulePx; dy += 1) {
        for (let dx = 0; dx < modulePx; dx += 1) {
          const x = baseX + col * modulePx + dx;
          const y = baseY + row * modulePx + dy;
          const index = (y * width + x) * 4;
          rgba[index] = 0;
          rgba[index + 1] = 0;
          rgba[index + 2] = 0;
        }
      }
    }
  }
  if (invert) {
    for (let index = 0; index < rgba.length; index += 4) {
      rgba[index] = 255 - rgba[index];
      rgba[index + 1] = 255 - rgba[index + 1];
      rgba[index + 2] = 255 - rgba[index + 2];
    }
  }
  return { rgba, width, height };
};

const flipModule = (rgba, width, modulePx, quietModules, row, col) => {
  const base = quietModules * modulePx;
  for (let dy = 0; dy < modulePx; dy += 1) {
    for (let dx = 0; dx < modulePx; dx += 1) {
      const index = ((base + row * modulePx + dy) * width + base + col * modulePx + dx) * 4;
      const wasBlack = rgba[index] === 0;
      const value = wasBlack ? 255 : 0;
      rgba[index] = value;
      rgba[index + 1] = value;
      rgba[index + 2] = value;
    }
  }
};

// ---------- 用例 ----------

test('自编码 flag{qr_ok}：解码还原文本且 version/ecLevel/mask/bytes 全对', () => {
  const matrix = buildQrV1LMatrix('flag{qr_ok}');
  const { rgba, width, height } = rasterizeQr(matrix, { modulePx: 4 });
  const results = decodeQrCodes(rgba, width, height);
  assert.equal(results.length, 1, '单码图应恰好一个结果');
  const hit = results[0];
  assert.equal(hit.text, 'flag{qr_ok}');
  assert.equal(hit.version, 1);
  assert.equal(hit.ecLevel, 'L');
  assert.equal(hit.mask, 0);
  assert.equal(hit.bytes, 'flag{qr_ok}'.length);
  // 四角坐标有限且落在画布内（供 UI 画框）。
  assert.ok(Number.isFinite(hit.corners.topLeft.x));
  assert.ok(hit.corners.bottomRight.x > hit.corners.topLeft.x);
});

test('反色二维码（黑底白码）：仍解出同一文本', () => {
  const matrix = buildQrV1LMatrix('flag{inverted_qr}');
  const { rgba, width, height } = rasterizeQr(matrix, { modulePx: 4, invert: true });
  const results = decodeQrCodes(rgba, width, height);
  assert.equal(results.length, 1);
  assert.equal(results[0].text, 'flag{inverted_qr}');
});

test('平移 + 3px/模块缩放 + 白边画布：仍解出同一文本', () => {
  const matrix = buildQrV1LMatrix('flag{shift_scale}');
  const { rgba, width, height } = rasterizeQr(matrix, { modulePx: 3, quiet: 4, offsetX: 17, offsetY: 9, width: 120, height: 100 });
  assert.equal(width, 120);
  assert.equal(height, 100);
  const results = decodeQrCodes(rgba, width, height);
  assert.equal(results.length, 1);
  assert.equal(results[0].text, 'flag{shift_scale}');
});

test('非 QR 图（纯噪声 / 全白 / 全黑）返回空数组', () => {
  const prng = makePrng(0x5eed00aa);
  const noise = new Uint8Array(96 * 96 * 4);
  for (let index = 0; index < noise.length; index += 4) {
    const value = Math.floor(prng() * 256);
    noise[index] = value;
    noise[index + 1] = Math.floor(prng() * 256);
    noise[index + 2] = Math.floor(prng() * 256);
    noise[index + 3] = 255;
  }
  assert.equal(decodeQrCodes(noise, 96, 96).length, 0, '噪声图无命中');

  const white = new Uint8Array(64 * 64 * 4).fill(255);
  assert.equal(decodeQrCodes(white, 64, 64).length, 0, '全白图无命中');

  const black = new Uint8Array(64 * 64 * 4);
  for (let index = 3; index < black.length; index += 4) black[index] = 255;
  assert.equal(decodeQrCodes(black, 64, 64).length, 0, '全黑图无命中');

  assert.equal(decodeQrCodes(new Uint8Array(8), 2, 1).length, 0, '尺寸不符返回空');
  assert.equal(decodeQrCodes(white, 0, 64).length, 0, '零宽返回空');
});

test('一图多码：两个同尺寸 Version 1 并排，两个文本都命中', () => {
  const matrixA = buildQrV1LMatrix('flag{alpha_code}');
  const matrixB = buildQrV1LMatrix('flag{beta_code}');
  const modulePx = 4;
  const quiet = 4;
  const gapModules = 6;
  const codeSpan = (QR_SIZE + quiet * 2) * modulePx;
  const width = codeSpan * 2 + gapModules * modulePx;
  const height = codeSpan;
  const rgba = new Uint8Array(width * height * 4).fill(255);
  for (let index = 3; index < rgba.length; index += 4) rgba[index] = 255;
  const stamp = (matrix, offsetX) => {
    const rendered = rasterizeQr(matrix, { modulePx, quiet, offsetX, offsetY: 0, width, height });
    for (let index = 0; index < rgba.length; index += 4) {
      if (rendered.rgba[index] === 0) {
        rgba[index] = 0;
        rgba[index + 1] = 0;
        rgba[index + 2] = 0;
      }
    }
  };
  stamp(matrixA, 0);
  stamp(matrixB, codeSpan + gapModules * modulePx);
  const results = decodeQrCodes(rgba, width, height);
  assert.equal(results.length, 2, '应解出两个码');
  const texts = results.map(hit => hit.text).sort();
  assert.equal(texts[0], 'flag{alpha_code}');
  assert.equal(texts[1], 'flag{beta_code}');
});

test('大画布干扰：600×450 渐变底 + 散布深色块，居中小码（2px/模块）仍命中', () => {
  const matrix = buildQrV1LMatrix('flag{pad_noise}');
  const modulePx = 2;
  const quiet = 4;
  const codeSpan = (QR_SIZE + quiet * 2) * modulePx;
  const width = 600;
  const height = 450;
  const qrX = Math.floor((width - codeSpan) / 2);
  const qrY = Math.floor((height - codeSpan) / 2);
  const rgba = new Uint8Array(width * height * 4);
  for (let y = 0; y < height; y += 1) {
    for (let x = 0; x < width; x += 1) {
      const value = 0xe8 - Math.floor((x / width) * 0x20); // 浅色横向渐变底
      const index = (y * width + x) * 4;
      rgba[index] = value;
      rgba[index + 1] = value;
      rgba[index + 2] = value;
      rgba[index + 3] = 255;
    }
  }
  const prng = makePrng(0x5eed00ff);
  let placed = 0;
  while (placed < 12) {
    const sx = Math.floor(prng() * (width - 6));
    const sy = Math.floor(prng() * (height - 6));
    const awayFromQr = sx + 6 < qrX - 20 || sx > qrX + codeSpan + 20 || sy + 6 < qrY - 20 || sy > qrY + codeSpan + 20;
    if (!awayFromQr) continue;
    for (let dy = 0; dy < 6; dy += 1) {
      for (let dx = 0; dx < 6; dx += 1) {
        const index = ((sy + dy) * width + sx + dx) * 4;
        const value = 30 + Math.floor(prng() * 30);
        rgba[index] = value;
        rgba[index + 1] = value;
        rgba[index + 2] = value;
      }
    }
    placed += 1;
  }
  const rendered = rasterizeQr(matrix, { modulePx, quiet, offsetX: qrX, offsetY: qrY, width, height });
  for (let index = 0; index < rgba.length; index += 4) {
    if (rendered.rgba[index] === 0) {
      rgba[index] = 0;
      rgba[index + 1] = 0;
      rgba[index + 2] = 0;
    }
  }
  const results = decodeQrCodes(rgba, width, height);
  assert.equal(results.length, 1);
  assert.equal(results[0].text, 'flag{pad_noise}');
});

test('RS 纠错对拍：翻转 2 个数据模块（1-L 可纠 3 个码字错误）后仍还原', () => {
  const matrix = buildQrV1LMatrix('flag{rs_fixed}');
  const modulePx = 4;
  const quiet = 4;
  const { rgba, width, height } = rasterizeQr(matrix, { modulePx, quiet });
  // (9,9) 与 (12,12) 均为 Version 1 数据区模块（远离功能图案）。
  flipModule(rgba, width, modulePx, quiet, 9, 9);
  flipModule(rgba, width, modulePx, quiet, 12, 12);
  const results = decodeQrCodes(rgba, width, height);
  assert.equal(results.length, 1);
  assert.equal(results[0].text, 'flag{rs_fixed}');
});

test('随机化压力：20 组随机 文本/模块像素/静区/画布余量/反色 组合全部还原', () => {
  const prng = makePrng(0xc0ffee);
  const alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789_{}FLAGMIX.';
  for (let round = 0; round < 20; round += 1) {
    const bodyLength = Math.floor(prng() * 11); // 'flag{' + body + '}' ≤ 17
    let text = 'flag{';
    for (let i = 0; i < bodyLength; i += 1) text += alphabet[Math.floor(prng() * alphabet.length)];
    text += '}';
    assert.ok(text.length <= 17);
    const modulePx = 2 + Math.floor(prng() * 4); // 2..5
    const quiet = 3 + Math.floor(prng() * 3); // 3..5
    const invert = prng() < 0.4;
    const extraW = Math.floor(prng() * 40);
    const extraH = Math.floor(prng() * 40);
    const matrix = buildQrV1LMatrix(text);
    const { rgba, width, height } = rasterizeQr(matrix, {
      modulePx,
      quiet,
      invert,
      width: (QR_SIZE + quiet * 2) * modulePx + extraW,
      height: (QR_SIZE + quiet * 2) * modulePx + extraH,
    });
    const results = decodeQrCodes(rgba, width, height);
    assert.equal(results.length, 1, `round ${round} 命中数`);
    assert.equal(results[0].text, text, `round ${round} 还原文本`);
    assert.equal(results[0].version, 1);
    assert.equal(results[0].ecLevel, 'L');
    assert.equal(results[0].mask, 0);
  }
});
