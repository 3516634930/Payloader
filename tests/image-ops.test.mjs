// 图片运算与转换工具测试（批次 SI·D 线）：全部向量程序化构造（rgba 数组直建），
// 不依赖图片编解码。QR 补定位角的"可解性"闭环由真题向量覆盖（结构断言在此）。
import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const srcDir = path.join(projectRoot, 'src');
const { loadModule } = createTsModuleLoader();
const ops = loadModule(path.join(srcDir, 'utils', 'ctf', 'imageOps.ts'));

const solid = (width, height, [r, g, b]) => ({
  data: (() => { const out = new Uint8ClampedArray(width * height * 4); for (let i = 0; i < width * height; i += 1) { out[i*4] = r; out[i*4+1] = g; out[i*4+2] = b; out[i*4+3] = 255; } return out; })(),
  width,
  height,
});

const pixel = (image, x, y) => {
  const base = (y * image.width + x) * 4;
  return [image.data[base], image.data[base + 1], image.data[base + 2]];
};

// ---- 双图组合 ----

test('combineImages：XOR 把互为掩码的双图还原出隐藏图案（经典双图异或）', () => {
  const size = 4;
  const a = solid(size, size, [0xf0, 0x0f, 0x33]);
  const b = solid(size, size, [0xff, 0x0f, 0x00]);
  const { image, notes } = ops.combineImages(a, b, 'xor');
  // node:vm 沙箱数组跨 realm：Array.from 转主 realm 再断言（AGENTS.md 踩坑记录）
  assert.deepEqual(Array.from(notes), []);
  assert.deepEqual(pixel(image, 0, 0), [0x0f, 0x00, 0x33]);
  // 逐像素换一个图案：把 a 的某像素改掉，XOR 结果随动
  a.data[0] = 0x00;
  const again = ops.combineImages(a, b, 'xor');
  assert.deepEqual(pixel(again.image, 0, 0), [0xff, 0x00, 0x33]);
});

test('combineImages：ADD/SUB 饱和截断；尺寸不一致取交集并给出中文备注', () => {
  const add = ops.combineImages(solid(2, 2, [200, 10, 0]), solid(2, 2, [100, 10, 0]), 'add');
  assert.deepEqual(pixel(add.image, 0, 0), [255, 20, 0]);
  const sub = ops.combineImages(solid(2, 2, [10, 100, 0]), solid(2, 2, [200, 10, 0]), 'sub');
  assert.deepEqual(pixel(sub.image, 0, 0), [0, 90, 0]);
  const mixed = ops.combineImages(solid(4, 2, [1, 2, 3]), solid(2, 4, [4, 5, 6]), 'xor');
  assert.equal(mixed.image.width, 2);
  assert.equal(mixed.image.height, 2);
  assert.match(mixed.notes[0], /按交集 2×2 左上对齐/);
});

// ---- 翻转 / 反色 / 拼接 ----

test('flipImage：水平/垂直镜像像素到位；invertImage 补色且 alpha 不动', () => {
  const image = {
    data: new Uint8ClampedArray([1,0,0,7, 2,0,0,7, 3,0,0,7, 4,0,0,7]),
    width: 2, height: 2,
  };
  const horizontal = ops.flipImage(image, 'horizontal');
  assert.deepEqual(pixel(horizontal, 0, 0), [2, 0, 0]);
  assert.deepEqual(pixel(horizontal, 1, 1), [3, 0, 0]);
  const vertical = ops.flipImage(image, 'vertical');
  assert.deepEqual(pixel(vertical, 0, 0), [3, 0, 0]);
  const inverted = ops.invertImage(image);
  assert.deepEqual(pixel(inverted, 0, 0), [254, 255, 255]);
  assert.equal(inverted.data[3], 7);
});

test('concatImages：横向串接宽度累加、纵向串接高度累加，白底补齐', () => {
  const left = solid(2, 1, [10, 0, 0]);
  const right = solid(1, 2, [0, 20, 0]);
  const horizontal = ops.concatImages([left, right], 'h');
  assert.equal(horizontal.width, 3);
  assert.equal(horizontal.height, 2);
  assert.deepEqual(pixel(horizontal, 0, 0), [10, 0, 0]);
  assert.deepEqual(pixel(horizontal, 2, 0), [0, 20, 0]);
  assert.deepEqual(pixel(horizontal, 2, 1), [0, 20, 0]);
  assert.deepEqual(pixel(horizontal, 1, 1), [255, 255, 255]); // 白底补齐
  const vertical = ops.concatImages([left, right], 'v');
  assert.equal(vertical.width, 2);
  assert.equal(vertical.height, 3);
});

// ---- 01 串转图 ----

test('bitsToImage：完全平方自动方形、行宽推断、1=黑 0=白、指定宽覆盖、非法抛中文错误', () => {
  const square = ops.bitsToImage('1000010001100011');
  assert.equal(square.image.width, 4);
  assert.equal(square.image.height, 4);
  assert.match(square.widthGuess, /完全平方/);
  assert.deepEqual(pixel(square.image, 0, 0), [0, 0, 0]); // '1' 黑
  assert.deepEqual(pixel(square.image, 1, 0), [255, 255, 255]); // '0' 白
  const lined = ops.bitsToImage('10\n01\n11\n00');
  assert.ok(lined.image.width === 2 && lined.image.height === 4, `行宽推断 2×4（实际 ${lined.image.width}×${lined.image.height}）`);
  const forced = ops.bitsToImage('01010101', 4);
  assert.equal(forced.image.width, 4);
  assert.equal(forced.image.height, 2);
  assert.match(forced.widthGuess, /指定宽 4/);
  assert.throws(() => ops.bitsToImage('101'), /指定宽度/);
});

// ---- 坐标串转图 ----

test('coordsToImage：散点白点黑底、负坐标归一、坐标去重、空输入抛错', () => {
  const { image, pointCount } = ops.coordsToImage('(0,0) (3,0)\n0,3\n3,3');
  assert.equal(pointCount, 4);
  assert.equal(image.width, 4);
  assert.equal(image.height, 4);
  assert.deepEqual(pixel(image, 0, 0), [255, 255, 255]);
  assert.deepEqual(pixel(image, 1, 1), [0, 0, 0]);
  const shifted = ops.coordsToImage('-2,-2\n-1,-2');
  assert.equal(shifted.image.width, 2);
  assert.deepEqual(pixel(shifted.image, 0, 0), [255, 255, 255]);
  const dedup = ops.coordsToImage('5,5\n5,5\n5,5');
  assert.equal(dedup.pointCount, 1);
  assert.throws(() => ops.coordsToImage('没有任何坐标'), /未解析出任何/);
});

// ---- RGB 串 ⇄ 图 ----

test('rgbTextToImage：dec 三元组（完全平方方形）与 hex 连串两种形态自动识别', () => {
  const decText = Array.from({ length: 9 }, (_, i) => `${i * 20},${i * 10},${i * 5}`).join('\n');
  const dec = ops.rgbTextToImage(decText);
  assert.equal(dec.format, 'dec');
  assert.equal(dec.image.width, 3);
  assert.deepEqual(pixel(dec.image, 0, 0), [0, 0, 0]);
  assert.deepEqual(pixel(dec.image, 2, 2), [160, 80, 40]);
  const hex = ops.rgbTextToImage('ff0000 00ff00 0000ff ffff00 ff00ff 00ffff 000000 ffffff 808080'.replace(/ /g, ''));
  assert.equal(hex.format, 'hex');
  assert.equal(hex.image.width, 3);
  assert.deepEqual(pixel(hex.image, 0, 0), [255, 0, 0]);
  assert.throws(() => ops.rgbTextToImage('abc'), /无法识别 RGB 数据形态/);
});

test('imageToRgbText ⇄ rgbTextToImage：hex/dec 双向往返无损', () => {
  const source = solid(2, 2, [0x12, 0x34, 0x56]);
  const asHex = ops.imageToRgbText(source, 'hex');
  assert.equal(asHex, '123456\n123456\n123456\n123456');
  const back = ops.rgbTextToImage(asHex, 2);
  assert.deepEqual(pixel(back.image, 1, 1), [0x12, 0x34, 0x56]);
  const asDec = ops.imageToRgbText(source, 'dec');
  assert.equal(asDec, '18,52,86\n18,52,86\n18,52,86\n18,52,86');
  const backDec = ops.rgbTextToImage(asDec, 2);
  assert.deepEqual(pixel(backDec.image, 0, 1), [0x12, 0x34, 0x56]);
});

// ---- 字符画（Novel_In_Image 形态） ----

test('imageToAscii / asciiToImage：黑→@、白→空格精确，灰阶落在坡内且黑白往返无损', () => {
  const image = {
    data: new Uint8ClampedArray([0,0,0,255, 255,255,255,255, 128,128,128,255, 255,255,255,255]),
    width: 2, height: 2,
  };
  const art = ops.imageToAscii(image);
  const lines = art.split('\n');
  assert.ok(lines.length === 2 && lines[0].length === 2 && lines[1].length === 2, '2×2 字符画');
  assert.equal(lines[0][0], '@');
  assert.equal(lines[0][1], ' ');
  assert.equal(lines[1][1], ' ');
  assert.ok(ops.ASCII_RAMP.includes(lines[1][0]), `灰 128 落在字符坡内（实际 "${lines[1][0]}"）`);
  const restored = ops.asciiToImage(art);
  assert.deepEqual(pixel(restored, 0, 0), [0, 0, 0]);
  assert.deepEqual(pixel(restored, 1, 0), [255, 255, 255]);
  // 长文本字符画（flag 藏在文本里的形态）：不等宽行取最大宽
  const wide = ops.asciiToImage('@@@ \n@@  \n@   \n    ');
  assert.equal(wide.width, 4);
});

// ---- flood-fill 掩码 ----

test('floodFillMask：同色连通域高亮计数、容差扩散、越界种子抛错', () => {
  // 4×4：左上 3 像素 L 形红色（200,10,10），右下一个近似红（205,12,12），其余白
  const image = solid(4, 4, [255, 255, 255]);
  const paint = (x, y, [r, g, b]) => { const base = (y * 4 + x) * 4; image.data[base] = r; image.data[base+1] = g; image.data[base+2] = b; };
  paint(0, 0, [200, 10, 10]); paint(1, 0, [200, 10, 10]); paint(0, 1, [200, 10, 10]);
  paint(3, 3, [205, 12, 12]);
  const strict = ops.floodFillMask(image, 0, 0, 0);
  assert.equal(strict.hitCount, 3); // 右下的近似红不连通（对角不相邻）且超容差
  assert.deepEqual(pixel(strict.mask, 0, 0).slice(0, 1), [255]); // 红高亮
  assert.equal(strict.mask.data[(1 * 4 + 1) * 4 + 3], 0); // 未命中区透明
  const tolerant = ops.floodFillMask(image, 3, 3, 8);
  assert.equal(tolerant.hitCount, 1); // 容差内自身命中，但与左上仍不连通
  assert.throws(() => ops.floodFillMask(image, 9, 9), /超出图像范围/);
});

// ---- QR 定位角补全 ----

test('addQrFinderPatterns：自动估算模块宽、三个角出现 7×7 定位结构、过小图抛中文错误', () => {
  // 25×25 模块、moduleSize=2 → 50×50 图；画交替模块行（QR 数据区纹理形态，游程=模块宽 2px）
  const moduleCount = 25;
  const moduleSize = 2;
  const sizePx = moduleCount * moduleSize;
  const image = solid(sizePx, sizePx, [255, 255, 255]);
  for (let m = 8; m < 20; m += 2) {
    for (let k = 0; k < moduleSize; k += 1) {
      for (let row = 0; row < moduleSize; row += 1) {
        paintBlock(image, sizePx, m * moduleSize + k, 12 * moduleSize + row, 0);
      }
    }
  }
  const { image: fixed, moduleSize: guessed, note } = ops.addQrFinderPatterns(image);
  assert.equal(guessed, moduleSize);
  assert.match(note, /7×7 定位角/);
  // 左上角定位结构：外环黑（0,0 起）、白环（1 模块内圈）、3×3 黑心
  const at = (mx, my) => pixel(fixed, mx * moduleSize, my * moduleSize);
  assert.deepEqual(at(1, 1).map(v => v < 128 ? 1 : 0), [1, 1, 1], '定位角外环左上为黑');
  assert.deepEqual(at(2, 2).map(v => v < 128 ? 1 : 0), [0, 0, 0], '白环为白');
  assert.deepEqual(at(4, 4).map(v => v < 128 ? 1 : 0), [1, 1, 1], '黑心为黑');
  // 右上与左下同样存在
  const topRight = pixel(fixed, (moduleCount - 2) * moduleSize, moduleSize);
  assert.ok(topRight.every(v => v < 128), '右上定位角外环为黑');
  const bottomLeft = pixel(fixed, moduleSize, (moduleCount - 2) * moduleSize);
  assert.ok(bottomLeft.every(v => v < 128), '左下定位角外环为黑');
  assert.throws(() => ops.addQrFinderPatterns(solid(10, 10, [0, 0, 0])), /小于最小 QR 版本|无法估算/);
});

function paintBlock(image, width, x, y, value) {
  const base = (y * width + x) * 4;
  image.data[base] = value;
  image.data[base + 1] = value;
  image.data[base + 2] = value;
}
