// 盲水印 FFT 版（批次 SI·C 线）：chishaxie/BlindWaterMark（bwmforpy3.py，CTF 事实标准）算法复刻，
// 语义与原版逐段对齐（源码已全文核对）：
// encode：水印置半高画布 (⌊h/2⌋, w) → random.seed(seed) 后 shuffle m=range(⌊h/2⌋)、n=range(w)
//         → 半高画布内置乱（取值方向）→ 全高 rwm 上半=置乱值、镜像位同值（对称对双写）
//         → fft2(载体) + alpha·rwm → ifft2 实部落图。
// decode：同 seed 半高/宽洗牌重放 → (fft2(水印图)−fft2(原图))/alpha 取实部
//         → 上半放值方向逆置换（uint8 负数按 numpy 语义 wrap 256）→ 下半=上半镜像复制（双重显影）。
// 命门两件已独立锚定：pyRandom 与本机 CPython 逐位一致（seed 0/1/5）；fft 与 numpy 对拍 1e-12
// 量级（含素数尺寸 Bluestein）。默认 seed=20160930 / alpha=3.0。逐通道 R/G/B 独立处理。
import { PythonRandom } from './pyRandom';
import { fft2d, ifft2d } from './fft';
import type { RgbaImage } from './imageOps';

export interface BlindWatermarkOptions {
  seed?: number;
  alpha?: number;
}

export const BW_DEFAULT_SEED = 20160930;
export const BW_DEFAULT_ALPHA = 3.0;

// 原版洗牌域：m=range(⌊h/2⌋)（半高）、n=range(w)，先 m 后 n（random 状态连续消耗）
const replayShuffles = (height: number, width: number, seed: number): { rows: number[]; cols: number[] } => {
  const random = new PythonRandom();
  random.seed(seed);
  const rows = Array.from({ length: Math.floor(height / 2) }, (_, index) => index);
  const cols = Array.from({ length: width }, (_, index) => index);
  random.shuffleInPlace(rows);
  random.shuffleInPlace(cols);
  return { rows, cols };
};

const extractChannel = (image: RgbaImage, channel: number): Float64Array => {
  const { data, width, height } = image;
  const out = new Float64Array(width * height);
  for (let index = 0; index < width * height; index += 1) out[index] = data[index * 4 + channel];
  return out;
};

// numpy uint8 负数语义：wrap 256（np.uint8(-50)=206），非 clip
const toUint8Wrap = (value: number): number => ((Math.trunc(value) % 256) + 256) % 256;

const luminanceAt = (image: RgbaImage, x: number, y: number): number => {
  const base = (y * image.width + x) * 4;
  return 0.299 * image.data[base] + 0.587 * image.data[base + 1] + 0.114 * image.data[base + 2];
};

export const blindWatermarkEncode = (
  image: RgbaImage,
  watermark: RgbaImage,
  options: BlindWatermarkOptions = {},
): RgbaImage => {
  const { width, height } = image;
  assertPixelBudget(width, height, '嵌入');
  const halfHeight = Math.floor(height / 2);
  // 原版断言语义：水印不超过半高画布（<= 允许，超界才报）
  if (watermark.height > halfHeight || watermark.width > width) {
    throw new Error(
      `水印尺寸 ${watermark.width}×${watermark.height} 超过半高画布上限 ${width}×${halfHeight}`,
    );
  }
  const seed = options.seed ?? BW_DEFAULT_SEED;
  const alpha = options.alpha ?? BW_DEFAULT_ALPHA;
  const { rows, cols } = replayShuffles(height, width, seed);
  // 半高画布置乱：hwm[i][j] = hwm2[m[i]][n[j]]（hwm2 = 左上放水印的亮度图）
  const scrambled = new Float64Array(halfHeight * width);
  for (let y = 0; y < halfHeight; y += 1) {
    for (let x = 0; x < width; x += 1) {
      const sourceY = rows[y];
      const sourceX = cols[x];
      scrambled[y * width + x] =
        sourceY < watermark.height && sourceX < watermark.width
          ? luminanceAt(watermark, sourceX, sourceY)
          : 0;
    }
  }
  // 全高 rwm：上半与镜像位双写同一置乱值（对称对双双赋值，与原版循环一致）
  const rwm = new Float64Array(width * height);
  for (let y = 0; y < halfHeight; y += 1) {
    for (let x = 0; x < width; x += 1) {
      const value = scrambled[y * width + x];
      rwm[y * width + x] = value;
      rwm[(height - 1 - y) * width + (width - 1 - x)] = value;
    }
  }
  const pixels = new Uint8ClampedArray(width * height * 4);
  for (let index = 0; index < width * height; index += 1) pixels[index * 4 + 3] = 255;
  for (let channel = 0; channel < 3; channel += 1) {
    const re = extractChannel(image, channel);
    const im = new Float64Array(width * height);
    const transformed = fft2d(re, im, width, height);
    for (let index = 0; index < width * height; index += 1) {
      transformed.re[index] += alpha * rwm[index];
    }
    const restored = ifft2d(transformed.re, transformed.im, width, height);
    for (let index = 0; index < width * height; index += 1) {
      pixels[index * 4 + channel] = Math.max(0, Math.min(255, Math.round(restored.re[index])));
    }
  }
  return { data: pixels, width, height };
};

export const BW_MAX_PIXELS = 1_000_000; // FFT 主线程同步运算的像素红线（reviewer P1：4M 像素实测 76-158s 冻结）

const assertPixelBudget = (width: number, height: number, action: string): void => {
  if (width * height > BW_MAX_PIXELS) {
    throw new Error(
      `图像 ${width}×${height}（${width * height} 像素）超过盲水印 ${BW_MAX_PIXELS} 像素上限：FFT 同步运算约需 ${Math.round((width * height / 1_000_000) * 20)} 秒以上会冻结页面，请先缩小图片再${action}`,
    );
  }
};

export const blindWatermarkDecode = (
  original: RgbaImage,
  watermarked: RgbaImage,
  options: BlindWatermarkOptions = {},
): RgbaImage => {
  if (original.width !== watermarked.width || original.height !== watermarked.height) {
    throw new Error(
      `两图尺寸必须一致（原图 ${original.width}×${original.height}，水印图 ${watermarked.width}×${watermarked.height}）`,
    );
  }
  const { width, height } = original;
  assertPixelBudget(width, height, '提取');
  const halfHeight = Math.floor(height / 2);
  const seed = options.seed ?? BW_DEFAULT_SEED;
  const alpha = options.alpha ?? BW_DEFAULT_ALPHA;
  const { rows, cols } = replayShuffles(height, width, seed);
  // 三通道差实部的均值（decode 只取实部还原，虚部无需累积——reviewer P2 死计算已删）
  const diffRe = new Float64Array(width * height);
  for (let channel = 0; channel < 3; channel += 1) {
    const re1 = extractChannel(original, channel);
    const im1 = new Float64Array(width * height);
    const f1 = fft2d(re1, im1, width, height);
    const re2 = extractChannel(watermarked, channel);
    const im2 = new Float64Array(width * height);
    const f2 = fft2d(re2, im2, width, height);
    for (let index = 0; index < width * height; index += 1) {
      diffRe[index] += (f2.re[index] - f1.re[index]) / 3;
    }
  }
  for (let index = 0; index < width * height; index += 1) diffRe[index] /= alpha;
  // 放值方向逆置换（仅上半域 i<半高），uint8 wrap；下半=上半镜像复制（双重显影，与原版一致）
  const pixels = new Uint8ClampedArray(width * height * 4);
  for (let index = 0; index < width * height; index += 1) pixels[index * 4 + 3] = 255;
  const canvas = new Float64Array(width * height);
  for (let y = 0; y < halfHeight; y += 1) {
    for (let x = 0; x < width; x += 1) {
      canvas[rows[y] * width + cols[x]] = toUint8Wrap(diffRe[y * width + x]);
    }
  }
  for (let y = 0; y < halfHeight; y += 1) {
    for (let x = 0; x < width; x += 1) {
      canvas[(height - 1 - y) * width + (width - 1 - x)] = canvas[y * width + x];
    }
  }
  for (let index = 0; index < width * height; index += 1) {
    const value = canvas[index];
    pixels[index * 4] = value;
    pixels[index * 4 + 1] = value;
    pixels[index * 4 + 2] = value;
  }
  return { data: pixels, width, height };
};
