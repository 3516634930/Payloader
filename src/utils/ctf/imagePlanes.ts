// 位平面与色道纯函数引擎（misc 域图片隐写基础件）：输入是解码后的 RGBA 像素数组，
// 输出是平面灰度 / 单通道 / LSB 组字节。全部只读输入、无 Canvas/DOM 依赖，可在 node 测试。
// Canvas 解码（createImageBitmap/getImageData）与导出（toBlob）由消费方组件负责。


// 超过该像素数的图片在 UI 层降采样后再进位平面分析（内存红线：4MP RGBA ≈ 16MB）。
export const MAX_ANALYSIS_PIXELS = 4_000_000;

// RGBA 中通道序：canvas getImageData 的固定内存布局。
export type RgbaChannel = 0 | 1 | 2 | 3;
export const PLANE_CHANNELS: Array<{ channel: RgbaChannel; label: string }> = [
  { channel: 0, label: 'R' },
  { channel: 1, label: 'G' },
  { channel: 2, label: 'B' },
  { channel: 3, label: 'A' },
];

// 提取单个位平面：bit=1 → 255，bit=0 → 0（黑白二值灰度，StegSolve 惯例）。
// 惰性现算——调用方不缓存全部 32 份平面，点开哪个算哪个。
export const extractBitPlane = (rgba: ArrayLike<number>, channel: RgbaChannel, bit: number): Uint8Array => {
  const pixels = Math.floor(rgba.length / 4);
  const plane = new Uint8Array(pixels);
  const mask = 1 << bit;
  for (let index = 0; index < pixels; index += 1) {
    plane[index] = rgba[index * 4 + channel] & mask ? 255 : 0;
  }
  return plane;
};

// 单通道灰度：把选中通道值复制出来（色道分离导出时填回 RGB 三通道）。
export const extractChannelPlane = (rgba: ArrayLike<number>, channel: RgbaChannel): Uint8Array => {
  const pixels = Math.floor(rgba.length / 4);
  const plane = new Uint8Array(pixels);
  for (let index = 0; index < pixels; index += 1) {
    plane[index] = rgba[index * 4 + channel];
  }
  return plane;
};

export interface LsbExtractOptions {
  channel: RgbaChannel;
  bit: number;
  // 单次提取字节上限（红线 64KB ≈ 52 万像素，避免巨图全量提取卡 UI）。
  maxBytes?: number;
}

// LSB 顺序提取：从 (0,0) 按行序逐像素取指定位，MSB-first 组字节（第 1 像素的位落 b7）。
// 这是 CTF 图片题最常见嵌法（StegSolve Data Extract 的默认序）。
export const extractLsbBytes = (rgba: ArrayLike<number>, options: LsbExtractOptions): Uint8Array => {
  const maxBytes = options.maxBytes ?? 64 * 1024;
  const pixels = Math.min(Math.floor(rgba.length / 4), maxBytes * 8);
  const mask = 1 << options.bit;
  const base = options.channel;
  const out = new Uint8Array(Math.ceil(pixels / 8));
  let byte = 0;
  let filled = 0;
  let written = 0;
  for (let index = 0; index < pixels; index += 1) {
    byte = (byte << 1) | (rgba[index * 4 + base] & mask ? 1 : 0);
    filled += 1;
    if (filled === 8) {
      out[written] = byte;
      written += 1;
      byte = 0;
      filled = 0;
    }
  }
  if (filled > 0) out[written] = byte << (8 - filled);
  return out;
};

// 把 LSB 提取结果按 latin1 解成预览文本（不可打印字符转义，避免控制字符污染 DOM）。
export const bytesToPreviewText = (bytes: Uint8Array, maxChars = 2048): string => {
  let text = '';
  const limit = Math.min(bytes.length, maxChars);
  for (let index = 0; index < limit; index += 1) {
    const code = bytes[index];
    if (code === 0x0a || code === 0x0d || code === 0x09) {
      text += String.fromCharCode(code);
    } else if (code >= 0x20 && code <= 0x7e) {
      text += String.fromCharCode(code);
    } else {
      text += `\\x${code.toString(16).padStart(2, '0')}`;
    }
  }
  if (bytes.length > limit) text += `… (+${bytes.length - limit} bytes)`;
  return text;
};

// 灰度像素（如亮度 L = 0.299R+0.587G+0.114B）打包成 RGBA：色道导出统一走 RGBA 数据源。
// alpha 通道导出时灰度值填 RGB、alpha 恒 255（否则导出图全透明没法看）。
export const grayToRgba = (plane: Uint8Array): Uint8ClampedArray<ArrayBuffer> => {
  const rgba = new Uint8ClampedArray(plane.length * 4);
  for (let index = 0; index < plane.length; index += 1) {
    const value = plane[index];
    rgba[index * 4] = value;
    rgba[index * 4 + 1] = value;
    rgba[index * 4 + 2] = value;
    rgba[index * 4 + 3] = 255;
  }
  return rgba;
};

