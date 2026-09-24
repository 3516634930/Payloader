// zsteg 式位平面全组合自动扫描引擎（misc 域图片隐写命中）：在 通道组 × bit × 字节内位序 ×
// 像素序 的全部 288 个组合上提取字节流并评分（zlib/gzip 魔数、flag 正则、可打印率、base64），
// 只返回带命中理由的组合，按 score 降序截 maxHits。提取语义以 imagePlanes.extractLsbBytes
// 为基准（行序 + MSB-first + 单通道），命中该基准的组合直接复用原函数避免行为漂移；
// 其余变体是本文件受控扩展：lsbFirst=字节内低位在前（第 1 个采样位落 b0），
// column=先固定 x 遍历 y。纯函数、只读输入、无 Canvas/DOM 依赖，可在 node 测试。
import { bytesToPreviewText, extractLsbBytes } from './imagePlanes';
import type { RgbaChannel } from './imagePlanes';

export interface BitPlaneHit {
  channel: string;
  // 1..8，1=LSB（zsteg b1 命名习惯；内部换算为 imagePlanes 的 0 起始 bit 下标）。
  bit: number;
  lsbFirst: boolean;
  pixelOrder: 'row' | 'column';
  score: number;
  reasons: string[];
  preview: string;
  byteCount: number;
}

export interface BitPlaneScanOptions {
  // 单组合提取字节上限（评分窗口），默认 256（zsteg -a 惯例）。
  maxBytes?: number;
  // 返回命中数上限，默认 20。
  maxHits?: number;
}

// 通道组按 zsteg 命名习惯：rgb/rgba/bgr/bgra 是"每像素内按该序连续取字节"的打包序；
// all 与 rgba 字节序相同（r,g,b,a），仅命名并存，命中时会并列出现。
const CHANNEL_GROUPS: Array<{ name: string; channels: RgbaChannel[] }> = [
  { name: 'r', channels: [0] },
  { name: 'g', channels: [1] },
  { name: 'b', channels: [2] },
  { name: 'a', channels: [3] },
  { name: 'rgb', channels: [0, 1, 2] },
  { name: 'bgr', channels: [2, 1, 0] },
  { name: 'rgba', channels: [0, 1, 2, 3] },
  { name: 'bgra', channels: [2, 1, 0, 3] },
  { name: 'all', channels: [0, 1, 2, 3] },
];

// 排序兜底的通道名次序（同分时按 r→g→b→a→rgb→bgr→rgba→bgra→all 稳定输出）。
const CHANNEL_RANK: Record<string, number> = {
  r: 0, g: 1, b: 2, a: 3, rgb: 4, bgr: 5, rgba: 6, bgra: 7, all: 8,
};

// flag 正则按工具箱常用赛题前缀维护（i 大小写不敏感）。通用分支的花括号内容限定可打印
// 字符：真实 flag 必为可打印串，而 288 组合的全噪声扫描下不限定的 [^}]{3,} 会贪婪吞掉
// 控制字符造成成片误报（实测纯随机图即触发），故收紧到 [ -~]。
const FLAG_PATTERN = /(flag|ctf|key|ctfshow|NSSCTF|DASCTF|BaseCTF|wanictf)\{|[A-Za-z0-9_]{2,}\{[ -~]{3,}\}/i;

// 单组合提取：bitIndex 为 0 起始（0=LSB）。列序像素定位 = (ordinal % height) 行 ×
// floor(ordinal / height) 列，即先固定 x 自上而下再右移，与行序（顺序内存序）互为转置。
const extractComboBytes = (
  rgba: ArrayLike<number>,
  width: number,
  height: number,
  channels: RgbaChannel[],
  bitIndex: number,
  lsbFirst: boolean,
  pixelOrder: 'row' | 'column',
  maxBytes: number,
): Uint8Array => {
  const pixels = Math.min(Math.floor(rgba.length / 4), width * height);
  // 与 extractLsbBytes 完全同语义的组合（单通道 + 行序 + MSB-first）直接复用原函数。
  if (channels.length === 1 && !lsbFirst && pixelOrder === 'row') {
    return extractLsbBytes(rgba, { channel: channels[0], bit: bitIndex, maxBytes });
  }
  const samples = Math.min(pixels * channels.length, maxBytes * 8);
  const out = new Uint8Array(Math.ceil(samples / 8));
  const mask = 1 << bitIndex;
  let byte = 0;
  let filled = 0;
  for (let sample = 0; sample < samples; sample += 1) {
    const ordinal = Math.floor(sample / channels.length);
    const channel = channels[sample % channels.length];
    const pixel = pixelOrder === 'row'
      ? ordinal
      : (ordinal % height) * width + Math.floor(ordinal / height);
    const bit = rgba[pixel * 4 + channel] & mask ? 1 : 0;
    byte = lsbFirst ? byte | (bit << filled) : (byte << 1) | bit;
    filled += 1;
    if (filled === 8) {
      out[sample >> 3] = byte;
      byte = 0;
      filled = 0;
    }
  }
  if (filled > 0) out[samples >> 3] = lsbFirst ? byte : byte << (8 - filled);
  return out;
};

const isPrintableByte = (code: number): boolean =>
  (code >= 0x20 && code <= 0x7e) || code === 0x09 || code === 0x0a || code === 0x0d;

const isBase64Byte = (code: number): boolean =>
  (code >= 0x41 && code <= 0x5a)
  || (code >= 0x61 && code <= 0x7a)
  || (code >= 0x30 && code <= 0x39)
  || code === 0x2b || code === 0x2f || code === 0x3d;

// 评分：强 100 / 中 60 / 弱 30，理由可叠加；纯噪声返回空 reasons（调用方据此丢弃）。
// 可打印口径与 bytesToPreviewText 一致（0x20-0x7e + \t\n\r），避免预览与评分打架。
const evaluateBytes = (bytes: Uint8Array): { score: number; reasons: string[] } => {
  const reasons: string[] = [];
  let score = 0;
  if (bytes.length >= 2) {
    const head = bytes[0] * 0x100 + bytes[1];
    if (head === 0x7801 || head === 0x789c || head === 0x78da || head === 0x1f8b) {
      reasons.push('zlib/gzip 魔数');
      score += 100;
    }
  }
  let text = '';
  for (let index = 0; index < bytes.length; index += 1) text += String.fromCharCode(bytes[index]);
  if (FLAG_PATTERN.test(text)) {
    reasons.push('flag 格式');
    score += 100;
  }
  if (bytes.length >= 16) {
    let printable = 0;
    let base64 = true;
    for (let index = 0; index < bytes.length; index += 1) {
      if (isPrintableByte(bytes[index])) printable += 1;
      if (!isBase64Byte(bytes[index])) base64 = false;
    }
    if (printable / bytes.length >= 0.9) {
      reasons.push('高可打印率');
      score += 60;
    }
    if (base64) {
      reasons.push('疑似 base64');
      score += 30;
    }
  }
  return { score, reasons };
};

// 全组合扫描主入口：9 通道组 × 8 位 × 2 字节内位序 × 2 像素序 = 288 次提取。
export const scanBitPlanes = (
  rgba: ArrayLike<number>,
  width: number,
  height: number,
  options?: BitPlaneScanOptions,
): BitPlaneHit[] => {
  const maxBytes = options?.maxBytes ?? 256;
  const maxHits = options?.maxHits ?? 20;
  if (rgba.length < 4 || width <= 0 || height <= 0) return [];
  const hits: BitPlaneHit[] = [];
  for (const group of CHANNEL_GROUPS) {
    for (let bit = 1; bit <= 8; bit += 1) {
      for (const lsbFirst of [false, true]) {
        for (const pixelOrder of ['row', 'column'] as const) {
          const bytes = extractComboBytes(
            rgba, width, height, group.channels, bit - 1, lsbFirst, pixelOrder, maxBytes,
          );
          const verdict = evaluateBytes(bytes);
          if (verdict.reasons.length === 0) continue;
          hits.push({
            channel: group.name,
            bit,
            lsbFirst,
            pixelOrder,
            score: verdict.score,
            reasons: verdict.reasons,
            preview: bytesToPreviewText(bytes),
            byteCount: bytes.length,
          });
        }
      }
    }
  }
  hits.sort((left, right) =>
    right.score - left.score
    || CHANNEL_RANK[left.channel] - CHANNEL_RANK[right.channel]
    || left.bit - right.bit
    || Number(left.lsbFirst) - Number(right.lsbFirst)
    || Number(left.pixelOrder === 'column') - Number(right.pixelOrder === 'column'));
  return hits.slice(0, maxHits);
};
