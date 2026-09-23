// codec ngram 评分叶子层（T6 解环下沉）：古典密码 quadgram 适应度评分与注水接口，
// 零依赖（自带 base64 解码，不依赖 realm atob）。609KB 评分表经 heavyData 动态 import 注入。

// ---- 古典密码无密钥自动破译（模拟退火 + 英文 trigram 适应度）----
// 纯统计搜索：只做密钥排列扰动与打分，不执行输入内容。总耗时受硬预算约束，
// 每个重启块之间让出主线程，保证智能解码界面不冻结。trigram 表可用
// scripts/build-trigram-table.cjs 从 Gutenberg 公版语料重建。


let classicalNgramLut: Float32Array | null = null;

// 评分表数据已拆至 ngramTableData.ts（动态 import 注水，见 codec/index.ts hydrateCodecHeavyData）。
let ngramTableB64: string | null = null;
export const injectClassicalNgramTable = (b64: string): void => {
  if (ngramTableB64 === b64) return;
  ngramTableB64 = b64;
  classicalNgramLut = null;
};
// 自带 base64 解码：不依赖 realm 全局 atob（vm/worker 环境可能没有）
export const classicalDecodeBase64 = (input: string): Uint8Array => {
  const table = new Uint8Array(123);
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  for (let index = 0; index < chars.length; index += 1) table[chars.charCodeAt(index)] = index;
  const clean = input.replace(/[^A-Za-z0-9+/]/g, '');
  const output = new Uint8Array(Math.floor(clean.length * 3 / 4));
  let outIndex = 0;
  let buffer = 0;
  let bits = 0;
  for (let index = 0; index < clean.length; index += 1) {
    buffer = (buffer << 6) | table[clean.charCodeAt(index)];
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      output[outIndex] = (buffer >> bits) & 0xff;
      outIndex += 1;
    }
  }
  return output.subarray(0, outIndex);
};
export const getClassicalNgramLut = (): Float32Array | null => {
  if (!ngramTableB64) return null;
  if (!classicalNgramLut) {
    const bytes = classicalDecodeBase64(ngramTableB64);
    const lut = new Float32Array(bytes.length);
    for (let index = 0; index < bytes.length; index += 1) lut[index] = bytes[index] / 25.5 - 10;
    classicalNgramLut = lut;
  }
  return classicalNgramLut;
};

// 适应度：字母流 quadgram log10 概率均值 ×100。语料实测英文约 -430~-450，随机串约 -870。
export const classicalNgramMean = (codes: Uint8Array): number => {
  const lut = getClassicalNgramLut();
  if (!lut) return -9999;
  let sum = 0;
  let count = 0;
  let p1 = -1;
  let p2 = -1;
  let p3 = -1;
  for (let index = 0; index < codes.length; index += 1) {
    const code = codes[index];
    if (code > 25) { p1 = -1; p2 = -1; p3 = -1; continue; }
    if (p1 >= 0 && p2 >= 0 && p3 >= 0) {
      sum += lut[((p1 * 26 + p2) * 26 + p3) * 26 + code];
      count += 1;
    }
    p1 = p2;
    p2 = p3;
    p3 = code;
  }
  return count > 0 ? (sum / count) * 100 : -9999;
};

// 采纳版：跳过位（空格/数字/点）按最差分 -9 计入均值——防稀疏碎片解码均值虚高。
// 纯英文字母 ≈ -430，带 20% 空格 ≈ -524，50% 数字碎片 ≈ -660。
export const classicalNgramMeanPenalized = (codes: Uint8Array): number => {
  const lut = getClassicalNgramLut();
  if (!lut) return -9999;
  let sum = 0;
  let count = 0;
  let p1 = -1;
  let p2 = -1;
  let p3 = -1;
  for (let index = 0; index < codes.length; index += 1) {
    const code = codes[index];
    if (code > 25) {
      sum += -9;
      count += 1;
      p1 = -1; p2 = -1; p3 = -1;
      continue;
    }
    if (p1 >= 0 && p2 >= 0 && p3 >= 0) {
      sum += lut[((p1 * 26 + p2) * 26 + p3) * 26 + code];
      count += 1;
    }
    p1 = p2;
    p2 = p3;
    p3 = code;
  }
  return count > 0 ? (sum / count) * 100 : -9999;
};

