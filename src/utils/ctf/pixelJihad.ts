// PixelJihad 图片 LSB 隐写（批次 SI·B 线）：oakes/PixelJihad（公有领域 UNLICENSE）算法复刻。
// 核心语义（源码核实）：种子 = SHA-256(口令) 的 8 个带符号 32 位字（空口令 = SHA-256("")）；
// 嵌入位置 loc = |hash[pos%8]·(pos+1)| % (w·h·4)，跳 alpha 通道与已用位置；
// 载荷 = JSON（无口令 {text}）或 sjcl AES-128-CCM 加密 JSON（口令，PBKDF2×1000），
// 按 UTF-16 码元 16 bit LSB-first 写入（先 16 bit 长度再逐字符）。
// 加密链直接 vendor 原版同款 sjcl 构建（src/vendor/sjcl.ts，BSD/GPL）——格式 100% 兼容原工具。
// vendor 文件的 UMD 尾巴 module.exports=sjcl 会覆盖命名导出载体，故以 namespace 形式引用
// （require 的返回值即 sjcl 对象本身，hash/encrypt/decrypt 全部直达；esbuild 的 CJS 互操作同语义）。
import * as sjclStar from '../../vendor/sjcl';
import type { RgbaImage } from './imageOps';

const sjcl = sjclStar as unknown as {
  hash: { sha256: { hash: (password: string) => number[] } };
  encrypt: (password: string, plaintext: string) => string;
  decrypt: (password: string, payload: string) => string;
};

// 种子词：sjcl.hash.sha256.hash 返回带符号 32 位数组（可直接参与 |·(pos+1)| 运算）
const hashWords = (password: string): number[] => sjcl.hash.sha256.hash(password);

// 与原版 getNext_location 同语义：pos=已写 bit 数；按 total 取模 → 越界回 0 → 已用 ++ → alpha ++
const nextLocation = (history: number[], words: number[], total: number): number => {
  const pos = history.length;
  let loc = Math.abs(words[pos % 8] * (pos + 1)) % total;
  for (;;) {
    if (loc >= total) loc = 0;
    else if (history.includes(loc)) loc += 1;
    else if ((loc + 1) % 4 === 0) loc += 1;
    else break;
  }
  history.push(loc);
  return loc;
};

export const pixelJihadEncode = (
  image: RgbaImage,
  message: string,
  password = '',
): RgbaImage => {
  const { width, height } = image;
  const total = width * height * 4;
  const carrier = password !== '' ? sjcl.encrypt(password, message) : JSON.stringify({ text: message });
  const units: number[] = [];
  for (let index = 0; index < carrier.length; index += 1) units.push(carrier.charCodeAt(index) & 0xffff);
  const bitCount = (units.length + 1) * 16;
  if (bitCount > Math.floor(total * 0.75)) {
    throw new Error(
      `消息 ${carrier.length} 字符需 ${bitCount} bit，超过载体容量 ${Math.floor(total * 0.75)} bit（约 3/4 像素字节）`,
    );
  }
  const words = hashWords(password);
  const pixels = new Uint8ClampedArray(image.data as ArrayLike<number>);
  const out: RgbaImage = { data: pixels, width, height };
  const history: number[] = [];
  const writeBit = (bit: number): void => {
    const loc = nextLocation(history, words, total);
    pixels[loc] = (pixels[loc] & 0xfe) | bit;
  };
  for (let bit = 0; bit < 16; bit += 1) writeBit((units.length >> bit) & 1);
  for (const unit of units) {
    for (let bit = 0; bit < 16; bit += 1) writeBit((unit >> bit) & 1);
  }
  return out;
};

export const pixelJihadDecode = (image: RgbaImage, password = ''): string => {
  const { width, height } = image;
  const total = width * height * 4;
  const words = hashWords(password);
  const history: number[] = [];
  const readBit = (): number => {
    const loc = nextLocation(history, words, total);
    return image.data[loc] & 1;
  };
  const readUnit = (): number => {
    let unit = 0;
    for (let bit = 0; bit < 16; bit += 1) unit |= readBit() << bit;
    return unit;
  };
  const unitCount = readUnit();
  if (unitCount === 0) throw new Error('读出的消息长度为 0：该图不含 PixelJihad 载荷或口令错误');
  if ((unitCount + 1) * 16 > Math.floor(total * 0.75)) {
    throw new Error(`读出的消息长度 ${unitCount} 超出载体容量：口令错误或数据损坏`);
  }
  let extracted = '';
  for (let index = 0; index < unitCount; index += 1) extracted += String.fromCharCode(readUnit());
  // sjcl 形态（有 ct 字段）需解密；{text} 明文形态直接取
  let payload: { ct?: string; text?: string };
  try {
    payload = JSON.parse(extracted) as { ct?: string; text?: string };
  } catch {
    throw new Error('提取内容不是合法 JSON：不是 PixelJihad 载荷或口令错误');
  }
  if (payload.ct !== undefined) {
    if (password === '') throw new Error('该图加密嵌入，请提供口令');
    return sjcl.decrypt(password, extracted);
  }
  return payload.text ?? '';
};
