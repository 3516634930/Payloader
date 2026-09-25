// outguess 0.2 JPEG 提取器（批次 SI-3，32 项对标收官件）：按规格重写 resurrecting-open-source-projects/outguess
// 的提取路径（BSD-2），依赖前置件 outguessCrypto.ts（ARC4 变体 + 伪随机游走迭代器）。
// 位流语义（jpeg-6b-steg/jdcoefct.c decompress_onepass 钩子 → jpg.c steg_use_bit）：
// - 逐 MCU、块内 k=0..63 自然序（含 DC）喂每个系数；系数（JCOEF short→unsigned short）满足
//   (temp & 1) == temp 即跳过——等价跳过 0 与 +1，-1（0xFFFF）与 |c|≥2 全部收 LSB；
// - 渐进 JPEG（SOF2）走 decompress_data 无钩子，vendor 解码器本就拒绝渐进，与原版能力一致。
// 提取语义（outguess-main.c steg_retrieve，默认无 -e 即无 Golay ECC）：
// - as = arc4_initkey("Encryption", key)，tas = as 结构体拷贝（同初态第二条流）；
// - 头 4 字节按位 LSB-first 读出（每位 iterator_next 推进）→ XOR as → seed(u16 LE) + origlen(u16)；
// - iterator_seed(iter, seed)；循环 origlen 次：iterator_adapt(iter, bits, 剩余字节) → 读 1 字节；
//   数据体 XOR tas 解密。ECC 模式（-e，Golay (24,12)）CTF 极罕见，本提取器不支持并在输入处注明。
import { readJpegCoefficients } from './jpegCoeffs';
import { Arc4Stream, arc4InitKey, iteratorAdapt, iteratorInit, iteratorNext, iteratorSeed } from './outguessCrypto';
import type { OutguessIteratorState } from './outguessCrypto';

export interface OutguessBitStream {
  bits: Uint8Array; // 1 = 该可嵌位为 1（系数 LSB）
  totalBits: number;
}

// (temp & 1) === temp ⇔ 系数低 16 位 ∈ {0,1}：逐字复刻 C 的 unsigned short 语义
const isSkippable = (coeff: number): boolean => {
  const temp = coeff & 0xffff;
  return (temp & 1) === temp;
};

export const collectOutguessBits = (mcuOrderCoefficients: Int32Array | number[]): OutguessBitStream => {
  const bits = new Uint8Array(mcuOrderCoefficients.length);
  let count = 0;
  for (let index = 0; index < mcuOrderCoefficients.length; index += 1) {
    const coeff = mcuOrderCoefficients[index];
    if (isSkippable(coeff)) continue;
    bits[count] = coeff & 1;
    count += 1;
  }
  return { bits, totalBits: count };
};

interface BitCursor {
  stream: OutguessBitStream;
  iter: OutguessIteratorState;
}

// steg_retrbyte：LSB-first（第 where 位 = 输出的第 where 比特），每位读后 iterator_next
const retrByte = (cursor: BitCursor): number => {
  const { bits, totalBits } = cursor.stream;
  let tmp = 0;
  for (let where = 0; where < 8; where += 1) {
    const off = cursor.iter.off;
    if (off >= totalBits) {
      throw new Error('outguess：位流耗尽（声明长度超出可嵌容量，多半是口令不对或图片无嵌入）');
    }
    tmp |= (bits[off] === 1 ? 1 : 0) << where;
    iteratorNext(cursor.iter);
  }
  return tmp >>> 0;
};

const toUnsigned16 = (value: number): number => value & 0xff;

export const outguessRevealFromCoefficients = (
  mcuOrderCoefficients: Int32Array | number[],
  password: string,
): { data: Uint8Array; seed: number; declaredLength: number } => {
  const stream = collectOutguessBits(mcuOrderCoefficients);
  if (stream.totalBits < 64) {
    throw new Error(`outguess：可嵌位仅 ${stream.totalBits} 位（需至少 64 位读头部），该图无法承载 outguess 嵌入`);
  }
  const key = new TextEncoder().encode(password);
  const as: Arc4Stream = arc4InitKey('Encryption', key);
  const tas = as.clone();
  const iter = iteratorInit(key);
  const cursor: BitCursor = { stream, iter };

  const header = new Uint8Array(4);
  for (let index = 0; index < 4; index += 1) header[index] = retrByte(cursor) ^ as.getbyte();
  const seed = header[0] | (header[1] << 8);
  const declaredLength = header[2] | (header[3] << 8);

  if (declaredLength === 0) {
    throw new Error('outguess：声明载荷长度为 0——口令错误或该图无嵌入');
  }
  if (declaredLength > Math.floor(stream.totalBits / 8)) {
    throw new Error(
      `outguess：声明长度 ${declaredLength} 字节超过可嵌容量 ${Math.floor(stream.totalBits / 8)} 字节——多半是口令错误`,
    );
  }

  iteratorSeed(iter, seed);
  const data = new Uint8Array(declaredLength);
  let remaining = declaredLength;
  let n = 0;
  while (remaining > 0) {
    iteratorAdapt(iter, stream.totalBits, remaining);
    data[n] = toUnsigned16(retrByte(cursor) ^ tas.getbyte());
    n += 1;
    remaining -= 1;
  }
  return { data, seed, declaredLength };
};

export const outguessReveal = (jpegBytes: Uint8Array, password: string): Uint8Array =>
  outguessRevealFromCoefficients(readJpegCoefficients(jpegBytes).mcuOrderCoefficients, password).data;
