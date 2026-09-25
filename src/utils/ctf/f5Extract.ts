// F5 隐写提取器（批次 SI·A 线收尾件）：Westfeld F5 Extract.java 语义——按 F5Random
// 派生的置乱序遍历 MCU 交织展平的全部 DCT 系数（块内 natural order，含 DC），跳过
// 每块 DC 与收缩产生的 0 系数；前 32 个可用位 LSB-first 组成长度头并去白噪（小端
// 4 字节），头部高字节 %32 是矩阵编码参数 k、低 23 位是声明载荷长度；k>0 时正文按
// 矩阵解码：每 2^k-1 个可用系数为一块，块内 LSB 为 1 的 code（1..n）异或出 k 位段，
// k 位段 MSB-first 拼字节；k=0 时每个可用系数直嵌 1 bit。每输出字节再与 PRNG 字节
// 异或去白噪。PRNG 消耗序必须与嵌入端逐拍一致，任何一处错位都会整体雪崩：
// Permutation 构造（coeff.length 次 getNextValue，每次 4 字节）→ 头部去白噪 4 字节
// → 每输出字节 1 字节。
import { F5Permutation, F5Random } from './f5Crypto';
import { readJpegCoefficients } from './jpegCoeffs';

export interface F5ExtractResult {
  data: Uint8Array;
  k: number;
  declaredLength: number;
  usableCoefficients: number;
}

// 口令 → 字节用 Latin-1：对齐 Java 口令的 8 位缺省编码与本仓 jphs 线约定；
// F5 载荷口令事实标准是 ASCII，此时与 UTF-8 等价
const passwordBytes = (password: string): Uint8Array => {
  const bytes = new Uint8Array(password.length);
  for (let index = 0; index < password.length; index += 1) {
    bytes[index] = password.charCodeAt(index) & 0xff;
  }
  return bytes;
};

// 可用位读取约定（Extract.java 的正负分支）：正系数取物理 LSB、负系数取反——
// F5 嵌入端按 |c|±1 翻转，双端共用同一读位函数才能维持块 hash 一致
const bitOf = (coefficient: number): number =>
  coefficient > 0 ? coefficient & 1 : 1 - (coefficient & 1);

export const f5ExtractFromCoefficients = (
  coeff: Int32Array,
  password: string,
): F5ExtractResult => {
  const random = new F5Random(passwordBytes(password));
  const permutation = new F5Permutation(coeff.length, random);

  // 可用系数总数（非 DC、非 0）：容量上限校验与结果字段共用
  let usableCoefficients = 0;
  for (let index = 0; index < coeff.length; index += 1) {
    if (index % 64 !== 0 && coeff[index] !== 0) usableCoefficients += 1;
  }

  // 头 32 位：与正文共用同一条可用系数流（跳 DC 与 0），LSB-first 累位
  let header = 0;
  let headerBits = 0;
  let cursor = 0;
  while (headerBits < 32) {
    if (cursor >= coeff.length) {
      throw new Error('系数容量不足：可用系数不够拼出 32 位长度头');
    }
    const index = permutation.getShuffled(cursor);
    cursor += 1;
    if (index % 64 === 0 || coeff[index] === 0) continue;
    header |= bitOf(coeff[index]) << headerBits;
    headerBits += 1;
  }
  // 去白噪：Permutation 构造后的前 4 个 PRNG 字节，小端异或
  header = (header
    ^ random.getNextByte()
    ^ (random.getNextByte() << 8)
    ^ (random.getNextByte() << 16)
    ^ (random.getNextByte() << 24)) >>> 0;
  const k = (header >>> 24) % 32;
  const declaredLength = header & 0x007fffff;
  const n = (1 << k) - 1;
  const bodyBitCapacity =
    n === 0 ? usableCoefficients - 32 : Math.floor((usableCoefficients - 32) / n) * k;
  if (declaredLength <= 0 || declaredLength * 8 > bodyBitCapacity) {
    throw new Error(
      `口令错误或非 F5 载荷：头部长度字段解码为 ${declaredLength} 字节，超出系数可用容量`,
    );
  }

  const output = new Uint8Array(declaredLength);
  let outputIndex = 0;
  // MSB-first 位流累积器：k 不整除 8（k=3/5/6/7）时段会跨字节，且 k 最大可到 31，
  // 32 位移位装不下 8+k-1 位 pending，必须用数值运算
  let pending = 0;
  let pendingBits = 0;
  const emitBytes = (): void => {
    while (pendingBits >= 8 && outputIndex < declaredLength) {
      const shift = pendingBits - 8;
      const byte = Math.floor(pending / 2 ** shift);
      pending -= byte * 2 ** shift;
      pendingBits -= 8;
      output[outputIndex] = byte ^ random.getNextByte(); // 输出侧去白噪：每字节 1 个 PRNG 字节
      outputIndex += 1;
    }
  };

  // 单一遍历循环：块状态（hash/code）作为循环携带变量，k=0 走逐位直嵌分支
  let hash = 0;
  let code = 0;
  while (outputIndex < declaredLength) {
    if (cursor >= coeff.length) {
      throw new Error('系数耗尽仍未凑齐头部声明的载荷长度（口令错误或非 F5 载荷）');
    }
    const index = permutation.getShuffled(cursor);
    cursor += 1;
    if (index % 64 === 0 || coeff[index] === 0) continue;
    if (n === 0) {
      pending = pending * 2 + bitOf(coeff[index]);
      pendingBits += 1;
      emitBytes();
      continue;
    }
    code += 1;
    if (bitOf(coeff[index]) === 1) hash ^= code;
    if (code === n) {
      pending = pending * 2 ** k + hash;
      pendingBits += k;
      hash = 0;
      code = 0;
      emitBytes();
    }
  }
  return { data: output, k, declaredLength, usableCoefficients };
};

export const f5Extract = (jpegBytes: Uint8Array, password: string): F5ExtractResult =>
  f5ExtractFromCoefficients(readJpegCoefficients(jpegBytes).mcuOrderCoefficients, password);
