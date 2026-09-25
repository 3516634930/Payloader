// outguess 0.2 提取前置件（批次 SI·A 线）：OpenBSD ARC4 变体 + 伪随机游走迭代器。
// 语义逐行对齐 resurrecting-open-source-projects/outguess（BSD-2，按规格重写）：
// - arc4_getbyte：标准 PRGA，i/j 均为 8 位自然回绕（JS 中 &0xff 等价 C 的 u_int8_t 溢出）
// - arc4_addrandom：先 i--，256 轮 j += s[i] + dat[n%len]（8 位回绕）
// - arc4_initkey：MD5(type ∥ key) 16 字节 → arc4_init + addrandom；两个域 "Seeding"/"Encryption"
// - iterator：off 初值 = getword % 32；next：off += getword % skipmod + 1；
//   adapt：skipmod = trunc(SKIPADJ(bits, bits-off) × (bits-off) / (8·datalen))——SKIPADJ 的
//   x/32 是 C 整数除、其除法是浮点，乘积截断回整数（C 语义，JS 必须显式 trunc）
import { md5Bytes } from '../codec/crypto';

export class Arc4Stream {
  private s = new Uint8Array(256);
  private i = 0;
  private j = 0;

  constructor() {
    for (let n = 0; n < 256; n += 1) this.s[n] = n;
  }

  getbyte(): number {
    this.i = (this.i + 1) & 0xff;
    const si = this.s[this.i];
    this.j = (this.j + si) & 0xff;
    const sj = this.s[this.j];
    this.s[this.i] = sj;
    this.s[this.j] = si;
    return this.s[(si + sj) & 0xff];
  }

  getword(): number {
    return (
      ((this.getbyte() << 24) | (this.getbyte() << 16) | (this.getbyte() << 8) | this.getbyte()) >>> 0
    );
  }

  addrandom(data: Uint8Array): void {
    if (data.length === 0) return;
    this.i = (this.i - 1) & 0xff;
    for (let n = 0; n < 256; n += 1) {
      this.i = (this.i + 1) & 0xff;
      const si = this.s[this.i];
      this.j = (this.j + si + data[n % data.length]) & 0xff;
      this.s[this.i] = this.s[this.j];
      this.s[this.j] = si;
    }
  }
}

export const arc4InitKey = (type: string, key: Uint8Array): Arc4Stream => {
  const stream = new Arc4Stream();
  const typeBytes = new TextEncoder().encode(type);
  const material = new Uint8Array(typeBytes.length + key.length);
  material.set(typeBytes, 0);
  material.set(key, typeBytes.length);
  stream.addrandom(md5Bytes(material));
  return stream;
};

export const OUTGUESS_INIT_SKIPMOD = 32;

export interface OutguessIteratorState {
  stream: Arc4Stream;
  off: number;
  skipmod: number;
}

export const iteratorInit = (key: Uint8Array): OutguessIteratorState => {
  const stream = arc4InitKey('Seeding', key);
  const skipmod = OUTGUESS_INIT_SKIPMOD;
  return { stream, off: stream.getword() % skipmod, skipmod };
};

export const iteratorNext = (state: OutguessIteratorState): number => {
  state.off += (state.stream.getword() % state.skipmod) + 1;
  return state.off;
};

export const iteratorSeed = (state: OutguessIteratorState, seed: number): void => {
  state.stream.addrandom(new Uint8Array([seed & 0xff, (seed >> 8) & 0xff]));
};

// SKIPADJ(x,y)：y > x/32（C 整除）→ 2，否则 2 − ((x/32 整除) − y)/((float)(x/32))
export const outguessSkipAdjust = (totalBits: number, remainingBits: number): number => {
  const segment = Math.floor(totalBits / 32);
  if (remainingBits > segment) return 2;
  return 2 - (segment - remainingBits) / segment;
};

export const iteratorAdapt = (state: OutguessIteratorState, totalBits: number, remainingBytes: number): void => {
  const remainingBits = totalBits - state.off;
  // 原式顺序（float×int）/int 全程浮点，末端 trunc 还原 C 赋值给 int 的截断
  state.skipmod = Math.trunc(
    (outguessSkipAdjust(totalBits, remainingBits) * remainingBits) / (8 * remainingBytes),
  );
  if (state.skipmod < 1) state.skipmod = 1; // C 中此处 %0 是未定义行为，防御 clamp
};
