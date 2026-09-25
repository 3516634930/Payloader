// Python random 模块复刻（批次 SI·C 线盲水印前置）：MT19937 + Python3 init_by_array 播种 +
// shuffle（_randbelow 拒绝采样）。与 CPython randommodule.c 语义逐位一致，供复刻
// chishaxie/BlindWaterMark 的 random.seed(20160930) 行列洗牌序列。
// 锚定向量（CPython 公开行为）：random.seed(0) 后 getrandbits(32) 首值 2357136044；
// MT19937 init_genrand(5489) 首输出 3499211612（MT19937 标准测试向量）。
const MT_SIZE = 624;
const MATRIX_A = 0x9908b0df;
const UPPER_MASK = 0x80000000;
const LOWER_MASK = 0x7fffffff;

export class PythonRandom {
  private mt = new Uint32Array(MT_SIZE);
  private index = MT_SIZE + 1;

  // 对应 Python random.seed(a)（a 为非负整数；负数按 CPython 取 abs 后同语义处理）
  seed(value: number): void {
    let magnitude = Math.abs(Math.trunc(value));
    if (!Number.isSafeInteger(magnitude)) throw new Error('random.seed 参数超出安全整数范围');
    // CPython：把 int 的绝对值按 32 位小端拆成 key 数组（0 的 key 为 [0]）
    const key: number[] = [];
    if (magnitude === 0) key.push(0);
    else {
      while (magnitude > 0) {
        key.push(magnitude % 0x100000000);
        magnitude = Math.floor(magnitude / 0x100000000);
      }
    }
    this.initByArray(key);
  }

  private initGenrand(seed: number): void {
    this.mt[0] = seed >>> 0;
    for (let i = 1; i < MT_SIZE; i += 1) {
      this.mt[i] = (Math.imul(this.mt[i - 1] ^ (this.mt[i - 1] >>> 30), 1812433253) + i) >>> 0;
    }
    this.index = MT_SIZE;
  }

  private initByArray(key: number[]): void {
    this.initGenrand(19650218);
    let i = 1;
    let j = 0;
    let k = Math.max(MT_SIZE, key.length);
    for (; k > 0; k -= 1) {
      this.mt[i] =
        (this.mt[i] ^ Math.imul(this.mt[i - 1] ^ (this.mt[i - 1] >>> 30), 1664525)) + key[j] + j >>> 0;
      i += 1;
      j += 1;
      if (i >= MT_SIZE) {
        this.mt[0] = this.mt[MT_SIZE - 1];
        i = 1;
      }
      if (j >= key.length) j = 0;
    }
    for (k = MT_SIZE - 1; k > 0; k -= 1) {
      this.mt[i] = (this.mt[i] ^ Math.imul(this.mt[i - 1] ^ (this.mt[i - 1] >>> 30), 1566083941)) - i >>> 0;
      i += 1;
      if (i >= MT_SIZE) {
        this.mt[0] = this.mt[MT_SIZE - 1];
        i = 1;
      }
    }
    this.mt[0] = 0x80000000;
    this.index = MT_SIZE;
  }

  private generateBlock(): void {
    for (let i = 0; i < MT_SIZE; i += 1) {
      const y = (this.mt[i] & UPPER_MASK) | (this.mt[(i + 1) % MT_SIZE] & LOWER_MASK);
      const next = this.mt[(i + 397) % MT_SIZE] ^ (y >>> 1) ^ (y & 1 ? MATRIX_A : 0);
      this.mt[i] = next >>> 0;
    }
    this.index = 0;
  }

  // genrand_uint32：tempering 后的 32 位输出
  nextUint32(): number {
    if (this.index >= MT_SIZE) this.generateBlock();
    let y = this.mt[this.index];
    this.index += 1;
    y ^= y >>> 11;
    y = (y ^ ((y << 7) & 0x9d2c5680)) >>> 0;
    y = (y ^ ((y << 15) & 0xefc60000)) >>> 0;
    y = y ^ (y >>> 18);
    return y >>> 0;
  }

  // random.getrandbits(k)，k ∈ [1,32]
  getrandbits(bits: number): number {
    if (!Number.isInteger(bits) || bits < 1 || bits > 32) {
      throw new Error(`getrandbits 仅支持 1..32 位，当前 ${bits}`);
    }
    return this.nextUint32() >>> (32 - bits);
  }

  // _randbelow_with_getrandbits：k = n 的 bit_length（32−clz32(n)），拒绝采样 r>=n
  private randbelow(n: number): number {
    if (n <= 1) return 0;
    const bitLength = 32 - Math.clz32(n);
    for (;;) {
      const r = this.getrandbits(bitLength);
      if (r < n) return r;
    }
  }

  // random.shuffle(list)（Fisher–Yates，i 从尾往头，j=_randbelow(i+1)）
  shuffleInPlace<T>(items: T[]): T[] {
    for (let i = items.length - 1; i > 0; i -= 1) {
      const j = this.randbelow(i + 1);
      const temp = items[i];
      items[i] = items[j];
      items[j] = temp;
    }
    return items;
  }
}
