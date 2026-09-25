// F5 隐写前置件（批次 SI·A 线）：Java sun.security.provider.SecureRandom（SHA1PRNG）与
// F5 的 Permutation 置换复刻（规格取自 OpenJDK jdk8u SecureRandom.java 与 Westfeld F5
// crypt/F5Random.java + crypt/Permutation.java，按算法规格重写非翻译源码）。
// SHA1PRNG 语义：state(20B) = SHA1(seed)；每块输出 = SHA1(state)，随后
// state = (state + 输出 + 1) mod 2^160（逐字节大端带进位，初始 carry=1）；未消费字节进
// remainder 下次先取。getNextValue：4 字节按 Java 带符号 byte 符号扩展组装 int32，% max，负则 +max。
import { sha1Bytes } from './rarCrypt';

export class F5Random {
  private state = new Uint8Array(20);
  private remainder = new Uint8Array(0);
  private remainderIndex = 0;

  constructor(password: Uint8Array) {
    this.state.set(sha1Bytes(password));
  }

  private nextBlock(): void {
    const output = sha1Bytes(this.state);
    // 显式拷贝为独立缓冲：sha1Bytes 返回的视图类型携带 ArrayBufferLike，避免严格模式赋值摩擦
    this.remainder = new Uint8Array(output);
    this.remainderIndex = 0;
    // state += output + 1 (mod 2^160)：从最低位（大端末字节）带进位
    let carry = 1;
    for (let index = 19; index >= 0; index -= 1) {
      const sum = this.state[index] + output[index] + carry;
      this.state[index] = sum & 0xff;
      carry = sum >> 8;
    }
    // OpenJDK：加法后若 state 全零（和恰为 2^160 的 2^-160 概率事件）则 state[0]=1，保证状态前进
    let allZero = true;
    for (let index = 0; index < 20; index += 1) {
      if (this.state[index] !== 0) {
        allZero = false;
        break;
      }
    }
    if (allZero) this.state[0] = 1;
  }

  getNextByte(): number {
    if (this.remainderIndex >= this.remainder.length) this.nextBlock();
    const value = this.remainder[this.remainderIndex];
    this.remainderIndex += 1;
    return value;
  }

  // Java 符号扩展语义：byte 是带符号的，参与 | 与 << 时按 int 符号扩展（用 Int8 视图还原）
  getNextValue(maxValue: number): number {
    const b0 = (this.getNextByte() << 24) >> 24;
    const b1 = (this.getNextByte() << 24) >> 24;
    const b2 = (this.getNextByte() << 24) >> 24;
    const b3 = (this.getNextByte() << 24) >> 24;
    let retVal = (b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)) % maxValue;
    if (retVal < 0) retVal += maxValue;
    return retVal;
  }
}

// F5 Permutation：降序 Fisher–Yates（getNextValue 的参数是递减的 maxRandom，不是恒定 size）
export class F5Permutation {
  readonly shuffled: Int32Array;

  constructor(size: number, random: F5Random) {
    this.shuffled = new Int32Array(size);
    for (let index = 0; index < size; index += 1) this.shuffled[index] = index;
    let maxRandom = size;
    for (let index = 0; index < size; index += 1) {
      const randomIndex = random.getNextValue(maxRandom);
      maxRandom -= 1;
      const temp = this.shuffled[randomIndex];
      this.shuffled[randomIndex] = this.shuffled[maxRandom];
      this.shuffled[maxRandom] = temp;
    }
  }

  getShuffled(index: number): number {
    return this.shuffled[index];
  }
}
