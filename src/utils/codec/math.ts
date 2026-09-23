// codec 纯数学叶子层（T5 解环下沉）：bigint 基础运算与因数分解，零 codec 内依赖
//（仅 bases 的 hexToBytes 字节工具），供 rsa/prng/attacks/binaryFormats/crypto 共同消费。
import { hexToBytes } from './bases';

export const bitLength = (value: bigint) => value === 0n ? 0 : value.toString(2).length;

export const bigintToBytes = (value: bigint) => {
  if (value < 0n) throw new Error('BigInt byte conversion only supports non-negative values');
  if (value === 0n) return new Uint8Array([0]);
  const hex = value.toString(16).padStart(Math.ceil(value.toString(16).length / 2) * 2, '0');
  return hexToBytes(hex);
};

export const bigintFromBytes = (bytes: Uint8Array) => {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
};

export const bigintModPow = (base: bigint, exponent: bigint, modulo: bigint) => {
  if (modulo <= 0n) throw new Error('RSA modulus n must be positive');
  if (exponent < 0n) throw new Error('RSA exponent must be non-negative');
  let result = 1n;
  let current = ((base % modulo) + modulo) % modulo;
  let power = exponent;
  while (power > 0n) {
    if (power & 1n) result = (result * current) % modulo;
    current = (current * current) % modulo;
    power >>= 1n;
  }
  return result;
};

export const bigintMod = (value: bigint, modulo: bigint) => ((value % modulo) + modulo) % modulo;

export const crtCombinePair = (leftValue: bigint, leftMod: bigint, rightValue: bigint, rightMod: bigint) => {
  const leftInverse = bigintModInverse(leftMod, rightMod);
  const rightInverse = bigintModInverse(rightMod, leftMod);
  if (leftInverse == null || rightInverse == null) throw new Error('CRT combine requires coprime moduli');
  const modulus = leftMod * rightMod;
  return bigintMod(
    leftValue * rightMod * rightInverse + rightValue * leftMod * leftInverse,
    modulus,
  );
};

export const bigintPow = (base: bigint, exponent: bigint) => {
  if (exponent < 0n) throw new Error('bigintPow only supports non-negative exponents');
  let result = 1n;
  let current = base;
  let power = exponent;
  while (power > 0n) {
    if (power & 1n) result *= current;
    power >>= 1n;
    if (power > 0n) current *= current;
  }
  return result;
};

export const rsaModPowSigned = (base: bigint, exponent: bigint, modulo: bigint) => {
  if (exponent >= 0n) return bigintModPow(base, exponent, modulo);
  const inverse = bigintModInverse(base, modulo);
  if (inverse == null) return null;
  return bigintModPow(inverse, -exponent, modulo);
};

export const bigintAbs = (value: bigint) => value < 0n ? -value : value;

export const bigintEgcd = (left: bigint, right: bigint): [bigint, bigint, bigint] => {
  if (right === 0n) return [bigintAbs(left), left < 0n ? -1n : 1n, 0n];
  const [gcd, x1, y1] = bigintEgcd(right, left % right);
  return [gcd, y1, x1 - (left / right) * y1];
};

export const bigintGcd = (left: bigint, right: bigint): bigint => {
  let a = bigintAbs(left);
  let b = bigintAbs(right);
  while (b !== 0n) {
    [a, b] = [b, a % b];
  }
  return a;
};

export const bigintModInverse = (value: bigint, modulo: bigint) => {
  const [gcd, x] = bigintEgcd(((value % modulo) + modulo) % modulo, modulo);
  if (gcd !== 1n) return null;
  return ((x % modulo) + modulo) % modulo;
};

export const factorSmallRsaModulus = (
  n: bigint,
  options: {
    maxBits?: number;
    allowPollardRho?: boolean;
    trialLimit?: bigint;
    fermatSteps?: number;
    rhoIterations?: number;
  } = {},
) => {
  const {
    maxBits = 190,
    allowPollardRho = true,
    trialLimit = 100_000n,
    fermatSteps = 50_000,
    rhoIterations = 20_000,
  } = options;
  if (n <= 3n || bitLength(n) > maxBits) return null;
  if (n % 2n === 0n) return [2n, n / 2n] as const;

  const isProbablePrime = (value: bigint) => {
    if (value < 2n) return false;
    for (const smallPrime of [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n]) {
      if (value === smallPrime) return true;
      if (value % smallPrime === 0n) return false;
    }
    let d = value - 1n;
    let s = 0n;
    while ((d & 1n) === 0n) {
      d >>= 1n;
      s += 1n;
    }
    const witnesses = [2n, 3n, 5n, 7n, 11n, 13n, 17n];
    for (const witness of witnesses) {
      if (witness >= value - 1n) continue;
      let x = bigintModPow(witness, d, value);
      if (x === 1n || x === value - 1n) continue;
      let composite = true;
      for (let round = 1n; round < s; round += 1n) {
        x = bigintModPow(x, 2n, value);
        if (x === value - 1n) {
          composite = false;
          break;
        }
      }
      if (composite) return false;
    }
    return true;
  };

  if (isProbablePrime(n)) return null;

  for (let divisor = 3n; divisor <= trialLimit && divisor * divisor <= n; divisor += 2n) {
    if (n % divisor === 0n) return [divisor, n / divisor] as const;
  }

  if (bitLength(n) <= 128) {
    let a = bigIntSqrt(n);
    if (a * a < n) a += 1n;
    for (let step = 0; step < fermatSteps; step += 1) {
      const b2 = a * a - n;
      const b = bigIntSqrt(b2);
      if (b * b === b2) {
        const p = a - b;
        const q = a + b;
        if (p > 1n && q > 1n && p * q === n) return [p, q] as const;
      }
      a += 1n;
    }
  }

  if (!allowPollardRho) return null;

  const pollardRhoFactor = (value: bigint) => {
    const f = (x: bigint, c: bigint) => bigintMod(x * x + c, value);
    const seeds = [
      [2n, 1n],
      [3n, 1n],
      [5n, 1n],
      [2n, 3n],
      [3n, 5n],
      [7n, 11n],
      [11n, 17n],
      [17n, 29n],
    ] as const;

    for (const [seed, constant] of seeds) {
      let x = seed % value;
      let y = x;
      let d = 1n;
      for (let iteration = 0; iteration < rhoIterations && d === 1n; iteration += 1) {
        x = f(x, constant);
        y = f(f(y, constant), constant);
        d = bigintGcd(bigintAbs(x - y), value);
      }
      if (d > 1n && d < value) return d;
    }
    return null;
  };

  const rhoFactor = pollardRhoFactor(n);
  if (rhoFactor && rhoFactor > 1n && rhoFactor < n) {
    const other = n / rhoFactor;
    return rhoFactor < other ? [rhoFactor, other] as const : [other, rhoFactor] as const;
  }

  return null;
};

export const factorSmallCompositeModulus = (n: bigint) => {
  if (n <= 1n) return null;
  const factors: bigint[] = [];
  const visit = (current: bigint): boolean => {
    if (current <= 1n) return true;
    const pair = factorSmallRsaModulus(current);
    if (!pair) {
      factors.push(current);
      return true;
    }
    const [left, right] = pair;
    if (left <= 1n || right <= 1n || left * right !== current) {
      factors.push(current);
      return true;
    }
    if (left === current || right === current) {
      factors.push(current);
      return true;
    }
    return visit(left) && visit(right);
  };
  return visit(n)
    ? factors.sort((left, right) => (left < right ? -1 : left > right ? 1 : 0))
    : null;
};

export const bigIntSqrt = (value: bigint) => {
  if (value < 0n) throw new Error('平方根输入不能为负数');
  if (value < 2n) return value;
  let small = 1n;
  let large = value;
  while (large - small > 1n) {
    const mid = (small + large) >> 1n;
    if (mid * mid <= value) small = mid;
    else large = mid;
  }
  return small;
};
