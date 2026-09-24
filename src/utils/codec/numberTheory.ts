// RsaCtfTool 纯数论攻击移植层：BigInt 底座（gmpy2 等价原语）+ 经典 RSA 数学攻击。
// 语义对齐 github.com/RsaCtfTool/RsaCtfTool（MIT）的 lib/algos.py 与 lib/number_theory.py：
// Wiener 连分数小私钥、Fermat 近素数分解、Pollard rho（Brent 变体）/ p-1、小因子试除、
// dp 泄露恢复 q、Hastad 同指数广播、模数共因子互解、CRT；底座提供 isqrt / iroot / gcdext /
// invmod / isprime / next_prime / 连分数展开与收敛子。全部纯函数：零网络、零全局可变状态、
// 确定性输出（超大数 Miller-Rabin 的补充轮次用 n 派生的确定性伪随机流，同输入同输出）。
// 仅复用 ./math 叶子原语，不修改任何现有文件。
import { bigintAbs, bigintGcd, bigintMod, bigintModPow, bigintPow, bitLength } from './math';

// ---- 内部常量与小工具 ----

// {2..37} 12 基底 Miller-Rabin 对 n < 3,317,044,064,679,887,385,961,981 判素是确定性的
const MILLER_RABIN_BASES = [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n] as const;
const DETERMINISTIC_PRIME_LIMIT = 3_317_044_064_679_887_385_961_981n;
const TRIAL_DIVISION_PRIMES = [
  2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n, 41n, 43n, 47n,
  53n, 59n, 61n, 67n, 71n, 73n, 79n, 83n, 89n, 97n,
] as const;

// splitmix64 单步混合（确定性）：超大 n 的 MR 补充轮次取基底用
const splitmix64Next = (state: bigint): bigint => {
  let z = (state + 0x9e3779b97f4a7c15n) & 0xffff_ffff_ffff_ffffn;
  z = ((z ^ (z >> 30n)) * 0xbf58_476d_1ce4_e5b9n) & 0xffff_ffff_ffff_ffffn;
  z = ((z ^ (z >> 27n)) * 0x94d0_49bb_1331_11ebn) & 0xffff_ffff_ffff_ffffn;
  return z ^ (z >> 31n);
};

const sievePrimesUpTo = (limit: number): number[] => {
  const primes: number[] = [];
  if (limit < 2) return primes;
  const composite = new Uint8Array(limit + 1);
  for (let value = 2; value <= limit; value += 1) {
    if (composite[value] === 1) continue;
    primes.push(value);
    for (let multiple = value * value; multiple <= limit; multiple += value) {
      composite[multiple] = 1;
    }
  }
  return primes;
};

// 第 5000 个素数为 48611，筛到 50000（π(50000)=5133）足以取满前 5000 个
const FIRST_5000_PRIMES: readonly number[] = sievePrimesUpTo(50_000).slice(0, 5_000);

// ---- 数论底座（gmpy2 等价） ----

/** 牛顿迭代整数平方根 floor(sqrt(n))（等价 gmpy2.isqrt）。 */
export const bigintIsqrt = (n: bigint): bigint => {
  if (n < 0n) throw new Error('bigintIsqrt 输入不能为负数');
  if (n < 2n) return n;
  let x = 1n << BigInt(Math.ceil(bitLength(n) / 2)); // 2^ceil(bits/2) 是 sqrt(n) 的上界初值
  while (true) {
    const y = (x + n / x) >> 1n;
    if (y >= x) return x;
    x = y;
  }
};

/** 牛顿迭代整数 k 次根 floor(n^(1/k))（等价 gmpy2.iroot(n, k)[0]）。 */
export const bigintIroot = (n: bigint, k: number): bigint => {
  if (!Number.isInteger(k) || k < 1) throw new Error('bigintIroot 次数 k 必须为正整数');
  if (n < 0n) throw new Error('bigintIroot 输入不能为负数');
  if (n < 2n || k === 1) return n;
  const kb = BigInt(k);
  let x = 1n << BigInt(Math.ceil(bitLength(n) / k));
  while (true) {
    const y = (((kb - 1n) * x) + n / x ** (kb - 1n)) / kb;
    if (y >= x) return x;
    x = y;
  }
};

/** 扩展欧几里得：返回 [g, s, t] 使 s*a + t*b = g（等价 gmpy2.gcdext）。 */
export const bigintGcdext = (a: bigint, b: bigint): [bigint, bigint, bigint] => {
  let oldR = a;
  let r = b;
  let oldS = 1n;
  let s = 0n;
  let oldT = 0n;
  let t = 1n;
  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
    [oldT, t] = [t, oldT - q * t];
  }
  if (oldR < 0n) return [-oldR, -oldS, -oldT];
  return [oldR, oldS, oldT];
};

/** 模逆 a^{-1} mod m，不互素返回 null（等价 gmpy2.invert 的失败语义）。 */
export const bigintInvMod = (a: bigint, m: bigint): bigint | null => {
  if (m <= 0n) return null;
  const [g, s] = bigintGcdext(a, m);
  if (g !== 1n) return null;
  return bigintMod(s, m);
};

/**
 * Miller-Rabin 判素：n < 3.317e24 时 {2..37} 12 基底结果确定性；
 * 更大的 n 追加 20 轮由 n 派生的确定性伪随机基底（保持纯函数可复现）。
 */
export const bigintIsPrime = (n: bigint): boolean => {
  if (n < 2n) return false;
  for (const small of TRIAL_DIVISION_PRIMES) {
    if (n === small) return true;
    if (n % small === 0n) return false;
  }
  let d = n - 1n;
  let s = 0n;
  while ((d & 1n) === 0n) {
    d >>= 1n;
    s += 1n;
  }
  const passesBase = (base: bigint): boolean => {
    if (base < 2n || base > n - 2n) return true; // 基底越界的小 n 场景已被试除覆盖
    let x = bigintModPow(base, d, n);
    if (x === 1n || x === n - 1n) return true;
    for (let round = 1n; round < s; round += 1n) {
      x = (x * x) % n;
      if (x === n - 1n) return true;
    }
    return false;
  };
  for (const base of MILLER_RABIN_BASES) {
    if (!passesBase(base)) return false;
  }
  if (n < DETERMINISTIC_PRIME_LIMIT) return true;
  let state = n & 0xffff_ffff_ffff_ffffn;
  const span = n - 4n;
  for (let round = 0; round < 20; round += 1) {
    state = splitmix64Next(state);
    if (!passesBase(3n + (state % span))) return false;
  }
  return true;
};

/** 大于 n 的最小素数（等价 gmpy2.next_prime）。 */
export const nextPrime = (n: bigint): bigint => {
  let candidate = n < 2n ? 2n : n + 1n;
  if (candidate > 2n && (candidate & 1n) === 0n) candidate += 1n;
  while (!bigintIsPrime(candidate)) candidate += 2n;
  return candidate;
};

/** 连分数展开：返回 n/d 的部分商序列 [a0, a1, ...]。 */
export const continuedFraction = (numerator: bigint, denominator: bigint): bigint[] => {
  if (denominator === 0n) throw new Error('continuedFraction 分母不能为 0');
  let n = numerator < 0n ? -numerator : numerator;
  let d = denominator < 0n ? -denominator : denominator;
  const terms: bigint[] = [];
  while (d !== 0n) {
    terms.push(n / d);
    [n, d] = [d, n % d];
  }
  if (numerator < 0n && terms.length > 0) terms[0] = -terms[0];
  return terms;
};

/** 连分数收敛子序列：由部分商递推得 [p, q] 对（p_i/q_i 逐步逼近展开值）。 */
export const convergents = (cf: readonly bigint[]): ReadonlyArray<readonly [bigint, bigint]> => {
  const result: Array<readonly [bigint, bigint]> = [];
  let prevP = 0n;
  let currP = 1n;
  let prevQ = 1n;
  let currQ = 0n;
  for (const a of cf) {
    const p = a * currP + prevP;
    const q = a * currQ + prevQ;
    result.push([p, q]);
    prevP = currP;
    currP = p;
    prevQ = currQ;
    currQ = q;
  }
  return result;
};

// ---- 中国剩余定理 ----

/** 合并 x ≡ a1 (mod n1)、x ≡ a2 (mod n2)：返回 [x, n1*n2]；模数非互素返回 null。 */
export const crtPair = (
  a1: bigint,
  n1: bigint,
  a2: bigint,
  n2: bigint,
): readonly [bigint, bigint] | null => {
  if (n1 <= 0n || n2 <= 0n) return null;
  const [g, s] = bigintGcdext(n1, n2);
  if (g !== 1n) return null;
  const modulus = n1 * n2;
  const step = bigintMod(bigintMod(a2 - a1, n2) * s, n2);
  return [bigintMod(a1 + n1 * step, modulus), modulus];
};

/** 依次合并多个同余方程 [value, modulus]；任一对模数非互素返回 null。 */
export const crtList = (
  congruences: ReadonlyArray<readonly [bigint, bigint]>,
): readonly [bigint, bigint] | null => {
  if (congruences.length === 0) return null;
  const [firstValue, firstModulus] = congruences[0];
  let value = bigintMod(firstValue, firstModulus);
  let modulus = firstModulus;
  for (let index = 1; index < congruences.length; index += 1) {
    const [nextValue, nextModulus] = congruences[index];
    const merged = crtPair(value, modulus, nextValue, nextModulus);
    if (merged === null) return null;
    [value, modulus] = merged;
  }
  return [value, modulus];
};

// ---- RSA 经典攻击（RsaCtfTool lib/algos.py 语义对齐） ----

/**
 * Wiener 小私钥攻击：d < n^0.25/3（且 q < p < 2q）时 k/d 是 e/n 的连分数收敛子。
 * 对每个候选 d 反解 phi = (e·d-1)/k，经 p+q 与 (p-q)^2 判别式锁定因子，
 * 最后用 m^(ed) ≡ m (mod n) 双明文点终验（m=2 与 m=0x10001）。
 */
export const wienerAttack = (e: bigint, n: bigint): bigint | null => {
  if (e <= 0n || n <= 1n) return null;
  for (const [k, d] of convergents(continuedFraction(e, n))) {
    if (k === 0n || d === 0n || (e * d - 1n) % k !== 0n) continue;
    const phi = (e * d - 1n) / k;
    const sum = n - phi + 1n; // 候选 p + q
    if (sum < 4n) continue;
    const disc = sum * sum - 4n * n; // 候选 (p - q)^2
    if (disc < 0n) continue;
    const root = bigintIsqrt(disc);
    if (root * root !== disc || ((sum + root) & 1n) !== 0n) continue;
    const p = (sum + root) >> 1n;
    const q = (sum - root) >> 1n;
    if (p < 2n || q < 2n || p * q !== n) continue;
    if (bigintModPow(2n, e * d, n) !== bigintMod(2n, n)) continue;
    if (bigintModPow(0x10001n, e * d, n) !== bigintMod(0x10001n, n)) continue;
    return d;
  }
  return null;
};

/** Fermat 分解：p、q 接近时自 a=ceil(sqrt(n)) 起检验 a^2-n 是否完全平方，命中即得 (a-b)(a+b)。 */
export const fermatFactor = (n: bigint, maxIter = 1_000_000): readonly [bigint, bigint] | null => {
  if (n <= 1n) return null;
  if ((n & 1n) === 0n) return [2n, n / 2n];
  let a = bigintIsqrt(n);
  if (a * a < n) a += 1n;
  for (let step = 0; step < maxIter; step += 1) {
    const b2 = a * a - n;
    const b = bigintIsqrt(b2);
    if (b * b === b2) {
      const p = a - b;
      const q = a + b;
      if (p > 1n && p * q === n) return [p, q];
    }
    a += 1n;
  }
  return null;
};

/** Pollard rho 的 Brent 变体：分段记忆 x、批量差分累乘取 gcd，比逐步 Floyd 少算 gcd。 */
const pollardRhoBrent = (n: bigint, c: bigint): bigint | null => {
  const f = (x: bigint): bigint => (x * x + c) % n;
  const batch = 128n;
  const stepLimit = 1_000_000n;
  let x = 2n;
  let y = 2n;
  let ys = 2n;
  let g = 1n;
  let r = 1n;
  let q = 1n;
  let steps = 0n;
  while (g === 1n && steps < stepLimit) {
    x = y;
    for (let i = 0n; i < r && steps < stepLimit; i += 1n, steps += 1n) y = f(y);
    let k = 0n;
    while (k < r && g === 1n && steps < stepLimit) {
      ys = y;
      const span = batch < r - k ? batch : r - k;
      for (let i = 0n; i < span && steps < stepLimit; i += 1n, steps += 1n) {
        y = f(y);
        q = (q * bigintAbs(x - y)) % n;
      }
      g = bigintGcd(q, n);
      k += batch;
    }
    r <<= 1n;
  }
  if (g === n) {
    // 批量差分乘积恰好归零（x ≡ y）：退回本段起点逐点 gcd 重扫
    g = 1n;
    y = ys;
    while (g === 1n) {
      y = f(y);
      g = bigintGcd(bigintAbs(x - y), n);
    }
  }
  return g > 1n && g < n ? g : null;
};

/** Pollard rho 因子分解入口：偶数直取 2，素数返回 null，多组 c 参数轮试 Brent 变体。 */
export const pollardRho = (n: bigint): bigint | null => {
  if (n <= 1n) return null;
  if ((n & 1n) === 0n) return 2n;
  if (bigintIsPrime(n)) return null;
  for (const c of [1n, 3n, 2n, 5n, 7n, 11n, 13n, 17n, 19n, 23n]) {
    const factor = pollardRhoBrent(n, c);
    if (factor !== null) return factor;
  }
  return null;
};

/**
 * Pollard p-1：某因子 p 满足 p-1 为 B-光滑时，a^(≤B 的素数幂全积) ≡ 1 (mod p)，
 * gcd(a-1, n) 即暴露 p。a 自 2 起对每个 ≤B 素数的最大幂逐次做模幂。
 */
export const pollardPMinus1 = (n: bigint, bound = 10_000): bigint | null => {
  if (n <= 1n) return null;
  if ((n & 1n) === 0n) return 2n;
  if (bigintIsPrime(n)) return null;
  const limit = Math.max(2, Math.floor(bound));
  let a = 2n;
  for (const p of sievePrimesUpTo(limit)) {
    let primePower = BigInt(p);
    while (primePower * BigInt(p) <= BigInt(limit)) primePower *= BigInt(p);
    a = bigintModPow(a, primePower, n);
  }
  const g = bigintGcd(a - 1n, n);
  return g > 1n && g < n ? g : null;
};

/** 小因子试除：检查前 5000 个素数（最大 48611），返回最小命中因子，无命中返回 null。 */
export const smallPrimeFactor = (n: bigint): bigint | null => {
  if (n <= 1n) return null;
  for (const p of FIRST_5000_PRIMES) {
    const prime = BigInt(p);
    if (prime * prime > n) return null;
    if (n % prime === 0n) return prime;
  }
  return null;
};

/**
 * dp 泄露攻击：e·dp - 1 = k·(p-1)，k ∈ [1, e)。遍历 k 反解候选 p = (e·dp-1)/k + 1，
 * 用 p 整除 n 锁定真因子，返回 q = n/p。
 */
export const solvePartialQ = (dp: bigint, n: bigint, e: bigint): bigint | null => {
  if (dp <= 0n || e <= 0n || n <= 1n) return null;
  const total = e * dp - 1n;
  const kLimit = e < 10_000_000n ? e : 10_000_000n; // O(e) 遍历的防呆上限
  for (let k = 1n; k < kLimit; k += 1n) {
    if (total % k !== 0n) continue;
    const p = total / k + 1n;
    if (p <= 1n || p >= n || n % p !== 0n) continue;
    const q = n / p;
    if (q > 1n && p * q === n) return q;
  }
  return null;
};

export interface HastadRecord {
  readonly n: bigint;
  readonly c: bigint;
  readonly e: bigint;
}

/**
 * Hastad 广播攻击：同一 e 的多组密文在互素模数上 CRT 合并得 m^e (mod Πn)，
 * 当 m^e < Πn 时直接整数开根恢复明文；指数不一致或开根校验失败返回 null。
 */
export const hastadBroadcast = (records: readonly HastadRecord[]): bigint | null => {
  if (records.length === 0) return null;
  const e = records[0].e;
  const exponent = Number(e);
  if (!Number.isSafeInteger(exponent) || exponent < 2) return null;
  if (records.some(record => record.e !== e)) return null;
  const merged = crtList(records.map(record => [bigintMod(record.c, record.n), record.n] as const));
  if (merged === null) return null;
  const [x] = merged;
  const root = bigintIroot(x, exponent);
  return bigintPow(root, e) === x ? root : null;
};

export interface RsaCiphertextKey {
  readonly n: bigint;
  readonly e: bigint;
  readonly c: bigint;
}

export interface CommonFactorHit {
  readonly indexA: number; // 被解密的密钥下标
  readonly indexB: number; // 与之共享素因子的密钥下标
  readonly shared: bigint; // 共享素因子 p
  readonly other: bigint; // 该密钥的另一因子 q
  readonly d: bigint; // 恢复出的私钥
  readonly plain: bigint; // 解密明文
}

const decryptWithSharedFactor = (
  key: RsaCiphertextKey,
  shared: bigint,
): { other: bigint; d: bigint; plain: bigint } | null => {
  const other = key.n / shared;
  const d = bigintInvMod(key.e, (shared - 1n) * (other - 1n));
  if (d === null) return null;
  return { other, d, plain: bigintModPow(key.c, d, key.n) };
};

/** 模数共因子攻击：两两 gcd(n_i, n_j) 命中非平凡因子即分解双方并各自解密。 */
export const commonFactorGcd = (keys: readonly RsaCiphertextKey[]): readonly CommonFactorHit[] => {
  const hits: CommonFactorHit[] = [];
  for (let i = 0; i < keys.length; i += 1) {
    for (let j = i + 1; j < keys.length; j += 1) {
      const shared = bigintGcd(keys[i].n, keys[j].n);
      if (shared <= 1n || shared >= keys[i].n || shared >= keys[j].n) continue;
      const hitI = decryptWithSharedFactor(keys[i], shared);
      if (hitI !== null) hits.push({ indexA: i, indexB: j, shared, ...hitI });
      const hitJ = decryptWithSharedFactor(keys[j], shared);
      if (hitJ !== null) hits.push({ indexA: j, indexB: i, shared, ...hitJ });
    }
  }
  return hits;
};
