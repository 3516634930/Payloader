// RsaCtfTool 数论攻击移植测试：全部密钥/样本程序化自造（确定性种子，无外部 fixture），逐攻击验证恢复结果。
// 断言刻意逐字段 equal：沙箱模块返回的数组/对象是 vm realm 产物，deepStrictEqual 会因原型差异误报（AGENTS.md 踩坑记录）。
import assert from 'node:assert/strict';
import path from 'node:path';
import { test } from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const { loadModule } = createTsModuleLoader();
const {
  bigintIsqrt, bigintIroot, bigintGcdext, bigintInvMod, bigintIsPrime, nextPrime,
  continuedFraction, convergents, crtPair, crtList,
  wienerAttack, fermatFactor, pollardRho, pollardPMinus1, smallPrimeFactor,
  solvePartialQ, hastadBroadcast, commonFactorGcd,
} = loadModule(path.join(projectRoot, 'src', 'utils', 'codec', 'numberTheory.ts'));

// ---- 测试侧确定性工具（构造密钥用） ----

const gcd = (a, b) => {
  let x = a < 0n ? -a : a;
  let y = b < 0n ? -b : b;
  while (y !== 0n) [x, y] = [y, x % y];
  return x;
};

const modPow = (base, exponent, modulus) => {
  let result = 1n;
  let current = ((base % modulus) + modulus) % modulus;
  let power = exponent;
  while (power > 0n) {
    if (power & 1n) result = (result * current) % modulus;
    current = (current * current) % modulus;
    power >>= 1n;
  }
  return result;
};

// splitmix64 确定性随机（固定种子：每次运行生成同一批密钥，失败可复现）
let rngState = 0x853c49e6748fea9bn;
const randomOdd = bits => {
  rngState = (rngState + 0x9e3779b97f4a7c15n) & 0xffffffffffffffffn;
  let z = rngState;
  z = ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n) & 0xffffffffffffffffn;
  z = ((z ^ (z >> 27n)) * 0x94d049bb133111ebn) & 0xffffffffffffffffn;
  z = z ^ (z >> 31n);
  return (z & ((1n << BigInt(bits)) - 1n)) | (1n << BigInt(bits - 1)) | 1n;
};
const randomPrime = bits => {
  let candidate = randomOdd(bits);
  while (!bigintIsPrime(candidate)) candidate += 2n;
  return candidate;
};

// ---- 数论底座 ----

test('bigintIsqrt 牛顿迭代整数平方根', () => {
  assert.equal(bigintIsqrt(10n ** 30n), 10n ** 15n);
  assert.equal(bigintIsqrt(10n ** 30n + 1n), 10n ** 15n);
  assert.equal(bigintIsqrt(10n ** 30n - 1n), 10n ** 15n - 1n);
  assert.equal(bigintIsqrt(0n), 0n);
  assert.equal(bigintIsqrt(1n), 1n);
  assert.equal(bigintIsqrt(2n), 1n);
  assert.equal(bigintIsqrt(998001n), 999n);
  assert.equal(bigintIsqrt(998002n), 999n);
});

test('bigintIroot 整数 k 次根', () => {
  assert.equal(bigintIroot(2n ** 63n, 3), 2n ** 21n); // 2097152^3 恰为 2^63
  assert.equal(bigintIroot(2n ** 63n - 1n, 3), 2n ** 21n - 1n);
  assert.equal(bigintIroot(10n ** 18n, 3), 10n ** 6n);
  assert.equal(bigintIroot(10n ** 18n - 1n, 3), 10n ** 6n - 1n);
  assert.equal(bigintIroot(2n ** 100n, 4), 2n ** 25n);
  assert.equal(bigintIroot(12345678901234567890n, 2), bigintIsqrt(12345678901234567890n));
  assert.equal(bigintIroot(7n, 1), 7n);
});

test('bigintGcdext 扩展欧几里得', () => {
  const [g, s, t] = bigintGcdext(240n, 46n);
  assert.equal(g, 2n);
  assert.equal(s, -9n);
  assert.equal(t, 47n);
  assert.equal(240n * s + 46n * t, g);
  const [g2, s2, t2] = bigintGcdext(17n, 3120n);
  assert.equal(g2, 1n);
  assert.equal(17n * s2 + 3120n * t2, 1n);
  const [g3, s3, t3] = bigintGcdext(1071n, 462n);
  assert.equal(g3, 21n);
  assert.equal(1071n * s3 + 462n * t3, 21n);
});

test('bigintInvMod 模逆', () => {
  assert.equal(bigintInvMod(3n, 11n), 4n);
  assert.equal(bigintInvMod(17n, 3120n), 2753n); // RSA 教科书例 e=17, phi=3120
  assert.equal(bigintInvMod(2n, 7n), 4n);
  assert.equal(bigintInvMod(6n, 9n), null); // 非互素
  assert.equal(bigintInvMod(5n, 1n), 0n);
});

test('bigintIsPrime Miller-Rabin 判素（含大数补充轮路径）', () => {
  assert.equal(bigintIsPrime(2n ** 127n - 1n), true); // Mersenne 素数
  assert.equal(bigintIsPrime(2n ** 61n - 1n), true);
  assert.equal(bigintIsPrime(2n ** 67n - 1n), false); // Mersenne 合数 193707721×761838257287
  assert.equal(bigintIsPrime(561n), false); // 卡迈克尔数 3·11·17
  assert.equal(bigintIsPrime(1729n), false); // 卡迈克尔数 7·13·19
  assert.equal(bigintIsPrime(252601n), false); // 卡迈克尔数 41·61·101
  assert.equal(bigintIsPrime((2n ** 127n - 1n) ** 2n), false); // 素数平方
  assert.equal(bigintIsPrime(10007n), true);
  assert.equal(bigintIsPrime(10007n * 10009n), false);
  assert.equal(bigintIsPrime(1n), false);
  assert.equal(bigintIsPrime(0n), false);
  // 超过 3.3e24 确定性界：走 n 派生伪随机 20 轮补充路径
  const bigPrime = nextPrime(2n ** 200n + 12345n);
  assert.ok(bigPrime > 2n ** 200n);
  assert.equal(bigintIsPrime(bigPrime), true);
  assert.equal(bigintIsPrime(bigPrime * bigPrime), false);
  assert.equal(bigintIsPrime(bigPrime * 65537n), false);
});

test('nextPrime 逐个跳到下一素数', () => {
  assert.equal(nextPrime(0n), 2n);
  assert.equal(nextPrime(1n), 2n);
  assert.equal(nextPrime(2n), 3n);
  assert.equal(nextPrime(3n), 5n);
  assert.equal(nextPrime(7n), 11n);
  const from = 10n ** 18n + 9n;
  const p = nextPrime(from);
  assert.ok(p > from && bigintIsPrime(p));
  for (let candidate = from + 1n; candidate < p; candidate += 1n) {
    assert.equal(bigintIsPrime(candidate), false); // 中间无素数
  }
});

test('continuedFraction/convergents 连分数与收敛子', () => {
  const cf = continuedFraction(355n, 113n);
  assert.equal(cf.length, 3);
  assert.equal(cf[0], 3n);
  assert.equal(cf[1], 7n);
  assert.equal(cf[2], 16n); // 欧几里得展开末项收敛为 16（与 [3;7,15,1] 等价）
  const convs = convergents(cf);
  assert.equal(convs.length, 3);
  assert.equal(convs[0][0], 3n);
  assert.equal(convs[0][1], 1n);
  assert.equal(convs[1][0], 22n);
  assert.equal(convs[1][1], 7n);
  assert.equal(convs[2][0], 355n);
  assert.equal(convs[2][1], 113n);
  // 相邻收敛子行列式 p_i·q_{i+1} - p_{i+1}·q_i = ±1
  assert.equal(convs[0][0] * convs[1][1] - convs[1][0] * convs[0][1], -1n);
  assert.equal(convs[1][0] * convs[2][1] - convs[2][0] * convs[1][1], 1n);
  const zero = continuedFraction(0n, 7n);
  assert.equal(zero.length, 1);
  assert.equal(zero[0], 0n);
});

test('crtPair/crtList 中国剩余定理', () => {
  const pair = crtPair(2n, 3n, 3n, 5n);
  assert.ok(pair !== null);
  assert.equal(pair[0], 8n);
  assert.equal(pair[1], 15n);
  assert.equal(crtPair(1n, 4n, 2n, 6n), null); // 模数非互素
  const merged = crtList([[2n, 3n], [3n, 5n], [2n, 7n]]);
  assert.ok(merged !== null);
  assert.equal(merged[0], 23n);
  assert.equal(merged[1], 105n);
  assert.equal(crtList([]), null);
  assert.equal(crtList([[1n, 4n], [2n, 6n]]), null);
});

// ---- 攻击向量（全部程序化构造） ----

test('wienerAttack 小私钥连分数恢复 d', () => {
  // 构造 d < n^0.25/3：p、q 各 64bit（同量级保证 q < p < 2q），d 取 ~2^28 且与 phi 互素
  let p = randomPrime(64);
  let q = randomPrime(64);
  if (p < q) [p, q] = [q, p];
  const n = p * q;
  const phi = (p - 1n) * (q - 1n);
  let d = nextPrime(1n << 28n);
  while (gcd(d, phi) !== 1n) d = nextPrime(d);
  assert.ok(3n * d < bigintIroot(n, 4)); // 显式验证 Wiener 前提 d < n^0.25/3
  const e = bigintInvMod(d, phi);
  assert.ok(e !== null);
  assert.equal(wienerAttack(e, n), d);
});

test('fermatFactor 近素数分解与迭代上限', () => {
  const p = nextPrime(10n ** 18n + 9n);
  const q = nextPrime(p + 2n);
  assert.ok(q > p);
  const n = p * q;
  const factors = fermatFactor(n);
  assert.ok(factors !== null);
  assert.equal(factors[0] * factors[1], n);
  assert.ok(factors[0] === p || factors[0] === q);
  const small = fermatFactor(21n);
  assert.ok(small !== null);
  assert.equal(small[0], 3n);
  assert.equal(small[1], 7n);
  const square = fermatFactor(289n);
  assert.ok(square !== null);
  assert.equal(square[0], 17n);
  assert.equal(square[1], 17n);
  // 因子相距 ~1e13：所需迭代远超上限 100，应返回 null
  const farP = nextPrime(10n ** 18n + 11n);
  const farQ = nextPrime(farP + 10n ** 13n);
  assert.notEqual(farP, farQ);
  assert.equal(fermatFactor(farP * farQ, 100), null);
});

test('pollardRho Brent 环分解 64bit 半素数', () => {
  const p = nextPrime(2n ** 31n + 12345n);
  const q = nextPrime(2n ** 31n + 987654321n);
  assert.notEqual(p, q);
  const n = p * q;
  const factor = pollardRho(n);
  assert.ok(factor !== null);
  assert.ok(factor === p || factor === q);
  assert.equal(n % factor, 0n);
  assert.equal(pollardRho(p), null); // 素数无分解
  assert.equal(pollardRho(2n ** 64n), 2n); // 偶数直接命中
  assert.equal(pollardRho(15n), 3n);
});

test('pollardPMinus1 幂光滑 p-1 因子分解', () => {
  // 攻击语义 M = lcm(1..B)：只保证命中 p-1 | M 的因子（每个素数幂都 ≤ B 的幂光滑）。
  // 搜索 p = k+1，k = 2^a·3^b·5^c·7^d 且各素数幂 ≤ 10000，k > 2^40。
  let smoothP = 0n;
  const powerLimit = 10_000n;
  const smoothLimit = 1n << 42n;
  outer:
  for (let a = 1n; a <= powerLimit; a *= 2n) {
    for (let b = 1n; b <= powerLimit && a * b <= smoothLimit; b *= 3n) {
      for (let c = 1n; c <= powerLimit && a * b * c <= smoothLimit; c *= 5n) {
        for (let d = 1n; d <= powerLimit && a * b * c * d <= smoothLimit; d *= 7n) {
          const k = a * b * c * d;
          if (k + 1n > 2n ** 40n && bigintIsPrime(k + 1n)) {
            smoothP = k + 1n;
            break outer;
          }
        }
      }
    }
  }
  assert.ok(smoothP > 2n ** 40n);
  const q = nextPrime(2n ** 61n + 1234567n);
  const n = smoothP * q;
  const factor = pollardPMinus1(n); // 默认 B=10000 覆盖 {2,3,5,7}
  assert.ok(factor !== null);
  assert.equal(factor, smoothP); // q-1 不光滑，命中的必是 p
  assert.equal(n % factor, 0n);
});

test('smallPrimeFactor 前 5000 素数试除', () => {
  const q = nextPrime(2n ** 61n + 7n);
  assert.equal(smallPrimeFactor(4999n * q), 4999n); // 4999 在前 5000 素数内
  assert.equal(smallPrimeFactor(2n * q), 2n);
  assert.equal(smallPrimeFactor(4n), 2n);
  assert.equal(smallPrimeFactor(48611n * q), 48611n); // 第 5000 个素数本身
  const big1 = nextPrime(50000n);
  const big2 = nextPrime(big1 + 10000n);
  assert.ok(big1 > 48611n);
  assert.equal(smallPrimeFactor(big1 * big2), null); // 两个因子都超出试除表
  assert.equal(smallPrimeFactor(2n ** 127n - 1n), null); // 大素数无小因子
  assert.equal(smallPrimeFactor(1n), null);
});

test('solvePartialQ dp 泄露遍历 k 恢复 q', () => {
  const e = 65537n;
  const p = nextPrime(2n ** 61n + 123n);
  let q = nextPrime(2n ** 61n + 456789n);
  assert.notEqual(p, q);
  while (gcd(e, (p - 1n) * (q - 1n)) !== 1n) q = nextPrime(q);
  const n = p * q;
  const d = bigintInvMod(e, (p - 1n) * (q - 1n));
  assert.ok(d !== null);
  const dp = d % (p - 1n);
  assert.ok(dp < p - 1n);
  assert.equal(solvePartialQ(dp, n, e), q);
  assert.equal(solvePartialQ(2n, 15n, 3n), null); // 无效 dp
  // 小例：n=55=5·11, e=3, phi=40 → d=27, dp=d mod 4=3；total=8, k=2 → p=5, q=11
  assert.equal(solvePartialQ(3n, 55n, 3n), 11n);
});

test('hastadBroadcast e=3 三模数广播 + CRT 整数开根', () => {
  const e = 3n;
  const seeds = [
    0x9e3779b97f4a7c15n, 0xbf58476d1ce4e5b9n, 0x94d049bb133111ebn,
    0x2545f4914f6cdd1dn, 0x9e3779b185ebca87n, 0x165667b19e3779f9n,
  ];
  const primes = seeds.map(seed => nextPrime(2n ** 127n + (seed & 0xffffffffffffn)));
  const moduli = [primes[0] * primes[1], primes[2] * primes[3], primes[4] * primes[5]];
  assert.equal(gcd(gcd(moduli[0], moduli[1]), moduli[2]), 1n); // 三模数互素前提
  const message = 0x5a5adeadbeefcafen; // ~2^63，m^3 远小于每个 ~2^254 模数
  const records = moduli.map(n => ({ n, c: modPow(message, e, n), e }));
  assert.equal(hastadBroadcast(records), message);
  // 明文立方超过模数乘积：CRT 合并值不再等于 m^3，开根校验失败
  const huge = nextPrime(2n ** 300n);
  const badRecords = moduli.map(n => ({ n, c: modPow(huge, e, n), e }));
  assert.equal(hastadBroadcast(badRecords), null);
  // 指数不一致直接拒绝
  assert.equal(hastadBroadcast([
    { n: moduli[0], c: records[0].c, e: 3n },
    { n: moduli[1], c: records[1].c, e: 5n },
  ]), null);
  assert.equal(hastadBroadcast([]), null);
});

test('commonFactorGcd 共享素因子互解', () => {
  const shared = nextPrime(2n ** 61n + 0x1111n);
  const q1 = nextPrime(2n ** 61n + 0x2222n);
  const q2 = nextPrime(2n ** 61n + 0x3333n);
  assert.notEqual(shared, q1);
  assert.notEqual(shared, q2);
  assert.notEqual(q1, q2);
  const n1 = shared * q1;
  const n2 = shared * q2;
  const e = 65537n;
  const m = 0x666c6167n; // 'flag'
  const c1 = modPow(m, e, n1);
  const c2 = modPow(m, e, n2);
  const hits = Array.from(commonFactorGcd([{ n: n1, e, c: c1 }, { n: n2, e, c: c2 }]));
  assert.equal(hits.length, 2); // 双方各产出一条解密
  const hitA = hits.find(hit => hit.indexA === 0);
  const hitB = hits.find(hit => hit.indexA === 1);
  assert.ok(hitA !== undefined && hitB !== undefined);
  assert.equal(hitA.indexB, 1);
  assert.equal(hitB.indexB, 0);
  assert.equal(hitA.shared, shared);
  assert.equal(hitB.shared, shared);
  assert.equal(hitA.other, q1);
  assert.equal(hitB.other, q2);
  assert.equal(hitA.plain, m);
  assert.equal(hitB.plain, m);
  assert.equal(modPow(c1, hitA.d, n1), m); // 恢复的 d 独立可解密
  // 无共因子的钥匙对不产生任何命中
  const clean1 = nextPrime(2n ** 61n + 0x5555n);
  const clean2 = nextPrime(2n ** 61n + 0x6666n);
  const nClean = clean1 * clean2;
  assert.equal(commonFactorGcd([
    { n: n1, e, c: c1 },
    { n: nClean, e, c: modPow(m, e, nClean) },
  ]).length, 0);
});
