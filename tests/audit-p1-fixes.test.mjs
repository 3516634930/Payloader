// 算法审计 P1 修复回归（2026-09-24 审计报告 algo-correctness-audit-2026-09-24.md）：
// P1-1 RSA Raw 拒绝用未验证分解的 φ=n−1 派生 d（原行为：分解失败把 n 当素数 → 静默乱码明文）
// P1-2 Bech32 segwit 地址剥离 witness version 首词（原行为：P2WPKH/P2WSH 抛 padding 非零、Taproot 错位）
// 向量程序化构造：定长种子 nextPrime 造 95bit 平衡半素数（本地不可分解），对拍 BIP-173 官方向量。
import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const srcDir = path.join(projectRoot, 'src');
const { loadModule } = createTsModuleLoader();
const { rsaRawTransform } = loadModule(path.join(srcDir, 'utils', 'codec', 'rsa.ts'));
const { nextPrime } = loadModule(path.join(srcDir, 'utils', 'codec', 'numberTheory.ts'));
const { decodeBech32 } = loadModule(path.join(srcDir, 'utils', 'codec', 'bases.ts'));

// 95bit 起点定长种子 → p/q 差距大（Fermat 不可解）且 190bit 平衡（Pollard ρ/p−1 本地不可解）。
const p = nextPrime(2n ** 94n + 12345678901n);
const q = nextPrime(2n ** 95n + 98765432107n);
const n = p * q;
const modPow = (base, exp, mod) => { let r = 1n; let b = base % mod; let e = exp; while (e > 0n) { if (e & 1n) r = r * b % mod; b = b * b % mod; e >>= 1n; } return r; };

test('P1-1：本地不可分解的 n + e=65537 拒绝 φ=n−1 派生 d，抛引导性错误而非乱码明文', () => {
  const m = 0xdeadbeefn;
  const c = modPow(m, 65537n, n);
  // 修复前：factorSmallCompositeModulus 返回 [n] → φ=n−1 → derivedD 存在 → 输出 c^(e⁻¹mod(n−1)) 乱码。
  // 修复后：素性检验拒绝该分解 → 无 d → 走到显式错误。
  assert.throws(
    () => rsaRawTransform('decode', `n=${n}\ne=65537\nc=${c}`),
    /requires d, p\/q\/e, low-e exact root, or p\/q\/dp\/dq CRT parameters/,
  );
});

test('P1-1：e=3 未填充小明文在不可分解 n 下仍可恢复（低指数根路径不再被伪 d 短路）', () => {
  const m = 0x4142434445464748n; // m^3 < 190bit n ✓
  const c = modPow(m, 3n, n);
  const result = JSON.parse(rsaRawTransform('decode', `n=${n}\ne=3\nc=${c}`));
  assert.equal(result.attack, 'low-public-exponent exact integer root');
  assert.equal(BigInt(result.output.decimal), m);
});

test('P1-1：可分解玩具 n（p=61,q=53）不受防线影响，正常解密', () => {
  const toyN = 61n * 53n;
  const e = 7n;
  const phi = 60n * 52n;
  let d = 1n;
  while ((e * d) % phi !== 1n) d += 1n;
  const m = 123n;
  const c = modPow(m, e, toyN);
  const result = JSON.parse(rsaRawTransform('decode', `n=${toyN}\ne=${e}\nc=${c}`));
  assert.equal(BigInt(result.output.decimal), m);
});

test('P1-2：BIP-173 官方向量 P2WPKH 剥离 version 0 后程序 20 字节', () => {
  const decoded = JSON.parse(decodeBech32('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'));
  assert.equal(decoded.checksumValid, true);
  assert.equal(decoded.witnessVersion, 0);
  assert.equal(decoded.programBytes, 20);
  assert.equal(decoded.dataHex, '751e76e8199196d454941c45d1b3a323f1433bd6');
});

test('P1-2：Taproot 地址（version 1）程序 32 字节不错位', () => {
  const decoded = JSON.parse(decodeBech32('bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0'));
  assert.equal(decoded.checksumValid, true);
  assert.equal(decoded.witnessVersion, 1);
  assert.equal(decoded.programBytes, 32);
});

test('P1-2：非 segwit hrp 的普通 bech32 不剥离（回归保护）', () => {
  const decoded = JSON.parse(decodeBech32('A12UEL5L'));
  assert.equal(decoded.hrp, 'a');
  assert.equal(decoded.witnessVersion, null);
  assert.equal(decoded.checksumValid, true);
});
