// ZipCrypto 已知明文攻击（Biham-Kocher）测试：向量全部由测试侧独立 ZipCrypto 加密器程序化构造
// （与 zip-brute.test.mjs 同语义），ground truth 由 stateAfter 直接前推计算，不依赖外部样本。
// 向量工程说明：攻击按 z 值升序扫描根候选，本文件用确定性口令搜索（约 3 万次、几十毫秒）构造
// "内部状态 z7 极小"的向量，使真根位于扫描最前端——测试验证的是攻击正确性与端到端链路，
// 随机向量的典型耗时见用例内注释与模块头注释的性能包络。
import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const srcDir = path.join(projectRoot, 'src');
const { loadModule } = createTsModuleLoader();
const { knownPlainTextAttack } = loadModule(path.join(srcDir, 'utils', 'ctf', 'zipKnownPlain.ts'));

// ---- 测试侧基础辅助（独立于被测模块）----

const CRC_TABLE = Array.from({ length: 256 }, (_, index) => {
  let value = index;
  for (let bit = 0; bit < 8; bit += 1) value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
  return value >>> 0;
});

const crcOf = bytes => {
  let crc = 0xffffffff;
  for (const byte of bytes) crc = ((crc >>> 8) ^ CRC_TABLE[(crc ^ byte) & 0xff]) >>> 0;
  return (crc ^ 0xffffffff) >>> 0;
};

const makePrng = seed => {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) | 0;
    let mixed = Math.imul(state ^ (state >>> 15), 1 | state);
    mixed = (mixed + Math.imul(mixed ^ (mixed >>> 7), 61 | mixed)) ^ mixed;
    return ((mixed ^ (mixed >>> 14)) >>> 0) / 4294967296;
  };
};

// ZipCrypto 加密方向（与解密互逆）：cipher = plain ^ stream(pw 状态)
const zipCryptoCrypt = (plain, password) => {
  let k0 = 0x12345678;
  let k1 = 0x23456789;
  let k2 = 0x34567890;
  const update = byte => {
    k0 = ((k0 >>> 8) ^ CRC_TABLE[(k0 ^ byte) & 0xff]) >>> 0;
    k1 = (Math.imul(k1 + (k0 & 0xff), 134775813) + 1) >>> 0;
    k2 = ((k2 >>> 8) ^ CRC_TABLE[(k2 ^ ((k1 >>> 24) & 0xff)) & 0xff]) >>> 0;
  };
  const stream = () => {
    const temp = (k2 | 2) & 0xffff;
    return ((temp * (temp ^ 1)) >>> 8) & 0xff;
  };
  for (let index = 0; index < password.length; index += 1) update(password.charCodeAt(index) & 0xff);
  const out = new Uint8Array(plain.length);
  for (let index = 0; index < plain.length; index += 1) {
    const p = plain[index] & 0xff;
    out[index] = p ^ stream();
    update(p);
  }
  return out;
};

// ground truth：口令 init 后逐字节前推得到任意位置的三把 keys
const stateAfter = (password, plainBytes) => {
  let x = 0x12345678;
  let y = 0x23456789;
  let z = 0x34567890;
  const update = byte => {
    x = ((x >>> 8) ^ CRC_TABLE[(x ^ byte) & 0xff]) >>> 0;
    y = (Math.imul(y + (x & 0xff), 134775813) + 1) >>> 0;
    z = ((z >>> 8) ^ CRC_TABLE[(z ^ ((y >>> 24) & 0xff)) & 0xff]) >>> 0;
  };
  for (let index = 0; index < password.length; index += 1) update(password.charCodeAt(index) & 0xff);
  for (const byte of plainBytes) update(byte);
  return [x, y, z];
};

// 条目向量：12 字节加密头（末 1-2 字节按 flag bit3 填校验字节）+ stored 数据全加密
const buildVector = ({ content, password, flagBits = 0x0001, time = 0x0000 }) => {
  const crc = crcOf(content);
  const prng = makePrng(0x5eedc0de);
  const header = Array.from({ length: 12 }, () => (prng() * 256) | 0);
  if ((flagBits & 0x0008) !== 0) header[11] = (time >>> 8) & 0xff;
  else {
    header[10] = (crc >>> 16) & 0xff;
    header[11] = (crc >>> 24) & 0xff;
  }
  const cipher = zipCryptoCrypt(Uint8Array.from([...header, ...content]), password);
  return { cipher, content: Uint8Array.from(content), header, crc, flagBits };
};

// 确定性口令搜索：使"窗口第 8 字节处的真 z"（攻击根）尽量小 → 真根位于升序扫描最前端
// offset 表示已知明文在数据段的起点：根位于 data[offset+7] 之前的状态
const findEarlyRootPassword = (header, content, offset = 0, threshold = 0x40000, maxTries = 400000) => {
  const prefix = [...header, ...content.slice(0, offset + 7)];
  for (let index = 0; index < maxTries; index += 1) {
    const password = `Pw${index}#kpa`;
    const z = stateAfter(password, prefix)[2] >>> 0;
    if (z >>> 0 < threshold) return password;
  }
  throw new Error('early-root 口令搜索失败：请调大 maxTries');
};

// PNG 结构化内容：magic + IHDR 长度/类型 + 宽高位深 + flag 文本 + 伪随机填充
const PNG_MAGIC = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
const IHDR_HEAD = [0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00];
const FLAG_TEXT = 'flag{bk_z1pcryp70_kpa_w1n_green_secret}';
const buildPngLikeContent = (length = 88) => Uint8Array.from([
  ...PNG_MAGIC,
  ...IHDR_HEAD,
  ...Array.from(FLAG_TEXT, char => char.charCodeAt(0) & 0xff),
  ...Array.from({ length: Math.max(0, length - 8 - 16 - FLAG_TEXT.length) }, (_, index) => (index * 37 + 11) & 0xff),
]);
// 另一条目的文本型内容（JFIF 头风格）
const buildTextLikeContent = (length = 88) => Uint8Array.from([
  ...Array.from('JFIF\x00\x01\x02known-prefix-abcdef', char => char.charCodeAt(0) & 0xff),
  ...Array.from({ length: Math.max(0, length - 27) }, (_, index) => (index * 29 + 7) & 0xff),
]);

// ---- 用例 ----

test('① 8 字节 PNG 头（数据段恰 8 字节）：恢复一致 keys + 全文解出 + 20s 红线', () => {
  const content = Uint8Array.from(PNG_MAGIC);
  const { cipher } = buildVector({ content, password: 'N0tInDict#8byte' });
  const result = knownPlainTextAttack(cipher, content);
  assert.notEqual(result.keys, null, '8 字节已知明文应给出一组与全部已知字节一致的 keys');
  assert.equal(result.keys.length, 3);
  for (const key of result.keys) assert.ok(Number.isInteger(key) && key >= 0 && key <= 0xffffffff, 'keys 应为 32 位无符号整数');
  assert.deepStrictEqual(Array.from(result.plaintext), Array.from(content), '数据段恰为已知明文：全文解出 = PNG 头 8 字节');
  assert.ok(result.tried > 0);
  assert.ok(result.elapsedMs <= 20000, `8 字节攻击耗时 ${result.elapsedMs}ms 超过 20s 红线`);
  // 8 字节为 BK 下限：96 位内部状态 vs ~53 位 keystream 约束，数学上存在海量一致 keys，
  // 启发式返回其中一组（对本向量即完全正确的一组——数据段再无其他字节可解）；唯一恢复见 ②
});

test('② 88 字节已知明文：keys 与 ground truth 逐位一致 + 条目全文解密', () => {
  const content = buildPngLikeContent(88);
  const password = findEarlyRootPassword(buildVector({ content, password: 'probe' }).header, content);
  assert.ok(password.startsWith('Pw'), `口令搜索应返回确定结果，得到 ${password}`);
  const { cipher, header } = buildVector({ content, password });
  const result = knownPlainTextAttack(cipher, content, { timeBudgetMs: 120000 });
  assert.deepStrictEqual(Array.from(result.keys), stateAfter(password, header), '88 字节已知明文应唯一恢复窗口起点三 keys');
  assert.deepStrictEqual(Array.from(result.plaintext), Array.from(content), '全文应与原始内容逐字节一致');
  assert.ok(result.elapsedMs <= 120000);
  console.log(`  88 字节已知明文攻击耗时 ${result.elapsedMs}ms（tried=${result.tried}）`);
});

test('③ 错误明文（改 1 字节）→ 预算内无解：keys=null / plaintext=null', () => {
  const content = buildPngLikeContent(88);
  const password = findEarlyRootPassword(buildVector({ content, password: 'x' }).header, content);
  const { cipher } = buildVector({ content, password });
  const poisoned = content.slice(0, 88);
  poisoned[20] ^= 0x5a;
  const result = knownPlainTextAttack(cipher, poisoned, { timeBudgetMs: 8000 });
  assert.equal(result.keys, null, '错误明文不应产出任何通过全部约束的 keys');
  assert.equal(result.plaintext, null);
  assert.ok(result.tried > 0);
  assert.ok(result.elapsedMs < 30000, '错误明文用例应在预算内快速返回');
});

test('④ 超小 timeBudgetMs：扫描被预算截断，tried>0 且 keys=null，onProgress 单调回报', () => {
  const content = buildPngLikeContent(88);
  const { cipher } = buildVector({ content, password: 'BudgetCut#7' });
  const seen = [];
  const result = knownPlainTextAttack(cipher, content.slice(0, 88), {
    timeBudgetMs: 25,
    onProgress: tried => seen.push(tried),
  });
  assert.equal(result.keys, null, '预算耗尽时应中断并返回 null');
  assert.ok(result.tried > 0, `tried=${result.tried} 应大于 0`);
  assert.ok(result.elapsedMs < 5000, '超小预算应快速返回');
  for (let index = 1; index < seen.length; index += 1) assert.ok(seen[index] >= seen[index - 1], '进度回调 tried 应单调不减');
});

test('⑤ 跨条目 keys 不可复用 + offset 中段已知明文：同口令两条目各自恢复各自的窗口状态', () => {
  const password = 'SamePwDiffEntry';
  const contentA = buildPngLikeContent(88);
  const contentB = buildTextLikeContent(88);
  const vectorA = buildVector({ content: contentA, password });
  const vectorB = buildVector({ content: contentB, password });
  const pwA = findEarlyRootPassword(vectorA.header, contentA);
  const pwB = findEarlyRootPassword(vectorB.header, contentB, 6);
  const searchedA = buildVector({ content: contentA, password: pwA });
  const searchedB = buildVector({ content: contentB, password: pwB });
  // 条目 A：offset 0
  const resultA = knownPlainTextAttack(searchedA.cipher, contentA, { timeBudgetMs: 120000 });
  assert.deepStrictEqual(Array.from(resultA.keys), stateAfter(pwA, searchedA.header));
  assert.deepStrictEqual(Array.from(resultA.plaintext), Array.from(contentA));
  // 条目 B：offset 6，已知明文从数据段第 6 字节开始（keys 返回 12+6 处状态，明文仍覆盖全数据段）
  const resultB = knownPlainTextAttack(searchedB.cipher, contentB.slice(6), {
    offset: 6,
    timeBudgetMs: 120000,
  });
  assert.deepStrictEqual(Array.from(resultB.keys), stateAfter(pwB, [...searchedB.header, ...contentB.slice(0, 6)]));
  assert.deepStrictEqual(Array.from(resultB.plaintext), Array.from(contentB));
  // 两条目口令相同但各自独立 init：keys 互不相同
  assert.notDeepStrictEqual(Array.from(resultA.keys), Array.from(resultB.keys), '同口令不同条目的内部 keys 应互不相同');
});

test('⑥ 加密头校验字节路径：CRC32 高 2 字节作为等效已知明文参与终验（错误校验字节 → null）', () => {
  const content = buildPngLikeContent(86);
  const probe = buildVector({ content, password: 'x' });
  const password = findEarlyRootPassword(probe.header, content);
  const { cipher, header, crc } = buildVector({ content, password });
  assert.equal(header[10], (crc >>> 16) & 0xff);
  assert.equal(header[11], (crc >>> 24) & 0xff);
  const result = knownPlainTextAttack(cipher, content, {
    timeBudgetMs: 120000,
    checkByte10: (crc >>> 16) & 0xff,
    checkByte11: (crc >>> 24) & 0xff,
  });
  assert.deepStrictEqual(Array.from(result.keys), stateAfter(password, header), '86 字节明文 + 2 校验字节应精确恢复');
  assert.deepStrictEqual(Array.from(result.plaintext), Array.from(content));
  console.log(`  86+2 校验字节攻击耗时 ${result.elapsedMs}ms`);
  // 校验字节错误：终验拦截，预算内无解
  const rejected = knownPlainTextAttack(cipher, content, {
    timeBudgetMs: 8000,
    checkByte11: ((crc >>> 24) & 0xff) ^ 0xff,
  });
  assert.equal(rejected.keys, null, '错误校验字节应把候选全部拦下');
});

test('⑦ 防呆：明文不足 8 字节 / 密文过短 / 非法 offset / 非法预算 抛中文错误', () => {
  const content = buildPngLikeContent(88);
  const { cipher } = buildVector({ content, password: 'Guard#1' });
  assert.throws(() => knownPlainTextAttack(cipher, content.slice(0, 7)), /不足.*8 字节/);
  assert.throws(() => knownPlainTextAttack(cipher.slice(0, 19), content.slice(0, 8)), /密文长度不足/);
  assert.throws(() => knownPlainTextAttack(cipher, content.slice(0, 8), { offset: -1 }), /offset/);
  assert.throws(() => knownPlainTextAttack(cipher, content.slice(0, 8), { timeBudgetMs: -5 }), /timeBudgetMs/);
  assert.throws(() => knownPlainTextAttack(cipher, content.slice(0, 8), { offset: 1000 }), /密文长度不足/);
});
