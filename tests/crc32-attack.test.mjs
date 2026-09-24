// CRC32 冲突爆破（meet-in-the-middle）与 ZIP 伪加密修复测试。
// 全部向量程序化构造（独立逐位 CRC 参考实现 + 手工拼最小 ZIP 字节流）；
// 沙箱导出的数组/对象先经 Array.from / JSON 往返转主 realm 再 deepStrictEqual（node:vm 跨 realm 原型差异）。
import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const srcDir = path.join(projectRoot, 'src');
const { loadModule } = createTsModuleLoader();
const {
  crc32BytesOf,
  crc32Combine,
  findCrc32Preimages,
  fixZipPseudoEncryption,
  crc32AttackReport,
  PRINTABLE_ASCII_CHARSET,
} = loadModule(path.join(srcDir, 'utils', 'codec', 'crc32Attack.ts'));

const toBytes = text => new Uint8Array(Array.from(text, char => char.charCodeAt(0) & 0xff));
const concatBytes = (left, right) => {
  const out = new Uint8Array(left.length + right.length);
  out.set(left, 0);
  out.set(right, left.length);
  return out;
};

// 独立参考实现：不查表、逐位移位，用于交叉验证 crc32Table 查表路径
const referenceCrc32 = bytes => {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) crc = crc & 1 ? (crc >>> 1) ^ 0xedb88320 : crc >>> 1;
  }
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

const randomFrom = (prng, alphabet, length) => Array.from({ length }, () => alphabet[(prng() * alphabet.length) | 0]).join('');
const FULL_BYTE_CHARSET = Array.from({ length: 256 }, (_, index) => String.fromCharCode(index)).join('');

// ---- 最小 ZIP 构造（stored 条目，无压缩；flags 可分别指定 local / central） ----

const le16 = value => [value & 0xff, (value >> 8) & 0xff];
const le32 = value => [value & 0xff, (value >> 8) & 0xff, (value >> 16) & 0xff, (value >>> 24) & 0xff];

const buildZip = entries => {
  const localParts = [];
  const centralParts = [];
  let offset = 0;
  for (const entry of entries) {
    const nameBytes = Array.from(Buffer.from(entry.name, 'latin1'));
    const dataBytes = Array.from(Buffer.from(entry.data, 'latin1'));
    const crc = crc32BytesOf(new Uint8Array(dataBytes));
    const local = [
      ...le32(0x04034b50), ...le16(20), ...le16(entry.localFlag), ...le16(0), ...le16(0), ...le16(0),
      ...le32(crc), ...le32(dataBytes.length), ...le32(dataBytes.length),
      ...le16(nameBytes.length), ...le16(0), ...nameBytes,
    ];
    const central = [
      ...le32(0x02014b50), ...le16(20), ...le16(20), ...le16(entry.centralFlag), ...le16(0), ...le16(0), ...le16(0),
      ...le32(crc), ...le32(dataBytes.length), ...le32(dataBytes.length),
      ...le16(nameBytes.length), ...le16(0), ...le16(0), ...le16(0), ...le16(0), ...le32(0),
      ...le32(offset), ...nameBytes,
    ];
    localParts.push([...local, ...dataBytes]);
    centralParts.push(central);
    offset += local.length + dataBytes.length;
  }
  const centralSize = centralParts.reduce((sum, part) => sum + part.length, 0);
  const eocd = [
    ...le32(0x06054b50), ...le16(0), ...le16(0),
    ...le16(entries.length), ...le16(entries.length),
    ...le32(centralSize), ...le32(offset), ...le16(0),
  ];
  return new Uint8Array(localParts.flat().concat(centralParts.flat(), eocd));
};

// ---- CRC32 基础向量 ----

test('crc32BytesOf 与标准向量及独立逐位参考实现对拍', () => {
  assert.equal(crc32BytesOf(toBytes('123456789')), 0xcbf43926);
  assert.equal(crc32BytesOf(toBytes('a')), 0xe8b7be43);
  assert.equal(crc32BytesOf(new Uint8Array(0)), 0);
  const prng = makePrng(0xfeedface);
  for (let round = 0; round < 30; round += 1) {
    const length = (prng() * 64) | 0;
    const bytes = new Uint8Array(Array.from({ length }, () => (prng() * 256) | 0));
    assert.equal(crc32BytesOf(bytes), referenceCrc32(bytes));
  }
});

// ---- crc32Combine 矩阵法 ----

test('crc32Combine 与整串 CRC 恒等（随机切分 + 零字节后缀 + lenB=0 退化）', () => {
  const prng = makePrng(0xc0ffee11);
  for (let round = 0; round < 40; round += 1) {
    const left = randomFrom(prng, PRINTABLE_ASCII_CHARSET, 1 + ((prng() * 12) | 0));
    const right = randomFrom(prng, PRINTABLE_ASCII_CHARSET, 1 + ((prng() * 12) | 0));
    const leftCrc = crc32BytesOf(toBytes(left));
    const rightCrc = crc32BytesOf(toBytes(right));
    assert.equal(crc32Combine(leftCrc, rightCrc, right.length), crc32BytesOf(toBytes(left + right)));
    // 线性映射 Z 满足 Z(0)=0：combine(0, x, n) === x，间接校验矩阵法与零字节语义一致
    assert.equal(crc32Combine(0, rightCrc, right.length), rightCrc);
  }
  const zeros = new Uint8Array(5);
  const flagCrc = crc32BytesOf(toBytes('flag'));
  assert.equal(crc32Combine(flagCrc, crc32BytesOf(zeros), 5), crc32BytesOf(concatBytes(toBytes('flag'), zeros)));
  assert.equal(crc32Combine(0x12345678, 0x9abcdef0, 0), (0x12345678 ^ 0x9abcdef0) >>> 0);
});

// ---- 原像爆破：各长度找回 ----

test('len=2：95² 暴力路径直接命中随机 2 字符串', () => {
  const prng = makePrng(0x2c0de);
  for (let round = 0; round < 5; round += 1) {
    const secret = randomFrom(prng, PRINTABLE_ASCII_CHARSET, 2);
    const crc = crc32BytesOf(toBytes(secret));
    const solutions = Array.from(findCrc32Preimages(crc, 2));
    assert.ok(solutions.includes(secret), `secret=${JSON.stringify(secret)}, solutions=${JSON.stringify(solutions)}`);
    for (const candidate of solutions) assert.equal(crc32BytesOf(toBytes(candidate)), crc);
  }
});

test('len=3：随机可打印串必在解集中', () => {
  const prng = makePrng(0x3eed3eed);
  for (let round = 0; round < 3; round += 1) {
    const secret = randomFrom(prng, PRINTABLE_ASCII_CHARSET, 3);
    const crc = crc32BytesOf(toBytes(secret));
    const solutions = Array.from(findCrc32Preimages(crc, 3));
    assert.ok(solutions.includes(secret), `secret=${JSON.stringify(secret)}, solutions=${JSON.stringify(solutions)}`);
  }
});

test('len=4：随机可打印串找回且全部解 CRC 一致', () => {
  const prng = makePrng(0x4b1d4b1d);
  for (let round = 0; round < 2; round += 1) {
    const secret = randomFrom(prng, PRINTABLE_ASCII_CHARSET, 4);
    const crc = crc32BytesOf(toBytes(secret));
    const solutions = Array.from(findCrc32Preimages(crc, 4));
    assert.ok(solutions.includes(secret), `secret=${JSON.stringify(secret)}, solutions=${JSON.stringify(solutions)}`);
    for (const candidate of solutions) assert.equal(crc32BytesOf(toBytes(candidate)), crc);
  }
});

test('len=5：找回 + 全解校验 + 性能红线 ≤3 秒', () => {
  const prng = makePrng(0x5eed05aa);
  const secret = randomFrom(prng, PRINTABLE_ASCII_CHARSET, 5);
  const crc = crc32BytesOf(toBytes(secret));
  const startedAt = Date.now();
  const solutions = Array.from(findCrc32Preimages(crc, 5));
  const elapsed = Date.now() - startedAt;
  assert.ok(solutions.includes(secret), `secret=${JSON.stringify(secret)}, solutions=${JSON.stringify(solutions)}`);
  for (const candidate of solutions) assert.equal(crc32BytesOf(toBytes(candidate)), crc);
  assert.ok(elapsed <= 3000, `len=5 爆破耗时 ${elapsed}ms 超过 3 秒红线`);
});

// ---- 边界与参数校验 ----

test('长度/目标/上限参数越界抛中文错误', () => {
  const crc = crc32BytesOf(toBytes('abcd'));
  for (const badLength of [0, 1, 6, 7]) {
    assert.throws(() => findCrc32Preimages(crc, badLength), /仅支持长度 2-5/, `length=${badLength} 应抛错`);
  }
  assert.throws(() => findCrc32Preimages(-1, 3), /0 到 0xFFFFFFFF/);
  assert.throws(() => findCrc32Preimages(0x100000000, 3), /0 到 0xFFFFFFFF/);
  assert.throws(() => findCrc32Preimages(crc, 3, '0123456789', 0), /maxSolutions/);
  assert.throws(() => findCrc32Preimages(crc, 3, ''), /字符集为空/);
  assert.throws(() => findCrc32Preimages(crc, 3, 'ab€'), /非 latin1/);
});

test('自定义字符集：4 位纯数字 PIN + 重复字符去重', () => {
  const pin = '0731';
  const crc = crc32BytesOf(toBytes(pin));
  const solutions = Array.from(findCrc32Preimages(crc, 4, '0123456789'));
  assert.ok(solutions.includes(pin), `solutions=${JSON.stringify(solutions)}`);
  for (const candidate of solutions) assert.equal(crc32BytesOf(toBytes(candidate)), crc);
  // 'aabbcc' 去重后等效 {a,b,c}：3 字符集内 'abc' 必命中
  const dedup = Array.from(findCrc32Preimages(crc32BytesOf(toBytes('abc')), 3, 'aabbcc'));
  assert.ok(dedup.includes('abc'), `dedup solutions=${JSON.stringify(dedup)}`);
});

test('全 256 字节域：len=4 仿射双射唯一解；len=5 精确截断到 maxSolutions', () => {
  const prng = makePrng(0xff00ff00);
  // 4 字节消息 → CRC32 是 GF(2) 仿射双射：全字节域内任一目标恰有 1 组解
  const secret4 = randomFrom(prng, FULL_BYTE_CHARSET, 4);
  const crc4 = crc32BytesOf(toBytes(secret4));
  const unique = Array.from(findCrc32Preimages(crc4, 4, FULL_BYTE_CHARSET, 16));
  assert.equal(unique.length, 1);
  assert.equal(unique[0], secret4);
  // 5 字节全字节域内每个目标恰有 2^8=256 组解（固定首字节后余 4 字节双射），
  // 这里验证 maxSolutions 截断语义：恰好返回 16 组且全部 CRC 正确
  const secret5 = randomFrom(prng, FULL_BYTE_CHARSET, 5);
  const crc5 = crc32BytesOf(toBytes(secret5));
  const truncated = Array.from(findCrc32Preimages(crc5, 5, FULL_BYTE_CHARSET, 16));
  assert.equal(truncated.length, 16);
  for (const candidate of truncated) assert.equal(crc32BytesOf(toBytes(candidate)), crc5);
  const single = Array.from(findCrc32Preimages(crc5, 5, FULL_BYTE_CHARSET, 1));
  assert.equal(single.length, 1);
});

// ---- ZIP 伪加密修复 ----

test('ZIP 伪加密：两处 bit0 清零、changes 完整、输入不可变', () => {
  const zipped = buildZip([{ name: 'a.txt', data: 'hello', localFlag: 1, centralFlag: 1 }]);
  const snapshot = Uint8Array.from(zipped);
  const result = fixZipPseudoEncryption(zipped);
  assert.deepEqual(Uint8Array.from(zipped), snapshot);
  assert.notEqual(result.fixed, null);
  const changes = JSON.parse(JSON.stringify(result.changes));
  assert.deepEqual(changes, [
    { offset: 48, field: 'central-directory', before: 1, after: 0 },
    { offset: 6, field: 'local-file-header', before: 1, after: 0 },
  ]);
  const expected = buildZip([{ name: 'a.txt', data: 'hello', localFlag: 0, centralFlag: 0 }]);
  assert.deepEqual(result.fixed, expected);
  assert.equal(result.fixed.length, zipped.length);
});

test('ZIP 伪加密：flag 其他位保留（0x0009 → 0x0008）', () => {
  const zipped = buildZip([{ name: 'a.txt', data: 'hello', localFlag: 0x0009, centralFlag: 0x0009 }]);
  const result = fixZipPseudoEncryption(zipped);
  const changes = JSON.parse(JSON.stringify(result.changes));
  assert.deepEqual(changes, [
    { offset: 48, field: 'central-directory', before: 9, after: 8 },
    { offset: 6, field: 'local-file-header', before: 9, after: 8 },
  ]);
  assert.deepEqual(result.fixed, buildZip([{ name: 'a.txt', data: 'hello', localFlag: 8, centralFlag: 8 }]));
});

test('ZIP 伪加密：单侧置位也成对清零；正常 ZIP 无 changes；垃圾字节 fixed=null', () => {
  // 仅 local 侧置位：CD 的 bit0 也要被清（写 0→0 不记 change）
  const oneSided = fixZipPseudoEncryption(buildZip([{ name: 'a.txt', data: 'hi', localFlag: 1, centralFlag: 0 }]));
  assert.deepEqual(JSON.parse(JSON.stringify(oneSided.changes)), [
    { offset: 6, field: 'local-file-header', before: 1, after: 0 },
  ]);
  assert.deepEqual(oneSided.fixed, buildZip([{ name: 'a.txt', data: 'hi', localFlag: 0, centralFlag: 0 }]));
  // 正常 ZIP：无加密位 → 无 changes，fixed 为等值副本
  const clean = fixZipPseudoEncryption(buildZip([{ name: 'a.txt', data: 'hello', localFlag: 0, centralFlag: 0 }]));
  assert.deepEqual(JSON.parse(JSON.stringify(clean.changes)), []);
  assert.deepEqual(clean.fixed, buildZip([{ name: 'a.txt', data: 'hello', localFlag: 0, centralFlag: 0 }]));
  // 垃圾字节：无 EOCD → fixed=null
  const garbage = fixZipPseudoEncryption(new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0x03]));
  assert.equal(garbage.fixed, null);
  assert.deepEqual(JSON.parse(JSON.stringify(garbage.changes)), []);
});

test('ZIP 伪加密：双条目 ZIP 只修被置位的条目', () => {
  const zipped = buildZip([
    { name: 'a.txt', data: 'hello', localFlag: 0, centralFlag: 0 },
    { name: 'b.txt', data: 'yo', localFlag: 1, centralFlag: 1 },
  ]);
  const result = fixZipPseudoEncryption(zipped);
  const changes = JSON.parse(JSON.stringify(result.changes));
  assert.equal(changes.length, 2);
  assert.deepEqual(new Set(changes.map(change => change.field)), new Set(['central-directory', 'local-file-header']));
  // 第二条目 local 偏移 40（30 头 + 5 名 + 5 数据），其 local flag 在 40+6；CD flag 在 40+37+51+8
  assert.deepEqual(changes, [
    { offset: 40 + 37 + 51 + 8, field: 'central-directory', before: 1, after: 0 },
    { offset: 46, field: 'local-file-header', before: 1, after: 0 },
  ]);
  assert.deepEqual(result.fixed, buildZip([
    { name: 'a.txt', data: 'hello', localFlag: 0, centralFlag: 0 },
    { name: 'b.txt', data: 'yo', localFlag: 0, centralFlag: 0 },
  ]));
});

// ---- 报告入口 ----

test('crc32AttackReport：crc 十六进制/十进制、缺省 length=4、max 截断、charset 含空格', () => {
  const secret = 'aB9z';
  const crc = crc32BytesOf(toBytes(secret));
  const parsed = JSON.parse(crc32AttackReport(`crc=0x${crc.toString(16)}`));
  assert.equal(parsed.target, `0x${crc.toString(16).padStart(8, '0')}`);
  assert.equal(parsed.length, 4);
  assert.equal(parsed.charsetSize, 95);
  assert.ok(parsed.solutions.includes(secret), `solutions=${JSON.stringify(parsed.solutions)}`);
  assert.equal(typeof parsed.elapsedMs, 'number');
  assert.ok(typeof parsed.note === 'string' && parsed.note.length > 0);
  // 十进制 + max 截断
  const limited = JSON.parse(crc32AttackReport(`crc=${crc} length=4 max=2`));
  assert.ok(limited.solutions.length <= 2);
  assert.ok(limited.solutions.includes(secret) || limited.solutions.length === 2);
  // charset 值内部含空格不被误切（'A ' 是 2 字符：A + 空格）
  const spaced = JSON.parse(crc32AttackReport(`crc=${crc32BytesOf(toBytes('A '))} length=2 charset=AB CD`));
  assert.equal(spaced.charsetSize, 5);
  assert.ok(spaced.solutions.includes('A '), `solutions=${JSON.stringify(spaced.solutions)}`);
  // 自定义字符集：4 位 PIN
  const pinCrc = crc32BytesOf(toBytes('0731'));
  const pin = JSON.parse(crc32AttackReport(`crc=0x${pinCrc.toString(16)} length=4 charset=0123456789`));
  assert.equal(pin.charsetSize, 10);
  assert.ok(pin.solutions.includes('0731'));
});

test('crc32AttackReport：zipHex 分支输出 changes 与 fixed 摘要', () => {
  const zipped = buildZip([{ name: 'a.txt', data: 'hello', localFlag: 1, centralFlag: 1 }]);
  const expected = buildZip([{ name: 'a.txt', data: 'hello', localFlag: 0, centralFlag: 0 }]);
  const parsed = JSON.parse(crc32AttackReport(`zipHex=${Buffer.from(zipped).toString('hex')}`));
  assert.equal(parsed.mode, 'zip-pseudo-fix');
  assert.equal(parsed.fixed, true);
  assert.equal(parsed.changeCount, 2);
  assert.equal(parsed.fixedBytes, zipped.length);
  assert.equal(parsed.fixedPreviewHex, Buffer.from(expected).toString('hex').slice(0, 64));
  const garbage = JSON.parse(crc32AttackReport('zipHex=deadbeef00112233'));
  assert.equal(garbage.fixed, false);
  assert.equal(garbage.changeCount, 0);
});

test('crc32AttackReport：非法输入抛中文错误', () => {
  assert.throws(() => crc32AttackReport(''), /输入为空/);
  assert.throws(() => crc32AttackReport('hello world'), /缺少 crc|无法解析/);
  assert.throws(() => crc32AttackReport('crc=0x123456789'), /crc 值非法|32 位/);
  assert.throws(() => crc32AttackReport('crc=99999999999'), /crc 值非法|32 位/);
  assert.throws(() => crc32AttackReport('zipHex=504b0'), /偶数/);
  assert.throws(() => crc32AttackReport('zipHex=50zz80'), /十六进制/);
  assert.throws(() => crc32AttackReport('crc=0x1a2b3c4d length=7'), /仅支持长度 2-5/);
  assert.throws(() => crc32AttackReport('crc=0x1a2b3c4d charset='), /字符集为空/);
  assert.throws(() => crc32AttackReport('crc=0x1a2b3c4d length=abc'), /length 值非法/);
});
