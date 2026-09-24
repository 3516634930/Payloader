// RAR4 条目解压器测试：stored 直取（CRC32 校验/只读红线）、真实压缩样本（libarchive
// 测试集 test_read_format_rar3_lowdist_reset.rar，BSD-2 许可，离线 uudecode 后 base64
// 内嵌——490 字节 RAR3 v29 Huffman-LZ 流，期望内容由 libarchive test_read_format_rar.c
// 给出）、真实 stored 样本（test_read_format_rar.rar，含目录/符号链接条目）、加密/目录/
// 分卷/旧版流/PPM 块标志/METHOD 越界的 unsupported 族、伪加密清位后重解管线、
// 截断容错、UNP_SIZE 炸弹预算、非 RAR4 输入抛错、CRC 不符抛错。
// 合成向量沿用 rar-inspect.test.mjs 的手写头字节工厂（CRC 填真实 CRC32——解压器契约就是校验它）。
import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const srcDir = path.join(projectRoot, 'src');
const { loadModule } = createTsModuleLoader();
const { inspectRar, fixRarPseudoEncryption } =
  loadModule(path.join(srcDir, 'utils', 'ctf', 'rarInspect.ts'));
const { extractRarEntry, RAR_EXTRACT_MAX_OUTPUT } =
  loadModule(path.join(srcDir, 'utils', 'ctf', 'rarExtract.ts'));

// ---- 测试侧 RAR4 造流工厂（与 rar-inspect.test.mjs 同构，增 FILE_CRC/UNP_VER 参数）----

const B = text => Array.from(text, char => char.charCodeAt(0) & 0xff);
const u16 = value => [value & 0xff, (value >> 8) & 0xff];
const u32 = value => [value & 0xff, (value >> 8) & 0xff, (value >> 16) & 0xff, (value >>> 24) & 0xff];
const MARKER = [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00];

// 测试侧独立 CRC32（多项式 0xEDB88320）：造向量时计算真实 FILE_CRC。
const TEST_CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) c = (c & 1) !== 0 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();
const crc32Of = bytes => {
  let c = 0xffffffff;
  for (const byte of bytes) c = TEST_CRC_TABLE[(c ^ byte) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
};

const buildMainHead = ({ flags = 0 } = {}) => [...u16(0x1f3c), 0x73, ...u16(flags), ...u16(13), ...u16(0), ...u32(0)];

const buildFileHead = ({
  name = 'flag.txt',
  data = [],
  method = 0x30,
  flags = 0x0000,
  attr = 0x20,
  hostOs = 2,
  unpSize = null,
  fileCrc = null,
  unpVer = 0x14,
}) => {
  const nameBytes = typeof name === 'string' ? B(name) : name;
  const unp = unpSize ?? data.length;
  const crc = fileCrc ?? crc32Of(data);
  const headSize = 32 + nameBytes.length;
  const head = [
    ...u16(0xabcd), // HEAD_CRC（假值：rarInspect 不校验，与解压器无关）
    0x74, // FILE_HEAD
    ...u16(flags),
    ...u16(headSize),
    ...u32(data.length), // PACK_SIZE
    ...u32(unp), // UNP_SIZE
    hostOs, // HOST_OS：2=Win32 3=Unix
    ...u32(crc), // FILE_CRC（真实值：解压器按它做 CRC32 校验）
    ...u32(0x60000000), // FTIME
    unpVer, // UNP_VER（压缩路径要求 29）
    method, // METHOD
    ...u16(nameBytes.length),
    ...u32(attr),
    ...nameBytes,
  ];
  return [...head, ...data];
};

const buildEndArc = () => [...u16(0x3d41), 0x7b, ...u16(0x0000), ...u16(7)];

const buildRar = parts => Uint8Array.from([...MARKER, ...parts.flat(Infinity)]);

const firstEntry = bytes => inspectRar(bytes).entries[0];

// ---- 真实样本（libarchive 测试集，离线 uudecode 后 base64 内嵌）----

const REAL_STORED_RAR_B64 = [
  'UmFyIRoHAM+QcwAADQAAAAAAAACEUnQgkDIAFAAAABQAAAADQqLIvrd22j4UMAgApIEAAHRlc3QudHh0gAi3dto+t3baPnRlc3Qg',
  'dGV4dCBkb2N1bWVudA0KnS90IJAyAAgAAAAIAAAAA3tEybbRTNg+FDAIAP+hAAB0ZXN0bGlua8AI0UzYPlBf2j50ZXN0LnR4dM3g',
  'dCCQOgAUAAAAFAAAAANCosi+Y3faPhQwEACkgQAAdGVzdGRpclx0ZXN0LnR4dMDMY3faPmN32j50ZXN0IHRleHQgZG9jdW1lbnQN',
  'CqHIdOCQMQAAAAAAAAAAAAMAAAAAY3faPhQwBwDtQQAAdGVzdGRpcsDMY3faPmR32j7m53TgkDYAAAAAAAAAAAADAAAAAJ2r1T4U',
  'MAwA7UEAAHRlc3RlbXB0eWRpcoDMnavVPsVd2j7EPXsAQAcA',
].join('');

const REAL_LZ_RAR_B64 = [
  'UmFyIRoHAM+QcwAADQAAAAAAAABqUXQAgDEA6gEAAEAAAAAD3Dj4bwAAAAAdNREAIAAAAGxvd2Rpc3QtcmVzZXQuYmluERERERER',
  'FVVVVWIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIi',
  'IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm',
  'ZmZmZVVVmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmREREREREREVUREVVVVVVVVVVVVVVVVAAECAwQFBgcICQoLDA0ODxARE',
  'hMUFRYXGBkaGxwdHh8gISIjJCUmJ/IcvkO/1YBERERERERVVVVViIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIi',
  'IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiImZmZmZm',
  'ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmVVVZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZkRERERERER',
  'FVERFVVVVVVVVVVVVVVVfIcBQUlRWWFpcXmBiZGZoam3VMQ9ewBABwA=',
].join('');

const realStoredRar = Uint8Array.from(Buffer.from(REAL_STORED_RAR_B64, 'base64'));
const realLzRar = Uint8Array.from(Buffer.from(REAL_LZ_RAR_B64, 'base64'));

// libarchive test_read_format_rar.c 中 test_read_format_rar3_lowdist_reset 的期望输出。
const LOWDIST_EXPECTED = Uint8Array.from([
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
  0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x0d, 0x0e,
  0x0f, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
]);

// ---- 用例 1：真实 stored 样本（多形态条目 + CRC 隐式通过）----

test('extractRarEntry 真实 stored 样本：文件/符号链接解出精确内容，目录返回 null', () => {
  const result = inspectRar(realStoredRar);
  assert.equal(result.version, 'rar4');
  assert.equal(result.entries.length, 5);
  const byName = new Map(result.entries.map(entry => [entry.name, entry]));
  const file = extractRarEntry(realStoredRar, byName.get('test.txt'));
  assert.equal(file.bytes === null, false);
  assert.equal(new TextDecoder().decode(file.bytes), 'test text document\r\n');
  const link = extractRarEntry(realStoredRar, byName.get('testlink'));
  assert.equal(new TextDecoder().decode(link.bytes), 'test.txt', 'Unix 符号链接按存储目标解出');
  const nested = extractRarEntry(realStoredRar, byName.get('testdir\\test.txt'));
  assert.equal(new TextDecoder().decode(nested.bytes), 'test text document\r\n');
  const dir = extractRarEntry(realStoredRar, byName.get('testdir'));
  assert.equal(dir.bytes, null);
  assert.ok(dir.unsupported.includes('目录'), `unsupported=${dir.unsupported}`);
  const emptyDir = extractRarEntry(realStoredRar, byName.get('testemptydir'));
  assert.equal(emptyDir.bytes, null);
});

// ---- 用例 2：真实 RAR3 LZ 压缩样本（ground truth 逐字节比对）----

test('extractRarEntry 真实 LZ 样本（RAR3 v29 流，method 0x35）：64 字节期望值逐字节一致', () => {
  const result = inspectRar(realLzRar);
  assert.equal(result.entries.length, 1);
  const entry = result.entries[0];
  assert.equal(entry.name, 'lowdist-reset.bin');
  assert.equal(entry.method, 0x35);
  assert.equal(entry.packedSize, 490);
  const extracted = extractRarEntry(realLzRar, entry);
  assert.equal(extracted.unsupported, undefined, `unsupported=${extracted.unsupported}`);
  assert.deepEqual(extracted.bytes, LOWDIST_EXPECTED, '与 libarchive 测试源码给出的期望输出逐字节一致（CRC32 亦通过）');
});

// ---- 用例 3：合成 stored 直取 + 只读红线 ----

test('extractRarEntry 合成 stored：内容/CRC 通过，输出为独立副本，输入字节不动', () => {
  const data = B('flag{stored_entry_extraction_ok}');
  const rar = buildRar([buildMainHead(), buildFileHead({ name: 'flag.txt', data }), buildEndArc()]);
  const before = Uint8Array.from(rar);
  const result = extractRarEntry(rar, firstEntry(rar));
  assert.deepEqual(result.bytes, Uint8Array.from(data));
  result.bytes[0] ^= 0xff; // 改输出不得波及输入
  assert.deepEqual(Uint8Array.from(rar), before, '输入只读红线：解压前后原字节完全一致');
  // 空文件 stored：UNP=PACK=0，FILE_CRC 跳过校验
  const empty = buildRar([buildMainHead(), buildFileHead({ name: 'empty.bin', data: [], fileCrc: 0 }), buildEndArc()]);
  const emptyResult = extractRarEntry(empty, firstEntry(empty));
  assert.equal(emptyResult.bytes.length, 0);
});

// ---- 用例 4：加密跳过 + 伪加密清位重解管线（rarInspect 修复器 → 本解压器）----

test('extractRarEntry 加密位：置位条目返回 null 与引导文案，清位修复后同一条目可解出', () => {
  const data = B('pseudo encrypted but really plain');
  const rar = buildRar([buildMainHead(), buildFileHead({ name: 'secret.txt', data, flags: 0x0004, method: 0x30 }), buildEndArc()]);
  const entry = firstEntry(rar);
  assert.equal(entry.encrypted, true);
  const skipped = extractRarEntry(rar, entry);
  assert.equal(skipped.bytes, null);
  assert.ok(skipped.unsupported.includes('fixRarPseudoEncryption'), `unsupported=${skipped.unsupported}`);
  const { fixed } = fixRarPseudoEncryption(rar);
  assert.ok(fixed !== null);
  const repaired = extractRarEntry(fixed, firstEntry(fixed));
  assert.deepEqual(repaired.bytes, Uint8Array.from(data), '伪加密清位 + stored 直取全管线打通');
});

// ---- 用例 5：目录判定三口径均跳过 ----

test('extractRarEntry 目录跳过：Win ATTR 0x10 / Unix ATTR 0x4000 / 尾随分隔符', () => {
  const rar = buildRar([
    buildMainHead(),
    buildFileHead({ name: 'windir\\', data: [], attr: 0x10, hostOs: 2 }),
    buildFileHead({ name: 'unixdir/', data: [], attr: 0x41ed, hostOs: 3 }),
    buildFileHead({ name: 'plaindir\\', data: [], attr: 0x20, hostOs: 2, fileCrc: 0 }),
    buildFileHead({ name: 'file.txt', data: B('hi'), attr: 0x20, hostOs: 2 }),
    buildEndArc(),
  ]);
  const entries = inspectRar(rar).entries;
  assert.equal(entries.length, 4);
  for (const entry of entries) {
    const extracted = extractRarEntry(rar, entry);
    if (entry.isDirectory) {
      assert.equal(extracted.bytes, null, `"${entry.name}" 应跳过`);
      assert.ok(extracted.unsupported.includes('目录'), `unsupported=${extracted.unsupported}`);
    } else {
      assert.deepEqual(extracted.bytes, Uint8Array.from(B('hi')), `"${entry.name}" 应正常解出`);
    }
  }
  assert.equal(entries[0].isDirectory && entries[1].isDirectory && entries[2].isDirectory && !entries[3].isDirectory, true);
});

// ---- 用例 6：截断容错与尺寸不一致 ----

test('extractRarEntry 截断：数据区被切/声明越界抛中文错误，stored 尺寸不一致抛错', () => {
  const data = Array.from({ length: 64 }, (_, index) => index & 0xff);
  const head = buildFileHead({ name: 'trunc.bin', data });
  const full = buildRar([buildMainHead(), head, buildEndArc()]);
  const dataStart = 7 + 13 + (head.length - data.length);
  assert.throws(() => extractRarEntry(full.slice(0, dataStart + 10), firstEntry(full)), /数据区越界/);
  // PACK 与 UNP 不一致（存储条目语义破坏）
  const mismatch = buildRar([
    buildMainHead(),
    buildFileHead({ name: 'bad.bin', data: B('0123456789'), unpSize: 9 }),
    buildEndArc(),
  ]);
  assert.throws(() => extractRarEntry(mismatch, firstEntry(mismatch)), /存储尺寸不一致/);
  // 数据完整时 ENDARC 之后的尾附字节不影响提取
  const junk = Uint8Array.from([...full, 0xde, 0xad, 0xbe, 0xef]);
  const extracted = extractRarEntry(junk, firstEntry(junk));
  assert.deepEqual(extracted.bytes, Uint8Array.from(data));
});

// ---- 用例 7：炸弹预算 ----

test('extractRarEntry 炸弹防护：UNP_SIZE 超 64MB 预算立即抛错，不触碰解压', () => {
  const rar = buildRar([
    buildMainHead(),
    buildFileHead({ name: 'bomb.bin', data: [0x00, 0x01, 0x02, 0x03], method: 0x33, unpVer: 29, unpSize: RAR_EXTRACT_MAX_OUTPUT + 1 }),
    buildEndArc(),
  ]);
  assert.throws(() => extractRarEntry(rar, firstEntry(rar)), /预算超限/);
  const exact = buildRar([
    buildMainHead(),
    buildFileHead({ name: 'edge.bin', data: [0x00], method: 0x30, unpSize: 1 }),
    buildEndArc(),
  ]);
  assert.equal(extractRarEntry(exact, firstEntry(exact)).bytes.length, 1, '等于上限不受影响（stored 单字节）');
});

// ---- 用例 8：非 RAR4 输入抛错 ----

test('extractRarEntry 非 RAR4 输入：PNG/随机字节/RAR5 签名均抛中文错误', () => {
  const png = Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, ...new Array(32).fill(0)]);
  assert.throws(() => extractRarEntry(png, { name: 'x', offset: 0, packedSize: 0, method: 0x30, encrypted: false, isDirectory: false }), /不是 RAR4/);
  const garbage = Uint8Array.from(new Array(64).fill(0x41));
  assert.throws(() => extractRarEntry(garbage, { name: 'x', offset: 0, packedSize: 0, method: 0x30, encrypted: false, isDirectory: false }), /不是 RAR4/);
  const rar5 = Uint8Array.from([0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00, ...new Array(32).fill(0)]);
  assert.throws(() => extractRarEntry(rar5, { name: 'x', offset: 0, packedSize: 0, method: 0x30, encrypted: false, isDirectory: false }), /不是 RAR4/);
  // 签名被改的 SimpleRAR 型：先修签名再解（管线口径）
  const good = buildRar([buildMainHead(), buildFileHead({ name: 'a.txt', data: B('rar sig fix then extract') }), buildEndArc()]);
  const broken = Uint8Array.from(good);
  broken[3] = 0x22;
  assert.throws(() => extractRarEntry(broken, firstEntry(good)), /不是 RAR4/);
});

// ---- 用例 9：unsupported 族（旧版流/PPM 块标志/METHOD 越界/分卷）----

test('extractRarEntry unsupported 族：旧版 UNP_VER/PPM 块标志/METHOD 越界/分卷位', () => {
  const old = buildRar([
    buildMainHead(),
    buildFileHead({ name: 'old.bin', data: [0x00, 0x01], method: 0x33, unpVer: 20, unpSize: 2 }),
    buildEndArc(),
  ]);
  const oldResult = extractRarEntry(old, firstEntry(old));
  assert.equal(oldResult.bytes, null);
  assert.ok(oldResult.unsupported.includes('UNP_VER=20'), `unsupported=${oldResult.unsupported}`);

  // 压缩流首表头最高位为 1 = PPM 块（-m5 best 常见形态）
  const ppm = buildRar([
    buildMainHead(),
    buildFileHead({ name: 'ppm.bin', data: [0x80, 0x00, 0x00, 0x00], method: 0x35, unpVer: 29, unpSize: 4 }),
    buildEndArc(),
  ]);
  const ppmResult = extractRarEntry(ppm, firstEntry(ppm));
  assert.equal(ppmResult.bytes, null);
  assert.ok(ppmResult.unsupported.includes('PPMd'), `unsupported=${ppmResult.unsupported}`);

  const badMethod = buildRar([
    buildMainHead(),
    buildFileHead({ name: 'weird.bin', data: [0x00], method: 0x36, unpSize: 1 }),
    buildEndArc(),
  ]);
  const methodResult = extractRarEntry(badMethod, firstEntry(badMethod));
  assert.equal(methodResult.bytes, null);
  assert.ok(methodResult.unsupported.includes('0x36'), `unsupported=${methodResult.unsupported}`);

  const split = buildRar([
    buildMainHead(),
    buildFileHead({ name: 'vol.bin', data: B('partial'), flags: 0x0002, unpSize: 7 }),
    buildEndArc(),
  ]);
  const splitResult = extractRarEntry(split, firstEntry(split));
  assert.equal(splitResult.bytes, null);
  assert.ok(splitResult.unsupported.includes('分卷'), `unsupported=${splitResult.unsupported}`);
});

// ---- 用例 10：CRC32 校验失败抛错（数据被篡改）----

test('extractRarEntry CRC 校验：stored 数据改动 1 字节即抛中文错误并给出两侧 CRC', () => {
  const rar = buildRar([buildMainHead(), buildFileHead({ name: 'tamper.txt', data: B('integrity check payload') }), buildEndArc()]);
  const tampered = Uint8Array.from(rar);
  const entry = firstEntry(rar);
  const headSize = rar[entry.offset + 5] | (rar[entry.offset + 6] << 8);
  tampered[entry.offset + headSize] ^= 0x01; // 切进数据区第一个字节
  assert.throws(() => extractRarEntry(tampered, entry), /CRC32 校验失败/);
});

// ---- 用例 11：真实 LZ 样本数据区位翻转的稳健性（抛错，不静默给出错误数据）----

test('extractRarEntry LZ 流损坏稳健性：位翻转要么受控报错要么解出仍与真值一致，绝不静默给错数据', () => {
  const entry = inspectRar(realLzRar).entries[0];
  const dataStart = entry.offset + (realLzRar[entry.offset + 5] | (realLzRar[entry.offset + 6] << 8));
  let controlled = 0;
  let intact = 0;
  // 逐位翻转压缩流前 3 个字节：允许两类结局——受控中文错误（流损坏/截断/CRC），
  // 或翻转位恰好语义无影响（如首表头 keep-old 位：首次旧表本就全零）而解出与真值一致；
  // 第三类"解出错误数据"必须为零（CRC32 拦截）。
  for (let probe = 0; probe < 24; probe += 1) {
    const corrupted = Uint8Array.from(realLzRar);
    corrupted[dataStart + probe] ^= 0x01 << (probe % 8);
    try {
      const result = extractRarEntry(corrupted, entry);
      if (result.bytes === null) {
        controlled += 1; // unsupported（如翻出 PPM 块标志）同样算受控
        continue;
      }
      assert.deepEqual(result.bytes, LOWDIST_EXPECTED, `probe=${probe} 解出与真值不一致（CRC 拦截应在此之前生效）`);
      intact += 1;
    } catch (error) {
      // 沙箱跨 realm：错误对象不是主 realm 的 Error 实例（AGENTS.md 踩坑记录），按 message 鸭子判断
      const message = typeof error?.message === 'string' ? error.message : String(error);
      if (!/损坏|截断|校验失败|预算|越界|不支持/.test(message)) throw error;
      controlled += 1;
    }
  }
  assert.equal(controlled + intact, 24, '24 个位翻转样本全部有受控结局');
  assert.ok(controlled >= 16, `至少大多数翻转被拦截（实际 controlled=${controlled}, intact=${intact}）`);
});
