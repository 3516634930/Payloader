// RAR4 取证引擎测试：inspectRar 逐头遍历（条目/偏移/尺寸/目录位/加密位）、伪加密位置位 →
// fixRarPseudoEncryption 清位（卷位不动、逐字节差异仅 flags）、签名损坏（SimpleRAR 型字符位
// 改写/尾字节 0x01/SFX 前缀）→ fixRarSignature 重写、坏头容错（HEAD_SIZE 越界/未知类型/截断）、
// RAR5 与非 RAR 输入。测试向量全部程序化手写头字节（CRC 填假值——引擎契约就是不校验 CRC），
// 数据段任意填充，无外部 fixture。
import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const srcDir = path.join(projectRoot, 'src');
const { loadModule } = createTsModuleLoader();
const { inspectRar, fixRarSignature, fixRarPseudoEncryption } =
  loadModule(path.join(srcDir, 'utils', 'ctf', 'rarInspect.ts'));

// ---- 测试侧 RAR4 造流工厂 ----

const B = text => Array.from(text, char => char.charCodeAt(0) & 0xff);
const u16 = value => [value & 0xff, (value >> 8) & 0xff];
const u32 = value => [value & 0xff, (value >> 8) & 0xff, (value >> 16) & 0xff, (value >>> 24) & 0xff];
const MARKER = [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00];

// 主头：CRC 假值 + 0x73 + flags + SIZE=13 + HIGH_POSAV(2) + POSAV(4)。
const buildMainHead = ({ flags = 0 } = {}) => [...u16(0x1f3c), 0x73, ...u16(flags), ...u16(13), ...u16(0), ...u32(0)];

// 文件头：基区 32 字节（CRC/0x74/flags/SIZE/PACK/UNP/HOST_OS/FILE_CRC/FTIME/UNP_VER/METHOD/
// NAME_SIZE/ATTR）+ 可选 LARGE 高位区（8）+ 名区 + 可选 SALT（8），随后拼数据段。
// 注：文件头语义下 0x0001 是"跨卷前置位"而非通用 LONG_BLOCK（引擎读 PACK_SIZE 不依赖该位，
// 与 unrar 一致），故此处不自动置 0x0001——真实单卷档案的文件头本就不置它。
const buildFileHead = ({ name = 'flag.txt', data = [], method = 0x30, flags = 0x0000, attr = 0x20, hostOs = 2, unpSize = null, large = null, salt = false }) => {
  const nameBytes = typeof name === 'string' ? B(name) : name;
  const unp = unpSize ?? data.length;
  let fullFlags = flags;
  if (large) fullFlags |= 0x0100;
  if (salt) fullFlags |= 0x0400;
  const saltBytes = salt ? [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88] : [];
  const headSize = 32 + (large ? 8 : 0) + nameBytes.length + saltBytes.length;
  const head = [
    ...u16(0xabcd), // HEAD_CRC（假值，引擎不校验）
    0x74, // FILE_HEAD
    ...u16(fullFlags),
    ...u16(headSize),
    ...u32(data.length), // PACK_SIZE 低 32 位
    ...u32(unp), // UNP_SIZE 低 32 位
    hostOs, // HOST_OS：0=MS-DOS 1=OS/2 2=Win32 3=Unix
    ...u32(0xdeadbeef), // FILE_CRC
    ...u32(0x60000000), // FTIME
    0x14, // UNP_VER
    method, // METHOD
    ...u16(nameBytes.length),
    ...u32(attr),
    ...(large ? [...u32(large.highPack ?? 0), ...u32(large.highUnp ?? 0)] : []),
    ...nameBytes,
    ...saltBytes,
  ];
  return [...head, ...data];
};

const buildEndArc = () => [...u16(0x3d41), 0x7b, ...u16(0x0000), ...u16(7)];

const buildRar = parts => Uint8Array.from([...MARKER, ...parts.flat(Infinity)]);

// ---- 用例 1：正常解析（多条目逐头跳进，偏移与造料真值一致）----

test('inspectRar 正常解析：version/条目数/名称/packedSize/method/offset 与造料一致，零 anomalies', () => {
  const data1 = B('CTF packed data for entry one');
  const data2 = B('second entry packed bytes 0123456789');
  const mainHead = buildMainHead();
  const head1 = buildFileHead({ name: 'flag.txt', data: data1, method: 0x33 });
  const head2 = buildFileHead({ name: 'dir\\nested.png', data: data2, method: 0x30 });
  const result = inspectRar(buildRar([mainHead, head1, head2, buildEndArc()]));
  assert.equal(result.version, 'rar4');
  assert.equal(result.entries.length, 2);
  assert.equal(result.entries[0].name, 'flag.txt');
  assert.equal(result.entries[0].offset, 7 + mainHead.length);
  assert.equal(result.entries[0].packedSize, data1.length);
  assert.equal(result.entries[0].method, 0x33);
  assert.equal(result.entries[0].encrypted, false);
  assert.equal(result.entries[0].isDirectory, false);
  assert.equal(result.entries[1].name, 'dir\\nested.png');
  assert.equal(result.entries[1].offset, 7 + mainHead.length + head1.length);
  assert.equal(result.entries[1].packedSize, data2.length);
  assert.equal(result.anomalies.length, 0, `anomalies=${JSON.stringify(result.anomalies)}`);
});

// ---- 用例 2：伪加密置位 → 清位修复（除 flags 低字节外逐字节一致）----

test('fixRarPseudoEncryption 加密位修复：0x0004 置位被标注并清除，其余字节不动', () => {
  const data = B('pseudo encrypted payload bytes');
  const mainHead = buildMainHead();
  const head = buildFileHead({ name: 'secret.txt', data, flags: 0x0004, method: 0x33 });
  const rar = buildRar([mainHead, head, buildEndArc()]);
  const inspected = inspectRar(rar);
  assert.equal(inspected.entries[0].encrypted, true);
  assert.ok(inspected.anomalies.some(note => note.includes('高概率伪加密')), `anomalies=${JSON.stringify(inspected.anomalies)}`);
  const { fixed, changes } = fixRarPseudoEncryption(rar);
  assert.ok(fixed !== null, '应产出修复副本');
  assert.equal(changes.length, 1);
  assert.ok(changes[0].includes('0x0004'), `changes=${JSON.stringify(changes)}`);
  const repaired = inspectRar(fixed);
  assert.equal(repaired.entries[0].encrypted, false);
  assert.ok(!repaired.anomalies.some(note => note.includes('伪加密')));
  // 逐字节差异仅 flags 低字节一处（0x0004 → 0x0000）
  const flagsLowIndex = 7 + mainHead.length + 3;
  let diffCount = 0;
  let diffIndex = -1;
  for (let index = 0; index < rar.length; index += 1) {
    if (rar[index] !== fixed[index]) { diffCount += 1; diffIndex = index; }
  }
  assert.equal(diffCount, 1, `diff 应只有 1 处，实际 ${diffCount}`);
  assert.equal(diffIndex, flagsLowIndex);
  assert.equal(fixed[flagsLowIndex], 0x00);
});

// ---- 用例 3：bit3 口径（0x0008）同清、卷位不动 ----

test('fixRarPseudoEncryption bit3/卷位：0x0008 一并清除，0x0002 卷位保留，遍历不脱轨', () => {
  const head = buildFileHead({ name: 'vol.bin', data: B('volume-data'), flags: 0x0004 | 0x0002 | 0x0008 });
  const rar = buildRar([buildMainHead(), head, buildEndArc()]);
  const { fixed, changes } = fixRarPseudoEncryption(rar);
  assert.ok(fixed !== null);
  assert.ok(changes[0].includes('0x0008'), `changes=${JSON.stringify(changes)}`);
  assert.equal(fixed[7 + 13 + 3], 0x02, '修复后 flags 低字节仅剩 0x0002 卷位');
  const repaired = inspectRar(fixed);
  assert.equal(repaired.entries.length, 1, '清位后逐头遍历仍对齐');
  assert.equal(repaired.entries[0].name, 'vol.bin');
  assert.equal(repaired.entries[0].encrypted, false);
  // 无加密位的文件：不产出修复副本
  const clean = buildRar([buildMainHead(), buildFileHead({ name: 'ok.txt', data: B('x') }), buildEndArc()]);
  const noop = fixRarPseudoEncryption(clean);
  assert.equal(noop.fixed, null);
  assert.equal(noop.changes.length, 0);
});

// ---- 用例 4：签名损坏（SimpleRAR 型）→ fixRarSignature 重写 ----

test('fixRarSignature：可读字符位与尾字节被改均可重写；SFX 前缀丢弃；完好文件返回 null', () => {
  const good = buildRar([
    buildMainHead(),
    buildFileHead({ name: 'a.txt', data: B('abc') }),
    buildFileHead({ name: 'b.txt', data: B('defg') }),
    buildEndArc(),
  ]);
  // 形态一：'Rar!' 可读字符位被改 1-2 字节（SimpleRAR 主形态）
  const charBroken = Uint8Array.from(good);
  charBroken[1] = 0x62; // 'a' → 'b'
  charBroken[4] = 0x1b; // 0x1A → 0x1B
  assert.throws(() => inspectRar(charBroken), /不是 RAR/);
  const charFix = fixRarSignature(charBroken);
  assert.ok(charFix.fixed !== null);
  assert.equal(charFix.changes.length, 1);
  assert.ok(charFix.changes[0].includes('偏移 0'), `changes=${JSON.stringify(charFix.changes)}`);
  const charRepaired = inspectRar(charFix.fixed);
  assert.equal(charRepaired.version, 'rar4');
  assert.equal(charRepaired.entries.length, 2);
  // 形态二：尾字节 0x01（marker SIZE 字段被改，形似 RAR5）——inspect 标注 version null，仍可修
  const tailBroken = Uint8Array.from(good);
  tailBroken[6] = 0x01;
  const tailInspected = inspectRar(tailBroken);
  assert.equal(tailInspected.version, null);
  assert.ok(tailInspected.anomalies.some(note => note.includes('第 7 字节')), `anomalies=${JSON.stringify(tailInspected.anomalies)}`);
  const tailFix = fixRarSignature(tailBroken);
  assert.ok(tailFix.fixed !== null);
  assert.equal(inspectRar(tailFix.fixed).version, 'rar4');
  // 形态三：SFX/附加数据前缀——窗口搜索命中偏移 64，重写并丢弃前缀
  const prefixed = Uint8Array.from([...new Array(64).fill(0x41), ...good]);
  assert.throws(() => inspectRar(prefixed), /不是 RAR/);
  const prefixFix = fixRarSignature(prefixed);
  assert.ok(prefixFix.fixed !== null);
  assert.equal(prefixFix.changes.length, 2);
  assert.ok(prefixFix.changes[0].includes('偏移 64'));
  assert.ok(prefixFix.changes[1].includes('前缀'));
  assert.equal(inspectRar(prefixFix.fixed).entries.length, 2);
  // 完好文件：无需修复
  const intact = fixRarSignature(good);
  assert.equal(intact.fixed, null);
  assert.equal(intact.changes.length, 0);
});

// ---- 用例 5：目录条目（Win 属性位 / Unix 属性位 / 尾随分隔符）----

test('inspectRar 目录判定：Win ATTR 0x10、Unix ATTR 0x4000 与尾随分隔符均识别', () => {
  const result = inspectRar(buildRar([
    buildMainHead(),
    buildFileHead({ name: 'assets\\', data: [], attr: 0x10, hostOs: 2 }),
    buildFileHead({ name: 'home/', data: [], attr: 0x41ed, hostOs: 3 }),
    buildFileHead({ name: 'readme.txt', data: B('hi'), attr: 0x20, hostOs: 2 }),
    buildEndArc(),
  ]));
  assert.equal(result.entries.length, 3);
  assert.equal(result.entries[0].isDirectory, true);
  assert.equal(result.entries[1].isDirectory, true);
  assert.equal(result.entries[2].isDirectory, false);
  assert.equal(result.entries[0].packedSize, 0);
});

// ---- 用例 6：坏头容错（HEAD_SIZE 越界 / 未知类型 / 数据区截断）----

test('inspectRar 坏头容错：坏头之前的条目保留，异常逐项标注且停止遍历', () => {
  const badSizeHead = [...u16(0x1234), 0x74, ...u16(0x0001), ...u16(3), ...new Array(12).fill(0)];
  const sizeBroken = inspectRar(buildRar([
    buildMainHead(),
    buildFileHead({ name: 'keep.txt', data: B('kept') }),
    badSizeHead,
    buildEndArc(),
  ]));
  assert.equal(sizeBroken.entries.length, 1);
  assert.equal(sizeBroken.entries[0].name, 'keep.txt');
  assert.ok(sizeBroken.anomalies.some(note => note.includes('HEAD_SIZE')), `anomalies=${JSON.stringify(sizeBroken.anomalies)}`);
  assert.ok(sizeBroken.anomalies.some(note => note.includes('ENDARC')));

  const unknownHead = [...u16(0x0000), 0x99, ...u16(0x0000), ...u16(7), ...new Array(10).fill(0)];
  const typeBroken = inspectRar(buildRar([
    buildMainHead(),
    buildFileHead({ name: 'keep2.txt', data: B('kept2') }),
    unknownHead,
    buildEndArc(),
  ]));
  assert.equal(typeBroken.entries.length, 1);
  assert.ok(typeBroken.anomalies.some(note => note.includes('未知头类型')), `anomalies=${JSON.stringify(typeBroken.anomalies)}`);

  const data = Array.from({ length: 50 }, (_, index) => index & 0xff);
  const head = buildFileHead({ name: 'trunc.bin', data });
  const full = buildRar([buildMainHead(), head, buildEndArc()]);
  const cut = 7 + 13 + (head.length - data.length) + 10; // 切进数据区第 10 字节
  const truncated = inspectRar(full.slice(0, cut));
  assert.equal(truncated.entries.length, 1);
  assert.equal(truncated.entries[0].packedSize, 50, '截断时 packedSize 仍按声明值记录');
  assert.ok(truncated.anomalies.some(note => note.includes('越过文件末尾')), `anomalies=${JSON.stringify(truncated.anomalies)}`);
});

// ---- 用例 7：非 RAR / RAR5 / LARGE 高位 / SALT 真加密形态 / 双名 ----

test('inspectRar 输入与形态：非 RAR 抛错，RAR5 拒解析，LARGE 合成 64 位，SALT 与双名标注', () => {
  assert.throws(() => inspectRar(Uint8Array.from(new Array(16).fill(0))), /不是 RAR/);
  assert.throws(() => inspectRar(Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, ...new Array(24).fill(0)])), /不是 RAR/);
  assert.throws(() => inspectRar(Uint8Array.from(MARKER.slice(0, 5))), /不是 RAR/);
  const rar5 = Uint8Array.from([0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00, ...new Array(8).fill(0)]);
  const rar5Result = inspectRar(rar5);
  assert.equal(rar5Result.version, null);
  assert.equal(rar5Result.entries.length, 0);
  assert.ok(rar5Result.anomalies.some(note => note.includes('RAR5')));

  const largeResult = inspectRar(buildRar([
    buildMainHead(),
    buildFileHead({ name: 'big.bin', data: [1, 2, 3, 4], unpSize: 0x100, large: { highPack: 1, highUnp: 0 } }),
    buildEndArc(),
  ]));
  assert.equal(largeResult.entries[0].packedSize, 2 ** 32 + 4, 'LARGE 高 32 位合成');
  assert.equal(largeResult.entries[0].name, 'big.bin', 'LARGE 时文件名从 +40 起读');

  const salted = inspectRar(buildRar([
    buildMainHead(),
    buildFileHead({ name: 'real.txt', data: B('cipherdata'), flags: 0x0004, salt: true }),
    buildEndArc(),
  ]));
  assert.equal(salted.entries[0].encrypted, true);
  assert.ok(salted.anomalies.some(note => note.includes('真加密形态')), `anomalies=${JSON.stringify(salted.anomalies)}`);

  const unicode = inspectRar(buildRar([
    buildMainHead(),
    buildFileHead({ name: [...B('name.txt'), 0x00, 0x00, 0x01, 0x02], data: B('u'), flags: 0x0200 }),
    buildEndArc(),
  ]));
  assert.equal(unicode.entries[0].name, 'name.txt', '双名取 NUL 前 ASCII 段');
  assert.ok(unicode.anomalies.some(note => note.includes('Unicode')), `anomalies=${JSON.stringify(unicode.anomalies)}`);

  // 未修复签名时清加密位：直接抛错引导先修签名
  const brokenSig = Uint8Array.from(buildRar([buildMainHead(), buildFileHead({ name: 'x', data: B('y'), flags: 0x0004 }), buildEndArc()]));
  brokenSig[3] = 0x22; // '!' → '"'
  assert.throws(() => fixRarPseudoEncryption(brokenSig), /签名/);
});
