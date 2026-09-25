// RAR3 密码爆破引擎测试：三类向量 + 单元基础件。
// —— 向量一（真实 WinRAR 产物）：libarchive 测试集 test_read_format_rar_encryption_data.rar
//    （uu 内嵌于 helpers/rar-test-vectors.mjs，口令 "12345678" 出处 test_read_format_rar_encryption_data.c）：
//    quick check 对/错口令矩阵、字典爆破命中并回传解压内容、解密后清位克隆接 rarExtract
//    真实 RAR3 LZ 解压 + CRC 闭环（foo.txt → "data of foo.txt\n"）。
// —— 向量二（真实产物）：test_read_format_rar4_encrypted.rar（b.txt 口令 "password" / d.txt 口令
//    "password2"，出处 test_read_format_rar_encryption.c）：部分加密档案的探测/字典命中/自定义候选
//    命中/闭环解压（"This is from b.txt"），并回归结构早筛误报被解压 CRC 终验否决
//    （"1111111" 在 b.txt 上能骗过首块 Huffman 结构检查，但必须被第二段否决）。
// —— 向量三（自造对称向量）：测试侧工厂构造带 salt 的存储条目加密 RAR（AES-128-CBC 加密方向用
//    node:crypto 独立 oracle，派生用被测模块——自洽性闭环；对外正确性由向量一/二的真实产物背书），
//    加密→爆破→命中→解密→round-trip→rarExtract 存储路径 + 尾块零填充早筛（unpSize%16≠0）。
// —— 单元：SHA-1 对 node:crypto 独立 oracle（空/边界 55-64-65/1M 多块）、AES-128 FIPS-197 C.1
//    块向量 + CBC 五块往返、deriveRar3Keys salt 长度守卫与确定性、探测/爆破的错误路径族
//    （非 RAR/RAR5/无加密条目/伪加密无盐/数据截断/20MB 上限/零预算）与 onProgress 阶段推进。
// node:vm 跨 realm 说明：加载器沙箱注入宿主 Uint8Array，被测模块产物均为宿主类型数组，
// 直接 Buffer.from/下标消费即可；自定义候选传宿主数组（Array.isArray 跨 realm 可靠）。
import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import crypto from 'node:crypto';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';
import { encryptionDataRar, rar4EncryptedRar } from './helpers/rar-test-vectors.mjs';

const srcDir = path.join(projectRoot, 'src');
const { loadModule } = createTsModuleLoader();
const { sha1Bytes, deriveRar3Keys, checkRar3Password, decryptRar3Stream, aes128CbcDecrypt } = loadModule(
  path.join(srcDir, 'utils', 'ctf', 'rarCrypt.ts'),
);
const { detectRarEncryptedEntries, bruteRarPassword, decryptRarEncryptedEntry, RAR_BRUTE_MAX_INPUT } = loadModule(
  path.join(srcDir, 'utils', 'ctf', 'rarBrute.ts'),
);
const { extractRarEntry } = loadModule(path.join(srcDir, 'utils', 'ctf', 'rarExtract.ts'));
const { inspectRar } = loadModule(path.join(srcDir, 'utils', 'ctf', 'rarInspect.ts'));

// ---- 测试侧基础辅助 ----

const toHex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
const latin1 = (text) => Uint8Array.from(Array.from(text, (ch) => ch.charCodeAt(0) & 0xff));
const u16 = (value) => [value & 0xff, (value >> 8) & 0xff];
const u32 = (value) => [value & 0xff, (value >> 8) & 0xff, (value >> 16) & 0xff, (value >>> 24) & 0xff];
const MARKER = [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00];

const TEST_CRC_TABLE = Array.from({ length: 256 }, (_, n) => {
  let value = n;
  for (let bit = 0; bit < 8; bit += 1) value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
  return value >>> 0;
});
const crc32Of = (bytes) => {
  let c = 0xffffffff;
  for (const byte of bytes) c = TEST_CRC_TABLE[(c ^ byte) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
};

// 测试侧独立参考实现：rarfile `rar3_s2k_core` 直译（Python→JS，markokr/rarfile
// src/rarfile/crypto.py）。与 src 的 unrar 口径移植构成两条独立路径，必须逐字节一致；
// SHA-1 主体用 node:crypto（Hash.copy() 快照等价 Python hashlib 的 digest 后继续 update），
// 仅 rar3_corrupt_block 块变异手工移植。覆盖长口令（种子 >64 字节触发变异分支——
// 口令 ≥29 字符；真实 fixture 口令均短，该分支只有本交叉验证能锚定）。
const refRar3S2k = (password, salt) => {
  const rotl32ref = (value, count) => ((value << count) | (value >>> (32 - count))) >>> 0;
  const utf16le = [];
  const limit = Math.min(password.length, 128);
  for (let i = 0; i < limit; i += 1) {
    utf16le.push(password.charCodeAt(i) & 0xff, (password.charCodeAt(i) >> 8) & 0xff);
  }
  const seed = Uint8Array.from([...utf16le, ...salt]);
  const seedLength = seed.length;
  const seedBuf = new Uint8Array(seedLength + 3);
  seedBuf.set(seed, 0);
  const corruptBlockRef = (pos) => {
    const readBe = (i) =>
      ((seedBuf[pos + i * 4] << 24) | (seedBuf[pos + i * 4 + 1] << 16) | (seedBuf[pos + i * 4 + 2] << 8) | seedBuf[pos + i * 4 + 3]) >>> 0;
    let a = readBe(0), b = readBe(1), c = readBe(2), d = readBe(3), e = readBe(4), f = readBe(5), g = readBe(6), h = readBe(7);
    let i2 = readBe(8), j = readBe(9), k = readBe(10), l = readBe(11), m = readBe(12), n = readBe(13), o = readBe(14), p = readBe(15);
    for (let round = 0; round < 4; round += 1) {
      let x = n ^ i2 ^ c ^ a; a = rotl32ref(x, 1);
      x = o ^ j ^ d ^ b; b = rotl32ref(x, 1);
      x = p ^ k ^ e ^ c; c = rotl32ref(x, 1);
      x = a ^ l ^ f ^ d; d = rotl32ref(x, 1);
      x = b ^ m ^ g ^ e; e = rotl32ref(x, 1);
      x = c ^ n ^ h ^ f; f = rotl32ref(x, 1);
      x = d ^ o ^ i2 ^ g; g = rotl32ref(x, 1);
      x = e ^ p ^ j ^ h; h = rotl32ref(x, 1);
      x = f ^ a ^ k ^ i2; i2 = rotl32ref(x, 1);
      x = g ^ b ^ l ^ j; j = rotl32ref(x, 1);
      x = h ^ c ^ m ^ k; k = rotl32ref(x, 1);
      x = i2 ^ d ^ n ^ l; l = rotl32ref(x, 1);
      x = j ^ e ^ o ^ m; m = rotl32ref(x, 1);
      x = k ^ f ^ p ^ n; n = rotl32ref(x, 1);
      x = l ^ g ^ a ^ o; o = rotl32ref(x, 1);
      x = m ^ h ^ b ^ p; p = rotl32ref(x, 1);
    }
    const putLe = (idx, v) => {
      seedBuf[pos + idx * 4] = v & 0xff;
      seedBuf[pos + idx * 4 + 1] = (v >>> 8) & 0xff;
      seedBuf[pos + idx * 4 + 2] = (v >>> 16) & 0xff;
      seedBuf[pos + idx * 4 + 3] = v >>> 24;
    };
    putLe(0, a); putLe(1, b); putLe(2, c); putLe(3, d); putLe(4, e); putLe(5, f); putLe(6, g); putLe(7, h);
    putLe(8, i2); putLe(9, j); putLe(10, k); putLe(11, l); putLe(12, m); putLe(13, n); putLe(14, o); putLe(15, p);
  };
  const hasher = crypto.createHash('sha1');
  const iv = new Uint8Array(16);
  let counter = 0;
  let nbytes = 0;
  for (let i = 0; i < 16; i += 1) {
    seedBuf[seedLength + 2] = (counter >> 16) & 0xff;
    for (let j = 0; j < 0x4000; j += 1) {
      const bufpos = nbytes & 63;
      nbytes += seedLength + 3;
      seedBuf[seedLength] = counter & 0xff;
      seedBuf[seedLength + 1] = (counter >> 8) & 0xff;
      counter += 1;
      hasher.update(seedBuf);
      if (seedLength > 64) {
        let dpos = 64 - bufpos;
        while (dpos + 64 <= seedLength) {
          corruptBlockRef(dpos);
          dpos += 64;
        }
      }
      if (j === 0) iv[i] = hasher.copy().digest()[19];
    }
  }
  const digest = hasher.digest();
  const key = new Uint8Array(16);
  for (let w = 0; w < 4; w += 1) {
    for (let b = 0; b < 4; b += 1) key[w * 4 + b] = digest[w * 4 + 3 - b];
  }
  return { key, iv };
};

// 闭环提取：解密 → 克隆档案清加密位（0x0004）→ 压缩条目原样放回解密流（LZ 解码到结束标志
// 自然停，尾块零填充不读）；存储条目重写 PACK_SIZE=UNP_SIZE 并裁掉填充 → rarExtract 校验 CRC。
const closedLoopExtract = (bytes, entry, password) => {
  const plain = decryptRarEncryptedEntry(bytes, entry, password);
  assert.notEqual(plain, null);
  const clone = bytes.slice();
  const flags = clone[entry.offset + 3] | (clone[entry.offset + 4] << 8);
  const cleared = flags & ~0x0004;
  clone[entry.offset + 3] = cleared & 0xff;
  clone[entry.offset + 4] = (cleared >> 8) & 0xff;
  if (entry.method === 0x30) {
    clone.set(u32(entry.unpSize), entry.offset + 7);
    clone.set(plain.subarray(0, entry.unpSize), entry.dataOffset);
  } else {
    clone.set(plain, entry.dataOffset);
  }
  const reinspect = inspectRar(clone);
  return extractRarEntry(clone, reinspect.entries.find((item) => item.name === entry.name));
};

// 测试侧加密方向工厂（存储条目）：头布局对齐 rarInspect 注释（SALT 0x400 时名区后随 8 字节盐，
// 均在 HEAD_SIZE 内）；AES-128-CBC 加密用 node:crypto 独立实现，明文零填充到 16 对齐
// （WinRAR 加密侧口径——存储条目 quick check 的尾块零填充早筛即依赖它）。
const buildEncryptedStoredRar = ({ name = 'flag.txt', content, password, salt }) => {
  const contentBytes = typeof content === 'string' ? latin1(content) : content;
  const saltBytes = typeof salt === 'string' ? latin1(salt) : salt;
  assert.equal(saltBytes.length, 8);
  const unpSize = contentBytes.length;
  const paddedLength = Math.max(16, Math.ceil(unpSize / 16) * 16);
  const padded = new Uint8Array(paddedLength);
  padded.set(contentBytes);
  const keys = deriveRar3Keys(password, saltBytes);
  const cipher = crypto.createCipheriv('aes-128-cbc', Buffer.from(keys.aesKey), Buffer.from(keys.iv));
  cipher.setAutoPadding(false);
  const cipherBytes = Uint8Array.from(Buffer.concat([cipher.update(Buffer.from(padded)), cipher.final()]));
  const nameBytes = latin1(name);
  const headSize = 32 + nameBytes.length + 8;
  const head = [
    ...u16(0), 0x74, ...u16(0x8000 | 0x0400 | 0x0004), ...u16(headSize),
    ...u32(cipherBytes.length), ...u32(unpSize), 2, ...u32(crc32Of(contentBytes)), ...u32(0),
    20, 0x30, ...u16(nameBytes.length), ...u32(0x20),
    ...nameBytes, ...saltBytes,
  ];
  const mainHead = [...u16(0x1f3c), 0x73, ...u16(0), ...u16(13), ...u16(0), ...u32(0)];
  const endArc = [...u16(0x3dc4), 0x7b, ...u16(0x4000), ...u16(7), ...u16(0), ...u32(0)];
  return Uint8Array.from([...MARKER, ...mainHead, ...head, ...cipherBytes, ...endArc]);
};

// ---- 单元：纯 JS SHA-1（node:crypto 独立 oracle） ----

test('sha1Bytes 与 node:crypto SHA-1 逐字节一致（空/边界块长/多块/1M）', () => {
  const inputs = [
    '',
    'abc',
    'a'.repeat(55),
    'a'.repeat(56),
    'a'.repeat(57),
    'a'.repeat(63),
    'a'.repeat(64),
    'a'.repeat(65),
    'a'.repeat(119),
    'a'.repeat(120),
    'a'.repeat(128),
    'x'.repeat(1000),
    'a'.repeat(1000000),
  ];
  for (const input of inputs) {
    const expected = crypto.createHash('sha1').update(input, 'latin1').digest('hex');
    assert.equal(toHex(sha1Bytes(latin1(input))), expected, `长度 ${input.length} 不一致`);
  }
  // NIST CAVP 固定向量双保险（不依赖运行时 oracle 的静态锚点）
  assert.equal(toHex(sha1Bytes(latin1('abc'))), 'a9993e364706816aba3e25717850c26c9cd0d89d');
  assert.equal(toHex(sha1Bytes(latin1(''))), 'da39a3ee5e6b4b0d3255bfef95601890afd80709');
});

// ---- 单元：AES-128 ----

test('aes128CbcDecrypt 命中 FIPS-197 附录 C.1 单块向量', () => {
  const key = Uint8Array.from('2b7e151628aed2a6abf7158809cf4f3c'.match(/../g), (h) => parseInt(h, 16));
  const cipher = Uint8Array.from('3ad77bb40d7a3660a89ecaf32466ef97'.match(/../g), (h) => parseInt(h, 16));
  const plain = aes128CbcDecrypt(key, new Uint8Array(16), cipher);
  assert.equal(toHex(plain), '6bc1bee22e409f96e93d7e117393172a');
});

test('aes128CbcDecrypt 与 node:crypto AES-128-CBC 五块往返（CBC 链路正确）', () => {
  const key = Uint8Array.from(crypto.randomBytes(16));
  const iv = Uint8Array.from(crypto.randomBytes(16));
  const plain = Uint8Array.from(crypto.randomBytes(80));
  const cipher = crypto.createCipheriv('aes-128-cbc', Buffer.from(key), Buffer.from(iv));
  cipher.setAutoPadding(false);
  const cipherBytes = Uint8Array.from(Buffer.concat([cipher.update(Buffer.from(plain)), cipher.final()]));
  const decrypted = aes128CbcDecrypt(key, iv, cipherBytes);
  assert.equal(decrypted.length, 80);
  assert.deepEqual(Array.from(decrypted), Array.from(plain));
});

test('aes128CbcDecrypt 对非法密钥/IV 抛错', () => {
  const data = new Uint8Array(16);
  assert.throws(() => aes128CbcDecrypt(new Uint8Array(15), new Uint8Array(16), data), /16 字节/);
  assert.throws(() => aes128CbcDecrypt(new Uint8Array(16), new Uint8Array(8), data), /16 字节/);
});

// ---- 单元：RAR3 密钥派生 ----

test('deriveRar3Keys salt 长度守卫与确定性', () => {
  const salt = Uint8Array.from('4f03bcd9d6164cdf'.match(/../g), (h) => parseInt(h, 16));
  const keys = deriveRar3Keys('12345678', salt);
  assert.notEqual(keys, null);
  assert.equal(keys.aesKey.length, 16);
  assert.equal(keys.iv.length, 16);
  const again = deriveRar3Keys('12345678', salt);
  assert.equal(toHex(again.aesKey), toHex(keys.aesKey));
  assert.equal(toHex(again.iv), toHex(keys.iv));
  assert.notEqual(toHex(keys.aesKey), toHex(deriveRar3Keys('12345679', salt).aesKey));
  // 无盐派生合法（老式口令混合形态）；长度 1-7/9 一律 null
  assert.notEqual(deriveRar3Keys('pw', new Uint8Array(0)), null);
  for (const length of [1, 2, 7, 9, 16]) {
    assert.equal(deriveRar3Keys('pw', new Uint8Array(length)), null, `salt 长度 ${length} 应返回 null`);
  }
});

test('deriveRar3Keys 与 rarfile 参考实现逐字节一致（含长口令 corrupt-block 分支）', () => {
  const salt = Uint8Array.from('deadbeefcafebabe'.match(/../g), (h) => parseInt(h, 16));
  const noSalt = new Uint8Array(0);
  // 种子 2*len+8 字节：28 字符=64（不触发变异）、29/40/128 字符（>64 触发）、
  // 空口令/短口令/无盐/非 ASCII 口令（UTF-16 双字节高字节路径）
  const cases = [
    ['', salt],
    ['a', salt],
    ['12345678', salt],
    ['p'.repeat(28), salt],
    ['p'.repeat(29), salt],
    ['long-password-0123456789abcdef-xyz', salt],
    ['x'.repeat(128), salt],
    ['x'.repeat(200), salt], // 超 128 字符截断
    ['密码口令', salt],
    ['abc', noSalt],
  ];
  for (const [password, saltBytes] of cases) {
    const mine = deriveRar3Keys(password, saltBytes);
    const reference = refRar3S2k(password, saltBytes);
    assert.equal(toHex(mine.aesKey), toHex(reference.key), `口令 "${password.slice(0, 12)}" 密钥不一致`);
    assert.equal(toHex(mine.iv), toHex(reference.iv), `口令 "${password.slice(0, 12)}" IV 不一致`);
  }
});

// ---- 向量一：真实 WinRAR 产物（口令 "12345678"） ----

test('向量一 detectRarEncryptedEntries：两加密条目与加密要素逐字段正确', () => {
  const bytes = encryptionDataRar();
  const entries = detectRarEncryptedEntries(bytes);
  assert.equal(entries.length, 2);
  const [foo, bar] = entries;
  assert.equal(foo.name, 'foo.txt');
  assert.equal(toHex(foo.salt), '4f03bcd9d6164cdf');
  assert.equal(foo.headSize, 47);
  assert.equal(foo.dataOffset, 20 + 47);
  assert.equal(foo.packedSize, 32);
  assert.equal(foo.unpSize, 16);
  assert.equal(foo.fileCrc, 0xa6ad865c);
  assert.equal(foo.unpVer, 29);
  assert.equal(foo.method, 0x33);
  assert.equal(foo.encrypted, true);
  assert.equal(bar.name, 'bar.txt');
  assert.equal(toHex(bar.salt), '4f03bcd9d6164cdf');
  assert.equal(bar.fileCrc, 0xcd90e2be);
});

test('向量一 checkRar3Password：正确口令命中、近似口令全拒', () => {
  const bytes = encryptionDataRar();
  const [foo, bar] = detectRarEncryptedEntries(bytes);
  assert.equal(checkRar3Password(bytes, foo, '12345678'), true);
  assert.equal(checkRar3Password(bytes, bar, '12345678'), true);
  for (const wrong of ['123456', '1234567', '123456789', '1234567890', 'password', '87654321', '000000', '']) {
    assert.equal(checkRar3Password(bytes, foo, wrong), false, `"${wrong}" 应被快筛拒绝`);
  }
});

test('向量一 bruteRarPassword：内置字典命中 "12345678"，进度回调推进，回传解压内容', async () => {
  const bytes = encryptionDataRar();
  const progresses = [];
  const hit = await bruteRarPassword(bytes, { onProgress: (p) => progresses.push(p) });
  assert.notEqual(hit, null);
  assert.equal(hit.password, '12345678');
  assert.ok(hit.tried > 0 && hit.tried <= 40, `字典内位置合理（实际 ${hit.tried}）`);
  assert.equal(Buffer.from(hit.content).toString('latin1'), 'data of foo.txt\n');
  assert.ok(progresses.length >= 1, '至少一次进度回报');
  assert.ok(progresses.every((p) => p.tried > 0));
  assert.ok(progresses.some((p) => p.password === '12345678' || p.tried >= 1));
  const first = progresses[0];
  assert.equal(first.stage, 'dictionary');
  assert.equal(first.password, null);
});

test('向量一 闭环：解密 → 清位 → rarExtract 真实 RAR3 LZ 解压 + CRC 校验出原文', () => {
  const bytes = encryptionDataRar();
  const [foo, bar] = detectRarEncryptedEntries(bytes);
  const fooResult = closedLoopExtract(bytes, foo, '12345678');
  assert.equal(fooResult.unsupported, undefined);
  assert.equal(Buffer.from(fooResult.bytes).toString('latin1'), 'data of foo.txt\n');
  const barResult = closedLoopExtract(bytes, bar, '12345678');
  assert.equal(Buffer.from(barResult.bytes).toString('latin1'), 'data of bar.txt\n');
  // 错误口令解密出的流喂给解压器必须 CRC 失败（快筛误报兜底演示：结构早筛已拒绝的口令
  // 即使强行走解压也过不了 CRC 终验）
  const plain = decryptRarEncryptedEntry(bytes, foo, '123456789');
  const clone = bytes.slice();
  const flags = clone[foo.offset + 3] | (clone[foo.offset + 4] << 8);
  const cleared = flags & ~0x0004;
  clone[foo.offset + 3] = cleared & 0xff;
  clone[foo.offset + 4] = (cleared >> 8) & 0xff;
  clone.set(plain, foo.dataOffset);
  const reinspect = inspectRar(clone);
  assert.throws(
    () => extractRarEntry(clone, reinspect.entries.find((item) => item.name === 'foo.txt')),
    /CRC32 校验失败|RAR LZ 流损坏|截断/,
  );
});

// ---- 向量二：真实产物部分加密（b.txt "password" / d.txt "password2"） ----

test('向量二 探测/字典命中/自定义候选命中/闭环解压', async () => {
  const bytes = rar4EncryptedRar();
  const entries = detectRarEncryptedEntries(bytes);
  // node:vm 跨 realm：沙箱 .map() 产物是沙箱 Array，宿主侧 Array.from 转换后再断言
  assert.deepEqual(Array.from(entries, (e) => e.name), ['b.txt', 'd.txt']);
  assert.equal(toHex(entries[0].salt), 'be021b9a792a8a55');
  assert.equal(entries[0].unpSize, 18);
  // d.txt 口令不在内置字典：自定义候选数组路径（宿主数组跨 realm 消费），命中回传解压内容
  const customProgresses = [];
  const dHit = await bruteRarPassword(bytes, {
    entry: entries[1],
    candidates: ['password', 'password1', 'password2'],
    onProgress: (p) => customProgresses.push(p),
  });
  assert.notEqual(dHit, null);
  assert.equal(dHit.password, 'password2');
  assert.equal(dHit.tried, 3);
  assert.equal(Buffer.from(dHit.content).toString('latin1'), 'This is from d.txt');
  assert.ok(customProgresses.some((p) => p.stage === 'custom'));
  // b.txt 口令在内置字典：默认两段式流程命中
  const bHit = await bruteRarPassword(bytes, { entry: entries[0] });
  assert.notEqual(bHit, null);
  assert.equal(bHit.password, 'password');
  assert.ok(bHit.tried <= 60, `字典内位置合理（实际 ${bHit.tried}）`);
  assert.equal(Buffer.from(bHit.content).toString('latin1'), 'This is from b.txt');
  // 结构早筛误报回归："1111111" 在 b.txt 上能通过首块 Huffman 结构检查（实测确定性命中），
  // 但第二段 rarExtract 解压 CRC 终验必须否决它，爆破继续直到真口令
  const falsePositiveRejected = await bruteRarPassword(bytes, {
    entry: entries[0],
    candidates: ['1111111', 'password'],
  });
  assert.notEqual(falsePositiveRejected, null);
  assert.equal(falsePositiveRejected.password, 'password');
  assert.equal(falsePositiveRejected.tried, 2);
  // 近似口令快筛全拒
  for (const wrong of ['password1', 'password123', 'Password', 'drowssap']) {
    assert.equal(checkRar3Password(bytes, entries[0], wrong), false, `"${wrong}" 应被快筛拒绝`);
    assert.equal(checkRar3Password(bytes, entries[1], wrong), false);
  }
  // 闭环：b.txt 真实 RAR3 LZ 解压出原文
  const bResult = closedLoopExtract(bytes, entries[0], 'password');
  assert.equal(Buffer.from(bResult.bytes).toString('latin1'), 'This is from b.txt');
});

// ---- 向量三：自造对称向量（存储条目，node:crypto 独立加密方向） ----

test('向量三 加密→爆破→解密→round-trip→rarExtract 存储路径 + 零填充早筛', async () => {
  const salt = Uint8Array.from('0011223344556677'.match(/../g), (h) => parseInt(h, 16));
  const content = 'flag{rar3_kdf_round_trip}';
  const password = 's3cret!';
  const bytes = buildEncryptedStoredRar({ content, password, salt });
  const entries = detectRarEncryptedEntries(bytes);
  assert.equal(entries.length, 1);
  assert.equal(entries[0].name, 'flag.txt');
  assert.equal(entries[0].method, 0x30);
  assert.equal(entries[0].unpSize, 25); // % 16 = 9 → 尾块零填充早筛路径生效
  assert.equal(entries[0].packedSize, 32);
  // 爆破：错误候选全拒，正确口令命中
  const hit = await bruteRarPassword(bytes, { candidates: ['wrong', '123456', 'flag', password] });
  assert.notEqual(hit, null);
  assert.equal(hit.password, password);
  assert.equal(hit.tried, 4);
  assert.equal(Buffer.from(hit.content).toString('latin1'), content);
  for (const wrong of ['wrong', '123456', 'flag', 's3cret', 's3cret!!']) {
    assert.equal(checkRar3Password(bytes, entries[0], wrong), false, `"${wrong}" 应被拒绝`);
  }
  // 解密 round-trip（含尾块零填充裁剪）
  const plain = decryptRarEncryptedEntry(bytes, entries[0], password);
  assert.equal(Buffer.from(plain.subarray(0, 25)).toString('latin1'), content);
  // 闭环走 rarExtract 存储路径（CRC 终验）
  const result = closedLoopExtract(bytes, entries[0], password);
  assert.equal(Buffer.from(result.bytes).toString('latin1'), content);
});

test('向量三 数字掩码段：默认两段流程（字典耗尽后）命中 1 位数字口令', async () => {
  const salt = Uint8Array.from('8899aabbccddeeff'.match(/../g), (h) => parseInt(h, 16));
  const bytes = buildEncryptedStoredRar({ content: '7', password: '7', salt });
  const progresses = [];
  const hit = await bruteRarPassword(bytes, { onProgress: (p) => progresses.push(p) });
  assert.notEqual(hit, null);
  assert.equal(hit.password, '7');
  assert.equal(Buffer.from(hit.content).toString('latin1'), '7');
  assert.ok(hit.tried > 165, `掩码段命中必须先耗尽字典（实际 ${hit.tried}）`);
  assert.ok(progresses.some((p) => p.stage === 'dictionary'), '字典阶段有进度回报');
  assert.ok(progresses.some((p) => p.stage === 'mask'), '掩码阶段有进度回报');
  assert.ok(progresses.some((p) => p.password === '7'), '命中时进度回报带口令');
});

// ---- 错误路径族 ----

test('detectRarEncryptedEntries/bruteRarPassword 错误路径族', async () => {
  // 非 RAR 输入
  assert.throws(() => detectRarEncryptedEntries(new Uint8Array(32)), /不是 RAR 文件/);
  // RAR5 签名
  const rar5 = Uint8Array.from([...MARKER.slice(0, 6), 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
  assert.throws(() => detectRarEncryptedEntries(rar5), /RAR5/);
  // 无加密条目（自造明文存储档案；marker 7 字节 + 主头 13 字节 → 文件头起于偏移 20）
  const salt = Uint8Array.from('0011223344556677'.match(/../g), (h) => parseInt(h, 16));
  const encrypted = buildEncryptedStoredRar({ content: 'plain', password: 'x', salt });
  const plainClone = encrypted.slice();
  const flags = plainClone[20 + 3] | (plainClone[20 + 4] << 8);
  const cleared = flags & ~0x0004;
  plainClone[20 + 3] = cleared & 0xff;
  plainClone[20 + 4] = (cleared >> 8) & 0xff;
  assert.throws(() => detectRarEncryptedEntries(plainClone), /未发现 RAR3 加密条目/);
  // 伪加密形态（置加密位但清 SALT 位）
  const pseudo = encrypted.slice();
  const pseudoFlags = pseudo[20 + 3] | (pseudo[20 + 4] << 8);
  const noSalt = pseudoFlags & ~0x0400;
  pseudo[20 + 3] = noSalt & 0xff;
  pseudo[20 + 4] = (noSalt >> 8) & 0xff;
  assert.throws(() => detectRarEncryptedEntries(pseudo), /伪加密/);
  // 数据区越界（截断：去掉末尾 20 字节，吃进声明的加密数据区）
  const truncated = encrypted.slice(0, encrypted.length - 20);
  assert.throws(() => detectRarEncryptedEntries(truncated), /截断|越界/);
  // 20MB 上限
  const oversized = new Uint8Array(RAR_BRUTE_MAX_INPUT + 1);
  oversized.set(MARKER, 0);
  assert.throws(() => detectRarEncryptedEntries(oversized), /20MB/);
  await assert.rejects(() => bruteRarPassword(oversized), /20MB/);
  // 零时间预算：候选未耗尽时立即止步返回 null
  const noHit = await bruteRarPassword(encryptionDataRar(), { timeBudgetMs: 0 });
  assert.equal(noHit, null);
  // 非法预算参数
  await assert.rejects(() => bruteRarPassword(encryptionDataRar(), { timeBudgetMs: -1 }), /timeBudgetMs/);
});

test('decryptRar3Stream 边界：不足一块返回 null，非 16 对齐只解完整块', () => {
  const salt = new Uint8Array(8);
  assert.equal(decryptRar3Stream(new Uint8Array(0), 'pw', salt), null);
  assert.equal(decryptRar3Stream(new Uint8Array(15), 'pw', salt), null);
  const partial = new Uint8Array(33);
  const out = decryptRar3Stream(partial, 'pw', salt);
  assert.notEqual(out, null);
  assert.equal(out.length, 32);
});
