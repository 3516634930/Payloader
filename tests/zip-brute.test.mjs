// ZIP 密码爆破引擎测试：全部加密向量程序化构造（测试侧独立实现 ZipCrypto 加密辅助函数 + WebCrypto 造 AE-2 条目），
// 不依赖外部样本。node:vm 跨 realm 约束：沙箱数组只经下标/方法调用消费（不做宿主 for...of/Array.from/Set 展开），
// 沙箱生成器只通过显式 .next() 驱动（for...of 会查宿主 Symbol.iterator 而拿不到沙箱生成器协议）。
import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { deflateRawSync } from 'node:zlib';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const srcDir = path.join(projectRoot, 'src');
const { loadModule } = createTsModuleLoader();
const { crc32BytesOf } = loadModule(path.join(srcDir, 'utils', 'codec', 'crc32Attack.ts'));
const { detectEncryptedEntries, bruteZipPassword, dictionaryCandidates, maskCandidates } = loadModule(
  path.join(srcDir, 'utils', 'ctf', 'zipBrute.ts'),
);

// ---- 测试侧基础辅助（独立于被测模块：CRC 表本地重建，ZipCrypto 按 APPNOTE XIII 直译） ----

const le16 = value => [value & 0xff, (value >> 8) & 0xff];
const le32 = value => [value & 0xff, (value >> 8) & 0xff, (value >> 16) & 0xff, (value >>> 24) & 0xff];

const CRC_TABLE = Array.from({ length: 256 }, (_, index) => {
  let value = index;
  for (let bit = 0; bit < 8; bit += 1) value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
  return value >>> 0;
});

const toLatin1 = text => Uint8Array.from(Array.from(text, char => char.charCodeAt(0) & 0xff));

const makePrng = seed => {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) | 0;
    let mixed = Math.imul(state ^ (state >>> 15), 1 | state);
    mixed = (mixed + Math.imul(mixed ^ (mixed >>> 7), 61 | mixed)) ^ mixed;
    return ((mixed ^ (mixed >>> 14)) >>> 0) / 4294967296;
  };
};

// ZipCrypto 加密方向：cipher = plain ^ stream(pw 状态)，逐字节 update_keys(plain)——与解密互逆
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

// 最小 ZIP 构造：entry = { name, flag, method, time, crc, data, extra?, usize? }
const buildZip = entries => {
  const localParts = [];
  const centralParts = [];
  let offset = 0;
  for (const entry of entries) {
    const nameBytes = Array.from(Buffer.from(entry.name, 'latin1'));
    const extraBytes = entry.extra ? Array.from(entry.extra) : [];
    const dataBytes = Array.from(entry.data);
    const usize = entry.usize ?? dataBytes.length;
    const local = [
      ...le32(0x04034b50), ...le16(20), ...le16(entry.flag), ...le16(entry.method),
      ...le16(entry.time ?? 0), ...le16(0), ...le32(entry.crc), ...le32(dataBytes.length), ...le32(usize),
      ...le16(nameBytes.length), ...le16(extraBytes.length), ...nameBytes, ...extraBytes, ...dataBytes,
    ];
    const central = [
      ...le32(0x02014b50), ...le16(20), ...le16(20), ...le16(entry.flag), ...le16(entry.method),
      ...le16(entry.time ?? 0), ...le16(0), ...le32(entry.crc), ...le32(dataBytes.length), ...le32(usize),
      ...le16(nameBytes.length), ...le16(extraBytes.length), ...le16(0), ...le16(0), ...le16(0),
      ...le32(0), ...le32(offset), ...nameBytes, ...extraBytes,
    ];
    localParts.push(local);
    centralParts.push(central);
    offset += local.length;
  }
  const centralBytes = centralParts.flat();
  const eocd = [
    ...le32(0x06054b50), ...le16(0), ...le16(0),
    ...le16(entries.length), ...le16(entries.length),
    ...le32(centralBytes.length), ...le32(offset), ...le16(0),
  ];
  return new Uint8Array(localParts.flat().concat(centralBytes, eocd));
};

// ZipCrypto 条目向量：12 字节加密头（末 1-2 字节按 flag bit3 填校验字节）+ 加密数据
const buildZipCryptoEntry = ({
  name = 'flag.txt',
  plain = '',
  password,
  flagBits = 0x0001,
  time = 0x0000,
  method = 0,
  storedCrc = null,
  plainBytes = null,
}) => {
  const content = plainBytes ?? Array.from(toLatin1(plain));
  const crc = storedCrc ?? crc32BytesOf(Uint8Array.from(content));
  const prng = makePrng(0x5eedc0de);
  const header = Array.from({ length: 12 }, () => (prng() * 256) | 0);
  if ((flagBits & 0x0008) !== 0) header[11] = (time >>> 8) & 0xff;
  else {
    header[10] = (crc >>> 16) & 0xff;
    header[11] = (crc >>> 24) & 0xff;
  }
  const data = zipCryptoCrypt(Uint8Array.from([...header, ...content]), password);
  return { name, flag: flagBits, method, time, crc, data, usize: content.length };
};

// WinZip AES（AE-x）stored 条目向量：PBKDF2-HMAC-SHA1×1000 派生 2*keyLen+2，AES-CTR 零计数器，HMAC-SHA1 截 10 字节
const buildAesEntry = async ({ name = 'secret.txt', plain, password, strength = 3, version = 2 }) => {
  const subtle = globalThis.crypto.subtle;
  const saltLength = { 1: 8, 2: 12, 3: 16 }[strength];
  const keyLength = { 1: 16, 2: 24, 3: 32 }[strength];
  const prng = makePrng(0xa55eed01);
  const salt = Uint8Array.from(Array.from({ length: saltLength }, () => (prng() * 256) | 0));
  const encoder = new TextEncoder();
  const baseKey = await subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
  const derived = new Uint8Array(
    await subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-1', iterations: 1000, salt }, baseKey, (keyLength * 2 + 2) * 8),
  );
  const aesKey = await subtle.importKey('raw', derived.slice(0, keyLength), 'AES-CTR', false, ['encrypt']);
  const cipher = new Uint8Array(
    await subtle.encrypt({ name: 'AES-CTR', counter: new Uint8Array(16), length: 64 }, aesKey, encoder.encode(plain)),
  );
  const macKey = await subtle.importKey('raw', derived.slice(keyLength, keyLength * 2), { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const mac = new Uint8Array(await subtle.sign('HMAC', macKey, cipher)).slice(0, 10);
  const data = Uint8Array.from([...salt, ...derived.slice(keyLength * 2, keyLength * 2 + 2), ...cipher, ...mac]);
  const extra = Uint8Array.from([...le16(0x9901), ...le16(7), ...le16(version), 0x41, 0x45, strength, ...le16(0)]);
  return { name, flag: 0x0001, method: 99, crc: 0, data, extra, usize: plain.length };
};

// 沙箱生成器宿主侧驱动：只调用 .next()，不触发宿主 Symbol.iterator 查找
const takeFromGenerator = (generator, count) => {
  const values = [];
  for (let index = 0; index < count; index += 1) {
    const step = generator.next();
    assert.equal(step.done, false, `生成器在第 ${index} 个候选前提前耗尽`);
    values.push(step.value);
  }
  return values;
};

// ---- detectEncryptedEntries ----

test('detectEncryptedEntries：zipcrypto stored 条目字段完整（名称/偏移/大小/CRC/方法）', () => {
  const plain = 'flag{z1pcryp70_he4der}';
  const zip = buildZip([buildZipCryptoEntry({ name: 'flag.txt', plain, password: 'S3cret!' })]);
  const entries = detectEncryptedEntries(zip);
  assert.equal(entries.length, 1);
  const meta = entries[0];
  assert.equal(meta.fileName, 'flag.txt');
  assert.equal(meta.method, 'zipcrypto');
  assert.equal(meta.localHeaderOffset, 0);
  assert.equal(meta.crc32, crc32BytesOf(toLatin1(plain)));
  assert.equal(meta.compressedSize, 12 + plain.length);
});

test('detectEncryptedEntries：混合 ZIP 只列加密条目并正确分型 zipcrypto / aes-256（AE-2 crc=0）', async () => {
  const aesEntry = await buildAesEntry({ name: 'secret.txt', plain: 'flag{aes_256_stored}', password: 'AesM4ster!9', strength: 3 });
  const zip = buildZip([
    { name: 'plain.txt', flag: 0, method: 0, crc: crc32BytesOf(toLatin1('plain data')), data: toLatin1('plain data') },
    buildZipCryptoEntry({ name: 'locked.txt', plain: 'flag{mixed_zipcrypto}', password: 'M1x3d!pw' }),
    aesEntry,
  ]);
  const entries = detectEncryptedEntries(zip);
  assert.equal(entries.length, 2);
  assert.equal(entries[0].fileName, 'locked.txt');
  assert.equal(entries[0].method, 'zipcrypto');
  assert.equal(entries[1].fileName, 'secret.txt');
  assert.equal(entries[1].method, 'aes-256');
  assert.equal(entries[1].crc32, 0); // AE-2 不存 CRC
  assert.ok(entries[1].localHeaderOffset > entries[0].localHeaderOffset);
});

test('detectEncryptedEntries 防呆：非 ZIP / 空条目 / 无加密条目 抛中文错误', () => {
  assert.throws(() => detectEncryptedEntries(new Uint8Array(64).fill(0x41)), /EOCD/);
  const emptyZip = new Uint8Array([
    ...le32(0x06054b50), ...le16(0), ...le16(0), ...le16(0), ...le16(0), ...le32(0), ...le32(0), ...le16(0),
  ]);
  assert.throws(() => detectEncryptedEntries(emptyZip), /条目数为 0/);
  const plainZip = buildZip([{ name: 'a.txt', flag: 0, method: 0, crc: crc32BytesOf(toLatin1('hi')), data: toLatin1('hi') }]);
  assert.throws(() => detectEncryptedEntries(plainZip), /未发现加密条目/);
});

// ---- bruteZipPassword：ZipCrypto 路径 ----

test('bruteZipPassword(zipcrypto)：小字典命中 + preview 含 flag + 命中终值进度回调', async () => {
  const plain = 'flag{z1pcryp70_he4der}';
  const zip = buildZip([buildZipCryptoEntry({ name: 'flag.txt', plain, password: 'S3cret!' })]);
  const [meta] = detectEncryptedEntries(zip);
  const events = [];
  const result = await bruteZipPassword(zip, meta, ['123456', 'password', 'S3cret!', 'ctf2025'], {
    onProgress: progress => events.push(progress),
  });
  assert.equal(result.password, 'S3cret!');
  assert.equal(result.tried, 3);
  assert.equal(result.total, 4);
  assert.equal(result.previewText, plain); // 内容 < 256 字节且全可打印
  assert.equal(events.length, 1); // 未到 512 批次，只有命中终值回调
  assert.equal(events[0].password, 'S3cret!');
});

test('bruteZipPassword(zipcrypto)：字典不含口令 → 错误口令不命中，全扫返回进度', async () => {
  const zip = buildZip([buildZipCryptoEntry({ plain: 'nothing here', password: 'Zz9-quite-hard' })]);
  const [meta] = detectEncryptedEntries(zip);
  const dict = ['123456', 'password', 'ctf', 'flag', 'infected'];
  const result = await bruteZipPassword(zip, meta, dict);
  assert.equal(result.password, null);
  assert.equal(result.previewText, null);
  assert.equal(result.tried, dict.length);
  assert.equal(result.total, dict.length);
});

test('bruteZipPassword：校验字节命中但 CRC 终验失败 → 拒绝（防 2 字节碰撞误报）', async () => {
  const plain = 'flag{crc_gate}';
  const realCrc = crc32BytesOf(toLatin1(plain));
  // 存一个低 16 位不同的坏 CRC：真口令的 12 字节头校验字节按坏 CRC 构造仍会命中，但内容 CRC 对不上
  const poisoned = buildZip([buildZipCryptoEntry({ plain, password: 'TruePw77', storedCrc: (realCrc ^ 0xa5a5) >>> 0 })]);
  const [poisonedMeta] = detectEncryptedEntries(poisoned);
  const rejected = await bruteZipPassword(poisoned, poisonedMeta, ['TruePw77']);
  assert.equal(rejected.password, null);
  assert.equal(rejected.tried, 1);
  // 对照：同内容存回正确 CRC 后即可命中，证明拦截确因 CRC 终验而非其他路径
  const good = buildZip([buildZipCryptoEntry({ plain, password: 'TruePw77' })]);
  const [goodMeta] = detectEncryptedEntries(good);
  const accepted = await bruteZipPassword(good, goodMeta, ['TruePw77']);
  assert.equal(accepted.password, 'TruePw77');
  assert.ok(accepted.previewText.includes('flag{crc_gate}'));
});

test('bruteZipPassword：flag bit3 置位时校验字节走 DOS 时间高字节路径', async () => {
  const plain = 'flag{t1me_b4sed_check}';
  const zip = buildZip([buildZipCryptoEntry({ plain, password: 'Tim3Pw!', flagBits: 0x0009, time: 0x6b5e })]);
  const [meta] = detectEncryptedEntries(zip);
  const result = await bruteZipPassword(zip, meta, ['wrong', 'Tim3Pw!']);
  assert.equal(result.password, 'Tim3Pw!');
  assert.ok(result.previewText.includes('flag{t1me_b4sed_check}'));
});

test('bruteZipPassword：以掩码生成器为候选源找回 4 位纯数字口令（生成器直入，total=Infinity）', async () => {
  const zip = buildZip([buildZipCryptoEntry({ plain: 'flag{mask_0731}', password: '0731' })]);
  const [meta] = detectEncryptedEntries(zip);
  const result = await bruteZipPassword(zip, meta, maskCandidates('0123456789', 1, 4));
  assert.equal(result.password, '0731');
  // 枚举序：len1 共 10 + len2 共 100 + len3 共 1000 + len4 内 '0731' 线性序号 731 → tried = 1942
  assert.equal(result.tried, 10 + 100 + 1000 + 731 + 1);
  assert.equal(result.total, Infinity);
});

test('bruteZipPassword：deflate 条目命中口令并解出明文前缀预览（DecompressionStream deflate-raw）', async () => {
  const plain = 'flag{d3fl4te_h1nt_me}';
  const rawDeflate = Array.from(deflateRawSync(Buffer.from(plain, 'latin1')));
  const entry = buildZipCryptoEntry({
    plainBytes: rawDeflate,
    password: 'Deflate!1',
    method: 8,
    storedCrc: crc32BytesOf(toLatin1(plain)), // CD 里存的是未压缩内容的 CRC
  });
  const zip = buildZip([entry]);
  const [meta] = detectEncryptedEntries(zip);
  const result = await bruteZipPassword(zip, meta, ['Deflate!1']);
  assert.equal(result.password, 'Deflate!1');
  // 批次 KW（TD-批次MISC2-2）：命中后整段解密 + inflate 出明文前缀，不再是"系统解压"提示文案
  assert.ok(result.previewText.includes('flag{d3fl4te_h1nt_me}'));
  assert.ok(!result.previewText.includes('系统解压'));
});

test('快筛误报否决：2 字节碰撞口令的垃圾流被 deflate 结构验证拒绝，继续枚举命中真口令', async () => {
  const plain = 'flag{f4lse_p0s1t1ve_gate}';
  const rawDeflate = Array.from(deflateRawSync(Buffer.from(plain, 'latin1')));
  const realCrc = crc32BytesOf(toLatin1(plain));
  const entry = buildZipCryptoEntry({ plainBytes: rawDeflate, password: 'RealPw42', method: 8, storedCrc: realCrc });
  const zip = buildZip([entry]);
  const [meta] = detectEncryptedEntries(zip);
  // 测试侧暴力找碰撞口令：解出的 12 字节头 [10..11] 恰好撞上 CRC 高 16 位（zipCryptoCrypt 对称可解密）
  const cipherHead = Uint8Array.from(entry.data.slice(0, 12));
  let collision = null;
  for (let index = 0; index < 5000000 && collision === null; index += 1) {
    const pw = `fp${index.toString(36)}`;
    const head = zipCryptoCrypt(cipherHead, pw);
    if (head[10] === ((realCrc >>> 16) & 0xff) && head[11] === ((realCrc >>> 24) & 0xff)) collision = pw;
  }
  assert.notEqual(collision, null, '500 万内未找到 2 字节碰撞口令（期望 ~65536 次命中）');
  // 碰撞口令排真口令之前：快筛命中 → 垃圾流 inflate 失败 → 否决继续 → 真口令命中并出明文预览
  const result = await bruteZipPassword(zip, meta, [collision, 'RealPw42']);
  assert.equal(result.password, 'RealPw42');
  assert.equal(result.tried, 2);
  assert.ok(result.previewText.includes('flag{f4lse_p0s1t1ve_gate}'));
});

// ---- bruteZipPassword：WinZip AES 路径 ----

test('bruteZipPassword(WinZip AES-256)：PBKDF2 + AES-CTR + HMAC 全链路命中并出预览', async () => {
  const entry = await buildAesEntry({ name: 'deep.txt', plain: 'flag{w1nz1p_aes_ctr_hmac}', password: 'Sup3rS3cret!', strength: 3 });
  const zip = buildZip([entry]);
  const [meta] = detectEncryptedEntries(zip);
  const result = await bruteZipPassword(zip, meta, ['123456', 'password', 'ctf2025', 'Sup3rS3cret!', 'infected']);
  assert.equal(result.password, 'Sup3rS3cret!');
  assert.equal(result.tried, 4);
  assert.equal(result.total, 5);
  assert.ok(result.previewText.includes('flag{w1nz1p_aes_ctr_hmac}'));
});

test('bruteZipPassword(WinZip AES-128)：错误口令被 2 字节验证值快速拒绝，末位真口令找回', async () => {
  const entry = await buildAesEntry({ name: 'k.txt', plain: 'flag{aes128_ok}', password: 'N0tInDict#7', strength: 1 });
  const zip = buildZip([entry]);
  const [meta] = detectEncryptedEntries(zip);
  assert.equal(meta.method, 'aes-128');
  const wrong = Array.from({ length: 24 }, (_, index) => `wrong-${index}`);
  const result = await bruteZipPassword(zip, meta, [...wrong, 'N0tInDict#7']);
  assert.equal(result.password, 'N0tInDict#7');
  assert.equal(result.tried, wrong.length + 1);
  assert.ok(result.previewText.includes('flag{aes128_ok}'));
});

test('bruteZipPassword：未知加密类型条目抛中文错误', async () => {
  // flag bit0 + bit6（强加密）且非 method 99 → unknown
  const strongZip = buildZip([{ name: 's.txt', flag: 0x0041, method: 8, crc: 0, data: new Uint8Array(24) }]);
  const [strongMeta] = detectEncryptedEntries(strongZip);
  assert.equal(strongMeta.method, 'unknown');
  await assert.rejects(() => bruteZipPassword(strongZip, strongMeta, ['123456']), /加密类型未知/);
});

// ---- maskCandidates ----

test('maskCandidates：惰性逐位枚举顺序（4 字符集 1..4 取前 256 个）、startIndex 跳跃、字符集去重', () => {
  const generator = maskCandidates('abcd', 1, 4);
  const got = takeFromGenerator(generator, 256);
  // 期望序：独立 odometer 参考实现，长度优先（len1 全部 → len2 全部 → …），同长度按定长逐位进位
  const expected = [];
  const pushProduct = length => {
    const digits = new Array(length).fill(0);
    for (;;) {
      expected.push(digits.map(digit => 'abcd'[digit]).join(''));
      let pos = length - 1;
      while (pos >= 0) {
        digits[pos] += 1;
        if (digits[pos] < 4) break;
        digits[pos] = 0;
        pos -= 1;
      }
      if (pos < 0) return;
    }
  };
  for (let length = 1; length <= 4 && expected.length < 256; length += 1) pushProduct(length);
  assert.deepEqual(got, expected.slice(0, 256));
  assert.deepEqual(got.slice(0, 6), ['a', 'b', 'c', 'd', 'aa', 'ab']);
  // startIndex=4：跳过 len1 的 a,b 与 len2 的 aa,ab → 剩 ba、bb
  const skipped = maskCandidates('ab', 1, 2, 4);
  assert.equal(skipped.next().value, 'ba');
  assert.equal(skipped.next().value, 'bb');
  assert.equal(skipped.next().done, true);
  // 重复字符去重：'aabb' ≡ 'ab'
  const dedup = maskCandidates('aabb', 2, 2);
  assert.equal(dedup.next().value, 'aa');
  assert.equal(dedup.next().value, 'ab');
  assert.equal(dedup.next().value, 'ba');
  assert.equal(dedup.next().value, 'bb');
  assert.equal(dedup.next().done, true);
});

test('maskCandidates：参数越界抛中文错误', () => {
  assert.throws(() => maskCandidates('', 1, 2).next(), /字符集为空/);
  assert.throws(() => maskCandidates('ab€', 1, 2).next(), /非 latin1/);
  assert.throws(() => maskCandidates('ab', 0, 2).next(), /minLength/);
  assert.throws(() => maskCandidates('ab', 3, 2).next(), /maxLength/);
  assert.throws(() => maskCandidates('ab', 1, 2, -1).next(), /startIndex/);
});

// ---- 预算 / 性能 / 进度 ----

test('时间预算：超小 budget 中断枚举且 tried>0、password=null', async () => {
  const zip = buildZip([buildZipCryptoEntry({ plain: 'flag{budget_cut}', password: 'NineChar9' })]);
  const [meta] = detectEncryptedEntries(zip);
  const result = await bruteZipPassword(zip, meta, maskCandidates('0123456789abcdef', 8, 8), { timeBudgetMs: 60 });
  assert.ok(result.tried > 0, `tried=${result.tried} 应大于 0`);
  assert.ok(result.tried < 4294967296, '应在 16^8 空间耗尽前被预算截断');
  assert.equal(result.password, null);
  assert.equal(result.total, Infinity);
});

test('紧循环（yieldEvery:0）：掩码命中路径与让步路径等价，10 万口令不慢于让步路径（TD-批次KP-1）', async () => {
  const zip = buildZip([buildZipCryptoEntry({ plain: 'flag{t1ght_l00p}', password: '0731' })]);
  const [meta] = detectEncryptedEntries(zip);
  const result = await bruteZipPassword(zip, meta, maskCandidates('0123456789', 1, 4), { yieldEvery: 0 });
  assert.equal(result.password, '0731');
  assert.equal(result.tried, 10 + 100 + 1000 + 731 + 1);
  assert.equal(result.total, Infinity);

  // 吞吐对照：同 10 万错误口令。注意 Node 的 setTimeout(0) ~1ms 无浏览器 15ms clamp，
  // 这里只要求紧循环不慢于让步路径（1.5 倍容忍 CI 抖动）；浏览器侧的数量级提升由实测覆盖。
  const dict = Array.from({ length: 100000 }, (_, index) => `tight-${index}`);
  const startedTight = Date.now();
  await bruteZipPassword(zip, meta, dict, { yieldEvery: 0 });
  const tightMs = Date.now() - startedTight;
  const startedYield = Date.now();
  await bruteZipPassword(zip, meta, dict, { yieldEvery: 512 });
  const yieldMs = Date.now() - startedYield;
  assert.ok(tightMs <= 5000, `紧循环 10 万口令耗时 ${tightMs}ms 超过 5 秒红线`);
  assert.ok(tightMs <= yieldMs * 1.5 + 50, `紧循环 ${tightMs}ms 显著慢于让步路径 ${yieldMs}ms，异常`);
});

test('紧循环（yieldEvery:0）：超小预算截断仍生效（时钟每 256 口令检查）', async () => {
  const zip = buildZip([buildZipCryptoEntry({ plain: 'flag{t1ght_cut}', password: 'Absent9x9' })]);
  const [meta] = detectEncryptedEntries(zip);
  const result = await bruteZipPassword(zip, meta, maskCandidates('0123456789abcdef', 8, 8), { timeBudgetMs: 60, yieldEvery: 0 });
  assert.ok(result.tried > 0, `tried=${result.tried} 应大于 0`);
  assert.equal(result.password, null);
});

test('AbortSignal：让步路径在 512 批次边界响应 abort 提前收口（password=null 且未扫完）', async () => {
  const zip = buildZip([buildZipCryptoEntry({ plain: 'flag{ab0rt_me}', password: 'definitely-absent' })]);
  const [meta] = detectEncryptedEntries(zip);
  const dict = Array.from({ length: 100000 }, (_, index) => `abort-${index}`);
  const controller = new AbortController();
  const seenAtAbort = { tried: 0 };
  const result = await bruteZipPassword(zip, meta, dict, {
    timeBudgetMs: 600000,
    signal: controller.signal,
    onProgress: progress => {
      if (progress.tried >= 1024 && !controller.signal.aborted) {
        seenAtAbort.tried = progress.tried;
        controller.abort();
      }
    },
  });
  assert.equal(result.password, null);
  assert.ok(result.tried <= seenAtAbort.tried + 1, `abort 后仍多扫（${result.tried} > ${seenAtAbort.tried}+1）`);
  assert.ok(result.tried < dict.length, '应在候选耗尽前被 abort 截断');
});

test('性能红线：10 万口令 ZipCrypto 字典全扫 ≤10 秒（node）', async () => {
  const zip = buildZip([buildZipCryptoEntry({ plain: 'flag{perf_redline}', password: 'definitely-not-in-list' })]);
  const [meta] = detectEncryptedEntries(zip);
  const dict = Array.from({ length: 100000 }, (_, index) => `candidate-pw-${index}`);
  const startedAt = Date.now();
  const result = await bruteZipPassword(zip, meta, dict);
  const elapsedMs = Date.now() - startedAt;
  assert.equal(result.password, null);
  assert.equal(result.tried, 100000);
  assert.ok(elapsedMs <= 10000, `10 万口令耗时 ${elapsedMs}ms 超过 10 秒红线`);
});

test('onProgress：512 一批节流回报 + 结束终值', async () => {
  const zip = buildZip([buildZipCryptoEntry({ plain: 'flag{pr0gress_cb}', password: 'AbsentPw42' })]);
  const [meta] = detectEncryptedEntries(zip);
  const dict = Array.from({ length: 2000 }, (_, index) => `nope-${index}`);
  const events = [];
  const result = await bruteZipPassword(zip, meta, dict, { onProgress: progress => events.push(progress) });
  assert.equal(result.password, null);
  const triedList = [];
  for (const event of events) triedList.push(event.tried);
  assert.deepEqual(triedList, [512, 1024, 1536, 2000]);
  for (let index = 0; index < 3; index += 1) assert.equal(events[index].password, null);
});

// ---- inflateRawPreview（TD-批次MISC2-2）----

test('inflateRawPreview：正常流全量解出 / 损坏流返回 null / 大输出 8KB 截断', async () => {
  const { inflateRawPreview } = loadModule(path.join(srcDir, 'utils', 'ctf', 'zipBrute.ts'));
  // 正常流：flag 明文 deflate 后完整解回
  const plain = 'flag{inflate_preview_ok} ' + 'A'.repeat(64);
  const normal = new Uint8Array(deflateRawSync(Buffer.from(plain, 'latin1')));
  const inflated = await inflateRawPreview(normal);
  assert.notEqual(inflated, null);
  assert.equal(Buffer.from(inflated).toString('latin1'), plain);

  // 损坏流：BTYPE=0b11（保留块类型，DEFLATE 规范强制报错）→ null（错误口令误报防线，确定性向量）
  const corrupted = new Uint8Array([0x07, 0x00, 0x00, 0x00]);
  const corruptedResult = await inflateRawPreview(corrupted);
  assert.equal(corruptedResult, null);

  // 解压炸弹形态：64KB 全零 deflate 后很小，解压输出被 8KB 上限截断
  const bomb = new Uint8Array(deflateRawSync(Buffer.alloc(65536, 0)));
  const capped = await inflateRawPreview(bomb);
  assert.notEqual(capped, null);
  assert.equal(capped.length, 8192);
});

// ---- 内置字典 ----

test('dictionaryCandidates：条目量级 ~150、去重、覆盖 CTF 高频弱口令', () => {
  const dict = dictionaryCandidates();
  assert.ok(dict.length >= 140 && dict.length <= 180, `字典长度 ${dict.length} 超出预期区间`);
  const copy = [];
  for (let index = 0; index < dict.length; index += 1) copy.push(dict[index]);
  assert.equal(new Set(copy).size, copy.length, '字典存在重复条目');
  for (const must of ['123456', 'password', 'ctf', 'flag', 'infected', 'qwerty', 'admin', '2025', 'fish', 'misc']) {
    assert.ok(dict.includes(must), `字典缺少高频口令 ${must}`);
  }
});
