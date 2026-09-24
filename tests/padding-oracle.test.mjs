// CBC PKCS#7 padding oracle 真实攻击引擎测试：固定向量（key=0..31、IV=0x80..0x8f）程序化构造，
// WebCrypto AES-CBC 加密 → paddingOracleDecrypt 仅凭 oracle 布尔回调还原；另覆盖 paddingOracleReport 双模式与防呆。
// 注：被测模块在 vm 沙箱内运行，跨 realm 断言一律经 Array.from / 索引循环转成主 realm 值（AGENTS.md 踩坑记录）。
import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const srcDir = path.join(projectRoot, 'src');
const { loadModule } = createTsModuleLoader();
const { paddingOracleDecrypt, paddingOracleReport } = loadModule(path.join(srcDir, 'utils', 'codec', 'paddingOracle.ts'));

const KEY = Uint8Array.from({ length: 32 }, (_, index) => index); // 固定 32 字节 key：0..31
const IV = Uint8Array.from({ length: 16 }, (_, index) => 0x80 + index); // 固定 IV：0x80..0x8f

// 沙箱 Uint8Array → 主 realm 十六进制字符串（跨 realm 断言统一走这里）
const hexOf = bytes => Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
const bytesOf = text => Uint8Array.from(Buffer.from(text, 'latin1'));
// 沙箱视图 → 主 realm Uint8Array（索引循环逐字节拷贝，规避 WebIDL 跨 realm 视图差异）
const hostBytes = view => {
  const out = new Uint8Array(view.length);
  for (let index = 0; index < view.length; index += 1) out[index] = view[index];
  return out;
};

const encryptAesCbc = async (plainBytes, keyBytes = KEY, ivBytes = IV) => {
  const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-CBC', false, ['encrypt']);
  return new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CBC', iv: ivBytes }, key, plainBytes));
};

// padding oracle：probePrev 作 IV 解密单块 target，PKCS#7 非法 → WebCrypto 抛错 → false（模拟 vulnerable server）
const makeOracle = keyBytes => {
  let keyPromise = null;
  return async (probePrev, target) => {
    keyPromise ??= crypto.subtle.importKey('raw', keyBytes, 'AES-CBC', false, ['decrypt']);
    const key = await keyPromise;
    try {
      await crypto.subtle.decrypt({ name: 'AES-CBC', iv: hostBytes(probePrev) }, key, hostBytes(target));
      return true;
    } catch {
      return false;
    }
  };
};

test('paddingOracleDecrypt 块对齐明文（32 字节 → 3 块）：完整还原且 padding 校验通过', async () => {
  const plain = '0123456789abcdef0123456789abcdef';
  const cipher = await encryptAesCbc(bytesOf(plain));
  assert.equal(cipher.length, 48);
  const result = await paddingOracleDecrypt(cipher, makeOracle(KEY), IV);
  assert.equal(result.blockCount, 3);
  assert.equal(hexOf(result.plaintext), hexOf(bytesOf(plain)));
  assert.equal(result.paddingInvalid, false);
  assert.ok(result.queries > 0 && result.queries < 256 * 16 * 3 * 2, `queries=${result.queries}`);
  assert.ok(Array.isArray(result.steps) && result.steps.length >= 5, `steps=${result.steps.length}`);
});

test('paddingOracleDecrypt 不对齐明文（18 字节 → 2 块）：完整还原', async () => {
  const plain = 'un-aligned secret!';
  assert.equal(plain.length, 18);
  const cipher = await encryptAesCbc(bytesOf(plain));
  assert.equal(cipher.length, 32);
  const result = await paddingOracleDecrypt(cipher, makeOracle(KEY), IV);
  assert.equal(result.blockCount, 2);
  assert.equal(hexOf(result.plaintext), hexOf(bytesOf(plain)));
  assert.equal(result.paddingInvalid, false);
  assert.ok(result.queries > 0 && result.queries < 256 * 16 * 2 * 2, `queries=${result.queries}`);
});

test('paddingOracleDecrypt 无 IV：跳过第 1 块，恢复第 2 块起的明文', async () => {
  const plain = 'abcdefghijklmnopqrstuvwxyz012345';
  const cipher = await encryptAesCbc(bytesOf(plain));
  const result = await paddingOracleDecrypt(cipher, makeOracle(KEY));
  assert.equal(result.blockCount, 3);
  assert.equal(hexOf(result.plaintext), hexOf(bytesOf(plain.slice(16))));
  assert.equal(result.paddingInvalid, false);
  assert.ok(result.steps[0].includes('跳过第 1 块'), result.steps[0]);
});

test('paddingOracleDecrypt 防呆：非 16 倍数长度 / 空密文 / 无 IV 单块直接抛错', async () => {
  await assert.rejects(paddingOracleDecrypt(new Uint8Array(17), makeOracle(KEY), IV), /不是 16 的整数倍/);
  await assert.rejects(paddingOracleDecrypt(new Uint8Array(0), makeOracle(KEY), IV), /密文为空/);
  await assert.rejects(paddingOracleDecrypt(new Uint8Array(16), makeOracle(KEY)), /缺少 IV/);
});

test('paddingOracleDecrypt 篡改末前块 → 末块 padding 必非法：paddingInvalid=true 且不剥离', async () => {
  const plain = 'victim block data!'; // 18 字节 → 2 块，末块明文 = 'a' + '!' + 14×0x0e
  const cipher = await encryptAesCbc(bytesOf(plain));
  cipher[15] ^= 0x5a; // 第 1 块末字节翻转：末块明文同步翻转 0x5a，其末字节 = 0x0e^0x5a = 0x54 > 16 → PKCS#7 必非法
  const result = await paddingOracleDecrypt(cipher, makeOracle(KEY), IV);
  assert.equal(result.blockCount, 2);
  assert.equal(result.paddingInvalid, true);
  assert.equal(result.plaintext.length, 32); // 校验失败不剥离，保留全部 32 字节
  const recovered = Array.from(result.plaintext);
  assert.equal(recovered[16], 0x61); // 'a'：P1[i] 只在 i=15 处受 C0[15] 篡改影响
  assert.equal(recovered[17], 0x21); // '!'
  for (let index = 18; index <= 30; index += 1) assert.equal(recovered[index], 0x0e);
  assert.equal(recovered[31], 0x54);
});

test('paddingOracleReport 模式A：随机 key/IV 本地自验证，matched=true', async () => {
  const reportDefault = JSON.parse(await paddingOracleReport(''));
  assert.match(reportDefault.mode, /^A/);
  assert.equal(reportDefault.matched, true);
  assert.equal(reportDefault.paddingInvalid, false);
  assert.ok(reportDefault.queries > 0);
  assert.ok(reportDefault.recovered.includes('flag{p4dding_0racle_r34l_attack}'));
  assert.match(reportDefault.cipherHex, /^[0-9a-f]{96}$/); // 32 字节明文 + 16 字节 pad → 3 块
  assert.ok(Array.isArray(reportDefault.steps) && reportDefault.steps.length >= 5);
  const reportCustom = JSON.parse(await paddingOracleReport('secret message for oracle'));
  assert.equal(reportCustom.matched, true);
  assert.equal(reportCustom.recovered, 'secret message for oracle');
  assert.equal(reportCustom.truncated, false);
});

test('paddingOracleReport 模式B：cipherHex/ivHex/keyHex 字段攻击给定密文（含无 IV 与非法 key）', async () => {
  const plain = 'mode-b given cipher attack';
  const cipher = await encryptAesCbc(bytesOf(plain));
  const withIv = JSON.parse(await paddingOracleReport(`cipherHex=${hexOf(cipher)}; ivHex=${hexOf(IV)}; keyHex=${hexOf(KEY)}`));
  assert.match(withIv.mode, /^B/);
  assert.equal(withIv.matched, null);
  assert.equal(withIv.recovered, plain);
  assert.equal(withIv.paddingInvalid, false);
  assert.ok(withIv.queries > 0);
  assert.equal(withIv.blocks, 2);
  const noIv = JSON.parse(await paddingOracleReport(['cipherHex=' + hexOf(cipher), 'keyHex=' + hexOf(KEY)].join('\n')));
  assert.equal(noIv.recovered, plain.slice(16)); // 无 ivHex：第 1 块跳过
  assert.ok(noIv.note.includes('跳过'));
  await assert.rejects(paddingOracleReport('cipherHex=00112233ff\nkeyHex=0011'), /keyHex 长度/);
});

test('paddingOracleDecrypt 歧义消解分支：stub oracle 构造双候选（D[14]=2/D[15]=0）确定性触发并精确还原', async () => {
  // reviewer P1-2：固定向量 0/6 触发歧义分支（仅模式A ~6% 概率触碰）。stub oracle 直接实现 PKCS#7
  // 语义（plain = probePrev ^ D_true，末字节 v∈1..16 且尾部 v 字节全等才 true），钉死 D 使 position-15
  // 扫描同时命中 g=1（单字节 0x01）与 g=2（碰巧 D[14]==2 的双字节 padding）→ 二轮扰动探测唯一幸存者必为 g=1。
  const D = new Uint8Array(16); // 真实中间值 D(C1)：其余字节取 0x5a 序列避免巧合
  for (let i = 0; i < 14; i += 1) D[i] = 0x5a ^ i;
  D[14] = 0x02; // v=2 路径：扫描时 base[14]=0 → plain[14]=D[14]=2 恰等于 v，双字节 padding 合法
  D[15] = 0x00; // 候选 g=1（plain[15]=1）与 g=2（plain[15]=2）并列
  const target = Uint8Array.from({ length: 16 }, (_, i) => 0xc3 ^ (i * 7)); // 任意密文块（stub 不解密它）
  const iv = new Uint8Array(16);
  iv[14] = 0x02; iv[15] = 0x01; // 使真实明文末两字节为 {0,1}：合法单字节 padding，剥离后 15 字节
  let probes = 0;
  const oracle = async probePrev => {
    probes += 1;
    const plain = new Uint8Array(16);
    for (let i = 0; i < 16; i += 1) plain[i] = probePrev[i] ^ D[i];
    const v = plain[15];
    if (v < 1 || v > 16) return false;
    for (let i = 16 - v; i < 16; i += 1) if (plain[i] !== v) return false;
    return true;
  };
  const result = await paddingOracleDecrypt(target, oracle, iv);
  assert.ok(result.steps.some(step => String(step).includes('歧义消解 1 处')), `歧义分支未触发: ${JSON.stringify(result.steps)}`);
  const expectedFull = new Uint8Array(16);
  for (let i = 0; i < 16; i += 1) expectedFull[i] = D[i] ^ iv[i];
  assert.equal(result.plaintext.length, 15); // padding=1 剥离
  for (let i = 0; i < 15; i += 1) assert.equal(result.plaintext[i], expectedFull[i], `byte ${i}`);
  assert.equal(result.paddingInvalid, false);
  assert.ok(probes > 256 * 16, `probes=${probes} 应含 256 全扫描 + 二轮探测`);
});

test('paddingOracleReport 模式B：cipherHex 超 64 块上限直接拒绝（reviewer P1-1 挂死防线）', async () => {
  const hugeHex = 'ab'.repeat(32 * 65); // 65 块
  await assert.rejects(paddingOracleReport(`cipherHex=${hugeHex}\nkeyHex=${hexOf(KEY)}`), /64 块上限/);
});
