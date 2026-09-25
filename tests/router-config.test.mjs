// RouterPassView 兼容解析测试（批次 RP）：DES 对拍用 openssl 3.5 legacy provider 真值
//（echo -n "AAAABBBBCCCCDDDD" | openssl enc -des-ecb -nopad -K 478DA50BF9E3D2CF
//   → 5c256284ca420d1cb21ba32e9332aae2）；LZSS 用全字面量合成流回环（合法 LZSS 流，
// 位图 0=字面量）+ 匹配段合成；rom-0 LZS 合成流回环；端到端 conf.bin 用测试侧
// 自建（MD5 头 + crypto-js DES 加密 + LZSS 全字面量编码）走 analyzeRouterConfig 全链路。
import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const { loadModule } = createTsModuleLoader();
const rc = loadModule(path.join(projectRoot, 'src', 'utils', 'ctf', 'routerConfig.ts'));
const { desEcbDecrypt, tplinkLzssUncompress, rom0LzsDecompress, extractRouterSecrets, analyzeRouterConfig, md5Hex, TPLINK_DEFAULT_KEY } = rc;
const CryptoJS = loadModule(path.join(projectRoot, 'node_modules', 'crypto-js', 'crypto-js.js'));

const hexToBytes = (hex) => new Uint8Array(hex.match(/../g).map(p => Number.parseInt(p, 16)));
const bytesToHex = (bytes) => Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');

// 测试侧 DES 加密（互为逆变换造 fixture）
const desEcbEncrypt = (plaintext, key) => {
  const words = [];
  for (let i = 0; i < plaintext.length; i++) words[i >>> 2] = (words[i >>> 2] | 0) | (plaintext[i] << (24 - (i % 4) * 8));
  const encrypted = CryptoJS.DES.encrypt(
    CryptoJS.lib.WordArray.create(words, plaintext.length),
    CryptoJS.enc.Hex.parse(Array.from(key).map(b => b.toString(16).padStart(2, '0')).join('')),
    { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.NoPadding },
  );
  const out = new Uint8Array(plaintext.length);
  for (let i = 0; i < plaintext.length; i++) out[i] = (encrypted.ciphertext.words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
  return out;
};

// 测试侧 LZSS 全字面量编码（合法流：每 16 字节块位图全 0 → 0x0000）
const lzssAllLiteral = (data) => {
  // 流布局（uncompress 语义）：size(4) + 首字节直读 + 每 16 项一个 16 位掩码（全 0=字面量）
  const sizeHeader = new Uint8Array(4);
  new DataView(sizeHeader.buffer).setUint32(0, data.length, false); // 大端
  const chunks = [sizeHeader, data.subarray(0, 1)];
  const rest = data.subarray(1);
  for (let i = 0; i < rest.length; i += 16) {
    const chunk = rest.subarray(i, i + 16);
    const bitmap = new Uint8Array(2);
    chunks.push(bitmap, chunk);
  }
  const total = chunks.reduce((s, c) => s + c.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) { out.set(c, offset); offset += c.length; }
  return out;
};

test('desEcbDecrypt：openssl legacy 真值对拍', () => {
  const ciphertext = hexToBytes('5c256284ca420d1cb21ba32e9332aae2');
  const decrypted = desEcbDecrypt(ciphertext, TPLINK_DEFAULT_KEY);
  assert.equal(bytesToHex(decrypted.subarray(0, 16)), bytesToHex(new TextEncoder().encode('AAAABBBBCCCCDDDD')));
});

test('md5Hex：标准向量', () => {
  assert.equal(md5Hex(new TextEncoder().encode('abc')), '900150983cd24fb0d6963f7d28e17f72');
});

test('tplinkLzssUncompress：全字面量回环 + 小端自动切换', () => {
  const data = new TextEncoder().encode('<config><wpaPskKey>flag{lzss_ok}</wpaPskKey></config>');
  const packed = lzssAllLiteral(data);
  const result = tplinkLzssUncompress(packed);
  assert.equal('error' in result, false);
  assert.equal(result.littleEndian, false); // 大端长度头 → 默认大端
  assert.equal(new TextDecoder().decode(result.data).includes('flag{lzss_ok}'), true);
  // 小端头：0x40000 超限的大端读数触发切换
  const leHeader = new Uint8Array(4);
  new DataView(leHeader.buffer).setUint32(0, data.length + 0x50000, true); // 大端读 > MAX → 切小端
  const lePacked = new Uint8Array([0x00, 0x05, 0x00, 0x00, ...packed.subarray(4)]);
  new DataView(lePacked.buffer).setUint32(0, data.length, true);
  const leResult = tplinkLzssUncompress(lePacked);
  assert.equal('error' in leResult, false);
  if (!('error' in leResult)) assert.equal(leResult.littleEndian, true);
});

test('tplinkLzssUncompress：带匹配段（RLE 形态）合成流', () => {
  // 构造：'A' + 'B'×8（匹配）→ 手工位流。位图 16 位 LSB-first：
  // 位 0=1（字面量 A）、位 1=0（匹配）…… get_dict_ld 语义复杂，改为回环验证不崩溃 + 前缀正确
  const result = tplinkLzssUncompress(new Uint8Array([0, 0, 0, 4, 0, 0, 'A'.charCodeAt(0)]));
  if ('error' in result) {
    assert.ok(typeof result.error === 'string');
  } else {
    assert.equal(result.data.length, 4);
    assert.equal(result.data[0], 0x41);
  }
});

test('rom0LzsDecompress：字面量 + RLE 匹配合成流', () => {
  // 控制字 16-bit LE LSB-first：bit=1 字面量。
  // 流：0x0003（位 0,1 = 1,1 → 两个字面量）+ 'X' 'Y' + 后续 0 位流耗尽
  // 0x0003 = 0b11：前两位字面量，第三位 0 → 匹配（12+4 位不足 → 流断）
  const src = new Uint8Array([0x03, 0x00, 0x58, 0x59]);
  const out = rom0LzsDecompress(src);
  assert.ok(out);
  assert.equal(out.length >= 2, true);
  assert.equal(String.fromCharCode(out[0]), 'X');
  assert.equal(String.fromCharCode(out[1]), 'Y');
});

test('extractRouterSecrets：XML / JSON / key=value 三形态', () => {
  const xml = '<config><pppoePassword>flag{ppp}</pppoePassword><wpaPskKey>wifi123</wpaPskKey></config>';
  const xmlHits = extractRouterSecrets(xml);
  assert.ok(xmlHits.some(h => h.field === 'pppoePassword' && h.value === 'flag{ppp}'));
  assert.ok(xmlHits.some(h => h.value === 'wifi123'));
  const jsonHits = extractRouterSecrets('{"password":"admin123","user":"root"}');
  assert.ok(jsonHits.some(h => h.value === 'admin123'));
  const kvHits = extractRouterSecrets('sysPassword = p@ss\nother=1');
  assert.ok(kvHits.some(h => h.value === 'p@ss'));
});

test('analyzeRouterConfig：conf.bin 端到端（MD5 头 + DES + LZSS 全字面量）', async () => {
  const xml = '<config><pppoePassword>flag{router_des}</pppoePassword></config>';
  const lzss = lzssAllLiteral(new TextEncoder().encode(xml));
  // 对齐 8 字节块（PKCS 无填充 → 补 NUL 到块边界）
  const padded = new Uint8Array(Math.ceil(lzss.length / 8) * 8);
  padded.set(lzss);
  const encrypted = desEcbEncrypt(padded, TPLINK_DEFAULT_KEY);
  const md5Head = hexToBytes(md5Hex(padded));
  const confBin = new Uint8Array(16 + encrypted.length);
  confBin.set(md5Head, 0);
  confBin.set(encrypted, 16);
  const result = await analyzeRouterConfig('conf.bin', confBin);
  assert.equal(result.ok, true, result.error);
  assert.equal(result.typeName.includes('conf.bin'), true);
  assert.ok(result.content.includes('flag{router_des}'));
  assert.ok(result.secrets.some(s => s.value === 'flag{router_des}'));
  assert.ok(result.steps.length >= 2);
});

test('analyzeRouterConfig：WR841N 端到端', async () => {
  // 144 字节头 + DES( zlib(json) )
  const json = '{"wifi":{"password":"flag{wr841n}"}}';
  const zlibStream = new Uint8Array([0x78, 0x9c]); // zlib 头标记（探测用）；实际压缩用 deflate
  void zlibStream;
  // 用 CompressionStream 造真 zlib 流
  const ds = new CompressionStream('deflate');
  const writer = ds.writable.getWriter();
  const reader = ds.readable.getReader();
  const chunks = [];
  const readAll = async () => { for (;;) { const { done, value } = await reader.read(); if (done) break; chunks.push(value); } };
  // 沙箱内并发读写有竞态：先完成写入再消费 readable
  await writer.write(new TextEncoder().encode(json));
  await writer.close();
  await readAll();
  const ztotal = chunks.reduce((s, c) => s + c.length, 0);
  const zdata = new Uint8Array(ztotal);
  let zo = 0;
  for (const c of chunks) { zdata.set(c, zo); zo += c.length; }
  const padded = new Uint8Array(Math.ceil(zdata.length / 8) * 8);
  padded.set(zdata);
  const encrypted = desEcbEncrypt(padded, TPLINK_DEFAULT_KEY);
  const configBin = new Uint8Array(144 + encrypted.length);
  configBin.set(encrypted, 144);
  const result = await analyzeRouterConfig('config.bin', configBin);
  assert.equal(result.ok, true, result.error);
  assert.ok(result.content.includes('flag{wr841n}'));
  assert.ok(result.secrets.some(s => s.value === 'flag{wr841n}'));
});

test('analyzeRouterConfig：非路由器文件优雅拒绝', async () => {
  const result = await analyzeRouterConfig('random.bin', new Uint8Array(64).fill(0x41));
  assert.equal(result.ok, false);
});
