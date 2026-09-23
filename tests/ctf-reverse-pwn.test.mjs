// 逆向域 / Pwn 域引擎测试：常量指纹扫描、块级熵、cyclic pattern、坏字符、格式化字符串序号。
// 全部样本程序化自造（无外部 fixture）；加载方式统一走 tests/helpers/compileTsModule.mjs
//（T4 测试基建收敛；沙箱内数组断言前用主 realm Array.from 转换）。
import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

// 加载方式统一走 tests/helpers/compileTsModule.mjs（T4 测试基建收敛：同一加载语义只写一遍）。
const srcDir = path.join(projectRoot, 'src');
const { loadModule } = createTsModuleLoader();

const fileDetect = loadModule(path.join(srcDir, 'utils', 'ctf', 'fileDetect.ts'));
const fingerprints = loadModule(path.join(srcDir, 'utils', 'ctf', 'constFingerprints.ts'));
const cyclic = loadModule(path.join(srcDir, 'utils', 'ctf', 'cyclic.ts'));
const pwnTools = loadModule(path.join(srcDir, 'utils', 'ctf', 'pwnTools.ts'));

// ---- 样本工厂 ----

// 假 ELF：ELF 魔数 + 0x2010 处 TEA delta（小端）+ 0x3000 起伪随机高熵段 + flag 字符串。
const makeFakeElf = () => {
  const bytes = new Uint8Array(0x4000);
  bytes.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0], 0);
  bytes.set([0xb9, 0x79, 0x37, 0x9e], 0x2010);
  // 伪随机高熵段（xorshift 确定性生成，测试可复现）
  let state = 0x2545f491;
  for (let offset = 0x3000; offset < 0x3800; offset += 1) {
    state ^= state << 13; state >>>= 0;
    state ^= state >>> 17;
    state ^= state << 5; state >>>= 0;
    bytes[offset] = state & 0xff;
  }
  bytes.set(Buffer.from('flag{rev_easy}', 'ascii'), 0x1234);
  return bytes;
};

// AES S-box 独立来源：GF(2^8) 乘法逆元 + 仿射变换逐字节生成（FIPS 197），与硬编码常量互证。
const gmul = (a, b) => {
  let product = 0;
  for (let bit = 0; bit < 8; bit += 1) {
    if (b & 1) product ^= a;
    const high = a & 0x80;
    a = (a << 1) & 0xff;
    if (high) a ^= 0x1b;
    b >>= 1;
  }
  return product;
};
const rotl8 = (value, shift) => ((value << shift) | (value >>> (8 - shift))) & 0xff;
const generatedSbox = (() => {
  const inverse = new Array(256).fill(0);
  for (let a = 1; a < 256; a += 1) {
    for (let b = 1; b < 256; b += 1) {
      if (gmul(a, b) === 1) { inverse[a] = b; break; }
    }
  }
  return Array.from({ length: 256 }, (_, x) => {
    const inverted = inverse[x];
    return inverted ^ rotl8(inverted, 1) ^ rotl8(inverted, 2) ^ rotl8(inverted, 3) ^ rotl8(inverted, 4) ^ 0x63;
  });
})();

// ---- 常量指纹 ----

test('假 ELF 命中 TEA delta + strings 搜到 flag（第一公里全链路）', () => {
  const bytes = makeFakeElf();
  const hits = fingerprints.scanConstFingerprints(bytes);
  const tea = hits.find(hit => hit.id === 'tea-family-delta');
  assert.ok(tea, `TEA delta 未命中，命中清单：${hits.map(hit => hit.id).join(', ')}`);
  assert.equal(tea.offset, 0x2010);
  assert.equal(tea.hits, 1);
  assert.ok(tea.suggestion.zh.includes('TEA'), '建议文案应指向 TEA 家族');
  assert.equal(tea.switchModuleId, 'cipher');

  const { values } = fileDetect.extractStrings(bytes);
  assert.ok(values.some(value => value.includes('flag{rev_easy}')), 'strings 应能搜到 flag{rev_easy}');
});

test('AES S-box / MD5 IV / 文本版本字符串多形态命中', () => {
  const bytes = new Uint8Array(0x400);
  bytes.set(generatedSbox.slice(0, 16), 0x100);
  bytes.set([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10], 0x200);
  bytes.set(Buffer.from('mbed TLS 2.28.8', 'ascii'), 0x300);
  const hits = fingerprints.scanConstFingerprints(bytes);
  const sbox = hits.find(hit => hit.id === 'aes-sbox');
  assert.ok(sbox && sbox.offset === 0x100, 'AES S-box 应在 0x100 命中');
  const md5 = hits.find(hit => hit.id === 'md5-sha1-iv');
  assert.ok(md5 && md5.offset === 0x200, 'MD5/SHA-1 IV 应在 0x200 命中');
  const mbedtls = hits.find(hit => hit.id === 'mbedtls-version');
  assert.ok(mbedtls && mbedtls.offset === 0x300, 'mbed TLS 版本串应在 0x300 命中');
});

test('S-box 常量库与 GF(2^8) 独立生成器逐字节一致（FIPS 197 锚点 0x53→0xED）', () => {
  assert.equal(generatedSbox[0x53], 0xed, 'FIPS 197 著名锚点失败');
  const sboxDef = fingerprints.FINGERPRINT_DEFS.find(def => def.id === 'aes-sbox');
  const patternBytes = sboxDef.patterns[0].bytes;
  assert.equal(Array.from(patternBytes).length, 16);
  for (let index = 0; index < 16; index += 1) {
    assert.equal(patternBytes[index], generatedSbox[index], `S-box 第 ${index} 字节与独立生成器不符`);
  }
});

test('扫描限量与去重：8MB 截断后不越界、同常量多次命中合并为单卡', () => {
  const bytes = new Uint8Array(0x9000);
  // TEA delta 出现两次 → 单卡 + hits=2
  bytes.set([0xb9, 0x79, 0x37, 0x9e], 0x100);
  bytes.set([0x9e, 0x37, 0x79, 0xb9], 0x200); // 大端形态也归并同卡
  const hits = fingerprints.scanConstFingerprints(bytes);
  const teaHits = hits.filter(hit => hit.id === 'tea-family-delta');
  assert.equal(teaHits.length, 1, '同常量必须去重为单卡');
  assert.equal(teaHits[0].hits, 2);
  assert.equal(teaHits[0].offset, 0x100);
  // maxBytes 截断：限制 0x150 时大端命中（0x200）不可见
  const truncated = fingerprints.scanConstFingerprints(bytes, { maxBytes: 0x150 });
  const truncatedTea = truncated.find(hit => hit.id === 'tea-family-delta');
  assert.ok(truncatedTea && truncatedTea.hits === 1, '截断后只应命中窗口内 1 次');
  // 空文件安全（跨 realm 空数组不能 deepEqual，断言长度）
  assert.equal(fingerprints.scanConstFingerprints(new Uint8Array(0)).length, 0);
});

// ---- 块级熵 ----

test('块级熵：明文区低熵、伪随机区高熵、区段偏移对齐', () => {
  const bytes = new Uint8Array(0x800);
  bytes.set(Buffer.from('A'.repeat(0x400), 'ascii'), 0);
  let state = 0x1234abcd;
  for (let offset = 0x400; offset < 0x800; offset += 1) {
    state ^= state << 13; state >>>= 0;
    state ^= state >>> 17;
    state ^= state << 5; state >>>= 0;
    bytes[offset] = state & 0xff;
  }
  const blocks = Array.from(fileDetect.blockEntropy(bytes), block => ({ offset: block.offset, length: block.length, entropy: block.entropy }));
  assert.equal(blocks.length, 0x800 / 256);
  assert.ok(blocks[0].entropy < 1, '全 A 块应近零熵');
  // 256B 随机块熵期望 ≈7.2-7.4（阈值 6.8 为块级缺省，整文件级 7.5 不适用于小块）
  assert.ok(blocks[4].entropy > 6.8, `伪随机块应高熵（实际 ${blocks[4].entropy.toFixed(3)}）`);
  const ranges = Array.from(fileDetect.highEntropyRanges(blocks), range => ({ start: range.startOffset, end: range.endOffset }));
  assert.equal(ranges.length, 1);
  assert.equal(ranges[0].start, 0x400);
  assert.equal(ranges[0].end, 0x800);
});

// ---- cyclic ----

test('cyclic 生成 200 字符 + 子串反查 offset 自洽（周期 3/4/8 全过）', () => {
  for (const period of [3, 4, 8]) {
    const pattern = cyclic.buildDeBruijn(period, 200);
    assert.equal(pattern.length, 200, `周期 ${period} 生成长度应为 200`);
    // 窗口唯一性：任取 4 个不重叠位置，period 长窗口的 indexOf 必须等于其自身位置
    for (const at of [0, 57, 113, 196 - Math.min(period, 4)]) {
      const window = pattern.slice(at, at + period);
      if (window.length < period) continue;
      assert.equal(pattern.indexOf(window), at, `周期 ${period} 窗口 ${window} 反查不唯一`);
    }
    // 反查 API：取末尾一个完整窗口（模拟"栈尾被覆盖"场景）
    const tail = pattern.slice(200 - period);
    const found = cyclic.findCyclicOffset(tail, period);
    assert.ok(!found.error, `周期 ${period} 反查失败：${JSON.stringify(found)}`);
    assert.equal(found.offset, 200 - period);
    assert.equal(found.endian, null);
  }
});

test('cyclic hex 反查：0x61613768 → 小端 32 位命中，offset 与完整序列一致', () => {
  const result = cyclic.findCyclicOffset('0x61613768', 4);
  assert.ok(!result.error, `反查失败：${JSON.stringify(result)}`);
  assert.equal(result.endian, 'little');
  assert.equal(result.width, 32);
  assert.equal(result.raw, 'h7aa');
  // 反查不受"页面生成 200 字符"限制（pwnlib 语义）：与足够长的完整序列对齐
  const sequence = cyclic.buildDeBruijn(4, result.offset + 10);
  assert.equal(sequence.indexOf('h7aa'), result.offset);
});

test('cyclic 64 位/大端/坏输入：位宽判定与字节序回退', () => {
  const pattern = cyclic.buildDeBruijn(8, 100000);
  const at = 5000;
  const window = pattern.slice(at, at + 8);
  const bytes = Array.from(window, char => char.charCodeAt(0));
  // 寄存器值 = LE 解释窗口字节 → 数值的书写序（BE）是窗口逆序；LE 反查应还原窗口原序位置
  const valueHex = [...bytes].reverse().map(byte => byte.toString(16).padStart(2, '0')).join('');
  const little = cyclic.findCyclicOffset(`0x${valueHex}`, 8);
  assert.ok(!little.error && little.endian === 'little' && little.width === 64, `64 位小端反查失败：${JSON.stringify(little)}`);
  assert.equal(little.offset, at);

  // 对称值（高位字节为 0）：LE 裁尾与 BE 裁头结果相同 → 恒选 pwn 主流的小端判定；
  // 裁零后 needle='aaa' 短于周期 → 多命中封顶清单，首命中为序列开头
  const symmetric = cyclic.findCyclicOffset('0x00616161', 8);
  assert.ok(!symmetric.error && symmetric.endian === 'little' && symmetric.offset === 0, `对称值应 LE 优先命中：${JSON.stringify(symmetric)}`);

  // BE 回退（可达场景）：LE needle 落在搜索前缀之外、其逆序（BE needle）在前缀内 → 判定 big
  const prefix = cyclic.buildDeBruijn(4, 2_000_000);
  let bigCase = null;
  for (let probe = 1_900_000; probe < 1_910_000 && !bigCase; probe += 4) {
    const candidate = prefix.slice(probe, probe + 4);
    if (prefix.indexOf([...candidate].reverse().join('')) === -1) bigCase = { at: probe, window: candidate };
  }
  assert.ok(bigCase, '前缀内应存在逆序不在前缀的窗口');
  const hexOf = value => Array.from(value, char => char.charCodeAt(0).toString(16).padStart(2, '0')).join('');
  const bigEndianHit = cyclic.findCyclicOffset(`0x${hexOf(bigCase.window)}`, 4);
  assert.ok(!bigEndianHit.error && bigEndianHit.endian === 'big' && bigEndianHit.offset === bigCase.at, `BE 回退失败：${JSON.stringify(bigEndianHit)}`);

  // 64 位寄存器高 2 字节为零（pattern 只覆盖低 6 字节的真实场景）：LE 裁掉末尾零字节后命中。
  // 裁零后 needle 短于周期 → 歧义真实存在，在用户发送长度（此处 10000）内收集全部命中并标 ambiguous。
  const window6 = pattern.slice(at, at + 6);
  const bytes6 = Array.from(window6, char => char.charCodeAt(0));
  const value6Hex = [...bytes6].reverse().map(byte => byte.toString(16).padStart(2, '0')).join('');
  const padded = cyclic.findCyclicOffset(`0x0000${value6Hex}`, 8, { withinBytes: 10000 });
  assert.ok(!padded.error && padded.endian === 'little' && padded.width === 64 && padded.trimmedZeroBytes === 2, `前导零裁剪失败：${JSON.stringify(padded)}`);
  assert.ok(Array.from(padded.offsets).includes(at), `命中清单必须包含真实位置 ${at}：${JSON.stringify(padded.offsets)}`);
  assert.equal(padded.ambiguous, padded.offsets.length > 1);
  // withinBytes 限定收集范围：1000 内 'paaaaa' 只命中 [120, 608]，远处的 5000 不再混入
  const narrow = cyclic.findCyclicOffset(`0x0000${value6Hex}`, 8, { withinBytes: 1000 });
  assert.ok(!narrow.error && narrow.offset === 120 && !Array.from(narrow.offsets).includes(5000), `范围内收集失败：${JSON.stringify(narrow)}`);

  assert.ok(cyclic.findCyclicOffset('0xzz', 4).error === 'format');
  assert.ok(cyclic.findCyclicOffset('', 4).error === 'format');
  assert.ok(cyclic.findCyclicOffset('0x01020304', 4).error === 'not-found'); // 不可打印字节
});

// ---- 坏字符 ----

test('坏字符：\\xNN 解析、命中高亮数据、集合解析', () => {
  const parsed = pwnTools.parsePayloadBytes('\\x31\\xc0\\x00\\x0a\\x50');
  assert.ok(parsed.ok && parsed.source === 'escape');
  assert.deepEqual(Array.from(parsed.bytes), [0x31, 0xc0, 0x00, 0x0a, 0x50]);

  const bareHex = pwnTools.parsePayloadBytes('31 c0 00 0a 50');
  assert.ok(bareHex.ok && bareHex.source === 'hex');
  assert.deepEqual(Array.from(bareHex.bytes), [0x31, 0xc0, 0x00, 0x0a, 0x50]);

  const report = pwnTools.checkBadChars(Array.from(parsed.bytes), pwnTools.parseBadCharSet('\\x00\\x0a'));
  assert.equal(report.total, 5);
  // 沙箱跨 realm 数组：断言前必须用主 realm Array.from 转换（.map 产物仍是沙箱 Array）
  assert.deepEqual(Array.from(report.hits, hit => hit.offset), [2, 3]);
  assert.deepEqual(Array.from(report.uniqueBad), [0x00, 0x0a]);

  const clean = pwnTools.checkBadChars(Array.from(parsed.bytes), [0xff]);
  assert.equal(clean.hits.length, 0);
});

// ---- 格式化字符串 ----

test('格式化字符串：泄漏值编号表与目标值命中序号', () => {
  // 真实 %p 泄漏输出值间必有分隔（空格/换行）；连续 hex 串在正则上本就有歧义，UI 提示用户保持分隔。
  const leak = 'AAAA 0x41414141\n0x7ffd1234 0x00000000';
  const analysis = pwnTools.analyzeFormatStringLeak(leak, '0x7FFD1234');
  assert.deepEqual(Array.from(analysis.values, entry => entry.hex), ['0x41414141', '0x7ffd1234', '0x00000000']);
  assert.equal(analysis.matchedIndex, 2, '目标值应命中第 2 个泄漏位');
  assert.equal(analysis.values[1].index, 2);

  // ASCII 目标：AAAA → 0x41414141（小端）
  const asciiTarget = pwnTools.analyzeFormatStringLeak(leak, 'AAAA');
  assert.equal(asciiTarget.matchedIndex, 1);

  // 无目标：只出编号表；目标不存在：matchedIndex=null + 说明
  const bare = pwnTools.analyzeFormatStringLeak(leak);
  assert.equal(bare.matchedIndex, null);
  assert.equal(bare.values.length, 3);
  const missing = pwnTools.analyzeFormatStringLeak(leak, '0xdeadbeef');
  assert.equal(missing.matchedIndex, null);
  assert.ok(missing.targetNote);
});
