// CyberChef 对标操作测试（批次 CC1）：位运算/移位/旋转/位反转/字节序/校验和矩阵/抽取器/
// strings/FILETIME/defang/熵报告/文本行工具。CRC 变体与 Fletcher 用 CyberChef 官方测试
// 向量锚定（"123456789" 全家桶是 CRC 校验的事实基准）。
import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const { loadModule } = createTsModuleLoader();
const cc = loadModule(path.join(projectRoot, 'src', 'utils', 'codec', 'opsCyberchef.ts'));
const {
  bitwiseWithKey, shiftBits, rotateBits, reverseBitsPerByte, swapEndianness,
  checksumMatrix, extractData, extractPrintableStrings,
  unixToFiletime, filetimeToUnix, defang, refang, entropyReport, textLineTool, inputToBytes,
} = cc;

const textBytes = s => new TextEncoder().encode(s);

test('inputToBytes：hex 与文本自动识别', () => {
  assert.deepEqual([...inputToBytes('414243')], [0x41, 0x42, 0x43]);
  assert.deepEqual([...inputToBytes('ABC')], [0x41, 0x42, 0x43]);
  assert.deepEqual([...inputToBytes('41 42 43')], [0x41, 0x42, 0x43]); // 带空格 hex
  // 非纯 hex 回落文本
  assert.deepEqual([...inputToBytes('Hello')], [0x48, 0x65, 0x6c, 0x6c, 0x6f]);
});

test('bitwiseWithKey：XOR/AND/OR/ADD/SUB 逐字节 key 循环', () => {
  const data = textBytes('ABCDEF');
  const key = textBytes('K');
  assert.deepEqual([...bitwiseWithKey(data, key, 'xor')], [...data.map(b => b ^ 0x4b)]);
  assert.deepEqual([...bitwiseWithKey(data, key, 'and')], [...data.map(b => b & 0x4b)]);
  assert.deepEqual([...bitwiseWithKey(data, key, 'add')], [...data.map(b => (b + 0x4b) & 0xff)]);
  // ADD mod 256 回绕：0xff + 1 = 0
  assert.deepEqual([...bitwiseWithKey(new Uint8Array([0xff]), new Uint8Array([1]), 'add')], [0]);
  assert.deepEqual([...bitwiseWithKey(new Uint8Array([0]), new Uint8Array([1]), 'sub')], [0xff]);
});

test('shiftBits：整体位流移位', () => {
  // 0b10000001 左移 1 = 0b00000010
  assert.deepEqual([...shiftBits(new Uint8Array([0b10000001]), 1, 'left')], [0b00000010]);
  // 0b10000001 右移 1 = 0b01000000
  assert.deepEqual([...shiftBits(new Uint8Array([0b10000001]), 1, 'right')], [0b01000000]);
  // 移位量 > 宽度自动取模：8 位一字节移 8 = 原样
  assert.deepEqual([...shiftBits(new Uint8Array([0x41]), 8, 'left')], [0x41]);
});

test('rotateBits：8/16/32 位宽循环旋转（Carry 回绕）', () => {
  // 0b10000001 rotate left 1 (8-bit) = 0b00000011
  assert.deepEqual([...rotateBits(new Uint8Array([0b10000001]), 1, 8, 'left')], [0b00000011]);
  // 0x1234 rotate left 4 (16-bit) = 0x2341
  assert.deepEqual([...rotateBits(new Uint8Array([0x12, 0x34]), 4, 16, 'left')], [0x23, 0x41]);
  // 0x12345678 rotate right 8 (32-bit) = 0x78123456
  assert.deepEqual(
    [...rotateBits(new Uint8Array([0x12, 0x34, 0x56, 0x78]), 8, 32, 'right')],
    [0x78, 0x12, 0x34, 0x56],
  );
});

test('reverseBitsPerByte：位镜像', () => {
  assert.deepEqual([...reverseBitsPerByte(new Uint8Array([0b10000000]))], [0b00000001]);
  assert.deepEqual([...reverseBitsPerByte(new Uint8Array([0b10110010]))], [0b01001101]);
});

test('swapEndianness：按组反转', () => {
  assert.deepEqual([...swapEndianness(new Uint8Array([0x11, 0x22, 0x33, 0x44]), 2)], [0x22, 0x11, 0x44, 0x33]);
  assert.deepEqual([...swapEndianness(new Uint8Array([0x11, 0x22, 0x33, 0x44]), 4)], [0x44, 0x33, 0x22, 0x11]);
  // 尾部不足一组保持原样
  assert.deepEqual([...swapEndianness(new Uint8Array([0x11, 0x22, 0x33]), 2)], [0x22, 0x11, 0x33]);
});

test('checksumMatrix：CRC 全家桶对拍 "123456789" 基准向量', () => {
  const rows = checksumMatrix(textBytes('123456789'));
  const by = Object.fromEntries(rows.map(r => [r.name, r.value]));
  // check 值来自 CRC catalog（reveng）权威表
  assert.equal(by['CRC-16/ARC'], 'bb3d');
  assert.equal(by['CRC-16/MODBUS'], '4b37');
  assert.equal(by['CRC-16/USB'], 'b4c8');
  assert.equal(by['CRC-16/KERMIT'], '2189');
  assert.equal(by['CRC-16/XMODEM'], '31c3');
  assert.equal(by['CRC-16/CCITT-FALSE'], '29b1');
  assert.equal(by['CRC-16/X-25'], '906e');
  assert.equal(by['CRC-16/DNP'], 'ea82');
  // CRC-32 (zlib) 的 "123456789" = cbf43926
  assert.equal(by['CRC-32 (zlib)'], 'cbf43926');
  // Adler-32 的 "123456789" = 091e01de
  assert.equal(by['Adler-32'], '091e01de');
  // XOR/SUM 基准
  assert.equal(by['XOR checksum（逐字节异或）'], '31');
});

test('checksumMatrix：Fletcher-16 对拍维基 abcde 样例', () => {
  // 维基百科 Fletcher-16 样例 abcde：sum1=0xF0（495 mod 255），sum2=0xC8（1475 mod 255）
  const rows = checksumMatrix(textBytes('abcde'));
  const f16 = rows.find(r => r.name === 'Fletcher-16');
  assert.equal(f16.value, '00f000c8'); // 展示格式 sum1(4)+sum2(4)
});

test('extractData：IP/URL/邮箱/域名抽取去重', () => {
  const text = 'visit https://a.example.com/x and http://b.cn, mail a@b.com or b@a.cn; ip 10.0.0.1 10.0.0.1 bad 999.1.1.1';
  assert.equal(extractData(text, 'ips'), '10.0.0.1');
  assert.ok(extractData(text, 'urls').includes('https://a.example.com/x'));
  assert.ok(extractData(text, 'emails').includes('a@b.com'));
  const domains = extractData(text, 'domains');
  assert.ok(domains.includes('a.example.com'));
  assert.ok(!domains.includes('999.1.1.1'));
});

test('extractPrintableStrings：unix strings 语义', () => {
  // 二进制里嵌 "flag{abc}" 与 "sh"，minLen=4 只取前者
  const bytes = new Uint8Array([0, 1, 2, ...textBytes('flag{abc}'), 0, ...textBytes('sh'), 0]);
  assert.deepEqual(Array.from(extractPrintableStrings(bytes, 4)), ['flag{abc}']); // 沙箱跨 realm 数组须转换（AGENTS.md 坑位）
  const loose = Array.from(extractPrintableStrings(bytes, 2));
  assert.ok(loose.includes('sh'));
  assert.ok(loose.includes('flag{abc}'));
});

test('FILETIME：双向换算（锚定 1970-01-01 与 2023-01-01）', () => {
  // Unix 0 → FILETIME 116444736000000000
  assert.equal(unixToFiletime(0).toString(), '116444736000000000');
  assert.equal(filetimeToUnix(116444736000000000n), 0);
  // 2023-01-01T00:00:00Z = 1672531200s → 1672531200*1e7 + delta = 133170048000000000
  assert.equal(unixToFiletime(1672531200).toString(), '133170048000000000');
  assert.equal(filetimeToUnix(133170048000000000n), 1672531200);
});

test('defang/refang：互逆', () => {
  const ioc = 'visit http://evil.example.com/x or mail a@b.com';
  const defanged = defang(ioc);
  assert.ok(defanged.includes('[.]') && defanged.includes('hxxp'));
  assert.equal(refang(defanged), ioc);
});

test('entropyReport：英文与随机文本的熵区分', () => {
  const english = entropyReport('the quick brown fox jumps over the lazy dog');
  const random = entropyReport('x7Kp2Qm9zR4vBw1Ld8nJ5tHc3fYs6uE0aW9qZ2rM8bV4kT1pD7gXjN5fL3hC');
  assert.ok(english.entropy > 3 && english.entropy < 5);
  assert.ok(random.entropy > english.entropy);
  // IoC：重复字符多的文本更高
  const repetitive = entropyReport('aaaaaaaaaa');
  assert.ok(repetitive.ioc > english.ioc);
});

test('textLineTool：head/sort/unique/去空行', () => {
  const input = 'b\na\nb\n\nc';
  assert.equal(textLineTool(input, 'unique', 10), 'b\na\n\nc');
  assert.equal(textLineTool(input, 'sort', 10), '\na\nb\nb\nc');
  assert.equal(textLineTool(input, 'head', 2), 'b\na');
  assert.equal(textLineTool(input, 'tail', 2), '\nc');
  assert.equal(textLineTool(input, 'strip-blank', 10), 'b\na\nb\nc');
});
