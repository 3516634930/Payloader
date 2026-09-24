// Base64 padding 隐写引擎测试：语义对齐社区 base64stego 脚本（= 前字符索引低 2i 位）。
// 向量程序化构造：编码器把隐藏字节按 2bit/行（1 个 =）/4bit/行（2 个 =）写进 padding 冗余位。
import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const srcDir = path.join(projectRoot, 'src');
const { loadModule } = createTsModuleLoader();
const { base64StegoDecode, base64StegoReport } = loadModule(path.join(srcDir, 'utils', 'codec', 'base64Stego.ts'));

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

// 编码器：给定明文字节流与"载体行"（原始文本按行 base64），把隐藏位写进各含 = 行的冗余位。
// 载体行要求：可解码回原文（行内容来自真实文本的 base64 化——先做一次真编码再改尾字符）。
const encodeStego = (plainText, hiddenText) => {
  const hiddenBytes = Array.from(Buffer.from(hiddenText, 'latin1'));
  let bitQueue = '';
  for (const byte of hiddenBytes) bitQueue += byte.toString(2).padStart(8, '0');
  const lines = [];
  // 块尺寸轮转 11/10 字节 → base64 padding 1/2 混合（9/12 字节整除无 padding 不携带信息）。
  const chunkSizes = [11, 10];
  let position = 0, chunkIndex = 0;
  while (position < plainText.length) {
    const size = chunkSizes[chunkIndex % chunkSizes.length];
    const chunk = plainText.slice(position, position + size);
    position += size;
    chunkIndex += 1;
    let b64 = Buffer.from(chunk, 'latin1').toString('base64');
    const padding = (b64.match(/=+$/) || [''])[0].length;
    if (padding > 0 && bitQueue.length >= 2 * padding) {
      const width = 2 * padding;
      const hiddenBits = bitQueue.slice(0, width); bitQueue = bitQueue.slice(width);
      const want = parseInt(hiddenBits, 2);
      const stripped = b64.replace(/=+$/, '');
      const lastIndex = B64.indexOf(stripped[stripped.length - 1]);
      // 编码端自由度： newIndex ≡ want (mod 2^width) 且落在合法码表区间（保持高位商不变即可）。
      const newIndex = (lastIndex - (lastIndex % (2 ** width))) + want;
      if (newIndex < 64 && newIndex >= 0) {
        b64 = stripped.slice(0, -1) + B64[newIndex] + '='.repeat(padding);
      }
    }
    lines.push(b64);
  }
  return lines.join('\n');
};

test('base64StegoDecode：隐写往返（1 与 2 个 = 混合行）完整还原隐藏文本', () => {
  const plain = 'Steganography is the art and science of writing hidden messages in such a way that no one apart from the sender and intended recipient suspects the existence of the message. '
    + 'This form of message protection has been used throughout history, from invisible inks to microdots, and now to the digital age where information hides in the redundant bits of encodings. '
    + 'Base64 padding steganography exploits the fact that trailing equals signs leave up to four bits unused per line, and every such line adds another fragment of the secret to the stream. '
    + 'Longer carrier texts carry more hidden bits per pass, which is exactly what this steganographic channel is designed to demonstrate here. '
    + 'Every additional padded line recovered during decoding adds two or four more bits to the reconstructed stream.';
  const stego = encodeStego(plain, 'flag{b64_stego_roundtrip}');
  const result = base64StegoDecode(stego);
  assert.ok(result.stegoLines > 0);
  assert.ok(result.text.includes('flag{b64_stego_roundtrip}'), `got ${JSON.stringify(result.text)} (${result.stegoLines} stego lines)`);
});

test('base64StegoDecode：真题语义（= 前字符索引 % 2^(2i)）逐位核对', () => {
  // 手工核对：行 "QUJD=" 解码 "ABC"；= 1 个 → 2bit。= 前字符是 'D'（B64.index=3）→ 3%4=3 → bits "11"
  const result = base64StegoDecode('QUJD=');
  assert.equal(result.bits, '11');
  assert.equal(result.stegoLines, 1);
});

test('base64StegoDecode：两个 = 的行贡献 4bit', () => {
  // "QQ=="：= 2 个 → 4bit；index('Q')=16 → 16%16=0 → "0000"
  const result = base64StegoDecode('QQ==');
  assert.equal(result.bits, '0000');
});

test('base64StegoDecode：无 = 行不携带信息，空输入安全', () => {
  assert.equal(base64StegoDecode('QUJDQUJD').bits, '');
  assert.equal(base64StegoDecode('').bits, '');
  assert.equal(base64StegoDecode('\r\n\r\n').bits, '');
});

test('base64StegoDecode：非 base64 行跳过（混合文本容错）', () => {
  const result = base64StegoDecode('hello world\nQUJD=\nnot base64!!\nQQE=');
  assert.equal(result.stegoLines, 2);
  assert.ok(result.bits.length === 4);
});

test('base64StegoReport：JSON 报告结构完整', () => {
  const report = JSON.parse(base64StegoReport('QUJD=\nQQE='));
  assert.equal(report.tool, 'base64-stego');
  assert.ok('hiddenText' in report && 'bits' in report);
});
