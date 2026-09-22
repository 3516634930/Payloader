#!/usr/bin/env node
// 构建 English quadgram 评分表（古典密码无密钥破译的适应度函数）
// 用法：node scripts/build-trigram-table.cjs
// 语料：Project Gutenberg 公版书，需先下载到 .trigram-build/（curl -sL https://www.gutenberg.org/cache/epub/<id>/pg<id>.txt）。
// 产物：26^4 = 456,976 项量化计数（每项 1 字节），base64 内嵌到 src/components/EncodingTools.tsx
// 的 CLASSICAL_NGRAM_TABLE_B64。量化公式：q = clamp(round((log10((count+0.01)/total) + 10) * 25.5), 0, 255)，
// 运行时解码 log10p = q / 25.5 - 10。

const fs = require('fs');
const path = require('path');

const rootDir = path.join(__dirname, '..');
const corpusDir = path.join(rootDir, '.trigram-build');

let corpus = '';
for (const file of fs.readdirSync(corpusDir).filter(name => /^pg\d+\.txt$/.test(name))) {
  const raw = fs.readFileSync(path.join(corpusDir, file), 'utf8');
  const start = raw.indexOf('*** START');
  const end = raw.indexOf('*** END');
  const body = raw.slice(start >= 0 ? raw.indexOf('\n', start) + 1 : 0, end >= 0 ? end : raw.length);
  corpus += body;
}

const letters = corpus.toUpperCase().replace(/[^A-Z]/g, '');
console.log(`corpus letters: ${letters.length}`);

// quadgram 计数
const Q = 26;
const counts = new Uint32Array(Q ** 4);
let total = 0;
let a = 0, b = 0, c = 0;
for (let i = 0; i < letters.length; i += 1) {
  const d = letters.charCodeAt(i) - 65;
  if (i >= 3) {
    counts[((a * Q + b) * Q + c) * Q + d] += 1;
    total += 1;
  }
  a = b; b = c; c = d;
}
let distinct = 0;
for (let i = 0; i < counts.length; i += 1) if (counts[i] > 0) distinct += 1;
console.log(`quadgram samples: ${total}, distinct: ${distinct}`);

const quantized = new Uint8Array(Q ** 4);
for (let i = 0; i < counts.length; i += 1) {
  const log10p = Math.log10((counts[i] + 0.01) / total);
  quantized[i] = Math.max(0, Math.min(255, Math.round((log10p + 10) * 25.5)));
}

const b64 = Buffer.from(quantized).toString('base64');
fs.writeFileSync(path.join(corpusDir, 'quadgram-table.b64'), b64, 'utf8');
console.log(`base64 length: ${b64.length} -> .trigram-build/quadgram-table.b64`);

// 自检：真实英文 vs 随机串
const lut = q => q / 25.5 - 10;
const score = text => {
  let s = 0, n = 0;
  for (let i = 0; i + 3 < text.length; i += 1) {
    s += lut(quantized[((text.charCodeAt(i) - 65) * Q + (text.charCodeAt(i + 1) - 65)) * Q * Q + (text.charCodeAt(i + 2) - 65) * Q + (text.charCodeAt(i + 3) - 65)]);
    n += 1;
  }
  return s / Math.max(1, n);
};
const english = 'THEANCIENTMANUSCRIPTWASHIDDENBENEATHTHEOLDLIBRARYFLOORFORMANYDECADESBEFORETHEARCHIVISTDISCOVEREDIT';
const random = 'QXZKJVWBMPYTCRDLGNFHSUEOAIQZXKVWBMPYTCRDLGNFHSUEOAIQZXKVWBMPYTCRDLGNFHSUEOAIQZXKVWBMP';
console.log(`english score/char: ${score(english).toFixed(3)}  random score/char: ${score(random).toFixed(3)}`);
