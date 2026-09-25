// outguess JS↔C 对拍（批次 SI-3）：固定口令/系数 pattern/seed/明文，JS 侧走产品代码
// （outguessCrypto.md5 → arc4 → iterator → outguessExtract），C 参照 driver（手抄原版
// 存档函数）同输入跑嵌入+提取；比较 usable/seed/len/headoffs/skipmods/plain 六面。
// 用法：node scripts/outguess-parity-check.mjs [gcc 输出的 driver 可执行文件路径]
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createTsModuleLoader } from '../tests/helpers/compileTsModule.mjs';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const { loadModule } = createTsModuleLoader();
const { outguessRevealFromCoefficients } = loadModule(
  path.join(projectRoot, 'src', 'utils', 'ctf', 'outguessExtract.ts'),
);
const { Arc4Stream, arc4InitKey, iteratorAdapt, iteratorInit, iteratorNext, iteratorSeed } = loadModule(
  path.join(projectRoot, 'src', 'utils', 'ctf', 'outguessCrypto.ts'),
);

const PASSWORD = 'parity-key';
const SEED = 0x2c4a;
const PLAINTEXT = Uint8Array.from('flag{outguess_js_c_parity_锚定}', (ch) => ch.charCodeAt(0) & 0xff);
// SKIPADJ=2 的散步设计使游走总距离期望≈整个位流；末端方差越界在原版 C 中是"嵌入写
// padding 不落盘 / 提取读未初始化堆"的数据损坏场景（原版自身救不回）——JS 侧位流耗尽
// 显式抛错与 C driver 的 exit(2) 行为对齐（都拒绝）。个别口令/seed 组合会踩进该带（约
// 2/10 概率），属原版固有缺陷的忠实复刻，对拍以默认参数与多数参数组为准。
const NCOEFF = 16000;
const driverPath = process.argv[2] ?? path.join(projectRoot, 'output', 'outguess-ref.exe');

const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

// md5 摘要直接从产品路径的 arc4InitKey 侧取：md5Bytes 由 outguessCrypto 内部调用，
// 此处独立调 codec/crypto 的 md5Bytes 复算（同一实现源）供 C driver 使用。
const { md5Bytes } = loadModule(path.join(projectRoot, 'src', 'utils', 'codec', 'crypto.ts'));
const encDigest = hex(md5Bytes(new TextEncoder().encode(`Encryption${PASSWORD}`)));
const seedDigest = hex(md5Bytes(new TextEncoder().encode(`Seeding${PASSWORD}`)));

// ---- JS 侧：嵌入（镜像）+ 产品提取 ----
const pattern = [7, -7, 2, -2, 0, 3, -1, 1, 5, -3];
const coeffs = Int32Array.from({ length: NCOEFF }, (_, i) => pattern[i % pattern.length]);
const positions = [];
for (let i = 0; i < coeffs.length; i += 1) if (coeffs[i] !== 0 && coeffs[i] !== 1) positions.push(i);
const totalBits = positions.length;
const writeBit = (bitIndex, bit) => { coeffs[positions[bitIndex]] = (coeffs[positions[bitIndex]] & ~1) | bit; };

const as = arc4InitKey('Encryption', new TextEncoder().encode(PASSWORD));
const tas = as.clone();
const iter = iteratorInit(new TextEncoder().encode(PASSWORD));

const header = new Uint8Array([SEED & 0xff, (SEED >> 8) & 0xff, PLAINTEXT.length & 0xff, (PLAINTEXT.length >> 8) & 0xff]);
const encHeader = new Uint8Array(4);
for (let i = 0; i < 4; i += 1) encHeader[i] = header[i] ^ as.getbyte();
const headOffs = [];
for (let i = 0; i < 4; i += 1) {
  headOffs.push(iter.off);
  for (let where = 0; where < 8; where += 1) {
    writeBit(iter.off, (encHeader[i] >> where) & 1);
    iteratorNext(iter);
  }
}
iteratorSeed(iter, SEED);
const encPlain = new Uint8Array(PLAINTEXT.length);
for (let i = 0; i < PLAINTEXT.length; i += 1) encPlain[i] = PLAINTEXT[i] ^ tas.getbyte();
const skipmods = [];
let remaining = PLAINTEXT.length;
let n = 0;
while (remaining > 0) {
  iteratorAdapt(iter, totalBits, remaining);
  skipmods.push(iter.skipmod);
  for (let where = 0; where < 8; where += 1) {
    writeBit(iter.off, (encPlain[n] >> where) & 1);
    iteratorNext(iter);
  }
  n += 1;
  remaining -= 1;
}

const { data, seed: gotSeed, declaredLength } = outguessRevealFromCoefficients(coeffs, PASSWORD);
const jsOut = [
  `usable=${totalBits}`,
  `seed=${gotSeed} len=${declaredLength}`,
  `headoffs=${headOffs.join(',')}`,
  `skipmods=${skipmods.join(',')}`,
  `plain=${hex(data)}`,
].join('\n');

// ---- C 参照 driver ----
const cOut = execFileSync(driverPath, [encDigest, seedDigest, String(NCOEFF), String(SEED), hex(PLAINTEXT)], {
  encoding: 'utf8',
}).replace(/\r/g, '').trimEnd(); // MinGW 文本模式输出 CRLF，比对前统一剥 \r

if (jsOut === cOut) {
  console.log('PARITY OK：JS 产品实现与 C 原版手抄参照六面全一致');
  console.log(jsOut.split('\n').slice(0, 3).join('\n'));
} else {
  const jsLines = jsOut.split('\n');
  const cLines = cOut.split('\n');
  console.error('PARITY MISMATCH');
  for (let i = 0; i < Math.max(jsLines.length, cLines.length); i += 1) {
    if (jsLines[i] !== cLines[i]) {
      console.error(`line ${i} differs (JS ${jsLines[i]?.length ?? 0}B, C ${cLines[i]?.length ?? 0}B)`);
      // 长行（skipmods/plain）按分隔符逐值定位第一处分歧
      const a = jsLines[i]?.split(/[ ,]/) ?? [];
      const b = cLines[i]?.split(/[ ,]/) ?? [];
      for (let j = 0; j < Math.max(a.length, b.length); j += 1) {
        if (a[j] !== b[j]) {
          console.error(`  first diff at token ${j}: JS=${a.slice(Math.max(0, j - 3), j + 3).join('|')} vs C=${b.slice(Math.max(0, j - 3), j + 3).join('|')}`);
          break;
        }
      }
    }
  }
  process.exit(1);
}
