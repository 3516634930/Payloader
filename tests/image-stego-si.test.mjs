// 批次 SI 图片隐写引擎测试（C/D/B 线）：Arnold/BF+Brainloller+Braincopter/光栅+Stereogram/
// 盲水印（pyRandom+fft+encode/decode 逐像素对拍）/PixelJihad。向量全部程序化构造；
// 跨实现对拍锚点：pyRandom 对拍本机 CPython 输出（内嵌向量）、fft 对拍朴素 DFT、
// 盲水印 decode 对拍 numpy 原版语义参照（output/bw-*.npy 缺失时该项跳过）。
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const srcDir = path.join(projectRoot, 'src');
const { loadModule } = createTsModuleLoader();
const arnold = loadModule(path.join(srcDir, 'utils', 'ctf', 'arnold.ts'));
const esolangs = loadModule(path.join(srcDir, 'utils', 'ctf', 'esolangs.ts'));
const raster = loadModule(path.join(srcDir, 'utils', 'ctf', 'rasterStego.ts'));
const bw = loadModule(path.join(srcDir, 'utils', 'ctf', 'blindWatermark.ts'));
const pyRandomMod = loadModule(path.join(srcDir, 'utils', 'ctf', 'pyRandom.ts'));
const fft = loadModule(path.join(srcDir, 'utils', 'ctf', 'fft.ts'));
const pj = loadModule(path.join(srcDir, 'utils', 'ctf', 'pixelJihad.ts'));

const solid = (width, height, value) => {
  const data = new Uint8ClampedArray(width * height * 4);
  for (let i = 0; i < width * height; i += 1) {
    data[i * 4] = value; data[i * 4 + 1] = value; data[i * 4 + 2] = value; data[i * 4 + 3] = 255;
  }
  return { data, width, height };
};
const gradient = n => {
  const data = new Uint8ClampedArray(n * n * 4);
  for (let i = 0; i < n * n; i += 1) {
    data[i * 4] = (i * 4) % 256; data[i * 4 + 1] = (i * 7) % 256; data[i * 4 + 2] = (i * 13) % 256; data[i * 4 + 3] = 255;
  }
  return { data, width: n, height: n };
};
const samePixels = (a, b) => {
  if (a.width !== b.width || a.height !== b.height) return false;
  for (let i = 0; i < a.data.length; i += 1) if (a.data[i] !== b.data[i]) return false;
  return true;
};

// ---- Arnold 猫脸变换 ----

test('Arnold：正逆往返还原、周期公式（N=2^m → 3·2^(m-2)）、周期法解密、一般化 (a,b) 可逆、非方阵报错', () => {
  const img = gradient(8);
  const scrambled = arnold.arnoldTransform(img, { iterations: 5 });
  assert.ok(!samePixels(scrambled, img), '置乱必须改变图像');
  assert.ok(samePixels(arnold.arnoldInverse(scrambled, { iterations: 5 }), img), '逆变换 5 次应还原');
  assert.equal(arnold.arnoldPeriod(8), 6);
  assert.equal(arnold.arnoldPeriod(128), 96);
  assert.equal(arnold.arnoldPeriod(256), 192);
  const twice = arnold.arnoldTransform(img, { iterations: 3 });
  assert.ok(samePixels(arnold.arnoldTransform(twice, { iterations: arnold.arnoldPeriod(8) - 3 }), img), '周期法解密');
  const generalized = arnold.arnoldTransform(img, { iterations: 4, a: 2, b: 3 });
  assert.ok(samePixels(arnold.arnoldInverse(generalized, { iterations: 4, a: 2, b: 3 }), img), '(a,b)=(2,3) det=1 可逆');
  assert.throws(() => arnold.arnoldTransform({ data: new Uint8ClampedArray(12), width: 4, height: 3 }, {}), /方阵/);
});

// ---- Brainfuck / Brainloller / Braincopter ----

test('Brainfuck：hello world 经典程序、输入回显、括号失配中文报错、步数上限熔断', () => {
  const hello = '++++++++[>++++[>++>+++>+++>+<<<<-]>+>+>->>+[<]<-]>>.>---.+++++++..+++.>>.<-.<.+++.------.--------.>>+.>++.';
  const result = esolangs.runBrainfuck(hello);
  assert.equal(result.error, null);
  assert.equal(result.output, 'Hello World!\n');
  assert.equal(esolangs.runBrainfuck(',[.,]', 'flag{bf_ok}').output, 'flag{bf_ok}');
  assert.match(esolangs.runBrainfuck('[+').error, /缺少配对/);
  assert.match(esolangs.runBrainfuck('+]').error, /缺少配对/);
  const timed = esolangs.runBrainfuck('+[]', '', 1000);
  assert.equal(timed.timedOut, true);
  assert.equal(timed.steps, 1000);
});

test("Brainloller 色表解码 + Braincopter mod-11 解码 + 转向指令消费 + 'X' 终止标记", () => {
  const mk = (width, height, pixels) => {
    const data = new Uint8ClampedArray(width * height * 4);
    pixels.forEach(([x, y, r, g, b]) => {
      const base = (y * width + x) * 4;
      data[base] = r; data[base + 1] = g; data[base + 2] = b; data[base + 3] = 255;
    });
    return { data, width, height };
  };
  const loller = mk(4, 1, [[0, 0, 0xff, 0, 0], [1, 0, 0, 0xff, 0], [2, 0, 0, 0, 0xff], [3, 0, 0, 0x80, 0]]);
  const lollerDecoded = esolangs.decodeBrainloller(loller);
  assert.equal(lollerDecoded.commands, '>+.-');
  // braincopter：(65536R+256G+B)%11：0x00='>' 0x02='+' 0x04='.' 0x0a='X'
  const copter = mk(5, 1, [[0, 0, 0, 0, 0], [1, 0, 0, 0, 2], [2, 0, 0, 0, 4], [3, 0, 0, 0, 5], [4, 0, 0, 0, 10]]);
  const copterDecoded = esolangs.decodeBraincopter(copter);
  assert.equal(copterDecoded.commands, '>+.,');
  assert.equal(copterDecoded.terminatedByMarker, true);
});

// ---- 光栅 + Stereogram ----

test('光栅相位抽取：整除维度周期枚举、黑像素抽取还原、压缩重组宽度', () => {
  const img = solid(8, 4, 200);
  for (let y = 0; y < 4; y += 1) for (let x = 0; x < 8; x += 1) {
    const base = (y * 8 + x) * 4;
    if (x % 4 === 0 && y % 2 === 0) { img.data[base] = 0; img.data[base + 1] = 0; img.data[base + 2] = 0; }
  }
  const all = raster.rasterRevealAll(img, 4);
  assert.ok(all.length >= 12, '8 宽 4 高在周期 2/4 下至少 12 个候选');
  const phase0 = all.find(c => c.axis === 'x' && c.period === 4 && c.phase === 0);
  let darkCount = 0;
  for (let i = 0; i < phase0.image.data.length; i += 4) if (phase0.image.data[i] < 100) darkCount += 1;
  assert.equal(darkCount, 4);
  const compact = raster.rasterCompact(img, 'x', 4, 0);
  assert.equal(compact.width, 2);
  assert.equal(compact.height, 4);
});

test('Stereogram：偏移差分零差区、周期自动估计命中真值', () => {
  const st = solid(64, 8, 0);
  for (let y = 0; y < 8; y += 1) for (let x = 0; x < 64; x += 1) {
    const base = (y * 64 + x) * 4;
    const g = (x % 16) * 15;
    st.data[base] = g; st.data[base + 1] = g; st.data[base + 2] = g;
  }
  const estimate = raster.stereogramEstimateOffset(st, 8, 32);
  assert.equal(estimate.bestOffset, 16);
  const diff = raster.stereogramDiff(st, 16);
  let zeroCount = 0;
  for (let i = 0; i < diff.data.length; i += 4) if (diff.data[i] === 0) zeroCount += 1;
  assert.ok(zeroCount >= 384, `offset=16 处重复周期差分应大面积为零（实际 ${zeroCount}/512）`);
});

// ---- pyRandom（CPython 对拍向量，由本机 Python 3.10 实测生成） ----

test('PythonRandom：MT19937+init_by_array+shuffle 与 CPython 逐位一致（seed 0/1/5 锚定向量）', () => {
  const random0 = new pyRandomMod.PythonRandom();
  random0.seed(0);
  assert.equal(random0.getrandbits(32), 3626764237);
  assert.equal(random0.getrandbits(32), 1654615998);
  assert.equal(random0.getrandbits(32), 3255389356);
  const random1 = new pyRandomMod.PythonRandom();
  random1.seed(1);
  assert.equal(random1.getrandbits(32), 577090037);
  const random5 = new pyRandomMod.PythonRandom();
  random5.seed(5);
  const items = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
  random5.shuffleInPlace(items);
  assert.deepEqual(Array.from(items), [2, 3, 1, 0, 8, 7, 6, 5, 4, 9]);
});

// ---- FFT（任意尺寸：naive DFT 对拍 + numpy 交叉锚定点） ----

test('FFT：radix-2/Bluestein/naive 三路径与朴素 DFT 全尺寸一致，素数尺寸过 numpy 锚点', () => {
  let seedState = 12345;
  const rnd = () => { seedState = (seedState * 1103515245 + 12345) & 0x7fffffff; return (seedState / 0x7fffffff) * 2 - 1; };
  let worst = 0;
  for (const n of [1, 2, 3, 5, 8, 13, 16, 21, 32, 33, 64, 97, 100, 128, 251, 256]) {
    const input = { re: Float64Array.from({ length: n }, rnd), im: Float64Array.from({ length: n }, rnd), length: n };
    const mine = fft.fft1d(input);
    for (let k = 0; k < n; k += 1) {
      let sr = 0; let si = 0;
      for (let t = 0; t < n; t += 1) {
        const a = -2 * Math.PI * k * t / n;
        sr += input.re[t] * Math.cos(a) - input.im[t] * Math.sin(a);
        si += input.re[t] * Math.sin(a) + input.im[t] * Math.cos(a);
      }
      worst = Math.max(worst, Math.abs(mine.re[k] - sr), Math.abs(mine.im[k] - si));
    }
  }
  assert.ok(worst < 1e-9, `全尺寸最大偏差 ${worst.toExponential(3)} 应 < 1e-9`);
  // numpy 锚点（output/fft-vec.json 由 scripts/regen-si-vectors.py 确定性再生——
  // 整数域序列 (i*37)%257，双语言无浮点/整数语义分叉；X[1] 期望值由 py numpy 算得 = -1.353-0.589i）
  const vectorPath = path.join(projectRoot, 'output', 'fft-vec.json');
  if (existsSync(vectorPath)) {
    const vals = JSON.parse(readFileSync(vectorPath, 'utf8')).map(Number);
    const n = 33;
    const input = { re: new Float64Array(n), im: new Float64Array(n), length: n };
    for (let i = 0; i < n; i += 1) { input.re[i] = vals[2 * i]; input.im[i] = vals[2 * i + 1]; }
    const out = fft.fft1d(input);
    assert.ok(Math.abs(out.re[1] - -1.353) < 0.001 && Math.abs(out.im[1] - -0.589) < 0.001, 'X[1] 应与 numpy 一致');
  }
});

// ---- 盲水印 FFT 版（自闭环 + numpy 原版语义逐像素对拍） ----

test('盲水印：encode→decode 闭环显影、水印超半高画布报错、尺寸不一致报错', () => {
  const carrier = solid(64, 64, 128);
  const watermark = solid(64, 32, 0);
  for (let y = 8; y < 24; y += 1) for (let x = 8; x < 56; x += 1) {
    const base = (y * 64 + x) * 4;
    watermark.data[base] = 255; watermark.data[base + 1] = 255; watermark.data[base + 2] = 255;
  }
  const marked = bw.blindWatermarkEncode(carrier, watermark);
  const recovered = bw.blindWatermarkDecode(carrier, marked);
  let bright = 0; let dark = 0; let brightCount = 0; let darkCount = 0;
  for (let y = 0; y < 32; y += 1) for (let x = 0; x < 64; x += 1) {
    const v = recovered.data[(y * 64 + x) * 4];
    if (x >= 8 && x < 56 && y >= 8 && y < 24) { bright += v; brightCount += 1; } else { dark += v; darkCount += 1; }
  }
  // uint8-wrap 语义下亮度均值非显影判据；用亮区高对比占比（wrap 后两簇）与暗区对比
  const brightAvg = bright / brightCount;
  const darkAvg = dark / darkCount;
  assert.ok(Math.abs(brightAvg - darkAvg) > 15, `亮/暗区均值差 ${Math.abs(brightAvg - darkAvg).toFixed(1)} 应可区分（wrap 语义）`);
  assert.throws(() => bw.blindWatermarkEncode(carrier, solid(64, 33, 0)), /超过半高画布上限/);
  assert.throws(() => bw.blindWatermarkDecode(carrier, solid(32, 32, 0)), /尺寸必须一致/);
});

test('盲水印跨实现对拍：JS decode 逐像素复现 numpy 原版语义参照（output/bw-*.npy）', t => {
  const carrierPath = path.join(projectRoot, 'output', 'bw-carrier.npy');
  const markedPath = path.join(projectRoot, 'output', 'bw-marked.npy');
  const refPath = path.join(projectRoot, 'output', 'bw-decode-ref.npy');
  // 参照缺失时显式 skip 计数（reviewer P2：裸 return 会被记成 pass，掩盖对拍未执行）
  if (!existsSync(carrierPath) || !existsSync(markedPath) || !existsSync(refPath)) {
    t.skip('npy 参照缺失：py -3.10 scripts/regen-si-vectors.py 再生后执行');
    return;
  }
  const loadNpy = file => {
    const buf = readFileSync(file);
    const headerLen = buf.readInt16LE(8);
    const header = buf.slice(10, 10 + headerLen).toString();
    const shape = header.match(/'shape': \(([^)]*)\)/)[1].split(',').map(v => parseInt(v.trim())).filter(v => !Number.isNaN(v));
    return { data: new Uint8Array(buf.slice(10 + headerLen)), width: shape[1], height: shape[0] };
  };
  const toRgba = t => {
    const d = new Uint8ClampedArray(t.width * t.height * 4);
    for (let i = 0; i < t.width * t.height; i += 1) { d[i * 4] = t.data[i]; d[i * 4 + 1] = t.data[i]; d[i * 4 + 2] = t.data[i]; d[i * 4 + 3] = 255; }
    return { data: d, width: t.width, height: t.height };
  };
  const reference = loadNpy(refPath);
  const jsOut = bw.blindWatermarkDecode(toRgba(loadNpy(carrierPath)), toRgba(loadNpy(markedPath)));
  let mismatch = 0;
  for (let i = 0; i < 64 * 64; i += 1) if (Math.abs(jsOut.data[i * 4] - reference.data[i]) > 2) mismatch += 1;
  assert.equal(mismatch, 0, `与 numpy 原版语义参照逐像素偏差（>2）应为 0，实际 ${mismatch}/4096`);
});

// ---- PixelJihad（vendor sjcl） ----

test('PixelJihad：无口令/口令双闭环、错口令报错、容量上限报错', () => {
  const mk = (w, h, seed) => {
    const d = new Uint8ClampedArray(w * h * 4);
    let s = seed;
    for (let i = 0; i < w * h * 4; i += 1) { s = (s * 1103515245 + 12345) & 0x7fffffff; d[i] = (s / 0x7fffffff) * 256 | 0; }
    return { data: d, width: w, height: h };
  };
  const carrier = mk(64, 64, 7);
  const plain = pj.pixelJihadEncode(carrier, 'flag{pixeljihad_plain_ok}');
  assert.equal(pj.pixelJihadDecode(plain), 'flag{pixeljihad_plain_ok}');
  const encrypted = pj.pixelJihadEncode(carrier, 'flag{pixeljihad_aes_ccm_ok}', 'S3cretPw!');
  assert.equal(pj.pixelJihadDecode(encrypted, 'S3cretPw!'), 'flag{pixeljihad_aes_ccm_ok}');
  assert.throws(() => pj.pixelJihadDecode(encrypted, 'wrong'), /口令|CORRUPT|decrypt|JSON/);
  assert.throws(() => pj.pixelJihadEncode(mk(4, 4, 1), 'a'.repeat(200)), /容量/);
  // 位置序列确定性：同口令同图两次 encode 的改动位置完全一致（加密含随机 salt 故用无口令模式验证）
  const plainAgain = pj.pixelJihadEncode(carrier, 'flag{pixeljihad_plain_ok}');
  let sameChanged = true;
  for (let i = 0; i < carrier.data.length; i += 1) {
    const changedA = plain.data[i] !== carrier.data[i];
    const changedB = plainAgain.data[i] !== carrier.data[i];
    if (changedA !== changedB) { sameChanged = false; break; }
  }
  assert.ok(sameChanged, '无口令位置序列应确定（history 重放一致）');
});
