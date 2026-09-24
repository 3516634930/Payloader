// GIF 深度解析引擎测试：inspectGif 结构解析、decodeGifFrame 真实 LZW 解码、delayBits 三口径
// （阈值二进制/ASCII/秒数字符）、异常路径（非 GIF/截断/尾附/无 GCE/帧数与像素红线）。
// 测试向量全部程序化构造（测试侧自带 LZW 编码器 + 子块打包），无外部 fixture。
//
// MP4/AVI 容器覆盖检查结论（sweep2 #19 附带项，fileDetect/embedScan 只读摸底，本任务不改现有文件）：
// - MP4：fileDetect.MAGIC_TABLE 仅 ftyp@4 魔数识别（fileDetect.ts 的 mp4 条目），无 box 级枚举
//   （moov/trak/mdat/udta 列表能力缺失）；embedScan 无 MP4 相关逻辑。
// - AVI：MAGIC_TABLE 未收录 RIFF....AVI（仅收录 RIFF....WAVE），连类型识别都没有，更无 RIFF chunk 枚举。
// - MKV/WebM：EBML 头 0x1A45DFA3 完全未收录，识别与枚举均空白。
// → 视频容器枚举面是独立缺口，不属于 GIF 引擎范围（清单已在交付报告列给主控决策）。
import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const srcDir = path.join(projectRoot, 'src');
const { loadModule } = createTsModuleLoader();
const { inspectGif, decodeGifFrame, decodeGifFrames, GIF_MAX_FRAMES } =
  loadModule(path.join(srcDir, 'utils', 'ctf', 'gifInspect.ts'));

// ---- 测试侧 GIF 造流工厂 ----

// 4 色全局色表：黑/红/绿/蓝。
const GCT = [0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0xff];
// 2 色局部色表：黄/蓝（覆盖全局色表的映射以验证局部优先）。
const LCT2 = [0xff, 0xff, 0x00, 0x00, 0x00, 0xff];

const u16 = value => [value & 0xff, (value >> 8) & 0xff];

// 测试侧 LZW 编码器：与解码器宽度记账严格镜像——解码端在读取时恒比编码端少一次字典追加
// （code===nextCode 的 Km+1 特例即源于此），故编码端码宽递增条件是 nextCode > (1<<codeWidth)
// （到达 (1<<width)+1 才加宽），不是 >=。字典满 4096 时发 clear 重置。LSB-first 位打包。
const lzwEncode = (indices, minCodeSize) => {
  const clearCode = 1 << minCodeSize;
  const eoiCode = clearCode + 1;
  let codeWidth = minCodeSize + 1;
  let nextCode = eoiCode + 1;
  const dict = new Map();
  const out = [];
  let bitBuffer = 0;
  let bitCount = 0;
  const write = code => {
    bitBuffer |= code << bitCount;
    bitCount += codeWidth;
    while (bitCount >= 8) {
      out.push(bitBuffer & 0xff);
      bitBuffer >>>= 8;
      bitCount -= 8;
    }
  };
  write(clearCode);
  let previous = -1;
  for (const symbol of indices) {
    if (previous < 0) {
      previous = symbol;
      continue;
    }
    const key = previous * 256 + symbol;
    if (dict.has(key)) {
      previous = dict.get(key);
      continue;
    }
    write(previous);
    if (nextCode < 4096) {
      dict.set(key, nextCode);
      nextCode += 1;
      if (nextCode > (1 << codeWidth) && codeWidth < 12) codeWidth += 1;
    } else {
      write(clearCode);
      codeWidth = minCodeSize + 1;
      nextCode = eoiCode + 1;
      dict.clear();
    }
    previous = symbol;
  }
  if (previous >= 0) write(previous);
  write(eoiCode);
  if (bitCount > 0) out.push(bitBuffer & 0xff);
  return out;
};

// 子块打包：数据按 ≤255 字节切段，[len][data]...[0x00]。
const subBlocks = data => {
  const out = [];
  for (let index = 0; index < data.length; index += 255) {
    const length = Math.min(255, data.length - index);
    out.push(length, ...data.slice(index, index + length));
  }
  out.push(0);
  return out;
};

// 隔行打包（编码侧）：行主序索引 → 四遍扫描序（0/8、4/8、2/4、1/2）。
const interlacePack = (indices, width, height) => {
  const out = [];
  for (const [start, step] of [[0, 8], [4, 8], [2, 4], [1, 2]]) {
    for (let row = start; row < height; row += step) {
      for (let x = 0; x < width; x += 1) out.push(indices[row * width + x]);
    }
  }
  return out;
};

const textBytes = text => Array.from(text, char => char.charCodeAt(0) & 0xff);

// 单帧字节流：GCE(delay/透明) + Image Descriptor(+局部色表/隔行标志) + LZW min code size + 数据子块链。
const makeFrameBytes = (frame, defaultWidth, defaultHeight) => {
  const width = frame.width ?? defaultWidth;
  const height = frame.height ?? defaultHeight;
  const indices = frame.indices || [0];
  if (frame.indices && frame.indices.length !== width * height) {
    throw new Error(`fixture 帧尺寸不符：${frame.indices.length} != ${width}*${height}`);
  }
  const scan = frame.interlaced ? interlacePack(indices, width, height) : indices;
  const bytes = [];
  if (!frame.skipGce) {
    const transparent = frame.transparentIndex ?? -1;
    bytes.push(0x21, 0xf9, 0x04, transparent >= 0 ? 0x01 : 0x00, ...u16(frame.delay ?? 0), transparent >= 0 ? transparent : 0, 0x00);
  }
  const lctBits = frame.localColors ? Math.log2(frame.localColors.length / 3) - 1 : 0;
  bytes.push(0x2c, ...u16(0), ...u16(0), ...u16(width), ...u16(height),
    (frame.localColors ? 0x80 | lctBits : 0) | (frame.interlaced ? 0x40 : 0));
  if (frame.localColors) bytes.push(...frame.localColors);
  bytes.push(2, ...subBlocks(lzwEncode(scan, 2)));
  return bytes;
};

// 整只 GIF：header + LSD + 全局色表 + 可选 NETSCAPE 循环节/Comment/PlainText + N 帧 + Trailer。
const buildGif = ({ version = '89a', width = 8, height = 8, gct = GCT, frames = [], comment = null, plainText = null, netscapeLoop = null, trailer = true }) => {
  const out = [];
  for (const char of `GIF${version}`) out.push(char.charCodeAt(0));
  out.push(...u16(width), ...u16(height), 0x80 | (Math.log2(gct.length / 3) - 1), 0, 0);
  out.push(...gct);
  if (netscapeLoop !== null) {
    out.push(0x21, 0xff, 0x0b, ...textBytes('NETSCAPE2.0'), 0x03, 0x01, ...u16(netscapeLoop), 0x00);
  }
  if (comment !== null) out.push(0x21, 0xfe, ...subBlocks(textBytes(comment)));
  if (plainText !== null) {
    out.push(0x21, 0x01, 0x0c, ...u16(0), ...u16(0), ...u16(width), ...u16(height), 1, 1, 0, 1,
      ...subBlocks(textBytes(plainText)));
  }
  for (const frame of frames) out.push(...makeFrameBytes(frame, width, height));
  if (trailer) out.push(0x3b);
  return Uint8Array.from(out);
};

// 已知图案：(3x + 5y) mod 4，覆盖全部 4 个色号且逐像素可断言。
const makePattern = (width, height) => {
  const indices = [];
  for (let y = 0; y < height; y += 1) {
    for (let x = 0; x < width; x += 1) indices.push((x * 3 + y * 5) & 3);
  }
  return indices;
};

const PATTERN8 = makePattern(8, 8);
const lastIndexOfSeq = (bytes, seq, from) => {
  for (let index = from; index >= seq.length - 1; index -= 1) {
    let matched = true;
    for (let offset = 0; offset < seq.length; offset += 1) {
      if (bytes[index - seq.length + 1 + offset] !== seq[offset]) {
        matched = false;
        break;
      }
    }
    if (matched) return index - seq.length + 1;
  }
  return -1;
};

// ---- 用例 1：inspectGif 基础结构 ----

test('inspectGif 基础结构：版本/尺寸/循环数/帧数/delays/全局色表/注释段 flag 命中', () => {
  const gif = buildGif({
    width: 8,
    height: 8,
    netscapeLoop: 3,
    comment: 'flag{gif_comment_hit}',
    frames: [{ delay: 7, indices: PATTERN8 }, { delay: 20, indices: PATTERN8 }],
  });
  const result = inspectGif(gif);
  assert.equal(result.version, '89a');
  assert.equal(result.logicalWidth, 8);
  assert.equal(result.logicalHeight, 8);
  assert.equal(result.loopCount, 3);
  assert.equal(result.frames.length, 2);
  assert.equal(result.frames.map(frame => frame.delayMs).join(','), '70,200');
  assert.equal(result.frames[0].lzwMinCodeSize, 2);
  assert.ok(result.globalColorTable);
  assert.equal(result.globalColorTable.length, 12);
  // 沙箱返回数组逐元素断言（AGENTS.md 踩坑：跨 realm 勿用 deepStrictEqual）
  for (let index = 0; index < GCT.length; index += 1) assert.equal(result.globalColorTable[index], GCT[index]);
  assert.equal(result.comments.length, 1);
  assert.ok(result.comments[0].includes('flag{gif_comment_hit}'), `comments=${JSON.stringify(result.comments)}`);
});

// ---- 用例 2：decodeGifFrame 全局色表逐像素还原 ----

test('decodeGifFrame：真实 LZW 编码图案逐像素还原为全局色表 RGBA', () => {
  const gif = buildGif({ width: 8, height: 8, frames: [{ delay: 5, indices: PATTERN8 }] });
  const result = inspectGif(gif);
  const rgba = decodeGifFrame(gif, result.frames[0], result.globalColorTable);
  assert.equal(rgba.length, 8 * 8 * 4);
  for (let pixel = 0; pixel < 64; pixel += 1) {
    const colorIndex = PATTERN8[pixel];
    assert.equal(rgba[pixel * 4], GCT[colorIndex * 3], `R@pixel${pixel}`);
    assert.equal(rgba[pixel * 4 + 1], GCT[colorIndex * 3 + 1], `G@pixel${pixel}`);
    assert.equal(rgba[pixel * 4 + 2], GCT[colorIndex * 3 + 2], `B@pixel${pixel}`);
    assert.equal(rgba[pixel * 4 + 3], 255, `A@pixel${pixel}`);
  }
});

// ---- 用例 3：局部色表覆盖 + 透明索引 ----

test('decodeGifFrame：局部色表优先于全局 + 透明索引 alpha=0', () => {
  const gif = buildGif({
    width: 2,
    height: 2,
    frames: [{ delay: 2, indices: [0, 1, 1, 0], localColors: LCT2, transparentIndex: 1 }],
  });
  const result = inspectGif(gif);
  const rgba = decodeGifFrame(gif, result.frames[0], result.globalColorTable);
  assert.equal(rgba[0], 0xff); // 索引 0 → 黄（来自局部色表，而非全局的黑）
  assert.equal(rgba[1], 0xff);
  assert.equal(rgba[2], 0x00);
  assert.equal(rgba[3], 255);
  assert.equal(rgba[4], 0x00); // 索引 1 → 蓝 + 透明
  assert.equal(rgba[5], 0x00);
  assert.equal(rgba[6], 0xff);
  assert.equal(rgba[7], 0);
});

// ---- 用例 4：隔行扫描帧还原 ----

test('decodeGifFrame：interlaced 帧四遍扫描还原为行主序图案', () => {
  const gif = buildGif({ width: 8, height: 8, frames: [{ delay: 5, indices: PATTERN8, interlaced: true }] });
  const result = inspectGif(gif);
  assert.equal(result.frames[0].interlaced, true);
  const rgba = decodeGifFrame(gif, result.frames[0], result.globalColorTable);
  for (let pixel = 0; pixel < 64; pixel += 1) {
    assert.equal(rgba[pixel * 4], GCT[PATTERN8[pixel] * 3], `R@pixel${pixel}`);
  }
});

// ---- 用例 5：decodeGifFrames 批量惰性填充 ----

test('decodeGifFrames：批量解码填充 frame.imageData，返回成功帧数', () => {
  const gif = buildGif({ width: 8, height: 8, frames: [{ delay: 1, indices: PATTERN8 }, { delay: 2, indices: PATTERN8 }] });
  const result = inspectGif(gif);
  assert.equal(result.frames[0].imageData, undefined);
  assert.equal(decodeGifFrames(gif, result), 2);
  assert.ok(result.frames[0].imageData);
  assert.equal(result.frames[0].imageData.length, 64 * 4);
  assert.equal(result.frames[1].imageData.length, 64 * 4);
});

// ---- 用例 6：delayBits 阈值二进制口径 ----

test('delayBits 阈值二进制口径：raw>50 → 1，[100,10] 交替 → 10101010', () => {
  const delays = [100, 10, 100, 10, 100, 10, 100, 10];
  const gif = buildGif({ width: 2, height: 1, frames: delays.map(delay => ({ delay, indices: [0, 1] })) });
  const result = inspectGif(gif);
  assert.ok(result.delayBits);
  assert.equal(result.delayBits.raw.join(','), delays.join(','));
  assert.equal(result.delayBits.asBinary, '10101010');
});

// ---- 用例 7：delayBits ASCII / 秒数字符口径 ----

test('delayBits ASCII 口径：[102,108,97,103] → flag；秒数字符口径 [1,2,3,0] → 1230', () => {
  const flagGif = buildGif({ width: 2, height: 1, frames: [102, 108, 97, 103].map(delay => ({ delay, indices: [0, 1] })) });
  const flagResult = inspectGif(flagGif);
  assert.equal(flagResult.delayBits.asAscii, 'flag');
  assert.ok(flagResult.anomalies.some(note => note.includes('可打印 ASCII')), `anomalies=${JSON.stringify(flagResult.anomalies)}`);

  const secondsGif = buildGif({ width: 2, height: 1, frames: [1, 2, 3, 0].map(delay => ({ delay, indices: [0, 1] })) });
  const secondsResult = inspectGif(secondsGif);
  assert.equal(secondsResult.delayBits.asSeconds, '1230');
});

// ---- 用例 8：非 GIF 输入抛错 ----

test('inspectGif 非 GIF 输入：PNG 头与超短流均抛中文错误', () => {
  const png = Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, ...new Array(32).fill(0)]);
  assert.throws(() => inspectGif(png), /不是 GIF/);
  assert.throws(() => inspectGif(Uint8Array.of(0x47, 0x49, 0x46, 0x38, 0x39, 0x61)), /不是 GIF|截断/);
});

// ---- 用例 9：截断流尽量解析 + 标注 ----

test('inspectGif 截断流：帧数据中截断只保留已完整帧并标注；去 Trailer 标注未闭合', () => {
  const full = buildGif({
    width: 8,
    height: 8,
    frames: [{ delay: 5, indices: PATTERN8 }, { delay: 6, indices: PATTERN8 }, { delay: 7, indices: PATTERN8 }],
  });
  const thirdFrameGce = lastIndexOfSeq(full, [0x21, 0xf9, 0x04], full.length - 1);
  assert.ok(thirdFrameGce > 0, 'fixture 中应能定位第 3 帧 GCE');
  const cutMidFrame = full.slice(0, thirdFrameGce + 12); // 切进第 3 帧 Image Descriptor 内部
  const midResult = inspectGif(cutMidFrame);
  assert.equal(midResult.frames.length, 2, '应保留前两帧');
  assert.ok(midResult.anomalies.some(note => /截断/.test(note)), `anomalies=${JSON.stringify(midResult.anomalies)}`);

  const cutTrailer = full.slice(0, full.length - 1); // 仅去掉 Trailer
  const trailerResult = inspectGif(cutTrailer);
  assert.equal(trailerResult.frames.length, 3);
  assert.ok(trailerResult.anomalies.some(note => note.includes('Trailer')));
});

// ---- 用例 10：Trailer 后尾附数据 ----

test('inspectGif Trailer 后尾附数据：anomaly 标注字节数', () => {
  const gif = buildGif({ width: 2, height: 2, frames: [{ delay: 5, indices: [0, 1, 2, 3] }] });
  const padded = Uint8Array.from([...Array.from(gif), 0xde, 0xad, 0xbe, 0xef]);
  const result = inspectGif(padded);
  assert.equal(result.frames.length, 1);
  assert.ok(result.anomalies.some(note => note.includes('尾附') && note.includes('4')), `anomalies=${JSON.stringify(result.anomalies)}`);
});

// ---- 用例 11：帧数红线 ----

test(`inspectGif 帧数超过 ${GIF_MAX_FRAMES}：只解析前 ${GIF_MAX_FRAMES} 帧并标注`, () => {
  const frames = [];
  for (let index = 0; index < GIF_MAX_FRAMES + 3; index += 1) {
    frames.push({ delay: 2, indices: [index & 3], width: 1, height: 1 });
  }
  const gif = buildGif({ width: 1, height: 1, frames });
  const result = inspectGif(gif);
  assert.equal(result.frames.length, GIF_MAX_FRAMES);
  assert.ok(result.anomalies.some(note => note.includes(String(GIF_MAX_FRAMES))), `anomalies=${JSON.stringify(result.anomalies.slice(-3))}`);
});

// ---- 用例 12：单帧像素红线 ----

test('decodeGifFrame 像素总数超 1600 万：抛中文错误 + inspectGif 预先标注', () => {
  const gif = buildGif({ width: 5000, height: 4000, frames: [{ delay: 1, indices: null, width: 5000, height: 4000 }] });
  const result = inspectGif(gif);
  assert.ok(result.anomalies.some(note => note.includes('1600 万')), `anomalies=${JSON.stringify(result.anomalies)}`);
  assert.throws(() => decodeGifFrame(gif, result.frames[0], result.globalColorTable), /1600 万/);
});

// ---- 用例 13：延时分布异常线索 + 无 GCE 帧 ----

test('延时异常线索：首帧 0/双值分布命中；无 GCE 帧 delay=0 并标注', () => {
  const mixed = buildGif({
    width: 2,
    height: 1,
    frames: [{ delay: 0, indices: [0, 1] }, { delay: 5, indices: [1, 0] }, { delay: 0, indices: [0, 1] }, { delay: 5, indices: [1, 0] }],
  });
  const mixedResult = inspectGif(mixed);
  assert.ok(mixedResult.anomalies.some(note => note.includes('首帧延时字段为 0')), `anomalies=${JSON.stringify(mixedResult.anomalies)}`);
  assert.ok(mixedResult.anomalies.some(note => note.includes('双值分布')));

  const noGce = buildGif({
    width: 2,
    height: 1,
    frames: [{ delay: 3, indices: [0, 1] }, { delay: 4, indices: [1, 0], skipGce: true }],
  });
  const noGceResult = inspectGif(noGce);
  assert.equal(noGceResult.frames[1].delayMs, 0);
  assert.ok(noGceResult.anomalies.some(note => note.includes('无 GCE')));
});

// ---- 用例 14：PlainText Extension 提取 ----

test('inspectGif PlainText Extension：跳过 12 字节头后提取文本', () => {
  const gif = buildGif({
    width: 4,
    height: 1,
    plainText: 'pt-secret-42',
    frames: [{ delay: 2, indices: [0, 1, 2, 3] }],
  });
  const result = inspectGif(gif);
  assert.equal(result.plainTexts.length, 1);
  assert.equal(result.plainTexts[0], 'pt-secret-42');
});

// ---- 用例 15：单帧无 delayBits + loopCount=0 无限循环 + 87a 版本 ----

test('单帧 GIF delayBits 为 null；loopCount=0 表示无限；GIF87a 可解析', () => {
  const single = buildGif({ width: 2, height: 1, frames: [{ delay: 5, indices: [0, 1] }] });
  assert.equal(inspectGif(single).delayBits, null);

  const ancient = buildGif({
    version: '87a',
    netscapeLoop: 0,
    width: 2,
    height: 1,
    frames: [{ delay: 1, indices: [0, 1] }, { delay: 2, indices: [1, 0] }],
  });
  const ancientResult = inspectGif(ancient);
  assert.equal(ancientResult.version, '87a');
  assert.equal(ancientResult.loopCount, 0);
});

// ---- 用例 16：LZW 边界——码宽递增与 clear 重置（120 像素图案跨过 8/9 码宽边界） ----

test('decodeGifFrame：跨码宽递增边界的图案仍逐像素还原（width 40×height 3）', () => {
  const pattern = makePattern(40, 3);
  const gif = buildGif({ width: 40, height: 3, frames: [{ delay: 5, indices: pattern }] });
  const result = inspectGif(gif);
  const rgba = decodeGifFrame(gif, result.frames[0], result.globalColorTable);
  for (let pixel = 0; pixel < 120; pixel += 1) {
    assert.equal(rgba[pixel * 4], GCT[pattern[pixel] * 3], `R@pixel${pixel}`);
    assert.equal(rgba[pixel * 4 + 3], 255, `A@pixel${pixel}`);
  }
});
