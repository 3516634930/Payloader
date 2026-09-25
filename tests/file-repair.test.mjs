// 文件头修复引擎（BMP/GIF/JPG）+ ZIP NTFS ADS 提取测试：
// - BMP：测试侧手写 24 位未压缩 BMP 构造器（54B 头 + 逐行非零像素 + 零补齐），坏魔数/坏宽高 →
//   修复后逐字节等于原始好文件（像素区零损伤），另覆盖负高自顶向下、健康直通、RLE 拒绝枚举。
// - GIF：测试侧自带 LZW 编码器（与 gifInspect 解码器宽度记账镜像，同 gif-inspect.test.mjs 的实现）
//   构造最小 GIF，坏头/坏 LSD 宽高 → 修复；guessGifSize 单帧精确/多帧包围盒；手工指定模式。
// - JPG：复用仓内真题资产 tests/real-challenges/09_trailing_zip/epic-floss-meme.jpg
//   （1200×900 progressive JPEG + 尾附 ZIP 352B）：EOI 截断补写后逐字节等于完整 jpg、
//   SOF2 宽高读出与测试侧独立解析一致、段结构枚举含 SOS/SOF2/尾附提示；SOI 重写用合成向量。
// - NTFS ADS：测试侧手拼最小 ZIP（local header + CD + EOCD，CRC32 自实现）：
//   冒号虚拟条目形态、0x000a extra field 流属性形态（u16/u8 名长两分支）、官方 24B 时间戳不误报、
//   7z 容器识别、EOCD/CD 截断后的本地头扫描兜底。
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const srcDir = path.join(projectRoot, 'src');
const { loadModule } = createTsModuleLoader();
const { repairBmp, repairGif, repairGifWithSize, guessGifSize, repairJpg } = loadModule(
  path.join(srcDir, 'utils', 'ctf', 'fileRepair.ts'),
);
const { extractNtfsAds } = loadModule(path.join(srcDir, 'utils', 'ctf', 'ntfsAds.ts'));

// 沙箱跨 realm 防御：逐字节比较，不依赖 assert 的原型判定。
const bytesEqual = (left, right) => {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
};

const utf8Bytes = text => new TextEncoder().encode(text);

// ---- BMP 构造器（Wikipedia BMP file format：54B 头，24bpp，行补齐到 4 字节倍数）----

const bmpRowSize = width => ((24 * width + 31) >> 5) << 2;

const buildBmp = (width, height, options = {}) => {
  const rowSize = bmpRowSize(width);
  const pixelBytes = rowSize * Math.abs(height);
  const total = 54 + pixelBytes;
  const buf = Buffer.alloc(total);
  buf.write('BM', 0, 'latin1');
  buf.writeUInt32LE(total, 2);
  buf.writeUInt32LE(54, 10); // bfOffBits
  buf.writeUInt32LE(40, 14); // BITMAPINFOHEADER
  buf.writeInt32LE(width, 18);
  buf.writeInt32LE(options.topDown ? -height : height, 22);
  buf.writeUInt16LE(1, 26); // planes
  buf.writeUInt16LE(24, 28); // bitCount
  buf.writeUInt32LE(0, 30); // BI_RGB
  buf.writeUInt32LE(pixelBytes, 34);
  const pixelBytesPerRow = Math.ceil((24 * width) / 8);
  for (let row = 0; row < Math.abs(height); row += 1) {
    for (let col = 0; col < rowSize; col += 1) {
      // 像素字节全非零、补齐字节恒零：宽度枚举的行补齐核验才能一锤定音（7×5 与 8×5 等
      // 同行长大小区分不开时，靠补齐位置的字节取值区分）。
      buf[54 + row * rowSize + col] = col < pixelBytesPerRow ? ((row * 31 + col * 7) % 251) + 1 : 0;
    }
  }
  return buf;
};

test('repairBmp：坏魔数 + 宽高被改成 1×1 → 反推 7×5 且逐字节还原好文件', async () => {
  const good = buildBmp(7, 5);
  const broken = Buffer.from(good);
  broken[0] = 0x58;
  broken[1] = 0x58;
  broken.writeInt32LE(1, 18);
  broken.writeInt32LE(1, 22);
  const result = await repairBmp(broken);
  assert.equal(result.width, 7);
  assert.equal(result.height, 5);
  assert.equal(result.bytes[0], 0x42);
  assert.equal(result.bytes[1], 0x4d);
  assert.ok(bytesEqual(result.bytes, good), '修复结果应逐字节等于原始好文件（像素区零损伤）');
  assert.ok(result.diagnosis.some(line => line.includes('魔数')), '诊断应记录魔数重写');
  assert.ok(result.diagnosis.some(line => line.includes('7×5')), '诊断应列出命中的候选');
});

test('repairBmp：仅宽度损坏时负高（自顶向下）符号保留', async () => {
  const good = buildBmp(7, 5, { topDown: true });
  const broken = Buffer.from(good);
  broken.writeInt32LE(1, 18);
  const result = await repairBmp(broken);
  assert.equal(result.width, 7);
  assert.equal(result.height, -5);
  assert.ok(bytesEqual(result.bytes, good));
});

test('repairBmp：健康文件直通不改动', async () => {
  const good = buildBmp(7, 5);
  const result = await repairBmp(good);
  assert.equal(result.width, 7);
  assert.equal(result.height, 5);
  assert.ok(bytesEqual(result.bytes, good));
  assert.ok(result.diagnosis.some(line => line.includes('一致：无需修复')));
});

test('repairBmp：RLE 变长压缩拒绝宽高反推（只诊断不改写）', async () => {
  const broken = buildBmp(7, 5);
  broken.writeInt32LE(1, 18);
  broken.writeInt32LE(1, 22);
  broken.writeUInt32LE(1, 30); // BI_RLE8
  const result = await repairBmp(broken);
  assert.equal(result.width, 1, 'RLE 下宽高保持原声明不被臆改');
  assert.ok(result.diagnosis.some(line => line.includes('不可反推')));
});

// ---- GIF 构造器（测试侧 LZW 编码器：码宽记账与 gifInspect 解码器严格镜像）----

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

const u16gif = value => [value & 0xff, (value >> 8) & 0xff];

const buildGif = (logicalWidth, logicalHeight, frames) => {
  const out = [];
  for (const ch of 'GIF89a') out.push(ch.charCodeAt(0));
  out.push(...u16gif(logicalWidth), ...u16gif(logicalHeight), 0x81, 0, 0); // packed=0x81：4 色全局色表
  out.push(0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0x00); // GCT 12B
  for (const frame of frames) {
    out.push(0x2c, ...u16gif(frame.left), ...u16gif(frame.top), ...u16gif(frame.w), ...u16gif(frame.h), 0x00);
    out.push(2); // LZW min code size
    const codes = lzwEncode(frame.indices, 2);
    for (let index = 0; index < codes.length; index += 255) {
      const chunk = codes.slice(index, index + 255);
      out.push(chunk.length, ...chunk);
    }
    out.push(0); // 子块终止符
  }
  out.push(0x3b); // Trailer
  return Buffer.from(out);
};

const frameIndices = count => Array.from({ length: count }, (_, index) => (index * 5 + Math.floor(index / 8)) % 4);

test('repairGif：坏头 + LSD 宽高清零 → 按单帧描述符精确还原 8×4', async () => {
  const good = buildGif(8, 4, [{ left: 0, top: 0, w: 8, h: 4, indices: frameIndices(32) }]);
  const broken = Buffer.from(good);
  broken.write('XXXXXX', 0, 'latin1');
  broken.writeUInt16LE(0, 6);
  broken.writeUInt16LE(0, 8);
  const result = await repairGif(broken);
  assert.equal(result.width, 8);
  assert.equal(result.height, 4);
  assert.equal(String.fromCharCode(...result.bytes.subarray(0, 6)), 'GIF89a');
  assert.ok(bytesEqual(result.bytes, good), '帧数据/LZW 流零损伤');
  assert.ok(result.diagnosis.some(line => line.includes("重写为 'GIF89a'")));
});

test('repairGif：LSD 被改小容不下帧覆盖区 → 扩写为多帧包围盒 12×6', async () => {
  const frames = [
    { left: 0, top: 0, w: 8, h: 4, indices: frameIndices(32) },
    { left: 4, top: 2, w: 8, h: 4, indices: frameIndices(32) },
  ];
  const good = buildGif(12, 6, frames);
  const broken = Buffer.from(good);
  broken.writeUInt16LE(4, 6);
  broken.writeUInt16LE(2, 8);
  const result = await repairGif(broken);
  assert.equal(result.width, 12);
  assert.equal(result.height, 6);
  assert.ok(bytesEqual(result.bytes, good));
});

test('repairGif：画布大于帧覆盖区（合法形态）不改动', async () => {
  const good = buildGif(16, 8, [{ left: 0, top: 0, w: 8, h: 4, indices: frameIndices(32) }]);
  const result = await repairGif(good);
  assert.equal(result.width, 16);
  assert.equal(result.height, 8);
  assert.ok(bytesEqual(result.bytes, good));
  assert.ok(result.diagnosis.some(line => line.includes('未改动')));
});

test('guessGifSize：单帧锚定 (0,0) 为精确值，多帧为覆盖包围盒', () => {
  const single = guessGifSize(buildGif(8, 4, [{ left: 0, top: 0, w: 8, h: 4, indices: frameIndices(32) }]));
  assert.equal(single.width, 8);
  assert.equal(single.height, 4);
  assert.equal(single.frameCount, 1);
  assert.equal(single.exact, true);
  const multi = guessGifSize(
    buildGif(12, 6, [
      { left: 0, top: 0, w: 8, h: 4, indices: frameIndices(32) },
      { left: 4, top: 2, w: 8, h: 4, indices: frameIndices(32) },
    ]),
  );
  assert.equal(multi.width, 12);
  assert.equal(multi.height, 6);
  assert.equal(multi.exact, false);
});

test('repairGifWithSize：手工指定宽高确定性重写（含坏头自愈）', async () => {
  const frames = [{ left: 0, top: 0, w: 8, h: 4, indices: frameIndices(32) }];
  const good = buildGif(100, 50, frames);
  const broken = Buffer.from(good);
  broken.write('ZZZZZZ', 0, 'latin1');
  const result = await repairGifWithSize(broken, 100, 50);
  assert.equal(result.width, 100);
  assert.equal(result.height, 50);
  assert.ok(bytesEqual(result.bytes, good));
  await assert.rejects(() => repairGifWithSize(good, 0, 50), /1-65535/);
  await assert.rejects(() => repairGifWithSize(good, 70000, 50), /1-65535/);
});

// ---- JPG（真题资产 + 合成向量）----

const JPG_ASSET = path.join(projectRoot, 'tests', 'real-challenges', '09_trailing_zip', 'epic-floss-meme.jpg');

const findFirstEoi = bytes => {
  for (let index = 2; index + 1 < bytes.length; index += 1) {
    if (bytes[index] === 0xff && bytes[index + 1] === 0xd9) return index;
  }
  return -1;
};

test('repairJpg：真题资产段结构枚举 + SOF2 宽高读出 + 尾附数据提示（不截断）', async () => {
  const original = fs.readFileSync(JPG_ASSET);
  const result = await repairJpg(original);
  // 测试侧独立解析 SOF2（FFC2@187：高 BE u16@192、宽 BE u16@194）与模块读数比对。
  const view = new DataView(original.buffer, original.byteOffset, original.byteLength);
  let sofOffset = -1;
  for (let index = 2; index + 1 < original.length; index += 1) {
    if (original[index] === 0xff && original[index + 1] === 0xc2) {
      sofOffset = index;
      break;
    }
  }
  assert.notEqual(sofOffset, -1);
  const expectedHeight = view.getUint16(sofOffset + 5);
  const expectedWidth = view.getUint16(sofOffset + 7);
  assert.equal(result.sofFrames.length, 1);
  assert.equal(result.sofFrames[0].width, expectedWidth);
  assert.equal(result.sofFrames[0].height, expectedHeight);
  assert.equal(result.sofFrames[0].name, 'SOF2');
  assert.ok(result.segments.some(segment => segment.name === 'SOS' && segment.entropyBytes > 0), 'SOS 段应带熵数据长度');
  assert.ok(result.segments.some(segment => segment.name === 'EOI'));
  const eoi = findFirstEoi(original);
  assert.ok(result.diagnosis.some(line => line.includes(`尾附数据`) && line.includes(String(original.length - eoi - 2))), '应提示 EOI 后尾附字节数且不截断');
  assert.equal(result.repairedEoi, false);
  assert.ok(bytesEqual(result.bytes, original), '无需修复时逐字节原样返回');
});

test('repairJpg：尾部截断（EOI 缺失）→ 补写 FFD9 后等于完整 jpg', async () => {
  const original = fs.readFileSync(JPG_ASSET);
  const eoi = findFirstEoi(original);
  const complete = original.subarray(0, eoi + 2);
  const truncated = original.subarray(0, eoi);
  const result = await repairJpg(truncated);
  assert.equal(result.repairedEoi, true);
  assert.ok(bytesEqual(result.bytes, complete), '补 EOI 后应逐字节等于完整 jpg');
  assert.ok(result.diagnosis.some(line => line.includes('截断') && line.includes('补写 FFD9')));
  assert.equal(result.width, 1200);
  assert.equal(result.height, 900);
});

test('repairJpg：合成向量 SOI 重写 + 段枚举正确', async () => {
  // SOI + APP0(JFIF, len=0x10) + EOI 的最小结构合法流（无任何 FF 序列干扰 SOI 定位）。
  const synth = Buffer.from('ffd8ffe000104a46494600010100000100010000ffd9', 'hex');
  const damaged = Buffer.from(synth);
  damaged[0] = 0x00;
  damaged[1] = 0x00;
  const result = await repairJpg(damaged);
  assert.equal(result.repairedSoi, true);
  assert.ok(bytesEqual(result.bytes, synth));
  assert.deepEqual(Array.from(result.segments, segment => segment.name), ['SOI', 'APP0', 'EOI']);
  assert.equal(result.segments[1].length, 16);
});

test('repairJpg：非 JPEG 垃圾输入拒绝修复', async () => {
  const result = await repairJpg(Buffer.from([0x00, 0x01, 0x02, 0x03]));
  assert.equal(result.bytes, undefined);
  assert.ok(result.diagnosis.some(line => line.includes('不是 JPEG')));
});

// ---- NTFS ADS（手拼最小 ZIP：local header + CD + EOCD）----

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let value = 0; value < 256; value += 1) {
    let entry = value;
    for (let bit = 0; bit < 8; bit += 1) entry = entry & 1 ? 0xedb88320 ^ (entry >>> 1) : entry >>> 1;
    table[value] = entry >>> 0;
  }
  return table;
})();

const crc32 = data => {
  let crc = 0xffffffff;
  for (const byte of data) crc = CRC_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
};

const u16le = value => {
  const buf = Buffer.alloc(2);
  buf.writeUInt16LE(value & 0xffff, 0);
  return buf;
};
const u32le = value => {
  const buf = Buffer.alloc(4);
  buf.writeUInt32LE(value >>> 0, 0);
  return buf;
};

// NTFS extra field（APPNOTE 4.5.5）：[tag 0x000a][size][4B 保留][属性…]。
const buildNtfsExtra = attributePayloads => {
  const body = Buffer.concat([Buffer.alloc(4), ...attributePayloads]);
  return Buffer.concat([u16le(0x000a), u16le(body.length), body]);
};
// 0x0001 流属性（CTF 私改形态）：[2B tag][2B size][2B 保留][2B 名长][名][数据]。
const buildStreamAttr = (name, data, nameLenWidth = 2) => {
  const nameBytes = Buffer.from(name, 'latin1');
  const reserved = Buffer.from([0, 0]);
  const lengthField = nameLenWidth === 2 ? u16le(nameBytes.length) : Buffer.from([nameBytes.length]);
  const payload = Buffer.concat([reserved, lengthField, nameBytes, Buffer.from(data, 'latin1')]);
  return Buffer.concat([u16le(0x0001), u16le(payload.length), payload]);
};
// 官方 24B 时间戳属性（3×8B FILETIME）。
const buildFiletimeAttr = () => {
  const payload = Buffer.alloc(24);
  payload.writeBigUInt64LE(132600000000000000n, 0); // ~2020-09 附近的 Mtime
  payload.writeBigUInt64LE(132600000000000001n, 8);
  payload.writeBigUInt64LE(132600000000000002n, 16);
  return Buffer.concat([u16le(0x0001), u16le(24), payload]);
};

const makeZip = entries => {
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const entry of entries) {
    const nameBytes = Buffer.from(entry.name, 'latin1');
    const dataBytes = Buffer.isBuffer(entry.data) ? entry.data : Buffer.from(entry.data, 'latin1');
    const localExtra = entry.localExtra ?? entry.extra ?? Buffer.alloc(0);
    const centralExtra = entry.centralExtra ?? entry.extra ?? Buffer.alloc(0);
    const crc = crc32(dataBytes);
    const local = Buffer.concat([
      Buffer.from([0x50, 0x4b, 0x03, 0x04]), u16le(20), u16le(0), u16le(0), u16le(0), u16le(0),
      u32le(crc), u32le(dataBytes.length), u32le(dataBytes.length),
      u16le(nameBytes.length), u16le(localExtra.length), nameBytes, localExtra, dataBytes,
    ]);
    locals.push(local);
    centrals.push(Buffer.concat([
      Buffer.from([0x50, 0x4b, 0x01, 0x02]), u16le(20), u16le(20), u16le(0), u16le(0), u16le(0), u16le(0),
      u32le(crc), u32le(dataBytes.length), u32le(dataBytes.length),
      u16le(nameBytes.length), u16le(centralExtra.length), u16le(0), u16le(0), u16le(0), u32le(0), u32le(offset),
      nameBytes, centralExtra,
    ]));
    offset += local.length;
  }
  const central = Buffer.concat(centrals);
  const eocd = Buffer.concat([
    Buffer.from([0x50, 0x4b, 0x05, 0x06]), u16le(0), u16le(0), u16le(entries.length), u16le(entries.length),
    u32le(central.length), u32le(offset), u16le(0),
  ]);
  return Buffer.concat([...locals, central, eocd]);
};

test('extractNtfsAds：冒号虚拟条目形态（7-Zip/WinRAR 惯例）提取流内容与 flag 命中', () => {
  const zipBytes = makeZip([
    { name: 'readme.txt', data: 'hello world' },
    { name: 'readme.txt:flag.txt', data: 'flag{ads_colon_entry}' },
  ]);
  const report = extractNtfsAds(zipBytes);
  assert.equal(report.entryCount, 2);
  assert.equal(report.streams.length, 1);
  const stream = report.streams[0];
  assert.equal(stream.source, 'entry-name');
  assert.equal(stream.entryName, 'readme.txt');
  assert.equal(stream.streamName, 'flag.txt');
  assert.ok(bytesEqual(stream.bytes, utf8Bytes('flag{ads_colon_entry}')));
  assert.ok(stream.preview.includes('flag{ads_colon_entry}'));
  assert.ok(stream.flags.some(hit => hit.sample === 'flag{ads_colon_entry}'));
});

test('extractNtfsAds：0x000a extra field 流属性（u16 名长）在 CD 与本地头两路都可提取', () => {
  const streamExtra = buildNtfsExtra([buildStreamAttr('hidden', 'flag{ads_extra_field}')]);
  const zipBytes = makeZip([
    { name: 'via-central.txt', data: 'x', centralExtra: streamExtra }, // 仅 CD 带 extra（Info-ZIP 惯例）
    { name: 'via-local.bin', data: 'y', localExtra: streamExtra }, // 仅本地头带 extra
  ]);
  const report = extractNtfsAds(zipBytes);
  assert.equal(report.streams.length, 2);
  for (const stream of report.streams) {
    assert.equal(stream.source, 'extra-field');
    assert.equal(stream.streamName, 'hidden');
    assert.ok(stream.preview.includes('flag{ads_extra_field}'));
  }
  assert.ok(report.streams.some(stream => stream.entryName === 'via-central.txt'));
  assert.ok(report.streams.some(stream => stream.entryName === 'via-local.bin'));
});

test('extractNtfsAds：u8 名长回退分支与 $DATA 后缀剥离', () => {
  const zipBytes = makeZip([
    { name: 'a.bin', data: 'x', extra: buildNtfsExtra([buildStreamAttr('pay', 'flag{u8_len}', 1)]) },
  ]);
  const report = extractNtfsAds(zipBytes);
  assert.equal(report.streams.length, 1);
  assert.equal(report.streams[0].streamName, 'pay');
  assert.ok(report.streams[0].preview.includes('flag{u8_len}'));

  const zipSuffixed = makeZip([{ name: 'b.txt:s.txt:$DATA', data: 'flag{dollar_data}' }]);
  const suffixed = extractNtfsAds(zipSuffixed);
  assert.equal(suffixed.streams[0].streamName, 's.txt');
  assert.ok(suffixed.streams[0].preview.includes('flag{dollar_data}'));
});

test('extractNtfsAds：官方 24B 时间戳属性不误报为流', () => {
  const zipBytes = makeZip([{ name: 'plain.txt', data: 'content', extra: buildNtfsExtra([buildFiletimeAttr()]) }]);
  const report = extractNtfsAds(zipBytes);
  assert.equal(report.streams.length, 0);
  assert.ok(report.diagnosis.some(line => line.includes('NTFS 时间戳')));
  assert.ok(report.diagnosis.some(line => line.includes('不是流载体')));
});

test('extractNtfsAds：7z/RAR 容器给出明确指引不误解析', () => {
  const sevenZ = extractNtfsAds(Buffer.from([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0x00, 0x01]));
  assert.equal(sevenZ.streams.length, 0);
  assert.ok(sevenZ.diagnosis.some(line => line.includes('7-Zip 容器')));
  const rar = extractNtfsAds(Buffer.concat([Buffer.from('Rar!', 'latin1'), Buffer.from([0x1a, 0x07, 0x01, 0x00])]));
  assert.ok(rar.diagnosis.some(line => line.includes('RAR 容器')));
});

test('extractNtfsAds：EOCD/中央目录被截断 → 本地头扫描兜底仍能提取冒号流', () => {
  const zipBytes = makeZip([{ name: 'note.txt:secret', data: 'flag{local_fallback}' }]);
  // 截掉尾部 22B EOCD + CD（最后一条目即 CD：长度 = 总长 - 22 - CD 长度，直接砍到本地头结束）。
  const cdOffset = zipBytes.length - 22 - (46 + 'note.txt:secret'.length); // 单条目 CD 长度
  const chopped = zipBytes.subarray(0, cdOffset);
  const report = extractNtfsAds(chopped);
  assert.equal(report.streams.length, 1);
  assert.equal(report.streams[0].streamName, 'secret');
  assert.ok(report.streams[0].preview.includes('flag{local_fallback}'));
  assert.ok(report.diagnosis.some(line => line.includes('本地头')));
});

test('extractNtfsAds：非 ZIP 输入的空报告路径', () => {
  const report = extractNtfsAds(Buffer.from('not a zip at all, just text........'));
  assert.equal(report.streams.length, 0);
  assert.equal(report.entryCount, 0);
  assert.ok(report.diagnosis.some(line => line.includes('未发现')));
});
