// 批次 K 杂项取证域引擎测试：全部二进制样本程序化自造（无外部 fixture），逐条验证探测结论。
// 加载方式统一走 tests/helpers/compileTsModule.mjs（T4 测试基建收敛）。
import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

// 加载方式统一走 tests/helpers/compileTsModule.mjs（T4 测试基建收敛：同一加载语义只写一遍）。
const srcDir = path.join(projectRoot, 'src');
const { loadModule } = createTsModuleLoader();

const fileDetect = loadModule(path.join(srcDir, 'utils', 'ctf', 'fileDetect.ts'));
const { zeroWidthEncode } = loadModule(path.join(srcDir, 'utils', 'codec', 'textEncodings.ts'));

// ---- 自造二进制工厂 ----

const crc32Of = bytes => {
  let table = crc32Of.table;
  if (!table) {
    table = crc32Of.table = new Uint32Array(256);
    for (let value = 0; value < 256; value += 1) {
      let entry = value;
      for (let bit = 0; bit < 8; bit += 1) entry = entry & 1 ? 0xedb88320 ^ (entry >>> 1) : entry >>> 1;
      table[value] = entry >>> 0;
    }
  }
  let crc = 0xffffffff;
  for (const byte of bytes) crc = table[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
};

function makePng(width, height) {
  const signature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  const data = Buffer.alloc(13);
  data.writeUInt32BE(width, 0);
  data.writeUInt32BE(height, 4);
  data[8] = 8; // bit depth
  data[9] = 0; // color type grayscale
  const type = Buffer.from('IHDR', 'ascii');
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32Of(Buffer.concat([type, data])), 0);
  const length = Buffer.alloc(4);
  length.writeUInt32BE(13, 0);
  const iend = Buffer.from([0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82]);
  return Buffer.concat([signature, length, type, data, crc, iend]);
}

function makeZip({ lfhEnc, cdEnc, entryName = 'flag.txt' }) {
  const name = Buffer.from(entryName, 'utf8');
  const data = Buffer.from('flag{zip_pseudo_enc}', 'utf8');
  const lfh = Buffer.alloc(30);
  lfh.writeUInt32LE(0x04034b50, 0);
  lfh.writeUInt16LE(lfhEnc ? 1 : 0, 6);
  lfh.writeUInt32LE(crc32Of(data), 14);
  lfh.writeUInt32LE(data.length, 18);
  lfh.writeUInt16LE(name.length, 26);
  const cd = Buffer.alloc(46);
  cd.writeUInt32LE(0x02014b50, 0);
  cd.writeUInt16LE(cdEnc ? 1 : 0, 8);
  cd.writeUInt32LE(crc32Of(data), 16);
  cd.writeUInt32LE(data.length, 20);
  cd.writeUInt16LE(name.length, 28);
  cd.writeUInt32LE(30, 42);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(1, 10);
  eocd.writeUInt32LE(46 + name.length * 2 + data.length, 12);
  eocd.writeUInt32LE(30, 16);
  return Buffer.concat([lfh, name, data, cd, name, eocd]);
}

// ---- 魔数识别 ----

test('detectFileTypes 识别常见魔数', () => {
  const samples = [
    ['89 50 4E 47 0D 0A 1A 0A 00 00 00 0D', 'png'],
    ['FF D8 FF E0 00 10', 'jpg'],
    ['47 49 46 38 39 61', 'gif'],
    ['50 4B 03 04 14 00', 'zip'],
    ['25 50 44 46 2D 31 2E', 'pdf'],
    ['D4 C3 B2 A1 02 00', 'pcap'],
    ['7F 45 4C 46 02 01', 'elf'],
    ['4D 5A 90 00', 'exe'],
    ['1F 8B 08 00', 'gz'],
    ['37 7A BC AF 27 1C', '7z'],
    ['52 49 46 46 24 00 00 00 57 45 42 50', 'webp'],
    ['CF FA ED FE 00 00 00 01', 'macho'],
    ['CE FA ED FE 00 00 00 01', 'machobe'],
  ];
  for (const [hex, expectedExt] of samples) {
    const bytes = Uint8Array.from(hex.split(' ').map(value => Number.parseInt(value, 16)));
    const detected = fileDetect.detectFileTypes(bytes).map(hit => hit.ext);
    assert.ok(detected.includes(expectedExt), `${expectedExt} 未被识别，实际: ${detected.join(',')}`);
  }
  assert.equal(fileDetect.detectFileTypes(new Uint8Array(16)).length, 0, '全零字节不应命中任何魔数');
  // CAFEBABE 是 Java class 魔数，不得误报为 Mach-O（fat binary 需更多上下文，暂不收录）
  const javaClass = Uint8Array.from([0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x02]);
  assert.ok(!fileDetect.detectFileTypes(javaClass).some(hit => hit.ext.startsWith('macho')), 'Java class 不得误报 Mach-O');
});

test('ZIP 容器按 central directory 细分 jar/apk，普通 ZIP 不误报', () => {
  // 普通条目名：只报泛称 ZIP archive，绝不误报 Java archive / Android package
  const plainZip = makeZip({ lfhEnc: false, cdEnc: false });
  const plainExts = fileDetect.detectFileTypes(plainZip).map(hit => hit.ext);
  assert.ok(plainExts.includes('zip'), `普通 ZIP 应报 zip，实际: ${plainExts.join(',')}`);
  assert.ok(!plainExts.includes('jar') && !plainExts.includes('apk'), `普通 ZIP 不得误报 jar/apk，实际: ${plainExts.join(',')}`);

  // META-INF/MANIFEST.MF 条目 → Java archive 细分（泛称 zip 仍保留，提示可用 ZIP 工具解）
  const jarZip = makeZip({ lfhEnc: false, cdEnc: false, entryName: 'META-INF/MANIFEST.MF' });
  const jarExts = fileDetect.detectFileTypes(jarZip).map(hit => hit.ext);
  assert.ok(jarExts.includes('jar') && jarExts.includes('zip'), `MANIFEST.MF 应细分 jar+zip，实际: ${jarExts.join(',')}`);

  // AndroidManifest.xml 条目 → Android package 细分
  const apkZip = makeZip({ lfhEnc: false, cdEnc: false, entryName: 'AndroidManifest.xml' });
  const apkExts = fileDetect.detectFileTypes(apkZip).map(hit => hit.ext);
  assert.ok(apkExts.includes('apk') && apkExts.includes('zip'), `AndroidManifest.xml 应细分 apk+zip，实际: ${apkExts.join(',')}`);

  // 只有魔数、没有 central directory（截断样本）：降级泛称 zip，不抛异常
  // （沙箱模块返回的数组是沙箱 realm 的 Array，deepStrictEqual 前先转主 realm 数组）
  const headOnly = plainZip.subarray(0, 30);
  const headExts = Array.from(fileDetect.detectFileTypes(headOnly), hit => hit.ext);
  assert.deepEqual(headExts, ['zip']);
});

test('压缩容器的熵提示区分"格式常态"与"疑似加密"', () => {
  // PNG（压缩容器）：高熵提示指向结构解析，不再说"可能已加密"
  const png = fileDetect.entropyVerdictText('high', 'zh', [{ ext: 'png', name: 'PNG image' }]);
  assert.ok(png.includes('压缩容器') && png.includes('属正常'), `PNG 高熵应提示格式常态，实际: ${png}`);
  // ELF（非压缩容器）：保持"可能已加密或压缩"的原判读
  const elf = fileDetect.entropyVerdictText('high', 'zh', [{ ext: 'elf', name: 'ELF executable' }]);
  assert.ok(elf.includes('可能已加密或压缩'), `ELF 高熵应保持疑似加密判读，实际: ${elf}`);
  // 不传类型（调用方无探测结果时）：保持原文案
  const bare = fileDetect.entropyVerdictText('high', 'zh');
  assert.ok(bare.includes('可能已加密或压缩'), `无类型上下文应保持原文案，实际: ${bare}`);
});

// ---- 信息熵 ----

test('shannonEntropy 三分判定', () => {
  assert.equal(fileDetect.shannonEntropy(new Uint8Array(4096)), 0, '全零文件熵应为 0');
  const random = new Uint8Array(65536);
  for (let index = 0; index < random.length; index += 1) random[index] = (index * 2654435761) >>> 24;
  assert.ok(fileDetect.shannonEntropy(random) > 7.5, '伪随机数据熵应 >7.5');
  const text = Uint8Array.from(Buffer.from('the quick brown fox jumps over the lazy dog. '.repeat(200), 'utf8'));
  const textEntropy = fileDetect.shannonEntropy(text);
  assert.ok(textEntropy > 3 && textEntropy < 5.5, `英文文本熵应在中低区间，实际 ${textEntropy}`);
  assert.equal(fileDetect.entropyLevel(7.8, 100), 'high');
  assert.equal(fileDetect.entropyLevel(4.2, 100), 'text');
});

// ---- strings 与可疑扫描 ----

test('extractStrings 提取 ASCII 与 UTF-16LE', () => {
  const parts = [
    Buffer.from([0x00, 0x01, 0x02]),
    Buffer.from('flag{forensics_strings_test}', 'ascii'),
    Buffer.from([0x00, 0x07]),
    Buffer.from('f\0l\0a\0g\0{\0u\0t\0f\0}\0', 'binary'),
    Buffer.from([0xff, 0xfe]),
  ];
  const { values, total } = fileDetect.extractStrings(Uint8Array.from(Buffer.concat(parts)), { limit: 100 });
  assert.ok(total >= 2, `应至少提取 2 条字符串，实际 ${total}`);
  assert.ok(values.some(value => value.includes('flag{forensics_strings_test}')), 'ASCII flag 未被提取');
  assert.ok(values.some(value => value.includes('flag{utf}')), 'UTF-16LE flag 未被提取');
});

test('scanSuspiciousContent 命中 flag 与关键词', () => {
  const scan = fileDetect.scanSuspiciousContent('noise picoCTF{h1dd3n_in_bytes} password=123 secret key material');
  assert.equal(scan.flags.length, 1, '应命中 1 个 flag');
  assert.equal(scan.flags[0].prefix, 'picoctf');
  assert.ok(scan.keywordHits.includes('password') && scan.keywordHits.includes('secret'), '关键词未命中');
  const clean = fileDetect.scanSuspiciousContent('just some ordinary binary noise without highlights');
  assert.equal(clean.flags.length, 0, '无 flag 文本不得误报');
});

// ---- hexdump ----

test('hexdumpPreview 格式', () => {
  const bytes = Uint8Array.from(Buffer.from('89 50 4E 47'.split(' ').map(value => Number.parseInt(value, 16))));
  const dump = fileDetect.hexdumpPreview(bytes, { length: 16 });
  assert.match(dump, /^00000000 {2}89 50 4E 47/, '首行应含偏移与十六进制');
  assert.match(dump, /\|\.PNG\s*\|$/, '尾栏应为 ASCII（不可打印转点）');
});

// ---- PNG 宽高修复 ----

test('PNG IHDR 校验与 CRC 爆破还原', async () => {
  const good = Uint8Array.from(makePng(300, 200));
  const ihdr = fileDetect.parsePngIhdr(good);
  assert.ok(ihdr, '合法 PNG 应解析出 IHDR');
  assert.equal(ihdr.width, 300);
  assert.equal(ihdr.height, 200);
  assert.equal(ihdr.crcOk, true, '合法 PNG CRC 应通过');

  const tamperedBuffer = makePng(300, 200);
  tamperedBuffer.writeUInt32BE(777, 16); // 只改宽、不动 CRC
  const tampered = Uint8Array.from(tamperedBuffer);
  assert.equal(fileDetect.parsePngIhdr(tampered).crcOk, false, '改宽后 CRC 应失败');

  const fixed = await fileDetect.fixPngDimensions(tampered);
  assert.ok(fixed, '应能爆破还原宽高');
  assert.equal(fixed.width, 300, `应还原出原宽 300，实际 ${fixed.width}`);
  assert.equal(fixed.height, 200);
  assert.equal(fileDetect.parsePngIhdr(fixed.bytes).crcOk, true, '修复后 CRC 应通过');
});

// ---- ZIP 伪加密 ----

test('ZIP 伪加密检测与标志位修复', () => {
  const pseudo = Uint8Array.from(makeZip({ lfhEnc: false, cdEnc: true }));
  const detected = fileDetect.detectZipEncryption(pseudo);
  assert.equal(detected.state, 'pseudo', 'LFH=0/CD=1 应判为伪加密');

  const fixed = fileDetect.fixZipPseudoEncryption(pseudo);
  assert.ok(fixed, '伪加密应可修复');
  assert.equal(fixed.cleared, 1, '应恰好清除 1 处标志位');
  assert.equal(fileDetect.detectZipEncryption(fixed.bytes).state, 'plain', '修复后应为未加密');

  assert.equal(fileDetect.detectZipEncryption(Uint8Array.from(makeZip({ lfhEnc: true, cdEnc: true }))).state, 'encrypted', '全 1 应判为真加密/全量伪加密');
  assert.equal(fileDetect.detectZipEncryption(Uint8Array.from(makeZip({ lfhEnc: false, cdEnc: false }))).state, 'plain');
  assert.equal(fileDetect.detectZipEncryption(Uint8Array.from(Buffer.from('not a zip file at all........'))).state, 'none');
});

// ---- 零宽字符接文件场景 ----

test('零宽字符从文本中提取并解码', () => {
  const payload = 'flag{zero_width}';
  const stego = `cover text${zeroWidthEncode(payload)}more cover`;
  const extraction = fileDetect.extractZeroWidthFromText(stego);
  assert.equal(extraction.zeroWidthCount, 128, `16 字节 payload 应产生 128 个零宽字符，实际 ${extraction.zeroWidthCount}`);
  assert.equal(extraction.payload, payload);
  const clean = fileDetect.extractZeroWidthFromText('no zero width here');
  assert.equal(clean.zeroWidthCount, 0);
});

// ---- 上限常量 ----

test('文件大小上限为 20MB', () => {
  assert.equal(fileDetect.MAX_FILE_BYTES, 20 * 1024 * 1024);
});

// ---- 推荐工具映射（recommendTools）----

const recommend = loadModule(path.join(srcDir, 'utils', 'ctf', 'recommendTools.ts'));

test('recommendTools PNG 给修复与位面组并追加通用组', () => {
  const tools = recommend.recommendTools([{ ext: 'png', name: 'PNG image' }]);
  assert.deepEqual(Array.from(tools, tool => tool.id), ['png-dimensions', 'png-bitplanes', 'png-channels', 'png-chunks', 'gen-strings', 'gen-hexdump', 'gen-entropy']);
  assert.equal(tools[0].cardId, 'ff-card-repair');
  assert.ok(tools[1] && !tools[1].soon, '位平面工具应已上线');
});

test('recommendTools pcap 给文件移交动作', () => {
  const tools = recommend.recommendTools([{ ext: 'pcap', name: 'PCAP capture' }]);
  const handoff = tools.find(tool => tool.handoffFile);
  assert.ok(handoff, 'pcap must hand off the file for magic routing');
});

test('recommendTools ELF 组含跨域引导并与通用组去重', () => {
  const tools = recommend.recommendTools([{ ext: 'elf', name: 'ELF executable' }]);
  const labels = Array.from(tools, tool => tool.label.zh);
  assert.equal(labels.filter(label => label === '可读字符串').length, 1);
  assert.equal(labels.filter(label => label === '信息熵').length, 1);
  const constantScan = tools.find(tool => tool.targetModuleId);
  assert.equal(constantScan.targetModuleId, 'reverse');
  assert.ok(labels.includes('hexdump'), 'generic hexdump still appended');
});

test('recommendTools 未知类型只给通用组', () => {
  const tools = recommend.recommendTools([]);
  assert.deepEqual(Array.from(tools, tool => tool.id), ['gen-strings', 'gen-hexdump', 'gen-entropy']);
});

// ---- 位平面与色道（imagePlanes）----

const imagePlanes = loadModule(path.join(srcDir, 'utils', 'ctf', 'imagePlanes.ts'));

// 8 像素一行，R 通道低位嵌 0x41（'A' = 01000001，MSB-first）：位序 0,1,0,0,0,0,0,1。
const makeRgbaWithByte = () => {
  const bits = [0, 1, 0, 0, 0, 0, 0, 1];
  const rgba = new Uint8Array(8 * 4);
  for (let index = 0; index < 8; index += 1) {
    rgba[index * 4] = bits[index];       // R
    rgba[index * 4 + 1] = 0x80;          // G 固定值，验证通道选择
    rgba[index * 4 + 2] = 0x20;          // B 固定值
    rgba[index * 4 + 3] = 0xff;          // A
  }
  return rgba;
};

test('extractLsbBytes 按行序 MSB-first 组字节提取', () => {
  const rgba = makeRgbaWithByte();
  const extracted = imagePlanes.extractLsbBytes(rgba, { channel: 0, bit: 0 });
  assert.equal(extracted.length, 1);
  assert.equal(extracted[0], 0x41, `R 通道 bit0 应提取出 'A'，实际 0x${extracted[0].toString(16)}`);

  // G 通道低位全 0 → 提取全零字节（通道选择未串位）。
  assert.deepEqual(Array.from(imagePlanes.extractLsbBytes(rgba, { channel: 1, bit: 0 })), [0]);

  // bit=7 时 R 值（0/1）的高位恒 0 → 全零；非目标位不影响结果。
  assert.deepEqual(Array.from(imagePlanes.extractLsbBytes(rgba, { channel: 0, bit: 7 })), [0]);
});

test('extractBitPlane 二值化与 extractChannelPlane 取通道', () => {
  const rgba = new Uint8Array([0x05, 0, 0, 255, 0x05, 0, 0, 255]);
  assert.deepEqual(Array.from(imagePlanes.extractBitPlane(rgba, 0, 2)), [255, 255], '0x05 的 bit2=1 → 白');
  assert.deepEqual(Array.from(imagePlanes.extractBitPlane(rgba, 0, 1)), [0, 0], '0x05 的 bit1=0 → 黑');
  assert.deepEqual(Array.from(imagePlanes.extractChannelPlane(rgba, 0)), [0x05, 0x05]);
  assert.equal(imagePlanes.MAX_ANALYSIS_PIXELS, 4_000_000, '4MP 红线常量');
});

test('bytesToPreviewText 转义不可打印字符', () => {
  const bytes = Uint8Array.from(Buffer.from('flag{ok}\x01\x00', 'binary'));
  assert.equal(imagePlanes.bytesToPreviewText(bytes), 'flag{ok}\\x01\\x00');
});

// ---- 嵌入扫描（embedScan）----

const embedScan = loadModule(path.join(srcDir, 'utils', 'ctf', 'embedScan.ts'));

test('scanEmbeddedSignatures 检出 IEND 后的 zip 且不报文件自身', () => {
  const png = makePng(300, 200);
  const zip = makeZip({ lfhEnc: false, cdEnc: false });
  const carrier = Uint8Array.from(Buffer.concat([png, zip, Buffer.from('junk')]));
  const hits = embedScan.scanEmbeddedSignatures(carrier);
  const zipHit = hits.find(hit => hit.ext === 'zip');
  assert.ok(zipHit, '应检出嵌入 zip');
  assert.equal(zipHit.offset, png.length, `zip 应在 PNG 结束处（${png.length}），实际 ${zipHit?.offset}`);
  assert.ok(!hits.some(hit => hit.ext === 'png'), 'offset 0 的文件自身签名不得报为嵌入');
  assert.equal(embedScan.scanEmbeddedSignatures(Uint8Array.from(png)).length, 0, '干净 PNG 无嵌入命中');
});

test('scanEmbeddedSignatures 文件本身是 zip 时不报自身 local header（噪声抑制）', () => {
  const zip = Uint8Array.from(makeZip({ lfhEnc: false, cdEnc: false }));
  const hits = embedScan.scanEmbeddedSignatures(zip);
  assert.equal(hits.filter(hit => hit.ext === 'zip').length, 0, 'zip 自身的 PK 头不得报为嵌入');
  // 非 zip 容器里的多个 PK 头仍应照报（限流 4 条）。
  const png = makePng(64, 32);
  const twoZips = Uint8Array.from(Buffer.concat([png, Buffer.from([0x50, 0x4b, 0x03, 0x04]), Buffer.alloc(10), Buffer.from([0x50, 0x4b, 0x03, 0x04]), Buffer.alloc(10)]));
  const pngHits = embedScan.scanEmbeddedSignatures(twoZips);
  assert.equal(pngHits.filter(hit => hit.ext === 'zip').length, 2, '非 zip 容器中的两个 PK 头都应检出');
});

test('findPngTrailer 检出 IEND 后尾附字节', () => {
  const png = makePng(300, 200);
  const trailer = Buffer.from('PK\x03\x04hidden-zip-bytes-here');
  const carrier = Uint8Array.from(Buffer.concat([png, trailer]));
  const hit = embedScan.findPngTrailer(carrier);
  assert.ok(hit, 'IEND 后有数据应检出尾附');
  assert.equal(hit.offset, png.length);
  assert.equal(hit.trailing.length, trailer.length);
  assert.equal(embedScan.findPngTrailer(Uint8Array.from(png)), null, '干净 PNG 无尾附');
});

test('findJpegTrailer 解析 marker 链到 EOI 且不误判 FF00 填充', () => {
  const jpeg = Buffer.concat([
    Buffer.from([0xff, 0xd8]),                                     // SOI
    Buffer.from([0xff, 0xe0, 0x00, 0x10]), Buffer.from('JFIF\0'), Buffer.from([1, 1, 0, 0, 1, 0, 1, 0, 0]), // APP0
    Buffer.from([0xff, 0xda, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3f, 0x00]), // SOS
    Buffer.from('AB\xff\x00CD'),                                   // 熵编码（FF00 是填充不是 EOI）
    Buffer.from([0xff, 0xd9]),                                     // EOI
  ]);
  const trailer = Buffer.from('tail-data');
  const carrier = Uint8Array.from(Buffer.concat([jpeg, trailer]));
  const hit = embedScan.findJpegTrailer(carrier);
  assert.ok(hit, 'EOI 后有数据应检出尾附');
  assert.equal(hit.offset, jpeg.length, `尾附应从 EOI 结束处开始，实际 ${hit?.offset}`);
  assert.equal(hit.trailing.length, trailer.length);
  assert.equal(embedScan.findJpegTrailer(Uint8Array.from(jpeg)), null, '无尾附 JPEG 返回 null');
  assert.equal(embedScan.findJpegTrailer(Uint8Array.from(Buffer.from('not jpeg'))), null, '非 JPEG 返回 null');
});

test('enumeratePngChunks 列出 tEXt/zTXt/iTXt 内容与 CRC 状态', () => {
  const textData = Buffer.concat([Buffer.from('Comment', 'ascii'), Buffer.from([0]), Buffer.from('flag{chunk_test}', 'ascii')]);
  const textChunk = Buffer.alloc(12 + textData.length);
  textChunk.writeUInt32BE(textData.length, 0);
  textChunk.write('tEXt', 4, 'ascii');
  textData.copy(textChunk, 8);
  textChunk.writeUInt32BE(crc32Of(textChunk.subarray(4, 8 + textData.length)), 8 + textData.length);

  const ztxData = Buffer.concat([Buffer.from('Note', 'ascii'), Buffer.from([0]), Buffer.from([0]), Buffer.from([0x78, 0x9c, 0x03, 0x00])]);
  const ztxChunk = Buffer.alloc(12 + ztxData.length);
  ztxChunk.writeUInt32BE(ztxData.length, 0);
  ztxChunk.write('zTXt', 4, 'ascii');
  ztxData.copy(ztxChunk, 8);
  ztxChunk.writeUInt32BE(crc32Of(ztxChunk.subarray(4, 8 + ztxData.length)), 8 + ztxData.length);

  // iTXt 未压缩：keyword\0 flag(0)\0 method(0)\0 lang\0 translated\0 text
  const itxData = Buffer.concat([
    Buffer.from('Title', 'ascii'), Buffer.from([0]),
    Buffer.from([0, 0]),
    Buffer.from('en', 'ascii'), Buffer.from([0]),
    Buffer.from([0]),
    Buffer.from('flag{itxt_plain}', 'ascii'),
  ]);
  const itxChunk = Buffer.alloc(12 + itxData.length);
  itxChunk.writeUInt32BE(itxData.length, 0);
  itxChunk.write('iTXt', 4, 'ascii');
  itxData.copy(itxChunk, 8);
  itxChunk.writeUInt32BE(crc32Of(itxChunk.subarray(4, 8 + itxData.length)), 8 + itxData.length);

  // iTXt 压缩：flag=1，压缩数据本体不解析（解压由 UI 层做），只验结构标记。
  const itxCData = Buffer.concat([
    Buffer.from('Cmd', 'ascii'), Buffer.from([0]),
    Buffer.from([1, 0]),
    Buffer.from('zh', 'ascii'), Buffer.from([0]),
    Buffer.from([0]),
    Buffer.from([0x78, 0x9c, 0x03, 0x00]),
  ]);
  const itxCChunk = Buffer.alloc(12 + itxCData.length);
  itxCChunk.writeUInt32BE(itxCData.length, 0);
  itxCChunk.write('iTXt', 4, 'ascii');
  itxCData.copy(itxCChunk, 8);
  itxCChunk.writeUInt32BE(crc32Of(itxCChunk.subarray(4, 8 + itxCData.length)), 8 + itxCData.length);

  // 文本 chunk 插在 IHDR 与 IEND 之间（PNG 规范位置；IEND 之后的字节属于"尾附数据"职责）。
  const basePng = makePng(64, 32);
  const head = basePng.subarray(0, 33);   // 签名 + IHDR
  const tail = basePng.subarray(33);      // IEND
  const carrier = Uint8Array.from(Buffer.concat([head, textChunk, ztxChunk, itxChunk, itxCChunk, tail]));
  const { chunks, truncated } = embedScan.enumeratePngChunks(carrier);
  const types = Array.from(chunks, chunk => chunk.type);
  assert.deepEqual(types, ['IHDR', 'tEXt', 'zTXt', 'iTXt', 'iTXt', 'IEND'], `chunk 序列不符: ${types.join(',')}`);
  assert.equal(truncated, false, '未达上限不得标截断');
  assert.ok(Array.from(chunks, chunk => chunk.crcOk).every(ok => ok), '构造 chunk 的 CRC 应全部通过');

  const text = chunks.find(chunk => chunk.type === 'tEXt').text;
  assert.equal(text.keyword, 'Comment');
  assert.equal(text.text, 'flag{chunk_test}', 'tEXt 应解出隐藏文本');

  const ztxt = chunks.find(chunk => chunk.type === 'zTXt').text;
  assert.equal(ztxt.keyword, 'Note');
  assert.equal(ztxt.compressed, true);
  assert.equal(ztxt.compressedBytes.length, 4, '压缩数据长度应为 4 字节');

  const itxPlain = Array.from(chunks, c => c.text).filter(t => t && t.keyword === 'Title')[0];
  assert.equal(itxPlain.text, 'flag{itxt_plain}', '未压缩 iTXt 应解出文本');
  assert.equal(itxPlain.compressed, undefined, '未压缩 iTXt 不标 compressed');

  const itxComp = Array.from(chunks, c => c.text).filter(t => t && t.keyword === 'Cmd')[0];
  assert.equal(itxComp.keyword, 'Cmd');
  assert.equal(itxComp.compressed, true, '压缩 iTXt 应标 compressed');
  assert.equal(itxComp.compressedBytes.length, 4);

  // CRC 破坏检测：翻转 tEXt 数据第一个字节后该 chunk 应标 crcOk=false，其余不受影响。
  const tampered = Uint8Array.from(carrier);
  tampered[33 + 8] ^= 0xff;
  const tamperedChunks = embedScan.enumeratePngChunks(tampered).chunks;
  assert.equal(tamperedChunks.find(chunk => chunk.type === 'tEXt').crcOk, false, '被篡改 chunk 应标 CRC 失败');
});

test('enumeratePngChunks 截断 PNG 保留已解析部分且损坏 chunk 可截断提示', () => {
  // 非法 length 的 chunk（声称 0xFFFFFF 字节）→ 在此处停止，保留 IHDR。
  const basePng = makePng(64, 32);
  const bogus = Buffer.alloc(12);
  bogus.writeUInt32BE(0xffffff, 0);
  bogus.write('IDAT', 4, 'ascii');
  const carrier = Uint8Array.from(Buffer.concat([basePng.subarray(0, 33), bogus]));
  const { chunks, truncated } = embedScan.enumeratePngChunks(carrier);
  assert.deepEqual(Array.from(chunks, chunk => chunk.type), ['IHDR'], '损坏处应截断并保留已解析 chunk');
  assert.equal(truncated, false, '结构损坏不是数量截断');

  // 数量截断：maxChunks=2 时 IHDR/tEXt 保留且 truncated=true。
  const textData = Buffer.concat([Buffer.from('K', 'ascii'), Buffer.from([0]), Buffer.from('v', 'ascii')]);
  const textChunk = Buffer.alloc(12 + textData.length);
  textChunk.writeUInt32BE(textData.length, 0);
  textChunk.write('tEXt', 4, 'ascii');
  textData.copy(textChunk, 8);
  textChunk.writeUInt32BE(crc32Of(textChunk.subarray(4, 8 + textData.length)), 8 + textData.length);
  const capped = embedScan.enumeratePngChunks(Uint8Array.from(Buffer.concat([basePng.subarray(0, 33), textChunk, basePng.subarray(33)])), { maxChunks: 2 });
  assert.equal(capped.chunks.length, 2, '应按 maxChunks 截断');
  assert.equal(capped.truncated, true, '应标 truncated');
});

// ---- recommendTools 上线状态 ----

test('recommendTools 位平面/色道/chunk/嵌入/EOI 工具已上线（无 soon 占位）', () => {
  const pngTools = recommend.recommendTools([{ ext: 'png', name: 'PNG image' }]);
  assert.deepEqual(Array.from(pngTools, tool => tool.id), ['png-dimensions', 'png-bitplanes', 'png-channels', 'png-chunks', 'gen-strings', 'gen-hexdump', 'gen-entropy']);
  assert.ok(pngTools.every(tool => !tool.soon), 'PNG 组不应再有 soon 占位');
  assert.equal(pngTools.find(tool => tool.id === 'png-bitplanes').cardId, 'ff-card-bitplanes');
  assert.equal(pngTools.find(tool => tool.id === 'png-channels').cardId, 'ff-card-channels');
  assert.equal(pngTools.find(tool => tool.id === 'png-chunks').cardId, 'ff-card-chunks');

  const jpgTools = recommend.recommendTools([{ ext: 'jpg', name: 'JPEG image' }]);
  const eoi = jpgTools.find(tool => tool.id === 'jpg-eoi');
  assert.ok(eoi && !eoi.soon, 'jpg-eoi 应已上线');
  assert.equal(eoi.cardId, 'ff-card-embedded', 'jpg-eoi 应指向统一嵌入卡');
  assert.ok(jpgTools.find(tool => tool.id === 'jpg-metadata').soon, 'jpg-metadata 不在本批次，保持 soon');

  const zipTools = recommend.recommendTools([{ ext: 'zip', name: 'ZIP archive' }]);
  const embedded = zipTools.find(tool => tool.id === 'archive-embedded');
  assert.ok(embedded && !embedded.soon, 'archive-embedded 应已上线');
  assert.equal(embedded.cardId, 'ff-card-embedded');
});
