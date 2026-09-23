// 批次 K 杂项取证域引擎测试：全部二进制样本程序化自造（无外部 fixture），逐条验证探测结论。
// 加载方式与 scripts/verify-encoding-tools.mjs 一致：ts.transpileModule + vm 沙箱逐模块加载 src 源码。
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import test from 'node:test';
import vm from 'node:vm';
import ts from 'typescript';

const require_ = createRequire(import.meta.url);
const srcDir = path.resolve('src');

const context = {
  module: { exports: {} },
  exports: {},
  require: require_,
  console,
  process,
  Buffer,
  crypto: globalThis.crypto,
  atob: value => Buffer.from(value, 'base64').toString('binary'),
  btoa: value => Buffer.from(value, 'binary').toString('base64'),
  TextEncoder,
  TextDecoder,
  Uint8Array,
  URL,
  URLSearchParams,
  Blob,
  CompressionStream,
  DecompressionStream,
  setTimeout,
  clearTimeout,
  globalThis: { Blob, CompressionStream, DecompressionStream },
};
context.global = context;
vm.createContext(context);

const moduleCache = new Map();
const loadModule = fileName => {
  const key = path.resolve(fileName);
  if (moduleCache.has(key)) return moduleCache.get(key).exports;
  const source = fs.readFileSync(key, 'utf8').replace(/^\uFEFF/, '');
  const compiled = ts.transpileModule(source, {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS, esModuleInterop: true },
    fileName: key,
  }).outputText;
  const mod = { exports: {} };
  moduleCache.set(key, mod);
  const localRequire = specifier => {
    if (specifier.startsWith('.')) {
      const base = path.resolve(path.dirname(key), specifier);
      for (const candidate of [base, `${base}.ts`, path.join(base, 'index.ts')]) {
        if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) return loadModule(candidate);
      }
      throw new Error(`module not found: ${specifier} (from ${key})`);
    }
    return require_(specifier);
  };
  const wrapper = vm.runInContext(`(function (exports, require, module, __filename, __dirname) {\n${compiled}\n})`, context, { filename: key });
  wrapper(mod.exports, localRequire, mod, key, path.dirname(key));
  return mod.exports;
};

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

function makeZip({ lfhEnc, cdEnc }) {
  const name = Buffer.from('flag.txt', 'utf8');
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
    ['50 4B 03 04 14 00', 'jar'],
    ['25 50 44 46 2D 31 2E', 'pdf'],
    ['D4 C3 B2 A1 02 00', 'pcap'],
    ['7F 45 4C 46 02 01', 'elf'],
    ['4D 5A 90 00', 'exe'],
    ['1F 8B 08 00', 'gz'],
    ['37 7A BC AF 27 1C', '7z'],
    ['52 49 46 46 24 00 00 00 57 45 42 50', 'webp'],
  ];
  for (const [hex, expectedExt] of samples) {
    const bytes = Uint8Array.from(hex.split(' ').map(value => Number.parseInt(value, 16)));
    const detected = fileDetect.detectFileTypes(bytes).map(hit => hit.ext);
    assert.ok(detected.includes(expectedExt), `${expectedExt} 未被识别，实际: ${detected.join(',')}`);
  }
  assert.equal(fileDetect.detectFileTypes(new Uint8Array(16)).length, 0, '全零字节不应命中任何魔数');
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
  assert.ok(tools[1].soon);
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
