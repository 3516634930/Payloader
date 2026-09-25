// CC2 批次测试：LZ-String 三形态官方压缩回环 + ZIP 清单（真 APK fixture）。
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import pkg from 'lz-string';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const { compressToBase64, compressToEncodedURIComponent, compressToUTF16 } = pkg;
const { loadModule } = createTsModuleLoader();
const cc2 = loadModule(path.join(projectRoot, 'src', 'utils', 'codec', 'opsCc2.ts'));
const { lzStringDecompress, listZip, formatZipListing } = cc2;

test('lzStringDecompress：Base64 / URI-safe / UTF16 官方压缩回环（含中文）', () => {
  const text = 'flag{lzstring_roundtrip_测试中文payload}';
  for (const [variant, packed] of [
    ['base64', compressToBase64(text)],
    ['uri', compressToEncodedURIComponent(text)],
    ['utf16', compressToUTF16(text)],
  ]) {
    const result = lzStringDecompress(packed, variant);
    assert.equal(result.text, text, `${variant} 形态`);
  }
});

test('lzStringDecompress：长 JSON 压缩回环（前端数据形态）', () => {
  const json = JSON.stringify({ token: 'x'.repeat(400), user: 'ctf', note: '压缩的 JSON 数据' });
  const packed = compressToBase64(json);
  const result = lzStringDecompress(packed, 'base64');
  assert.equal(result.text, json);
});

test('lzStringDecompress：非法输入优雅报错', () => {
  assert.equal(lzStringDecompress('', 'base64').text, null);
  const bad = lzStringDecompress('!!!!not-lz-string!!!!', 'base64');
  assert.equal(bad.text, null);
  assert.ok(bad.error !== undefined);
});

test('listZip：真 APK 中央目录清单', () => {
  const apk = new Uint8Array(fs.readFileSync(path.join(projectRoot, 'tests', 'fixtures', 'sample-mini.apk')));
  const listing = listZip(apk);
  assert.equal('error' in listing, false);
  const names = Array.from(listing.entries.map(e => e.name)); // 沙箱跨 realm 数组须转换（AGENTS.md 坑位）
  assert.deepEqual(names, ['AndroidManifest.xml', 'classes.dex', 'resources.arsc']);
  assert.equal(listing.entries[1].method, 'deflate');
  assert.equal(listing.entries[1].uncompressedSize, 3630688);
});

test('listZip：非 zip 拒绝 + 空目录拒绝', () => {
  assert.match((listZip(new Uint8Array(64))).error, /EOCD/);
  const empty = new Uint8Array(64);
  empty.set([0x50, 0x4b, 0x05, 0x06], 42);
  new DataView(empty.buffer).setUint16(42 + 10, 0, true);
  assert.match((listZip(empty)).error, /为空/);
});

test('formatZipListing：行格式', () => {
  const listing = { entries: [{ name: 'a.txt', compressedSize: 10, uncompressedSize: 20, method: 'stored' }] };
  assert.ok(formatZipListing(listing.entries).includes('a.txt'));
  assert.ok(formatZipListing(listing.entries).includes('stored'));
});
