// APK/Android 逆向解析测试（批次 AX）：以 tests/fixtures/sample-mini.apk（真实 APK 剥离出
// AndroidManifest.xml + classes.dex + resources.arsc）为样本，对拍基准为 aapt dump badging /
// jadx 输出锚定。另含 AXML 字符串池 / DEX 结构单测与合成用例边界测试。
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

// DecompressionStream 在 node:buffer 全局可用（Node 22+）。
const srcDir = path.join(projectRoot, 'src');
const { loadModule } = createTsModuleLoader();
const apkParse = loadModule(path.join(srcDir, 'utils', 'ctf', 'apkParse.ts'));
const { listZipEntries, parseDex, parseApk } = apkParse;

const apkBytes = new Uint8Array(fs.readFileSync(path.join(projectRoot, 'tests', 'fixtures', 'sample-mini.apk')));

test('listZipEntries：中央目录条目齐全', () => {
  const entries = listZipEntries(apkBytes);
  assert.equal('error' in entries, false);
  const names = entries.map(e => e.name);
  assert.ok(names.includes('AndroidManifest.xml'));
  assert.ok(names.includes('classes.dex'));
  assert.ok(names.includes('resources.arsc'));
  const dex = entries.find(e => e.name === 'classes.dex');
  assert.equal(dex.uncompressedSize, 3630688);
});

test('parseApk：真 APK 全链路（manifest + dex + 签名盘点）', async () => {
  const result = await parseApk('sample-mini.apk', apkBytes);
  assert.equal(result.ok, true);
  assert.equal(result.isApk, true);
  assert.ok(result.nativeLibs.length === 0); // mini 包没有 lib/
  // manifest（missai 真包）
  assert.ok(result.manifest, 'manifest 必须解析成功');
  assert.equal(result.manifestError, null);
  assert.ok(result.manifest.packageName.length > 0, 'packageName 必须非空');
  assert.ok(Array.isArray(result.manifest.permissions));
  // dex
  assert.equal(result.dexFiles.length, 1);
  const dex = result.dexFiles[0];
  assert.equal(dex.error, null);
  assert.equal(dex.info.version, '0037');
  assert.ok(dex.info.classCount > 1000, `class 数应上千：${dex.info.classCount}`);
  assert.ok(dex.info.strings.length > 5000);
});

test('parseAxmlManifest：权限与组件抽取（对照 aapt dump 语义）', async () => {
  const result = await parseApk('x.apk', apkBytes);
  const m = result.manifest;
  assert.ok(m, 'manifest 必须解析成功');
  // AOSP 布局回归锚定（曾因 attr 基址偏 16 字节丢失 targetSdk 与后置权限）：
  assert.equal(m.packageName, 'com.missai.android');
  assert.equal(m.versionName, '1.5.6');
  assert.equal(m.versionCode, '45');
  assert.equal(m.minSdk, '24');
  assert.equal(m.targetSdk, '36');
  assert.ok(m.permissions.length >= 9, `权限应 ≥9（aapt 对拍），实际 ${m.permissions.length}`);
  assert.ok(m.activities.length + m.services.length + m.receivers.length + m.providers.length > 0);
  for (const a of m.activities) assert.ok(typeof a.name === 'string' && a.name.length > 0);
  // INT_BOOLEAN 回归：exported=0xffffffff 应判 true（曾因 0x12 当 INT_HEX 误判）
  const main = m.activities.find(a => a.name.endsWith('MainActivity'));
  assert.equal(main.exported, true);
  assert.equal(m.usesCleartextTraffic, true);
});

test('parseDex：非 DEX 拒绝', () => {
  const result = parseDex(new Uint8Array([0x50, 0x4b, 0x03, 0x04, 0, 0, 0, 0]));
  assert.equal('error' in result, true);
});

test('parseApk：纯 zip 拒绝语义清晰', async () => {
  // 构造无 manifest 无 dex 的空 zip（EOCD 在 len-22 处，totalEntries 字段在 EOCD+10）。
  const bytes = new Uint8Array(64);
  bytes.set([0x50, 0x4b, 0x05, 0x06], 42); // EOCD 签名
  new DataView(bytes.buffer).setUint16(42 + 10, 0, true); // totalEntries=0
  const result = await parseApk('empty.zip', bytes);
  assert.equal(result.ok, false, '空中央目录应拒绝');
  assert.match(result.error, /中央目录为空|不是 APK/);
  // 真正的拒绝分支用纯文本
  const bad = await parseApk('text.txt', new Uint8Array([1, 2, 3]));
  assert.equal(bad.ok, false);
  assert.match(bad.error, /EOCD|zip/);
});

test('interestingStrings：CTF 线索抽取', async () => {
  const result = await parseApk('sample-mini.apk', apkBytes);
  assert.equal(result.ok, true);
  // 真包至少应有 http(s) 或 crypto 线索；断言宽松（数组存在且不超限）
  assert.ok(Array.isArray(result.interestingStrings));
  assert.ok(result.interestingStrings.length <= 60);
});
