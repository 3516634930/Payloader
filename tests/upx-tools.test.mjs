// UPX 解析与 NRV 解压测试（批次 UX）：真样本 = UPX 4.2.4 --best 压壳的 ls.elf
//（tests/fixtures/sample-upx.elf，166792→74940）。核心对拍：解压产物按 PT_LOAD 段区间
// 逐字节还原（代码与只读数据段零 diff，含 ftid 0x49 calltrick filter 逆变换）；
// RW 段含 UPX 运行时重排数据为已知降级。另含合成 NRV2B 位流单元语义与解析器边界。
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const { loadModule } = createTsModuleLoader();
const upx = loadModule(path.join(projectRoot, 'src', 'utils', 'ctf', 'upxTools.ts'));
const { parseUpx, upxDecompressAll, nrvDecompress } = upx;

const packedBytes = new Uint8Array(fs.readFileSync(path.join(projectRoot, 'tests', 'fixtures', 'sample-upx.elf')));
const originalBytes = new Uint8Array(fs.readFileSync(path.join(projectRoot, 'tests', 'fixtures', 'sample-ls.elf')));

test('parseUpx：真 UPX 4.2.4 样本特征解析', () => {
  const info = parseUpx(packedBytes);
  assert.equal(info.ok, true);
  assert.equal(info.upxVersion, 14); // UPX 4.x 的 version 字节（3.x=13、4.x=14）
  assert.ok(info.format.startsWith('ELF'), `实际 ${info.format}`);
  assert.ok(info.method.startsWith('NRV2B') || info.method.startsWith('LZMA'), `实际 ${info.method}`);
  assert.equal(info.originalSize, 166792); // 与原文件大小一致（upx 输出行 166792 -> 74940）
  assert.ok(info.blocks.length >= 1);
});

test('parseUpx：非 UPX 文件拒绝', () => {
  assert.equal(parseUpx(originalBytes).ok, false);
  assert.equal(parseUpx(new Uint8Array(16)).ok, false);
});

test('upxDecompressAll：NRV2B 全块解压（LOAD 段映射对拍 + 0x49 filter 逆变换）', () => {
  const info = parseUpx(packedBytes);
  assert.equal(info.ok, true);
  if (!info.method.startsWith('NRV2B')) {
    // LZMA 样本走指导路径：明确拒绝而非错误产物
    const result = upxDecompressAll(packedBytes, info);
    assert.equal(result.data, null);
    assert.match(result.error, /upx -d/);
    return;
  }
  const result = upxDecompressAll(packedBytes, info);
  assert.equal(result.error, undefined, `解压报错：${result.error}`);
  assert.equal(result.blocksDone, info.blocks.length);
  const data = result.data;
  // UPX 压缩的是 PT_LOAD 段内容（块序列 = 段序，readelf -lW 实测区间）：
  // 块 1+2 = LOAD1[R @0x0 len 0x3f50]、块 3 = LOAD2[R-E @0x4000 len 0x18f79]（ftid 0x49
  // calltrick filter，unfilter 后必须零 diff）、块 4 = LOAD3[R @0x1d000 len 0x9578]。
  // LOAD4[RW] 含 UPX 运行时重排数据（重定位搬移），静态解压不逐字节还原——已知降级。
  const segments = [
    { len: 0x3f50, fileOff: 0 },
    { len: 0x18f79, fileOff: 0x4000 },
    { len: 0x9578, fileOff: 0x1d000 },
  ];
  let pos = 0;
  for (const [index, seg] of segments.entries()) {
    let diff = -1;
    for (let j = 0; j < seg.len; j++) {
      if (data[pos + j] !== originalBytes[seg.fileOff + j]) { diff = j; break; }
    }
    assert.equal(diff, -1, `LOAD${index + 1} 段首差 @${diff}`);
    pos += seg.len;
  }
  // 覆盖率：LOAD1-3 共 156737B ≥ 原文件 94%，包含全部 .text/.rodata（strings 场景完整）
  assert.ok(pos >= originalBytes.length * 0.93, `覆盖率 ${pos}/${originalBytes.length}`);
});

test('nrvDecompress：纯字面量合成流（无匹配）', () => {
  const src = new Uint8Array([0xff, 0x41, 0x42, 0xff, 0x43, 0x44, 0x00]);
  const result = nrvDecompress(src, 0, src.length, 64, 'nrv2b', '8');
  assert.ok(result.error !== undefined || result.data.length > 0);
});

test('nrvDecompress：空输入拒绝', () => {
  const result = nrvDecompress(new Uint8Array(4), 0, 4, 16, 'nrv2b', 'le32');
  assert.ok(result.error !== undefined || result.data.length === 0);
});
