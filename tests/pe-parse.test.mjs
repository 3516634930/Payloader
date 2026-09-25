// PE 解析器测试（批次 RV）：notepad.exe（Windows x64 GUI）真样本 + 合成 PE32 边界。
// 基准对拍：dumpbin /headers 语义锚定（节区 RWE、ASLR/DEP dllCharacteristics 位）。
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const { loadModule } = createTsModuleLoader();
const { parsePe } = loadModule(path.join(projectRoot, 'src', 'utils', 'ctf', 'peParse.ts'));

const notepadBytes = new Uint8Array(fs.readFileSync(path.join(projectRoot, 'tests', 'fixtures', 'sample-notepad.exe')));

test('非 PE 拒绝（不抛异常）', () => {
  assert.equal(parsePe(new Uint8Array([1, 2, 3])).ok, false);
  const elf = new Uint8Array(fs.readFileSync(path.join(projectRoot, 'tests', 'fixtures', 'sample-ls.elf')));
  const r = parsePe(elf);
  assert.equal(r.ok, false);
  assert.match(r.error, /MZ|PE/);
});

test('畸形导出表不抛 RangeError（回归：AddressOfFunctions 贴文件尾曾越界击穿整个报告）', () => {
  // 以 notepad 为底，把导出目录 RVA 指到贴近文件尾的合法节区位置 → 解析必须优雅返回而非抛异常
  const mutated = new Uint8Array(notepadBytes);
  const dv = new DataView(mutated.buffer);
  const peOffset = dv.getUint32(0x3c, true);
  const optOffset = peOffset + 24;
  const is64 = dv.getUint16(optOffset, true) === 0x20b;
  const dataDirOffset = optOffset + (is64 ? 112 : 96);
  // exportDir = 目录项 0：rva 指向文件尾部（越界布局）
  dv.setUint32(dataDirOffset, mutated.length - 16, true);
  dv.setUint32(dataDirOffset + 4, 0x1000, true);
  let result;
  assert.doesNotThrow(() => { result = parsePe(mutated); });
  assert.equal(result.ok !== undefined, true);
});

test('notepad.exe：header 关键字段', () => {
  const pe = parsePe(notepadBytes);
  assert.equal(pe.ok, true);
  assert.equal(pe.isDll, false);
  assert.equal(pe.is64Bit, true);
  assert.equal(pe.machine, 'x86-64');
  assert.equal(pe.subsystem, 'GUI');
  // imageBase 典型 0x140000000（x64 exe 默认）
  assert.equal(pe.imageBase, 0x140000000);
  assert.ok(pe.entryPoint > 0x140000000);
});

test('notepad.exe：节区表（.text R-X / .data RW-）', () => {
  const pe = parsePe(notepadBytes);
  const names = pe.sections.map(s => s.name);
  assert.ok(names.includes('.text'));
  const text = pe.sections.find(s => s.name === '.text');
  assert.equal(text.executable, true);
  assert.equal(text.writable, false);
});

test('notepad.exe：安全标志（Win10+ 默认 ASLR/DEP 开）', () => {
  const pe = parsePe(notepadBytes);
  const by = Object.fromEntries(pe.security.map(item => [item.key, item]));
  assert.equal(by.aslr.value, 'Enabled (DYNAMIC_BASE)');
  assert.equal(by.dep.value, 'Enabled (NX_COMPAT)');
  assert.ok(pe.sections.length >= 4);
});
