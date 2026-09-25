// ELF 解析器测试（批次 PW1）：以 tests/fixtures/sample-ls.elf（Ubuntu ls，x64 PIE stripped）
// 与 sample-libc.so 为真样本，逐项对拍 readelf（docker ctf-tools -h/-l/-S/-d/-W --dyn-syms 输出锚定）：
// entry=0x6a60 / 14 phdr / 30 shdr / NX on / Canary on / PIE / Full RELRO(BIND_NOW) /
// BuildID cfffcdd5…474 / system=0x54490 / execve=0xe0db0 / __libc_start_main=0x29fa0。
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const srcDir = path.join(projectRoot, 'src');
const { loadModule } = createTsModuleLoader();
const { parseElf, fileOffsetToVaddr, vaddrToFileOffset } = loadModule(
  path.join(srcDir, 'utils', 'ctf', 'elfParse.ts'),
);

const lsBytes = new Uint8Array(fs.readFileSync(path.join(projectRoot, 'tests', 'fixtures', 'sample-ls.elf')));
const libcBytes = new Uint8Array(fs.readFileSync(path.join(projectRoot, 'tests', 'fixtures', 'sample-libc.so')));

test('魔数与非 ELF 拒绝（不抛异常）', () => {
  assert.equal(parseElf(new Uint8Array([1, 2, 3])).ok, false);
  assert.equal(parseElf(new Uint8Array(8)).ok, false);
  const bad = new Uint8Array(lsBytes);
  bad[1] = 0x42;
  const r = parseElf(bad);
  assert.equal(r.ok, false);
  assert.match(r.error, /ELF/);
});

test('sample-ls.elf：header 关键字段对齐 readelf -h', () => {
  const elf = parseElf(lsBytes);
  assert.equal(elf.ok, true);
  assert.equal(elf.eiClass, 64);
  assert.equal(elf.endian, 'little');
  assert.equal(elf.typeId, 3);
  assert.equal(elf.machine, 'x86-64');
  assert.equal(elf.entry, 0x6a60);
  assert.equal(elf.osabi, 'SYSV');
});

test('sample-ls.elf：checksec 全项对齐 readelf 推导', () => {
  const elf = parseElf(lsBytes);
  const by = Object.fromEntries(elf.checksec.map(item => [item.key, item]));
  assert.equal(by.nx.value, 'NX enabled');
  assert.equal(by.canary.value, 'Canary found');
  assert.equal(by.pie.value, 'PIE enabled');
  assert.equal(by.relro.value, 'Full RELRO');
  assert.equal(by.stripped.value, 'Stripped');
  const stack = elf.programHeaders.find(p => p.type === 'GNU_STACK');
  assert.equal(stack.executable, false);
  assert.equal(stack.flags, 'RW');
});

test('sample-ls.elf：节区/程序头/interp/BuildID 对齐 readelf -S/-l/-n', () => {
  const elf = parseElf(lsBytes);
  assert.equal(elf.sections.length, 30);
  const names = elf.sections.map(s => s.name);
  assert.ok(names.includes('.text'));
  assert.ok(names.includes('.dynsym'));
  assert.ok(names.includes('.got'));
  assert.equal(elf.programHeaders.length, 14);
  assert.ok(elf.programHeaders.some(p => p.type === 'INTERP'));
  assert.equal(elf.interp, '/lib64/ld-linux-x86-64.so.2');
  assert.equal(elf.buildId, 'cfffcdd57bea0d21063e18b66ced151bd382d474');
});

test('sample-ls.elf：dynsym 导入符号（UND）对齐 readelf -W --dyn-syms', () => {
  const elf = parseElf(lsBytes);
  const imports = elf.dynamicSymbols.filter(s => !s.defined && s.name);
  const names = imports.map(s => s.name);
  assert.ok(names.includes('__stack_chk_fail'));
  assert.ok(names.includes('malloc'));
  assert.ok(elf.dynamicSymbols.length >= 130, `dynsym 规模 ${elf.dynamicSymbols.length}`);
  // stripped：.symtab 不存在
  assert.equal(elf.symbolTable.length, 0);
});

test('sample-ls.elf：vaddr↔offset 双向映射', () => {
  const elf = parseElf(lsBytes);
  const text = elf.sections.find(s => s.name === '.text');
  const off = vaddrToFileOffset(elf, text.addr + 0x10);
  assert.equal(typeof off, 'number');
  assert.equal(fileOffsetToVaddr(elf, off), text.addr + 0x10);
  assert.equal(vaddrToFileOffset(elf, 0xdeadbee0), null);
});

test('sample-libc.so：共享对象语义 + ret2libc 核心符号偏移', () => {
  const elf = parseElf(libcBytes);
  assert.equal(elf.ok, true);
  assert.equal(elf.isSharedObject, true);
  const by = Object.fromEntries(elf.checksec.map(item => [item.key, item]));
  assert.equal(by.pie.value, 'SO（基址待泄漏）');
  const system = elf.dynamicSymbols.find(s => s.name === 'system' && s.defined);
  const execve = elf.dynamicSymbols.find(s => s.name === 'execve' && s.defined);
  const startMain = elf.dynamicSymbols.find(s => s.name === '__libc_start_main' && s.defined);
  assert.ok(system, 'system 必须在 dynsym');
  assert.ok(execve, 'execve 必须在 dynsym');
  assert.ok(startMain, '__libc_start_main 必须在 dynsym');
  assert.equal(system.value, 0x54490);
  assert.equal(execve.value, 0xe0db0);
  assert.equal(startMain.value, 0x29fa0);
});

test('checksec 每项建议文案完整', () => {
  const elf = parseElf(lsBytes);
  for (const item of elf.checksec) {
    assert.ok(item.advice.length >= 10, `${item.key} 建议过短`);
    assert.ok(item.label && item.value);
  }
});

test('32 位合成 ELF：ELF32 头字段解析走通', () => {
  // 手工合成 ELF32 小端 ET_EXEC / EM_386，一个 PT_LOAD phdr（0x8048000 R-X）。
  const buf = new Uint8Array(52 + 32);
  const dv = new DataView(buf.buffer);
  buf.set([0x7f, 0x45, 0x4c, 0x46, 1, 1, 1, 0], 0);
  dv.setUint16(16, 2, true);        // ET_EXEC
  dv.setUint16(18, 3, true);        // EM_386
  dv.setUint32(20, 1, true);        // version
  dv.setUint32(24, 0x8048000, true); // entry
  dv.setUint32(28, 52, true);       // phoff
  dv.setUint32(32, 0, true);        // shoff（无节区）
  dv.setUint16(42, 32, true);       // phentsize
  dv.setUint16(44, 1, true);        // phnum
  // phdr@52: type=LOAD flags=RX(R=4|X=1) offset=0 vaddr=0x8048000
  dv.setUint32(52, 1, true);
  dv.setUint32(56, 0, true);
  dv.setUint32(60, 0x8048000, true);
  dv.setUint32(64, 0x8048000, true);
  dv.setUint32(68, 0x100, true);
  dv.setUint32(72, 0x100, true);
  dv.setUint32(76, 5, true);
  const elf = parseElf(buf);
  assert.equal(elf.ok, true);
  assert.equal(elf.eiClass, 32);
  assert.equal(elf.machine, 'x86');
  assert.equal(elf.entry, 0x8048000);
  assert.equal(elf.programHeaders.length, 1);
  assert.equal(elf.programHeaders[0].flags, 'RE');
  // 无 GNU_STACK 段 → NX off
  const by = Object.fromEntries(elf.checksec.map(item => [item.key, item]));
  assert.equal(by.nx.value, 'NX disabled');
  // vaddr 映射走 32 位 LOAD
  assert.equal(fileOffsetToVaddr(elf, 0x40), 0x8048040);
});
