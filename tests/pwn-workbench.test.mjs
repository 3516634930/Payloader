// Pwn 工作台逻辑测试（批次 PW2/PW3/PW4）：libc 符号/基址换算、gadget 扫描（capstone 真反汇编）、
// p32/p64 打包、ROP 链、fmtstr 半值写入、shellcode 字节语义（反汇编核对）、exp 模板生成。
// 锚定基准：readelf 对拍过的 sample-ls.elf / sample-libc.so；shellcode 字节用 capstone 反汇编验证语义。
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const srcDir = path.join(projectRoot, 'src');
const { loadModule } = createTsModuleLoader();
const elfParse = loadModule(path.join(srcDir, 'utils', 'ctf', 'elfParse.ts'));
const { parseElf } = elfParse;
const libcTools = loadModule(path.join(srcDir, 'utils', 'ctf', 'libcTools.ts'));
const { findLibcSymbol, collectLibcKeys, computeLibcBase, computeLibcAddress, isPageAligned, libcTailCode, scanBinSh } = libcTools;
const capstoneBridge = loadModule(path.join(srcDir, 'utils', 'ctf', 'capstoneBridge.ts'));
const { disassembleBytes, scanGadgets, scanElfGadgets, archForElf, CS_ARCH_X86, CS_MODE_64, CS_MODE_32 } = capstoneBridge;
const pwnPayloads = loadModule(path.join(srcDir, 'utils', 'ctf', 'pwnPayloads.ts'));
const {
  packValue, bytesToHex, bytesToHexEscape, parseAddress, buildRopChain,
  buildFmtstrWrite, SHELLCODE_LIBRARY, buildExpTemplate,
} = pwnPayloads;

const lsBytes = new Uint8Array(fs.readFileSync(path.join(projectRoot, 'tests', 'fixtures', 'sample-ls.elf')));
const libcBytes = new Uint8Array(fs.readFileSync(path.join(projectRoot, 'tests', 'fixtures', 'sample-libc.so')));
const lsElf = parseElf(lsBytes);
const libcElf = parseElf(libcBytes);

// ---- PW2：libc 工作台 ----

test('findLibcSymbol：system/execve 偏移与 readelf 对拍', () => {
  assert.equal(findLibcSymbol(libcElf, 'system').offset, 0x54490);
  assert.equal(findLibcSymbol(libcElf, 'execve').offset, 0xe0db0);
  assert.equal(findLibcSymbol(libcElf, '__libc_start_main').offset, 0x29fa0);
  assert.equal(findLibcSymbol(libcElf, 'no_such_symbol_xyz'), null);
});

test('scanBinSh：在 libc 里找到 /bin/sh（Ubuntu glibc 常在 0x1d8678 附近）', () => {
  const hits = scanBinSh(libcElf, libcBytes);
  assert.ok(hits.length >= 1, 'libc 必含 /bin/sh');
  assert.equal(hits[0].preview, '/bin/sh');
  // 官方验证：readelf 找到的 .rodata 偏移段内
  assert.ok(hits[0].offset > 0x100000 && hits[0].offset < 0x300000);
});

test('computeLibcBase：泄漏→基址换算与页对齐校验', () => {
  // 泄漏 puts 地址 0x7f...123450，puts 偏移 0x123450 → 基址页对齐
  const leak = 0x7f0000123450;
  const base = computeLibcBase(leak, 0x123450);
  assert.equal(base.base, 0x7f0000000000);
  assert.equal(isPageAligned(base.base), true);
  assert.equal(base.hex, '0x7f0000000000');
  // 目标地址
  assert.equal(computeLibcAddress(base.base, 0x54490), '0x7f0000054490');
  // 负基址报错
  const bad = computeLibcBase(0x100, 0x200);
  assert.equal('error' in bad, true);
});

test('libcTailCode：尾码 12 位', () => {
  assert.equal(libcTailCode(0x7f123456789a), '89a');
  assert.equal(libcTailCode(0x7f1234567800), '800');
  assert.equal(libcTailCode(0x7f1234567000), '000');
});

test('collectLibcKeys：常用符号齐备', () => {
  const keys = collectLibcKeys(libcElf, libcBytes);
  const names = keys.symbols.map(s => s.name);
  for (const expected of ['system', 'execve', '__libc_start_main', 'puts', 'write', 'read', 'mprotect']) {
    assert.ok(names.includes(expected), `缺 ${expected}`);
  }
});

// ---- PW3：capstone 反汇编 + gadget ----

test('disassembleBytes：x64 反汇编语义', async () => {
  const lines = await disassembleBytes(Uint8Array.from([0x5f, 0xc3, 0x0f, 0x05]), 0x401000, { arch: CS_ARCH_X86, mode: CS_MODE_64 });
  assert.equal(lines.length, 3);
  assert.equal(lines[0].mnemonic, 'pop');
  assert.equal(lines[0].opStr, 'rdi');
  assert.equal(lines[1].mnemonic, 'ret');
  assert.equal(lines[2].mnemonic, 'syscall');
  assert.equal(lines[0].bytes, '5f');
});

test('scanGadgets：合成代码中扫出 pop rdi ; ret / pop rsi ; ret / leave ; ret', async () => {
  // 人工编一段含多 gadget 的代码
  const code = Uint8Array.from([
    0x90,                         // nop
    0x5f, 0xc3,                   // pop rdi ; ret
    0x5e, 0xc3,                   // pop rsi ; ret
    0x5a, 0xc3,                   // pop rdx ; ret
    0xc9, 0xc3,                   // leave ; ret
    0x48, 0x83, 0xc4, 0x08, 0xc3, // add rsp, 8 ; ret
    0x0f, 0x05,                   // syscall
  ]);
  const hits = await scanGadgets(code, 0x401000, 0, { arch: CS_ARCH_X86, mode: CS_MODE_64 }, { limit: 50 });
  const texts = hits.map(h => h.gadgets);
  // 长链优先：pop rdi 前有 nop，故链为 'nop ; pop rdi ; ret'
  assert.ok(texts.includes('nop ; pop rdi ; ret'), `实际：${texts.join(' | ')}`);
  assert.ok(texts.includes('pop rsi ; ret'));
  assert.ok(texts.includes('pop rdx ; ret'));
  assert.ok(texts.includes('leave ; ret'));
  assert.ok(texts.includes('add rsp, 8 ; ret'));
  assert.ok(texts.some(t => t.endsWith('syscall')));
  // filter 生效
  const only = await scanGadgets(code, 0x401000, 0, { arch: CS_ARCH_X86, mode: CS_MODE_64 }, { filter: 'pop rdi' });
  assert.ok(only.every(h => h.gadgets.includes('pop rdi')));
});

test('scanElfGadgets：真 ELF（sample-ls.elf）可执行段能扫出 ret/pop rdi', async () => {
  const result = await scanElfGadgets(lsElf, lsBytes, { limit: 400 });
  assert.equal(result.error, undefined);
  assert.ok(result.hits.length > 50, `gadget 数过少：${result.hits.length}`);
  const texts = result.hits.map(h => h.gadgets);
  assert.ok(texts.some(t => t === 'ret' || t.endsWith('; ret')), '必须有 ret 类 gadget');
  // ls.elf 的地址全是 PIE 相对偏移（< 0x20000）
  assert.ok(result.hits.every(h => h.address < 0x30000));
});

test('archForElf：架构映射', () => {
  const x64 = archForElf({ machine: 'x86-64' });
  assert.equal(x64.arch, CS_ARCH_X86);
  assert.equal(x64.mode, CS_MODE_64);
  const x86 = archForElf({ machine: 'x86' });
  assert.equal(x86.arch, CS_ARCH_X86);
  assert.equal(x86.mode, CS_MODE_32);
  assert.equal(archForElf({ machine: 'MIPS' }), null);
});

// ---- PW4：payload 构造 ----

test('packValue：p32/p64 端序', () => {
  assert.equal(bytesToHex(packValue(0x0804c010, 32, 'little')), '10c00408');
  assert.equal(bytesToHex(packValue(0x0804c010, 32, 'big')), '0804c010');
  assert.equal(bytesToHex(packValue(0x7f00deadbeef, 64, 'little')), 'efbeadde007f0000');
  assert.equal(bytesToHexEscape(packValue(0x6161616c, 32)), '\\x6c\\x61\\x61\\x61');
});

test('parseAddress：0x/十进制/边界', () => {
  assert.equal(parseAddress('0x401234'), 0x401234);
  assert.equal(parseAddress('401234'), 401234);
  assert.equal(parseAddress('0x0'), 0);
  assert.equal(parseAddress('xyz'), null);
  assert.equal(parseAddress(''), null);
});

test('buildFmtstrWrite：64 位半值不溢出（回归：1<<32 曾致 mask=0）', () => {
  const result = buildFmtstrWrite({ target: 0x404018, value: 0xdeadbeefcafe, argIndex: 6, bits: 64, endian: 'little' });
  assert.equal(result.ok, true);
  // 0xdeadbeefcafe → low32=0xbeefcafe（大）、high32=0x0000dead（小）：先写小的 high
  assert.equal(result.writes[0].half, 'high');
  assert.equal(result.writes[0].value, 0xdead);
  assert.equal(result.writes[1].half, 'low');
  assert.equal(result.writes[1].value, 0xbeefcafe);
  // 64 位地址后置（NUL 截断防护）：payload 以格式串开头
  assert.ok(result.payload.startsWith("b'"));
  assert.ok(result.payload.endsWith(')'));
});

test('buildFmtstrWrite：两半相等不产生 %0c（回归：%0c 输出 1 字符使计数偏 1）', () => {
  // 0x12341234 → low=0x1234 high=0x1234：第二段 count=0 应跳过 %c
  const result = buildFmtstrWrite({ target: 0x804c010, value: 0x12341234, argIndex: 7, bits: 32, endian: 'little' });
  assert.equal(result.ok, true);
  assert.ok(!result.payload.includes('%0c'), result.payload);
  // 第一段 count = 0x1234 - 8 = 4652（串首 8 地址字节）
  assert.ok(result.payload.includes('%4652c'), result.payload);
});

test('buildRopChain：三地址链打包与 python literal', () => {
  const result = buildRopChain([
    { value: '0x40123a', note: 'pop rdi' },
    { value: '0x404018', note: 'binsh' },
    { value: '', note: '占位（跳过）' },
    { value: '0x401030', note: 'system' },
  ], 64);
  assert.equal(result.ok, true);
  assert.equal(result.totalLength, 24);
  assert.equal(result.hex, '3a1240000000000018404000000000003010400000000000');
  assert.equal(result.pythonLiteral, 'flat(0x40123a, 0x404018, 0x401030)');
  const bad = buildRopChain([{ value: 'zz', note: '' }], 64);
  assert.equal(bad.ok, false);
});

test('buildFmtstrWrite：32 位半值写入（0x0804c010 ← 0x08048579 经典题值）', () => {
  const result = buildFmtstrWrite({ target: 0x0804c010, value: 0x08048579, argIndex: 7, bits: 32, endian: 'little' });
  assert.equal(result.ok, true);
  // 0x08048579 → low=0x8579 high=0x0804；先写小的 high(0x0804) 再写大的 low(0x8579)
  assert.equal(result.writes[0].half, 'high');
  assert.equal(result.writes[0].value, 0x0804);
  assert.equal(result.writes[1].half, 'low');
  assert.equal(result.writes[1].value, 0x8579);
  // %c 计数：串首 8 字节地址已打印 → 第一段 = 0x0804 - 8 = 2044
  assert.ok(result.payload.includes('%2044c'), result.payload);
  // 第二段 = 0x8579 - 0x0804 = 32117（写入序号：low 在槽 9、high 在槽 10）
  assert.ok(result.payload.includes('%32117c'), result.payload);
  assert.ok(result.payload.includes('%9$hn'), result.payload);
  assert.ok(result.payload.includes('%10$hn'), result.payload);
});

test('buildFmtstrWrite：先大后小走回绕保护 + 非法输入', () => {
  // low=0xfff0 > high=0x0001：先写 high(1)，再写 low(0xfff0)
  const result = buildFmtstrWrite({ target: 0x404018, value: 0xfff00001, argIndex: 6, bits: 32, endian: 'little' });
  assert.equal(result.ok, true);
  assert.equal(result.writes[0].value, 0x0001);
  const bad1 = buildFmtstrWrite({ target: 0, value: 1, argIndex: 7, bits: 32, endian: 'little' });
  assert.equal(bad1.ok, false);
  const bad2 = buildFmtstrWrite({ target: 0x404018, value: 0x1_0000_0000, argIndex: 7, bits: 32, endian: 'little' });
  assert.equal(bad2.ok, false);
  const bad3 = buildFmtstrWrite({ target: 0x404018, value: 1, argIndex: 0, bits: 32, endian: 'little' });
  assert.equal(bad3.ok, false);
});

test('SHELLCODE_LIBRARY：字节反汇编语义核对（capstone）', async () => {
  for (const entry of SHELLCODE_LIBRARY) {
    const mode = entry.arch === 'x86-64' ? CS_MODE_64 : CS_MODE_32;
    const lines = await disassembleBytes(entry.bytes, 0x1000, { arch: CS_ARCH_X86, mode });
    // 全字节必须完整解码（无非法指令）
    const consumed = lines.reduce((sum, l) => sum + l.size, 0);
    assert.equal(consumed, entry.bytes.length, `${entry.id} 反汇编未覆盖全部字节`);
    assert.ok(lines.length >= 3, `${entry.id} 指令数异常`);
  }
  const execve64 = SHELLCODE_LIBRARY.find(e => e.id === 'execve-x64');
  // 末尾必为 syscall，且含 pop rdi / movabs rdi, 0x68732f2f6e69622f（"//sh"/"bin//" 串）
  const lines = await disassembleBytes(execve64.bytes, 0x1000, { arch: CS_ARCH_X86, mode: CS_MODE_64 });
  assert.equal(lines[lines.length - 1].mnemonic, 'syscall');
  assert.ok(lines.some(l => l.opStr.includes('0x68732f2f6e69622f')), 'movabs "/bin//sh" 未出现');
  // 无 00/0a 坏字符声明与实际一致
  for (const b of execve64.bytes) {
    assert.notEqual(b, 0x00);
    assert.notEqual(b, 0x0a);
  }
});

test('buildExpTemplate：四场景生成合法 python', () => {
  for (const scenario of ['ret2libc', 'rop', 'stack-overflow', 'fmtstr']) {
    const text = buildExpTemplate({ arch: 64, scenario, host: '1.2.3.4', port: '9999', leakSymbol: 'puts' });
    assert.ok(text.includes('from pwn import'));
    assert.ok(text.includes("remote('1.2.3.4', 9999)"));
    assert.ok(text.includes('io.interactive()'), `${scenario} 缺 interactive`);
    // 32 位模板
    const text32 = buildExpTemplate({ arch: 32, scenario, host: '', port: '', leakSymbol: '' });
    assert.ok(text32.includes("context.arch = 'i386'"));
    assert.ok(text32.includes("process('./pwn')"));
  }
});
