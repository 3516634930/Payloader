// CTF 题型速查种子数据（批次 M）：逆向域。
// 条目跳工具命令 tab 对应命令集（src/data/toolCommands.ts），snippet 取该题型第一步最常用的命令。

import type { CheatEntry } from './index';

export const reverseCheatEntries: CheatEntry[] = [
  {
    id: 'reverse-identify',
    title: { zh: '第一步：file / strings / checksec', en: 'First moves: file / strings / checksec' },
    summary: {
      zh: '拿到二进制先看清身份：文件类型、可读字符串、保护机制，一半的题在这一步就有线索。',
      en: 'Profile the binary first: type, readable strings, protections. Half of the challenges leak hints right here.',
    },
    snippet: 'file ./challenge\nstrings -n 6 ./challenge | grep -iE "flag|correct|wrong"\nchecksec --file=./challenge',
    tip: { zh: 'strings 直接 grep flag 常常一步出答案；写死的结果别错过。', en: 'grep flag in strings often ends the challenge instantly — don\'t miss hardcoded results.' },
    jump: { kind: 'tool', id: 'ctf-rev-tools' },
  },
  {
    id: 'reverse-ghidra',
    title: { zh: 'Ghidra 反编译', en: 'Ghidra decompilation' },
    summary: {
      zh: '大程序首选 GUI 反编译：导入自动分析后直奔 main 与字符串交叉引用。',
      en: 'First choice for larger binaries: import, auto-analyze, then jump to main and string cross-references.',
    },
    snippet: './ghidraRun\n# 无界面模式（脚本批量）\n./analyzeHeadless ./proj demo -import ./challenge -postScript decompile.java',
    tip: { zh: '拖入本域即可先做结构分析：节区/导入导出/安全标志 + 任意地址反汇编（内置 capstone，离线）；APK 安卓题走杂项域 APK 卡出 manifest/DEX。', en: 'Drop a binary here first: sections, imports/exports, security flags, and disassembly at any address (offline capstone); Android APKs go to the APK card in Misc for manifest/DEX.' },
    jump: { kind: 'tool', id: 'ghidra' },
  },
  {
    id: 'reverse-radare2',
    title: { zh: 'radare2 命令行逆向', en: 'radare2 on the command line' },
    summary: {
      zh: '轻量快速，适合小体量二进制：aaa 分析后 pdf 看反汇编，izz 全量字符串。',
      en: 'Lightweight and fast for small binaries: aaa to analyze, pdf to disassemble, izz for all strings.',
    },
    snippet: 'r2 -A ./challenge\n[0x00000000]> pdf @ main\n[0x00000000]> izz~flag',
    tip: { zh: '记不住命令先记三个：aaa（分析）、pdf（反汇编）、axt（交叉引用）。', en: 'Remember three: aaa (analyze), pdf (disassemble), axt (xrefs).' },
    jump: { kind: 'tool', id: 'radare2' },
  },
  {
    id: 'reverse-gdb',
    title: { zh: 'GDB 动态调试', en: 'GDB dynamic debugging' },
    summary: {
      zh: '静态看不懂就跑起来跟：断在校验函数，看寄存器和栈上参与比较的真实值。',
      en: 'When static reading stalls, run it: break on the check function and watch the real values in registers and on the stack.',
    },
    snippet: 'gdb -q ./challenge\n(gdb) break main\n(gdb) run\n(gdb) x/s $rdi',
    tip: { zh: '配 pwndbg / GEF 插件后视觉好得多；patch 跳转（set $pc）可绕过死循环。', en: 'Install pwndbg or GEF; patching jumps (set $pc) skips anti-debug loops.' },
    jump: { kind: 'tool', id: 'gdb-enhanced' },
  },
  {
    id: 'reverse-angr',
    title: { zh: 'angr 符号执行', en: 'angr symbolic execution' },
    summary: {
      zh: '校验逻辑复杂但目标明确（走到“正确”分支）时，让求解器替你算出输入。',
      en: 'When the check is convoluted but the goal is clear (reach the success branch), let the solver compute the input.',
    },
    snippet: 'import angr\np = angr.Project("./challenge", auto_load_libs=False)\ns = p.factory.entry_state()\nsm = p.factory.simulation_manager(s)\nsm.explore(find=lambda st: b"correct" in st.posix.dumps(1))\nprint(sm.found[0].posix.dumps(0))',
    tip: { zh: '路径爆炸时加 avoid 指向失败分支，或用 find= 地址直接指定目标。', en: 'Avoid path explosion with avoid= on the failure branch, or aim find= at the success address.' },
    jump: { kind: 'tool', id: 'angr' },
  },
  {
    id: 'reverse-binwalk',
    title: { zh: 'binwalk 文件/固件提取', en: 'binwalk extraction' },
    summary: {
      zh: '二进制里藏图片、压缩包、固件镜像时，binwalk 扫嵌入签名并一刀切出来。',
      en: 'When images, archives, or firmware images hide inside a binary, binwalk finds embedded signatures and carves them out.',
    },
    snippet: 'binwalk ./challenge\nbinwalk -e ./challenge   # 自动提取',
    tip: { zh: 'binwalk 提不干净就手动 dd 按偏移切；配合 hexdump 看文件头。', en: 'If -e fails, carve manually with dd at the reported offset; check headers in a hexdump.' },
    jump: { kind: 'tool', id: 'binwalk' },
  },
  {
    id: 'reverse-decompilers',
    title: { zh: '反编译器横向对比', en: 'Decompiler cheat sheet' },
    summary: {
      zh: '同一函数多换几个反编译器看，输出质量差异巨大；objdump/readelf 兜底看结构与符号。',
      en: 'View the same function in several decompilers — output quality varies wildly; objdump/readelf cover structure and symbols.',
    },
    snippet: 'objdump -d -M intel ./challenge | head -100\nreadelf -a ./challenge | head -50',
    tip: { zh: '符号被剥就先看 entry 和字符串引用，反推关键函数再交给反编译器。', en: 'For stripped binaries, start from entry and string xrefs, then decompile the key function.' },
    jump: { kind: 'tool', id: 'decompilers' },
  },
];
