// CTF 题型速查注册表（批次 M）：moduleId → 速查条目。
// 条目只挂项目知识库已有 payload/tool 条目（构建时校验见 tests/ctf-cheatsheets.test.mjs），不重复建设知识内容。

import { webCheatEntries } from './web';
import { reverseCheatEntries } from './reverse';
import { pwnCheatEntries } from './pwn';
import { aiCheatEntries } from './ai';

import type { CheatJump, CheatEntry, CheatSheet } from '../../../types';

export type { CheatJump, CheatEntry, CheatSheet };

export const ctfCheatSheets: Record<string, CheatSheet> = {
  web: { entries: webCheatEntries },
  reverse: { entries: reverseCheatEntries },
  pwn: { entries: pwnCheatEntries },
  ai: { entries: aiCheatEntries },
};
