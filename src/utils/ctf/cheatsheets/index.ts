// CTF 题型速查注册表（批次 M）：moduleId → 速查条目。
// 条目只挂项目知识库已有 payload/tool 条目（构建时校验见 tests/ctf-cheatsheets.test.mjs），不重复建设知识内容。

import { webCheatEntries } from './web';
import { reverseCheatEntries } from './reverse';
import { pwnCheatEntries } from './pwn';
import { aiCheatEntries } from './ai';

export interface CheatJump {
  kind: 'payload' | 'tool';
  id: string;
}

export interface CheatEntry {
  id: string;
  title: { zh: string; en: string };
  summary: { zh: string; en: string };
  // 可直接复制的命令 / payload 片段；点击复制。
  snippet?: string;
  tip?: { zh: string; en: string };
  // 知识库跳转目标；缺省为纯文本条目（如实展示，不伪造跳转）。
  jump?: CheatJump;
}

export interface CheatSheet {
  entries: CheatEntry[];
}

export const ctfCheatSheets: Record<string, CheatSheet> = {
  web: { entries: webCheatEntries },
  reverse: { entries: reverseCheatEntries },
  pwn: { entries: pwnCheatEntries },
  ai: { entries: aiCheatEntries },
};
