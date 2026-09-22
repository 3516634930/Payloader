import type { ComponentType } from 'react';
import type { OperationId } from '../codec';
import CheatsheetWorkspace from '../../components/ctf/CheatsheetWorkspace';
import CipherWorkspace from '../../components/ctf/CipherWorkspace';
import FileForensicsWorkspace from '../../components/ctf/FileForensicsWorkspace';
import TrafficWorkspace from '../../components/ctf/traffic/TrafficWorkspace';

// CTF 解题工具箱模块注册表（批次 J）：加新题型域 = 在 ctfModules 追加一个 ToolkitModule 对象，不改框架代码。
// entryKinds 声明该域接受的入口类型，框架据此决定智能识别 hero 上是否显示"拖入文件"第二入口。

export type ModuleEntryKind = 'text' | 'file' | 'cheatsheet';

export interface CtfWorkspaceProps {
  module: ToolkitModule;
  // 工作区挂载后把"聚焦指定操作"的能力注册给框架，供智能识别 hero 的检测芯片跨域转发；
  // seedInput 为 hero 当前输入（芯片跳转时同步带入工作台，undefined 表示不带数据）。
  registerFocus?: (focus: ((id: OperationId, seedInput?: string) => void) | null) => void;
  // 框架层截获的文件入口（hero 按钮/页面拖拽），token 变化表示新文件；由接受文件的工作区消费。
  pendingFile?: { file: File; token: number } | null;
  // 工作区消费掉 pendingFile 后回调；框架据此清空入口，避免残留文件在域切换/重挂载时重放。
  onFileConsumed?: () => void;
}

export interface ToolkitModule {
  id: string;
  name: { zh: string; en: string };
  icon: string;
  entryKinds: ModuleEntryKind[];
  Workspace: ComponentType<CtfWorkspaceProps>;
  // 切换域时保持挂载（隐藏不卸载），保留工作台输入与选择状态。
  keepMounted?: boolean;
  // 建设中域的规划能力预告，显示在占位页。
  note?: { zh: string; en: string };
}

export const ctfModules: ToolkitModule[] = [
  {
    id: 'cipher',
    name: { zh: '密码与编码', en: 'Ciphers & Encoding' },
    icon: '🔐',
    entryKinds: ['text'],
    Workspace: CipherWorkspace,
    keepMounted: true,
  },
  {
    id: 'misc',
    name: { zh: '杂项取证', en: 'Misc & Forensics' },
    icon: '🧩',
    entryKinds: ['file'],
    Workspace: FileForensicsWorkspace,
  },
  {
    id: 'traffic',
    name: { zh: '流量分析', en: 'Traffic Analysis' },
    icon: '📡',
    entryKinds: ['file'],
    Workspace: TrafficWorkspace,
  },
  {
    id: 'web',
    name: { zh: 'Web', en: 'Web' },
    icon: '🌐',
    entryKinds: ['cheatsheet'],
    Workspace: CheatsheetWorkspace,
    note: {
      zh: '规划能力：Web 题交互式工具台（请求重放、编码链分析）。',
      en: 'Planned: an interactive Web workbench (request replay, encoding chain analysis).',
    },
  },
  {
    id: 'reverse',
    name: { zh: '逆向', en: 'Reverse' },
    icon: '🔍',
    entryKinds: ['cheatsheet'],
    Workspace: CheatsheetWorkspace,
    note: {
      zh: '规划能力：逆向域专属工具（反编译辅助、字符串/签名增强扫描）。',
      en: 'Planned: dedicated reversing tools (decompiler helpers, enhanced string/signature scans).',
    },
  },
  {
    id: 'pwn',
    name: { zh: 'Pwn', en: 'Pwn' },
    icon: '⚔️',
    entryKinds: ['cheatsheet'],
    Workspace: CheatsheetWorkspace,
    note: {
      zh: '规划能力：Pwn 域专属工具（gadget 检索、payload 布局生成器）。',
      en: 'Planned: dedicated Pwn tools (gadget lookup, payload layout builders).',
    },
  },
  {
    id: 'ai',
    name: { zh: 'AI', en: 'AI' },
    icon: '🤖',
    entryKinds: ['cheatsheet'],
    Workspace: CheatsheetWorkspace,
    note: {
      zh: '规划能力：AI 题专属工具（提示注入用例库、系统提示对照）。',
      en: 'Planned: dedicated AI tools (prompt injection case library, system prompt diffing).',
    },
  },
];
