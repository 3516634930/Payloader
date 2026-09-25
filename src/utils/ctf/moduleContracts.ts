import type { OperationId } from '../codec/types';

// CTF 解题工具箱模块契约层（T2 分层解耦）：纯类型 + 纯数据，零运行时 import（type-only 引用
// 编译后擦除），因此 node 沙箱可直接加载做运行时断言，工具层也能脱离 React 消费。
// 组件注入在组件层 registry.tsx 完成（contract + Workspace → 完整注册表）。
// 加新题型域 = 在 ctfModuleContracts 追加一条契约并在 registry 注册工作区组件，不改框架代码。
// entryKinds 声明该域接受的入口类型，框架据此决定智能识别 hero 上是否显示"拖入文件"第二入口。

export type ModuleEntryKind = 'text' | 'file' | 'cheatsheet';

export interface CtfWorkspaceProps {
  module: ModuleContract;
  // 工作区挂载后把"聚焦指定操作"的能力注册给框架，供智能识别 hero 的检测芯片跨域转发；
  // seedInput 为 hero 当前输入（芯片跳转时同步带入工作台，undefined 表示不带数据）。
  registerFocus?: (focus: ((id: OperationId, seedInput?: string) => void) | null) => void;
  // 框架层截获的文件入口（hero 按钮/页面拖拽），token 变化表示新文件；由接受文件的工作区消费。
  pendingFile?: { file: File; token: number } | null;
  // 工作区消费掉 pendingFile 后回调；框架据此清空入口，避免残留文件在域切换/重挂载时重放。
  onFileConsumed?: () => void;
  // 工作区把当前文件交回框架重走魔数路由（推荐工具条的跨域按钮，如 PCAP → 流量分析域）。
  onHandOffFile?: (file: File) => void;
  // 工作区请求切到目标题型域（纯导航，不带文件，如 ELF 常量扫描引导 → 逆向速查域）。
  onSwitchModule?: (moduleId: string) => void;
}

// 域契约（声明性数据）：不含任何组件引用，漂移即破坏魔数路由与 hero 形态（verify 运行时守护）。
export interface ModuleContract {
  id: string;
  name: { zh: string; en: string };
  icon: string;
  entryKinds: ModuleEntryKind[];
  // 切换域时保持挂载（隐藏不卸载），保留工作台输入与选择状态。
  keepMounted?: boolean;
  // 智能识别 hero 形态：full = 完整 hero（输入 + 密钥栏 + 识别 + 输出，缺省）；
  // collapsed = 首屏折叠为单行紧凑条，展开后才是完整 hero（文件/速查工作区升为该域首屏主体）。
  heroMode?: 'full' | 'collapsed';
  // 建设中域的规划能力预告，显示在占位页。
  note?: { zh: string; en: string };
}

export const ctfModuleContracts: ModuleContract[] = [
  {
    id: 'cipher',
    name: { zh: '密码与编码', en: 'Ciphers & Encoding' },
    icon: '🔐',
    entryKinds: ['text'],
    keepMounted: true,
  },
  {
    id: 'misc',
    name: { zh: '杂项取证', en: 'Misc & Forensics' },
    icon: '🧩',
    entryKinds: ['file'],
    keepMounted: true,
    heroMode: 'collapsed',
  },
  {
    id: 'traffic',
    name: { zh: '流量分析', en: 'Traffic Analysis' },
    icon: '📡',
    entryKinds: ['file'],
    keepMounted: true,
    heroMode: 'collapsed',
  },
  {
    id: 'web',
    name: { zh: 'Web', en: 'Web' },
    icon: '🌐',
    entryKinds: ['text', 'cheatsheet'],
    heroMode: 'collapsed',

  },
  {
    id: 'reverse',
    name: { zh: '逆向', en: 'Reverse' },
    icon: '🔍',
    entryKinds: ['file', 'cheatsheet'],
    keepMounted: true,
    heroMode: 'collapsed',
    note: {
      zh: '规划能力：反编译辅助（Ghidra/dogbolt 指导页）、字符串/签名增强扫描。',
      en: 'Planned: decompiler helpers (Ghidra/dogbolt guides), enhanced string/signature scans.',
    },
  },
  {
    id: 'pwn',
    name: { zh: 'Pwn', en: 'Pwn' },
    icon: '⚔️',
    entryKinds: ['text', 'cheatsheet'],
    keepMounted: true,
    heroMode: 'collapsed',
    note: {
      zh: '规划能力：gadget 检索、payload 布局生成器。',
      en: 'Planned: gadget lookup, payload layout builders.',
    },
  },
  {
    id: 'ai',
    name: { zh: 'AI', en: 'AI' },
    icon: '🤖',
    entryKinds: ['cheatsheet'],
    heroMode: 'collapsed',
    note: {
      zh: '规划能力：AI 题专属工具（提示注入用例库、系统提示对照）。',
      en: 'Planned: dedicated AI tools (prompt injection case library, system prompt diffing).',
    },
  },
];
