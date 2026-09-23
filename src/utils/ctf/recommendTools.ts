import type { DetectedType } from './fileDetect';

// 推荐工具映射（文件探测结果驱动工具呈现）：按探测出的文件类型给出适用操作锚点。
// 纯函数、不耦合具体工具实现——新工具上线后在对应类型组注册一个条目即可出现在推荐条；
// 按钮只做三件事：域内锚点滚动（cardId）、把文件交回框架重走魔数路由（handoffFile）、纯切域（targetModuleId）。

export interface ToolAnchor {
  id: string;
  label: { zh: string; en: string };
  // 域内锚点滚动目标卡；卡片未渲染（内容未命中或工具未上线）时向用户 toast missingMessage。
  cardId?: string;
  // 把当前文件交回框架（CtfToolkit.handleFileSelected），复用魔数路由自动跨域（PCAP → 流量分析域）。
  handoffFile?: boolean;
  // 纯导航切域（不带文件），如 ELF → 逆向速查域的常量扫描引导。
  targetModuleId?: string;
  missingMessage: { zh: string; en: string };
  // 工具规划中：视觉弱化，点击提示后续版本提供；上线后摘掉即与普通锚点一致。
  soon?: boolean;
}

const ARCHIVE_EXTS = new Set(['jar', 'apk', '7z', 'rar4', 'rar5']);
const EXECUTABLE_EXTS = new Set(['elf', 'exe', 'macho']);
const PCAP_EXTS = new Set(['pcap', 'pcapbe', 'pcapng']);

const PNG_TOOLS: ToolAnchor[] = [
  {
    id: 'png-dimensions',
    label: { zh: '宽高修复', en: 'Fix dimensions' },
    cardId: 'ff-card-repair',
    missingMessage: {
      zh: '宽高修复仅在 PNG 宽高校验失败时可用；当前文件没有可修复项。',
      en: 'Dimension repair only applies when the PNG CRC check fails; nothing to fix here.',
    },
  },
  {
    id: 'png-bitplanes',
    label: { zh: '位平面', en: 'Bit planes' },
    cardId: 'ff-card-bitplanes',
    soon: true,
    missingMessage: {
      zh: '位平面分析在后续版本提供，当前可先用 strings 与 hexdump 继续。',
      en: 'Bit-plane analysis is coming in a later release; strings and hexdump still work.',
    },
  },
  {
    id: 'png-channels',
    label: { zh: '色道分离', en: 'Color channels' },
    cardId: 'ff-card-channels',
    soon: true,
    missingMessage: {
      zh: '色道分离在后续版本提供，当前可先用 strings 与 hexdump 继续。',
      en: 'Channel splitting is coming in a later release; strings and hexdump still work.',
    },
  },
  {
    id: 'png-chunks',
    label: { zh: 'chunk 枚举', en: 'Chunk list' },
    cardId: 'ff-card-chunks',
    soon: true,
    missingMessage: {
      zh: 'chunk 枚举在后续版本提供，当前可先用 hexdump 查看文件头。',
      en: 'Chunk enumeration is coming in a later release; use the hexdump to inspect the header.',
    },
  },
];

const JPG_TOOLS: ToolAnchor[] = [
  {
    id: 'jpg-eoi',
    label: { zh: 'EOI 后附加扫描', en: 'After-EOI scan' },
    cardId: 'ff-card-jpg-eoi',
    soon: true,
    missingMessage: {
      zh: 'EOI 后附加数据扫描在后续版本提供，当前可先用 strings 与 hexdump 继续。',
      en: 'After-EOI scanning is coming in a later release; strings and hexdump still work.',
    },
  },
  {
    id: 'jpg-metadata',
    label: { zh: '元数据', en: 'Metadata' },
    cardId: 'ff-card-jpg-metadata',
    soon: true,
    missingMessage: {
      zh: '元数据提取在后续版本提供，当前可先用 strings 继续。',
      en: 'Metadata extraction is coming in a later release; strings still works.',
    },
  },
];

const GENERIC_TOOLS: ToolAnchor[] = [
  {
    id: 'gen-strings',
    label: { zh: '可读字符串', en: 'Strings' },
    cardId: 'ff-card-strings',
    missingMessage: {
      zh: '当前文件没有提取到可读字符串。',
      en: 'No readable strings were extracted from this file.',
    },
  },
  {
    id: 'gen-hexdump',
    label: { zh: 'hexdump', en: 'Hexdump' },
    cardId: 'ff-card-hexdump',
    missingMessage: {
      zh: '当前文件没有 hexdump 预览。',
      en: 'No hexdump preview for this file.',
    },
  },
  {
    id: 'gen-entropy',
    label: { zh: '信息熵', en: 'Entropy' },
    cardId: 'ff-card-summary',
    missingMessage: {
      zh: '当前文件没有概要信息。',
      en: 'No summary is available for this file.',
    },
  },
];

const pushUnique = (tools: ToolAnchor[], additions: ToolAnchor[]) => {
  // 去重键 = 文案 + 目标（cardId/跨域动作）：exe 组与通用组都有"可读字符串/信息熵"时只保留一个。
  const seen = new Set(tools.map(tool =>
    `${tool.label.zh}|${tool.cardId ?? tool.targetModuleId ?? (tool.handoffFile ? 'handoff' : '')}`));
  for (const tool of additions) {
    const key = `${tool.label.zh}|${tool.cardId ?? tool.targetModuleId ?? (tool.handoffFile ? 'handoff' : '')}`;
    if (seen.has(key)) continue;
    seen.add(key);
    tools.push(tool);
  }
};

// 根据探测类型给推荐工具组：类型专属在前（修复类最先），通用组兜底；未命中任何专属类型时只给通用组。
export const recommendTools = (types: DetectedType[]): ToolAnchor[] => {
  const exts = new Set(types.map(type => type.ext));
  const tools: ToolAnchor[] = [];

  if (exts.has('png')) pushUnique(tools, PNG_TOOLS);
  if (exts.has('jpg')) pushUnique(tools, JPG_TOOLS);

  if (exts.has('zip') || [...exts].some(ext => ARCHIVE_EXTS.has(ext))) {
    pushUnique(tools, [
      {
        id: 'archive-pseudo',
        label: { zh: '伪加密修复', en: 'Pseudo-encryption fix' },
        cardId: 'ff-card-repair',
        missingMessage: {
          zh: '伪加密修复目前支持 ZIP 家族格式（zip/jar/apk）；当前压缩包没有可修复项。',
          en: 'Pseudo-encryption repair currently covers the ZIP family (zip/jar/apk); nothing to fix here.',
        },
      },
      {
        id: 'archive-embedded',
        label: { zh: '嵌入提取', en: 'Embedded files' },
        cardId: 'ff-card-embedded',
        soon: true,
        missingMessage: {
          zh: '嵌入文件提取在后续版本提供，当前可先用 strings 与 hexdump 继续。',
          en: 'Embedded-file extraction is coming in a later release; strings and hexdump still work.',
        },
      },
    ]);
  }

  if ([...exts].some(ext => EXECUTABLE_EXTS.has(ext))) {
    pushUnique(tools, [
      {
        id: 'exe-strings',
        label: { zh: '可读字符串', en: 'Strings' },
        cardId: 'ff-card-strings',
        missingMessage: {
          zh: '当前文件没有提取到可读字符串。',
          en: 'No readable strings were extracted from this file.',
        },
      },
      {
        id: 'exe-constants',
        label: { zh: '常量扫描（逆向域）', en: 'Constant scan (Reverse)' },
        targetModuleId: 'reverse',
        missingMessage: {
          zh: '逆向域暂未打开。',
          en: 'The Reverse module is not open.',
        },
      },
      {
        id: 'exe-entropy',
        label: { zh: '信息熵', en: 'Entropy' },
        cardId: 'ff-card-summary',
        missingMessage: {
          zh: '当前文件没有概要信息。',
          en: 'No summary is available for this file.',
        },
      },
    ]);
  }

  if ([...exts].some(ext => PCAP_EXTS.has(ext))) {
    pushUnique(tools, [
      {
        id: 'pcap-traffic',
        label: { zh: '转到流量分析域', en: 'Open in Traffic Analysis' },
        handoffFile: true,
        missingMessage: {
          zh: '当前没有可移交的文件。',
          en: 'There is no file to hand off.',
        },
      },
    ]);
  }

  // PDF/MP4/WAV 等未单列的类型与无匹配类型：通用组兜底。
  pushUnique(tools, GENERIC_TOOLS);
  return tools;
};
