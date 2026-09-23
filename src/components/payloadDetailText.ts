import type { I18nText, TutorialContent } from '../types';

export type DetailSection = 'payloads' | 'chain' | 'tutorial';

const uiText = {
  notFound: { zh: 'Payload 未找到', en: 'Payload not found' },
  category: { zh: '分类', en: 'Category' },
  subCategory: { zh: '子分类', en: 'Sub-category' },
  difficulty: { zh: '难度', en: 'Difficulty' },
  prerequisites: { zh: '使用前确认', en: 'Before use' },
  tabPayloads: { zh: 'Payload 列表', en: 'Payload list' },
  tabAttackChain: { zh: '攻击链', en: 'Attack chain' },
  tabTutorial: { zh: '教程', en: 'Tutorial' },
  normalMode: { zh: '标准 Payload', en: 'Standard payloads' },
  wafMode: { zh: 'WAF 绕过 Payload', en: 'WAF bypass payloads' },
  copyVisible: { zh: '复制当前列表', en: 'Copy visible' },
  copiedVisible: { zh: '已复制当前列表', en: 'Visible copied' },
  copy: { zh: '复制', en: 'Copy' },
  copied: { zh: '已复制', en: 'Copied' },
  syntax: { zh: '语法解析', en: 'Syntax' },
  platformAll: { zh: '全平台', en: 'All platforms' },
  platformWindows: { zh: 'Windows', en: 'Windows' },
  platformLinux: { zh: 'Linux', en: 'Linux' },
  admin: { zh: '需要管理员权限', en: 'Requires admin' },
  chainPayload: { zh: '关联 Payload', en: 'Related payload' },
  chainFallbackTitle: { zh: '按当前模式验证', en: 'Validate with the selected mode' },
  chainFallbackDesc: { zh: '先确认授权范围和上传点，再从 Payload 列表复制当前模式下的条目，在测试环境中验证响应、落点和防护效果。', en: 'Confirm authorization and the upload point, copy an item from the current mode, then validate the response, storage path, and defensive effect in a test environment.' },
  notesTitle: { zh: '结果分析', en: 'Result analysis' },
  noNotes: { zh: '暂无结果分析。', en: 'No result analysis.' },
  opsec: { zh: '注意事项', en: 'Tips' },
  refs: { zh: '参考资料', en: 'References' },
  overview: { zh: '概述', en: 'Overview' },
  vulnerability: { zh: '原理', en: 'Principle' },
  exploitation: { zh: '使用方法', en: 'Usage' },
  mitigation: { zh: '防护建议', en: 'Mitigation' },
  searchPlaceholder: { zh: '筛选当前 Payload...', en: 'Filter this payload...' },
  clearSearch: { zh: '清除', en: 'Clear' },
  noItemsTitle: { zh: '没有匹配的 Payload', en: 'No matching payloads' },
  noItemsHint: { zh: '换个关键词试试。', en: 'Try another keyword.' },
  noWafTitle: { zh: '当前条目暂无 WAF 绕过内容', en: 'No WAF bypass content for this item' },
  noWafHint: { zh: '这里不会用标准 Payload 冒充绕过方案，可切回标准模式查看已有内容。', en: 'Standard payloads are not presented as bypasses. Switch to standard mode to view available content.' },
  backToNormal: { zh: '切回标准模式', en: 'Use standard mode' },
  wafAvailable: { zh: 'WAF 内容可用', en: 'WAF content available' },
  wafUnavailable: { zh: '无 WAF 内容', en: 'No WAF content' },
};

export const label = (key: keyof typeof uiText, language: 'zh' | 'en') => uiText[key][language];

export const countLabel = (count: number, total: number, language: 'zh' | 'en') => (
  language === 'zh' ? `${count}/${total} 条可复制` : `${count}/${total} copyable`
);

export const payloadIdAliases: Record<string, string> = {
  'jwt-none-alg': 'jwt-none-attack',
  'jwt-none-algo': 'jwt-none-attack',
  'jwt-weak-secret': 'jwt-secret-bruteforce',
  'jwt-kid-injection': 'jwt-key-confusion',
  'jwt-jku-spoofing': 'jwt-jku-x5u-injection',
};

const tutorialPlaceholders = new Set([
  '选择对应payload测试',
  '选择对应 payload 测试',
  '选择绕过技术',
  'select the corresponding payload to test',
  'select a bypass technique',
]);

const tutorialFieldIsSubstantive = (value: I18nText) => {
  const values = typeof value === 'string' ? [value] : [value.zh, value.en];
  return values.some(candidate => {
    const normalized = String(candidate || '').trim().toLowerCase();
    return normalized.length >= 20 && !tutorialPlaceholders.has(normalized);
  });
};

export const tutorialIsSubstantive = (tutorial?: TutorialContent) => Boolean(
  tutorial
  && tutorialFieldIsSubstantive(tutorial.overview)
  && tutorialFieldIsSubstantive(tutorial.vulnerability)
  && tutorialFieldIsSubstantive(tutorial.exploitation)
  && tutorialFieldIsSubstantive(tutorial.mitigation)
);
