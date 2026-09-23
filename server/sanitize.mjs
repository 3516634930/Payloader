// 存储条目清洗（纯函数，自 data-store.mjs 机械迁移）：settings/payload/tool/nav 四域 sanitize 族
// 与 makeId/cloneValue 工具。文本归一依赖 text-quality，零 db 与 IO 依赖，独立可测。

import { publicProjectRoute } from './project-attribution.mjs';
import {
  dedupeCommandEntries,
  ensureDisplayTextObject,
  isObject,
  isPlatform,
  localizeKnownToolEnglish,
  normalizeList,
  normalizeText,
  scrubLowQualityEnglishContent,
  scrubRetiredEdrContent,
  textValue,
  toText,
} from './text-quality.mjs';

const projectUrl = publicProjectRoute;

const defaultSettings = {
  siteTitle: { zh: 'PAYLOADER', en: 'PAYLOADER' },
  siteSubtitle: { zh: '渗透测试辅助平台', en: 'Pentest Assistance Platform' },
  browserTitle: { zh: 'Payloader - 渗透测试辅助平台', en: 'Payloader - Pentest Assistance Platform' },
  logoIcon: '⚡',
  logoUrl: '',
  projectUrl,
};
const json = value => JSON.stringify(value ?? null);
const parseJson = value => {
  if (typeof value !== 'string' || value.length === 0) return null;
  return JSON.parse(value);
};

const protectedExternalUrl = 'https://xss.icu/';
const protectedXssToolId = 'xss-platform';
const systemToolIds = new Set([protectedXssToolId]);

const sanitizeLogoUrl = value => {
  const logoUrl = String(value ?? '').trim();
  return /^\/uploads\/logo\/logo-[a-zA-Z0-9.-]+\.(png|jpe?g|webp)$/.test(logoUrl) ? logoUrl : '';
};

const makeId = (prefix, fallback = 'item') => {
  const source = String(fallback || 'item')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 48);
  const suffix = Math.random().toString(36).slice(2, 8);
  return `${prefix}-${source || 'item'}-${suffix}`;
};

export const sanitizeSettings = value => {
  const candidate = isObject(value) ? value : {};
  const merged = { ...defaultSettings, ...candidate };
  return {
    siteTitle: normalizeText(merged.siteTitle),
    siteSubtitle: normalizeText(merged.siteSubtitle),
    browserTitle: normalizeText(merged.browserTitle),
    logoIcon: String(merged.logoIcon ?? defaultSettings.logoIcon).trim() || defaultSettings.logoIcon,
    logoUrl: sanitizeLogoUrl(merged.logoUrl),
    projectUrl,
  };
};

const sanitizePayloadExecution = value => {
  const candidate = isObject(value) ? value : {};
  return {
    title: ensureDisplayTextObject(candidate.title),
    command: String(candidate.command ?? '').trim(),
    description: candidate.description == null ? undefined : ensureDisplayTextObject(candidate.description),
    syntaxBreakdown: normalizeList(candidate.syntaxBreakdown).map(sanitizeSyntaxPart).filter(Boolean),
    platform: isPlatform(candidate.platform) ? candidate.platform : 'all',
    requiresAdmin: Boolean(candidate.requiresAdmin),
  };
};

const sanitizeSyntaxPart = value => {
  if (!isObject(value)) return null;
  const part = String(value.part ?? '').trim();
  if (!part) return null;
  return {
    part,
    explanation: ensureDisplayTextObject(value.explanation),
    type: typeof value.type === 'string' ? value.type : undefined,
  };
};

const sanitizeAttackChainStep = value => {
  if (!isObject(value)) return null;
  const payload = String(value.payload ?? '').trim();
  const step = {
    title: ensureDisplayTextObject(value.title),
    description: ensureDisplayTextObject(value.description),
  };
  if (payload) step.payload = payload;
  return step;
};

const sanitizeStoredPublicPayload = value => {
  const candidate = isObject(value) ? value : {};
  const name = ensureDisplayTextObject(candidate.name);
  const id = typeof candidate.id === 'string' && candidate.id.trim() ? candidate.id.trim() : makeId('payload', name.zh || name.en || 'payload');
  return {
    id,
    name,
    description: ensureDisplayTextObject(candidate.description),
    category: ensureDisplayTextObject(candidate.category),
    subCategory: candidate.subCategory == null ? undefined : ensureDisplayTextObject(candidate.subCategory),
    tags: normalizeList(candidate.tags).map(String).map(item => item.trim()).filter(Boolean),
    prerequisites: normalizeList(candidate.prerequisites).map(ensureDisplayTextObject),
    execution: dedupeCommandEntries(normalizeList(candidate.execution).map(sanitizePayloadExecution).filter(item => item.command)),
    analysis: candidate.analysis == null ? undefined : ensureDisplayTextObject(candidate.analysis),
    opsecTips: normalizeList(candidate.opsecTips).map(ensureDisplayTextObject),
    wafBypass: dedupeCommandEntries(normalizeList(candidate.wafBypass).map(sanitizePayloadExecution).filter(item => item.command)),
    attackChain: normalizeList(candidate.attackChain).map(sanitizeAttackChainStep).filter(Boolean),
    references: normalizeList(candidate.references).map(String).map(item => item.trim()).filter(Boolean),
    tutorial: isObject(candidate.tutorial) ? {
      overview: ensureDisplayTextObject(candidate.tutorial.overview),
      vulnerability: ensureDisplayTextObject(candidate.tutorial.vulnerability),
      exploitation: ensureDisplayTextObject(candidate.tutorial.exploitation),
      mitigation: ensureDisplayTextObject(candidate.tutorial.mitigation),
      difficulty: ['beginner', 'intermediate', 'advanced', 'expert'].includes(candidate.tutorial.difficulty) ? candidate.tutorial.difficulty : 'beginner',
    } : undefined,
  };
};

export const sanitizePayload = value => {
  const scrubbed = scrubLowQualityEnglishContent(scrubRetiredEdrContent(value).value).value;
  const candidate = isObject(scrubbed) ? scrubbed : {};
  const name = ensureDisplayTextObject(candidate.name);
  const execution = normalizeList(candidate.execution).map(sanitizePayloadExecution).filter(item => item.command);
  return {
    id: typeof candidate.id === 'string' && candidate.id.trim() ? candidate.id.trim() : makeId('payload', name.zh || name.en || 'payload'),
    name,
    description: ensureDisplayTextObject(candidate.description),
    category: ensureDisplayTextObject(candidate.category),
    subCategory: candidate.subCategory == null ? undefined : ensureDisplayTextObject(candidate.subCategory),
    tags: normalizeList(candidate.tags).map(String).map(item => item.trim()).filter(Boolean),
    prerequisites: normalizeList(candidate.prerequisites).map(ensureDisplayTextObject),
    execution: execution.length ? execution : [{ title: toText('Command'), command: String(candidate.command ?? 'echo TODO').trim() || 'echo TODO', platform: 'all' }],
    analysis: candidate.analysis == null ? undefined : ensureDisplayTextObject(candidate.analysis),
    opsecTips: normalizeList(candidate.opsecTips).map(ensureDisplayTextObject),
    wafBypass: normalizeList(candidate.wafBypass).map(sanitizePayloadExecution).filter(item => item.command),
    attackChain: normalizeList(candidate.attackChain).map(sanitizeAttackChainStep).filter(Boolean),
    references: normalizeList(candidate.references).map(String).map(item => item.trim()).filter(Boolean),
    tutorial: isObject(candidate.tutorial) ? {
      overview: ensureDisplayTextObject(candidate.tutorial.overview),
      vulnerability: ensureDisplayTextObject(candidate.tutorial.vulnerability),
      exploitation: ensureDisplayTextObject(candidate.tutorial.exploitation),
      mitigation: ensureDisplayTextObject(candidate.tutorial.mitigation),
      difficulty: ['beginner', 'intermediate', 'advanced', 'expert'].includes(candidate.tutorial.difficulty) ? candidate.tutorial.difficulty : 'beginner',
    } : undefined,
  };
};

const sanitizeToolCommandItem = value => {
  const candidate = isObject(value) ? value : {};
  const command = String(candidate.command ?? '').trim();
  if (!command) return null;
  let name = localizeKnownToolEnglish(candidate.name);
  const description = localizeKnownToolEnglish(candidate.description);
  if (isObject(name) && !name.zh.trim() && !name.en.trim()) {
    const fallbackLabel = textValue(description).trim() || command.split(/\r?\n/, 1)[0].trim() || 'Command';
    name = localizeKnownToolEnglish(toText(fallbackLabel));
  }
  return {
    name,
    command,
    description,
    syntaxBreakdown: normalizeList(candidate.syntaxBreakdown).map(sanitizeSyntaxPart).filter(Boolean),
    examples: normalizeList(candidate.examples).map(localizeKnownToolEnglish),
    platform: isPlatform(candidate.platform) ? candidate.platform : 'all',
  };
};

export const sanitizeTool = value => {
  const candidate = isObject(value) ? value : {};
  const name = localizeKnownToolEnglish(candidate.name);
  const commands = normalizeList(candidate.commands).map(sanitizeToolCommandItem).filter(Boolean);
  const id = typeof candidate.id === 'string' && candidate.id.trim() ? candidate.id.trim() : makeId('tool', name.zh || name.en || 'tool');
  const externalUrl = candidate.externalUrl === protectedExternalUrl && systemToolIds.has(id) ? protectedExternalUrl : '';
  const description = localizeKnownToolEnglish(candidate.description);
  const category = localizeKnownToolEnglish(candidate.category);
  const installation = candidate.installation == null ? undefined : localizeKnownToolEnglish(candidate.installation);
  const item = {
    id,
    name,
    description,
    category,
    commands: commands.length ? commands : (externalUrl ? [] : [{ name: toText('Command'), command: 'echo TODO', description: toText('TODO'), platform: 'all' }]),
    installation,
    references: normalizeList(candidate.references).map(String).map(item => item.trim()).filter(Boolean),
  };
  if (externalUrl) {
    item.externalUrl = externalUrl;
    item.systemLocked = true;
  }
  return item;
};

export const sanitizeNavItem = value => {
  const candidate = isObject(value) ? value : {};
  const name = normalizeText(candidate.name);
  const item = {
    id: typeof candidate.id === 'string' && candidate.id.trim() ? candidate.id.trim() : makeId('nav', name.zh || name.en || 'node'),
    name,
  };
  if (typeof candidate.icon === 'string' && candidate.icon.trim()) item.icon = candidate.icon.trim();
  if (typeof candidate.payloadId === 'string' && candidate.payloadId.trim()) item.payloadId = candidate.payloadId.trim();
  if (typeof candidate.toolId === 'string' && candidate.toolId.trim()) item.toolId = candidate.toolId.trim();
  const children = normalizeList(candidate.children).map(sanitizeNavItem);
  if (children.length) item.children = children;
  return item;
};

const cloneValue = value => parseJson(json(value));

export {
  cloneValue,
  defaultSettings,
  makeId,
  projectUrl,
  protectedExternalUrl,
  protectedXssToolId,
  sanitizeAttackChainStep,
  sanitizeLogoUrl,
  sanitizePayloadExecution,
  sanitizeStoredPublicPayload,
  sanitizeSyntaxPart,
  sanitizeToolCommandItem,
  systemToolIds,
};
