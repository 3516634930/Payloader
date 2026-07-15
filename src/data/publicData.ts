import type { NavItem, PayloadItem, PublicData, SiteSettings, ToolCommand } from '../types';

const isObject = (value: unknown): value is Record<string, unknown> => (
  Boolean(value && typeof value === 'object' && !Array.isArray(value))
);

const isArray = <T>(value: unknown): T[] => (Array.isArray(value) ? value as T[] : []);
const publicProjectRoute = '/api/r/p';
const safeLogoUrlPattern = /^\/uploads\/logo\/logo-[a-zA-Z0-9.-]+\.(png|jpe?g|webp)$/;

const normalizeText = (value: unknown, fallback: SiteSettings['siteTitle']): SiteSettings['siteTitle'] => {
  if (typeof value === 'string') {
    return { zh: value, en: value };
  }
  if (isObject(value) && typeof value.zh === 'string' && typeof value.en === 'string') {
    return { zh: value.zh, en: value.en };
  }
  return fallback;
};

export const defaultSettings = (): SiteSettings => ({
  siteTitle: { zh: 'PAYLOADER', en: 'PAYLOADER' },
  siteSubtitle: { zh: '渗透测试辅助平台', en: 'Pentest Assistance Platform' },
  browserTitle: { zh: 'Payloader - 渗透测试辅助平台', en: 'Payloader - Pentest Assistance Platform' },
  logoIcon: '⚡',
  logoUrl: '',
  projectUrl: publicProjectRoute,
  xeyeEnabled: true,
});

export const emptyPublicData = (): PublicData => ({
  settings: defaultSettings(),
  payloads: [],
  tools: [],
  navigation: [],
  toolNavigation: [],
});

export const parsePublicData = (value: unknown): PublicData => {
  const fallback = emptyPublicData();
  if (!isObject(value)) return emptyPublicData();
  const rawSettings = isObject(value.settings) ? value.settings : {};
  return {
    settings: {
      siteTitle: normalizeText(rawSettings.siteTitle, fallback.settings.siteTitle),
      siteSubtitle: normalizeText(rawSettings.siteSubtitle, fallback.settings.siteSubtitle),
      browserTitle: normalizeText(rawSettings.browserTitle, fallback.settings.browserTitle),
      logoIcon: typeof rawSettings.logoIcon === 'string' && rawSettings.logoIcon.trim()
        ? rawSettings.logoIcon.trim()
        : fallback.settings.logoIcon,
      logoUrl: typeof rawSettings.logoUrl === 'string' && safeLogoUrlPattern.test(rawSettings.logoUrl.trim())
        ? rawSettings.logoUrl.trim()
        : fallback.settings.logoUrl,
      projectUrl: publicProjectRoute,
      xeyeEnabled: rawSettings.xeyeEnabled !== false,
    },
    payloads: isArray<PayloadItem>(value.payloads),
    tools: isArray<ToolCommand>(value.tools),
    navigation: isArray<NavItem>(value.navigation),
    toolNavigation: isArray<NavItem>(value.toolNavigation),
  };
};
