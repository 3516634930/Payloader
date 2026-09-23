import { createContext, useContext, useMemo } from 'react';
import type { Language } from './i18n';
import type { GlobalVariable, NavItem, PayloadItem, SiteSettings, ToolCommand } from './types';
import type { SearchMatches } from './searchIndex';

export type ThemeMode = 'dark' | 'light';
export type ActiveTab = 'payloads' | 'tools' | 'ctf';
export type ActiveView = 'workspace' | 'clientDownloads';
export type PayloadMode = 'normal' | 'waf';

// ① 静态数据：启动加载后恒定的 publicData 切片与加载状态。消费面最广、变更频率最低。
export interface StaticDataContextType {
  allPayloads: PayloadItem[];
  allToolCommands: ToolCommand[];
  allPayloadNavigation: NavItem[];
  allToolNavigation: NavItem[];
  settings: SiteSettings;
  dataLoading: boolean;
  dataError: string | null;
}

// ② 语言：消费组件只读，切换频率极低；独立成域让搜索/导航等高频更新不再波及它们。
export interface LanguageContextType {
  language: Language;
  setLanguage: React.Dispatch<React.SetStateAction<Language>>;
}

// ③ 导航：写方是四个导航入口（Header/Sidebar/MainContent/CheatsheetSection）。
export interface NavContextType {
  activeTab: ActiveTab;
  setActiveTab: React.Dispatch<React.SetStateAction<ActiveTab>>;
  activeView: ActiveView;
  setActiveView: React.Dispatch<React.SetStateAction<ActiveView>>;
  selectedPayloadId: string | null;
  setSelectedPayloadId: React.Dispatch<React.SetStateAction<string | null>>;
  selectedToolId: string | null;
  setSelectedToolId: React.Dispatch<React.SetStateAction<string | null>>;
  bypassMode: PayloadMode;
  setBypassMode: React.Dispatch<React.SetStateAction<PayloadMode>>;
}

// ④ 搜索：唯一高频族（每次键入 value 换引用），消费面仅 Header/MainContent/Sidebar。
export interface SearchContextType {
  searchQuery: string;
  setSearchQuery: React.Dispatch<React.SetStateAction<string>>;
  deferredSearchQuery: string;
  searchMatches: SearchMatches;
}

// ⑤ 会话：会话内用户可变数据。
export interface SessionContextType {
  globalVariables: GlobalVariable[];
  setGlobalVariables: React.Dispatch<React.SetStateAction<GlobalVariable[]>>;
  theme: ThemeMode;
  setTheme: React.Dispatch<React.SetStateAction<ThemeMode>>;
  // CTF 工作台全局密钥：带 key 参数的操作在私有值为空时自动回退到它（批次 M）。
  globalSecret: string;
  setGlobalSecret: React.Dispatch<React.SetStateAction<string>>;
}

export const StaticDataContext = createContext<StaticDataContextType | null>(null);
export const LanguageContext = createContext<LanguageContextType | null>(null);
export const NavContext = createContext<NavContextType | null>(null);
export const SearchContext = createContext<SearchContextType | null>(null);
export const SessionContext = createContext<SessionContextType | null>(null);

function useContextOrThrow<T>(context: React.Context<T | null>, hookName: string): T {
  const value = useContext(context);
  if (!value) {
    throw new Error(`${hookName} must be used within its Provider`);
  }
  return value;
}

export const useStaticData = () => useContextOrThrow(StaticDataContext, 'useStaticData');
export const useLanguage = () => useContextOrThrow(LanguageContext, 'useLanguage');
export const useNav = () => useContextOrThrow(NavContext, 'useNav');
export const useSearch = () => useContextOrThrow(SearchContext, 'useSearch');
export const useSession = () => useContextOrThrow(SessionContext, 'useSession');

// 旧聚合形状：未迁移组件的渐进迁移兼容层。聚合对象订阅全部 5 个 context，
// 任何一个域变更都会触发重渲染——迁移到上面的细分 hook 才能获得精准重渲染。
export interface AppContextType extends
  StaticDataContextType,
  LanguageContextType,
  NavContextType,
  SearchContextType,
  SessionContextType {}

export const useAppContext = (): AppContextType => {
  const staticData = useStaticData();
  const language = useLanguage();
  const nav = useNav();
  const search = useSearch();
  const session = useSession();
  return useMemo(
    () => ({ ...staticData, ...language, ...nav, ...search, ...session }),
    [staticData, language, nav, search, session],
  );
};
