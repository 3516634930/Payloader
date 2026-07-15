import { createContext, useContext } from 'react';
import type { Language } from './i18n';
import type { GlobalVariable, NavItem, PayloadItem, SiteSettings, ToolCommand } from './types';
import type { SearchMatches } from './searchIndex';

export type ThemeMode = 'dark' | 'light';
export type ActiveTab = 'payloads' | 'tools';
export type ActiveView = 'workspace' | 'clientDownloads';
export type PayloadMode = 'normal' | 'waf';

export interface AppContextType {
  globalVariables: GlobalVariable[];
  setGlobalVariables: React.Dispatch<React.SetStateAction<GlobalVariable[]>>;
  allPayloads: PayloadItem[];
  allToolCommands: ToolCommand[];
  allPayloadNavigation: NavItem[];
  allToolNavigation: NavItem[];
  settings: SiteSettings;
  dataLoading: boolean;
  dataError: string | null;
  selectedPayloadId: string | null;
  setSelectedPayloadId: React.Dispatch<React.SetStateAction<string | null>>;
  selectedToolId: string | null;
  setSelectedToolId: React.Dispatch<React.SetStateAction<string | null>>;
  bypassMode: PayloadMode;
  setBypassMode: React.Dispatch<React.SetStateAction<PayloadMode>>;
  activeTab: ActiveTab;
  setActiveTab: React.Dispatch<React.SetStateAction<ActiveTab>>;
  activeView: ActiveView;
  setActiveView: React.Dispatch<React.SetStateAction<ActiveView>>;
  theme: ThemeMode;
  setTheme: React.Dispatch<React.SetStateAction<ThemeMode>>;
  searchQuery: string;
  setSearchQuery: React.Dispatch<React.SetStateAction<string>>;
  deferredSearchQuery: string;
  searchMatches: SearchMatches;
  language: Language;
  setLanguage: React.Dispatch<React.SetStateAction<Language>>;
}

export const AppContext = createContext<AppContextType | null>(null);

export const useAppContext = () => {
  const context = useContext(AppContext);
  if (!context) {
    throw new Error('useAppContext must be used within AppProvider');
  }
  return context;
};
