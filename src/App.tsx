import { useState, useEffect, createContext, useContext } from 'react';
import Header from './components/Header';
import Sidebar from './components/Sidebar';
import MainContent from './components/MainContent';
import type { GlobalVariable } from './types';
import type { Language } from './i18n';
import './styles/global.css';

type ThemeMode = 'dark' | 'light';

interface AppContextType {
  globalVariables: GlobalVariable[];
  setGlobalVariables: React.Dispatch<React.SetStateAction<GlobalVariable[]>>;
  selectedPayloadId: string | null;
  setSelectedPayloadId: React.Dispatch<React.SetStateAction<string | null>>;
  selectedToolId: string | null;
  setSelectedToolId: React.Dispatch<React.SetStateAction<string | null>>;
  bypassMode: 'normal' | 'waf' | 'edr';
  setBypassMode: React.Dispatch<React.SetStateAction<'normal' | 'waf' | 'edr'>>;
  activeTab: 'payloads' | 'tools';
  setActiveTab: React.Dispatch<React.SetStateAction<'payloads' | 'tools'>>;
  theme: ThemeMode;
  setTheme: React.Dispatch<React.SetStateAction<ThemeMode>>;
  searchQuery: string;
  setSearchQuery: React.Dispatch<React.SetStateAction<string>>;
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

function App() {
  const [globalVariables, setGlobalVariables] = useState<GlobalVariable[]>([
    { key: 'TARGET_IP', value: '192.168.1.100', description: { zh: '目标IP地址', en: 'Target IP Address' } },
    { key: 'TARGET_DOMAIN', value: 'target.com', description: { zh: '目标域名', en: 'Target Domain' } },
    { key: 'ATTACKER_IP', value: '10.10.14.5', description: { zh: '攻击者IP', en: 'Attacker IP' } },
    { key: 'USERNAME', value: 'admin', description: { zh: '用户名', en: 'Username' } },
    { key: 'PASSWORD', value: 'password123', description: { zh: '密码', en: 'Password' } },
    { key: 'DOMAIN', value: 'corp.local', description: { zh: '域名', en: 'Domain' } },
  ]);

  const [selectedPayloadId, setSelectedPayloadId] = useState<string | null>(null);
  const [selectedToolId, setSelectedToolId] = useState<string | null>(null);
  const [bypassMode, setBypassMode] = useState<'normal' | 'waf' | 'edr'>('normal');
  const [activeTab, setActiveTab] = useState<'payloads' | 'tools'>('payloads');
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');

  // Theme with localStorage persistence
  const [theme, setTheme] = useState<ThemeMode>(() => {
    try {
      const saved = localStorage.getItem('cyber-arsenal-theme');
      return (saved === 'light' || saved === 'dark') ? saved : 'dark';
    } catch {
      return 'dark';
    }
  });

  // Language with localStorage persistence
  const [language, setLanguage] = useState<Language>(() => {
    try {
      const saved = localStorage.getItem('payloader-language');
      return (saved === 'zh' || saved === 'en') ? saved : 'zh';
    } catch {
      return 'zh';
    }
  });

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    try {
      localStorage.setItem('cyber-arsenal-theme', theme);
    } catch { /* ignore */ }
  }, [theme]);

  useEffect(() => {
    try {
      localStorage.setItem('payloader-language', language);
    } catch { /* ignore */ }
  }, [language]);

  return (
    <AppContext.Provider value={{
      globalVariables,
      setGlobalVariables,
      selectedPayloadId,
      setSelectedPayloadId,
      selectedToolId,
      setSelectedToolId,
      bypassMode,
      setBypassMode,
      activeTab,
      setActiveTab,
      theme,
      setTheme,
      searchQuery,
      setSearchQuery,
      language,
      setLanguage
    }}>
      <div className="app-container">
        <Header 
          sidebarCollapsed={sidebarCollapsed}
          setSidebarCollapsed={setSidebarCollapsed}
        />
        <div className="main-layout">
          <Sidebar collapsed={sidebarCollapsed} />
          <MainContent />
        </div>
      </div>
    </AppContext.Provider>
  );
}

export default App;
