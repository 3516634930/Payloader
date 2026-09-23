import { lazy, Suspense, useState, useEffect, useMemo, useCallback, useDeferredValue } from 'react';
import { useMantineColorScheme } from '@mantine/core';
// 全局样式必须在组件 import 之前，保证 bundle 中先于组件 CSS（组件 <style> 迁出后级联改由 import 顺序决定）
import './styles/global.css';
import Header from './components/Header';
import Sidebar from './components/Sidebar';
import MainContent from './components/MainContent';
import {
  LanguageContext,
  NavContext,
  SearchContext,
  SessionContext,
  StaticDataContext,
} from './appContext';
import type { ActiveTab, ActiveView, PayloadMode, ThemeMode } from './appContext';
import { emptyPublicData, parsePublicData } from './data/publicData';
import { defaultGlobalVariables } from './data/globalVariables';
import type { GlobalVariable, PublicClientBuildInfo, PublicData } from './types';
import type { Language } from './i18n';
import { getText } from './i18n';
import { buildSearchIndex, matchSearchIndex } from './searchIndex';

const LazyEncodingTools = lazy(() => import('./components/EncodingTools'));

function App() {
  const [globalVariables, setGlobalVariables] = useState<GlobalVariable[]>(defaultGlobalVariables);
  const [publicData, setPublicData] = useState<PublicData>(() => emptyPublicData());
  const [clientBuildInfo, setClientBuildInfo] = useState<PublicClientBuildInfo | null>(null);
  const [dataLoading, setDataLoading] = useState(true);
  const [dataError, setDataError] = useState<string | null>(null);
  const isPackagedOfflineClient = window.location.protocol === 'payloader:';
  const allPayloads = useMemo(() => publicData.payloads, [publicData.payloads]);
  const allToolCommands = useMemo(() => publicData.tools, [publicData.tools]);
  const allPayloadNavigation = useMemo(() => publicData.navigation, [publicData.navigation]);
  const allToolNavigation = useMemo(() => publicData.toolNavigation, [publicData.toolNavigation]);
  const settings = useMemo(() => publicData.settings, [publicData.settings]);

  const [selectedPayloadId, setSelectedPayloadId] = useState<string | null>(null);
  const [selectedToolId, setSelectedToolId] = useState<string | null>(null);
  const [bypassMode, setBypassMode] = useState<PayloadMode>('normal');
  const [activeTab, setActiveTab] = useState<ActiveTab>('payloads');
  const [activeView, setActiveView] = useState<ActiveView>('workspace');
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => window.matchMedia('(max-width: 900px)').matches);
  const [searchQuery, setSearchQuery] = useState('');
  // CTF 工作台全局密钥（批次 M）：跨工作台实例共享（智能识别 hero ↔ 密码工作台 ↔ 渗透编解码），
  // Vigenère → AES 等多步连用时密钥只填一次；会话级状态，不落盘。
  const [globalSecret, setGlobalSecret] = useState('');
  // The public language switch stays disabled until English content passes coverage checks.
  const [language, setLanguage] = useState<Language>('zh');
  const [settledSearchQuery, setSettledSearchQuery] = useState('');
  const deferredSearchQuery = useDeferredValue(settledSearchQuery);
  const searchIndex = useMemo(
    () => buildSearchIndex(allPayloads, allToolCommands, language),
    [allPayloads, allToolCommands, language],
  );
  const searchMatches = useMemo(
    () => matchSearchIndex(searchIndex, deferredSearchQuery),
    [deferredSearchQuery, searchIndex],
  );
  const closeSidebar = useCallback(() => setSidebarCollapsed(true), []);

  useEffect(() => {
    const timer = window.setTimeout(
      () => setSettledSearchQuery(searchQuery),
      searchQuery ? 80 : 0,
    );
    return () => window.clearTimeout(timer);
  }, [searchQuery]);

  // Theme with localStorage persistence
  const [theme, setTheme] = useState<ThemeMode>(() => {
    try {
      const saved = localStorage.getItem('cyber-arsenal-theme');
      return (saved === 'light' || saved === 'dark') ? saved : 'dark';
    } catch {
      return 'dark';
    }
  });
  const { setColorScheme } = useMantineColorScheme();

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    setColorScheme(theme);
    try {
      localStorage.setItem('cyber-arsenal-theme', theme);
    } catch { /* ignore */ }
  }, [theme, setColorScheme]);

  useEffect(() => {
    document.title = getText(settings.browserTitle, language) || 'Payloader';
  }, [settings.browserTitle, language]);

  useEffect(() => {
    document.documentElement.lang = language === 'zh' ? 'zh-CN' : 'en';
    const desc = language === 'zh'
      ? '面向授权安全测试与研究的本地知识工作台，提供可检索的载荷与工具命令、变量替换、内容管理、离线客户端和编解码工具。'
      : 'A local security knowledge workbench with searchable payloads, tool commands, variable replacement, content management, offline clients, and codec utilities.';
    document.querySelector('meta[name="description"]')?.setAttribute('content', desc);
  }, [language]);

  useEffect(() => {
    const media = window.matchMedia('(max-width: 900px)');
    const apply = () => setSidebarCollapsed(media.matches);
    media.addEventListener('change', apply);
    return () => media.removeEventListener('change', apply);
  }, []);

  useEffect(() => {
    let isCurrent = true;

    fetch('/api/public-data')
      .then(response => {
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}`);
        }
        return response.json();
      })
      .then(data => {
        if (isCurrent) {
          setPublicData(parsePublicData(data));
          setDataError(null);
        }
      })
      .catch(error => {
        if (isCurrent) {
          setPublicData(emptyPublicData());
          setDataError(error instanceof Error ? error.message : 'Failed to load data');
        }
      })
      .finally(() => {
        if (isCurrent) {
          setDataLoading(false);
        }
      });

    return () => {
      isCurrent = false;
    };
  }, []);

  const refreshClientBuildInfo = useCallback(async (signal?: AbortSignal) => {
    if (isPackagedOfflineClient) {
      setClientBuildInfo(null);
      return;
    }
    try {
      const response = await fetch('/api/client-build', {
        method: 'GET',
        signal,
        cache: 'no-store',
      });
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      const data = await response.json();
      if (data?.offlineClient) {
        setClientBuildInfo(null);
        return;
      }
      setClientBuildInfo(data);
    } catch (error) {
      if (error instanceof DOMException && error.name === 'AbortError') {
        return;
      }
      setClientBuildInfo(null);
    }
  }, [isPackagedOfflineClient]);

  useEffect(() => {
    if (isPackagedOfflineClient) return;
    const controller = new AbortController();
    const initialTimer = window.setTimeout(() => {
      void refreshClientBuildInfo(controller.signal);
    }, 0);

    const timer = window.setInterval(() => {
      if (document.visibilityState === 'visible') {
        void refreshClientBuildInfo();
      }
    }, 15000);

    const handleVisibilityChange = () => {
      if (document.visibilityState === 'visible') {
        void refreshClientBuildInfo();
      }
    };

    window.addEventListener('focus', handleVisibilityChange);
    document.addEventListener('visibilitychange', handleVisibilityChange);

    return () => {
      controller.abort();
      window.clearTimeout(initialTimer);
      window.clearInterval(timer);
      window.removeEventListener('focus', handleVisibilityChange);
      document.removeEventListener('visibilitychange', handleVisibilityChange);
    };
  }, [refreshClientBuildInfo, isPackagedOfflineClient]);

  // 5 个 context value 按域 useMemo：域内字段不变时保持引用稳定，消费组件据此跳过重渲染。
  const staticDataValue = useMemo(
    () => ({
      allPayloads,
      allToolCommands,
      allPayloadNavigation,
      allToolNavigation,
      settings,
      dataLoading,
      dataError,
    }),
    [allPayloads, allToolCommands, allPayloadNavigation, allToolNavigation, settings, dataLoading, dataError],
  );
  const languageValue = useMemo(() => ({ language, setLanguage }), [language]);
  const navValue = useMemo(
    () => ({
      activeTab,
      setActiveTab,
      activeView,
      setActiveView,
      selectedPayloadId,
      setSelectedPayloadId,
      selectedToolId,
      setSelectedToolId,
      bypassMode,
      setBypassMode,
    }),
    [activeTab, activeView, selectedPayloadId, selectedToolId, bypassMode],
  );
  const searchValue = useMemo(
    () => ({ searchQuery, setSearchQuery, deferredSearchQuery, searchMatches }),
    [searchQuery, deferredSearchQuery, searchMatches],
  );
  const sessionValue = useMemo(
    () => ({ globalVariables, setGlobalVariables, theme, setTheme, globalSecret, setGlobalSecret }),
    [globalVariables, theme, globalSecret],
  );
  // 引用稳定回调：内联箭头会在 App 每次渲染（含搜索键入）时换引用，击穿下游 memo。
  const openClientDownloads = useCallback(() => {
    setActiveView('clientDownloads');
    setSelectedPayloadId(null);
    setSelectedToolId(null);
    setSearchQuery('');
  }, [setActiveView, setSelectedPayloadId, setSelectedToolId, setSearchQuery]);
  const handleSidebarNavigate = useCallback(() => {
    setActiveView('workspace');
    if (window.matchMedia('(max-width: 900px)').matches) {
      setSidebarCollapsed(true);
    }
  }, [setActiveView]);

  return (
    <StaticDataContext.Provider value={staticDataValue}>
      <LanguageContext.Provider value={languageValue}>
        <NavContext.Provider value={navValue}>
          <SearchContext.Provider value={searchValue}>
            <SessionContext.Provider value={sessionValue}>
              <div className="app-container">
                <a className="skip-link" href="#main-content">跳到主要内容</a>
                <Header
                  sidebarCollapsed={sidebarCollapsed}
                  setSidebarCollapsed={setSidebarCollapsed}
                  clientBuildInfo={clientBuildInfo}
                  showClientDownloads={!isPackagedOfflineClient}
                  encodingTools={(
                    <Suspense fallback={<div className="lazy-loading" role="status" aria-live="polite">正在加载编解码工具...</div>}>
                      <LazyEncodingTools />
                    </Suspense>
                  )}
                  onOpenClientDownloads={openClientDownloads}
                />
                <div className="main-layout">
                  {activeTab !== 'ctf' && (
                    <>
                      <Sidebar
                        collapsed={sidebarCollapsed}
                        onClose={closeSidebar}
                        onNavigate={handleSidebarNavigate}
                      />
                      {!sidebarCollapsed && (
                        <button
                          className="sidebar-backdrop"
                          onClick={closeSidebar}
                          aria-label="关闭导航"
                        />
                      )}
                    </>
                  )}
                  <MainContent clientBuildInfo={clientBuildInfo} />
                </div>
              </div>
            </SessionContext.Provider>
          </SearchContext.Provider>
        </NavContext.Provider>
      </LanguageContext.Provider>
    </StaticDataContext.Provider>
  );
}

export default App;
