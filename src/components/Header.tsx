import { useEffect, useId, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { useLanguage, useNav, useSearch, useSession, useStaticData } from '../appContext';
import type { ActiveTab } from '../appContext';
import { t, getText } from '../i18n';
import { protectedExternalLinks } from '../protectedLinks';
import type { PublicClientBuildInfo } from '../types';
import '../styles/header.css';

interface HeaderProps {
  sidebarCollapsed: boolean;
  setSidebarCollapsed: (collapsed: boolean) => void;
  clientBuildInfo: PublicClientBuildInfo | null;
  showClientDownloads?: boolean;
  encodingTools: ReactNode;
  onOpenClientDownloads: () => void;
}

const variableGroupLabels: Record<string, { zh: string; en: string }> = {
  target: { zh: '目标信息', en: 'Target' },
  request: { zh: '请求参数', en: 'Request' },
  auth: { zh: '认证会话', en: 'Auth' },
  callback: { zh: '回连与带外', en: 'Callback' },
  file: { zh: '文件与字典', en: 'Files' },
  cloud: { zh: '云资源', en: 'Cloud' },
  infra: { zh: '内网与基础设施', en: 'Infra' },
  other: { zh: '其它', en: 'Other' },
};

const pinnedVariableKeys = new Set(['URL', 'TARGET', 'PATH', 'PARAM', 'PARAM_VALUE', 'COOKIE', 'HEADER_AUTH', 'ATTACKER_IP', 'LPORT']);

const formatDownloadSize = (size: number) => {
  if (!Number.isFinite(size) || size <= 0) return '';
  if (size >= 1024 * 1024) return `${(size / 1024 / 1024).toFixed(1)} MB`;
  if (size >= 1024) return `${(size / 1024).toFixed(0)} KB`;
  return `${Math.round(size)} B`;
};

const focusableSelector = [
  'a[href]',
  'button:not([disabled])',
  'input:not([disabled])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  '[tabindex]:not([tabindex="-1"])',
].join(',');

function Header({ sidebarCollapsed, setSidebarCollapsed, clientBuildInfo, showClientDownloads = true, encodingTools, onOpenClientDownloads }: HeaderProps) {
  const { globalVariables, setGlobalVariables, theme, setTheme } = useSession();
  const { bypassMode, setBypassMode, activeTab, setActiveTab, setActiveView, setSelectedPayloadId, setSelectedToolId } = useNav();
  const { searchQuery, setSearchQuery } = useSearch();
  const { settings } = useStaticData();
  const { language } = useLanguage();
  const [showVariables, setShowVariables] = useState(false);
  const [showEncoding, setShowEncoding] = useState(false);
  const [showMobileUtilities, setShowMobileUtilities] = useState(false);
  const [variableSearch, setVariableSearch] = useState('');
  const [collapsedVariableGroups, setCollapsedVariableGroups] = useState<Set<string>>(() => new Set(['cloud', 'infra']));
  const encodingDialogRef = useRef<HTMLDivElement>(null);
  const previousFocus = useRef<HTMLElement | null>(null);
  const mobileUtilitiesRef = useRef<HTMLDivElement>(null);
  const mobileUtilitiesButtonRef = useRef<HTMLButtonElement>(null);
  const variablesToggleRef = useRef<HTMLButtonElement>(null);
  const variablesPanelRef = useRef<HTMLDivElement>(null);
  const encodingTitleId = useId();
  const clientDownloadCount = clientBuildInfo?.items?.length || (clientBuildInfo?.latest ? 1 : 0);
  const clientDownloadLabel = language === 'zh' ? '下载客户端' : 'Download Client';
  const clientDownloadSize = clientBuildInfo?.latest?.size ? formatDownloadSize(clientBuildInfo.latest.size) : '';
  const clientDownloadTitle = language === 'zh'
    ? `查看 Payloader 客户端下载列表${clientDownloadCount ? `（${clientDownloadCount} 个版本）` : ''}`
    : `Open Payloader client downloads${clientDownloadCount ? ` (${clientDownloadCount} builds)` : ''}`;

  const updateVariable = (key: string, value: string) => {
    setGlobalVariables(prev => 
      prev.map(v => v.key === key ? { ...v, value } : v)
    );
  };

  const toggleVariableGroup = (group: string) => {
    setCollapsedVariableGroups(prev => {
      const next = new Set(prev);
      if (next.has(group)) next.delete(group);
      else next.add(group);
      return next;
    });
  };

  const variableGroups = (() => {
    const query = variableSearch.trim().toLowerCase();
    const groups = new Map<string, typeof globalVariables>();

    for (const variable of globalVariables) {
      const group = variable.group || 'other';
      const searchable = [
        variable.key,
        variable.value,
        getText(variable.description, language),
        getText(variableGroupLabels[group] || variableGroupLabels.other, language),
      ].join(' ').toLowerCase();

      if (query && !searchable.includes(query)) continue;
      const existing = groups.get(group) || [];
      existing.push(variable);
      groups.set(group, existing);
    }

    return Array.from(groups.entries()).map(([group, variables]) => ({
      group,
      variables: variables.sort((a, b) => {
        const pinnedA = pinnedVariableKeys.has(a.key) ? 0 : 1;
        const pinnedB = pinnedVariableKeys.has(b.key) ? 0 : 1;
        if (pinnedA !== pinnedB) return pinnedA - pinnedB;
        return a.key.localeCompare(b.key);
      }),
    }));
  })();

  const toggleTheme = () => {
    setTheme(prev => prev === 'dark' ? 'light' : 'dark');
  };

  const switchTab = (tab: ActiveTab) => {
    setActiveView('workspace');
    setActiveTab(tab);
    setSelectedPayloadId(null);
    setSelectedToolId(null);
  };

  // WAI-ARIA tabs 模式：roving tabindex + 左右方向键在三个内容 tab 间移动并激活
  const contentTabs: ActiveTab[] = ['payloads', 'tools', 'ctf'];
  const handleTabKeyDown = (event: React.KeyboardEvent<HTMLButtonElement>, tab: ActiveTab) => {
    if (event.key !== 'ArrowLeft' && event.key !== 'ArrowRight') return;
    event.preventDefault();
    const index = contentTabs.indexOf(tab);
    const nextIndex = event.key === 'ArrowRight'
      ? (index + 1) % contentTabs.length
      : (index + contentTabs.length - 1) % contentTabs.length;
    const nextTab = contentTabs[nextIndex];
    switchTab(nextTab);
    const buttons = event.currentTarget.parentElement?.querySelectorAll<HTMLButtonElement>('[role="tab"]');
    buttons?.[nextIndex]?.focus();
  };

  const openEncoding = () => {
    setShowMobileUtilities(false);
    setShowEncoding(true);
  };

  const openVariables = () => {
    setShowMobileUtilities(false);
    setShowVariables(true);
  };

  const openClientDownloads = () => {
    setShowMobileUtilities(false);
    onOpenClientDownloads();
  };

  useEffect(() => {
    if (!showMobileUtilities) return;

    const closeOnOutsidePointer = (event: MouseEvent) => {
      const target = event.target as Node;
      if (!mobileUtilitiesRef.current?.contains(target) && !mobileUtilitiesButtonRef.current?.contains(target)) {
        setShowMobileUtilities(false);
      }
    };
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return;
      setShowMobileUtilities(false);
      mobileUtilitiesButtonRef.current?.focus();
    };

    document.addEventListener('mousedown', closeOnOutsidePointer);
    document.addEventListener('keydown', closeOnEscape);
    return () => {
      document.removeEventListener('mousedown', closeOnOutsidePointer);
      document.removeEventListener('keydown', closeOnEscape);
    };
  }, [showMobileUtilities]);

  useEffect(() => {
    if (!showVariables) return;

    const closeVariables = (event: MouseEvent) => {
      const target = event.target as Node;
      if (!variablesPanelRef.current?.contains(target) && !variablesToggleRef.current?.contains(target)) {
        setShowVariables(false);
      }
    };
    const closeVariablesOnEscape = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return;
      setShowVariables(false);
      (variablesToggleRef.current || mobileUtilitiesButtonRef.current)?.focus();
    };
    document.addEventListener('mousedown', closeVariables);
    document.addEventListener('keydown', closeVariablesOnEscape);
    return () => {
      document.removeEventListener('mousedown', closeVariables);
      document.removeEventListener('keydown', closeVariablesOnEscape);
    };
  }, [showVariables]);

  useEffect(() => {
    if (!showEncoding) return;

    const activeElement = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    previousFocus.current = activeElement && activeElement !== document.body
      ? activeElement
      : mobileUtilitiesButtonRef.current;
    const dialog = encodingDialogRef.current;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';

    const focusDialog = window.requestAnimationFrame(() => {
      const firstFocusable = dialog?.querySelector<HTMLElement>(focusableSelector);
      (firstFocusable || dialog)?.focus();
    });
    const handleDialogKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.preventDefault();
        setShowEncoding(false);
        return;
      }
      if (event.key !== 'Tab' || !dialog) return;

      const focusable = Array.from(dialog.querySelectorAll<HTMLElement>(focusableSelector))
        .filter(element => element.offsetParent !== null);
      if (!focusable.length) {
        event.preventDefault();
        dialog.focus();
        return;
      }
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };

    document.addEventListener('keydown', handleDialogKeyDown);
    return () => {
      window.cancelAnimationFrame(focusDialog);
      document.removeEventListener('keydown', handleDialogKeyDown);
      document.body.style.overflow = previousOverflow;
      previousFocus.current?.focus();
    };
  }, [showEncoding]);

  return (
    <>
      <header className="header">
        <div className="header-left">
          {activeTab !== 'ctf' && (
            <button
              className="menu-toggle"
              type="button"
              onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
              aria-label={sidebarCollapsed ? '打开分类导航' : '收起分类导航'}
              aria-controls="primary-navigation"
              aria-expanded={!sidebarCollapsed}
            >
              <span aria-hidden="true">☰</span>
            </button>
          )}
          <div className="logo">
            {settings.logoUrl ? (
              <img className="logo-image" src={settings.logoUrl} alt="" />
            ) : (
              <span className="logo-icon">{settings.logoIcon || '⚡'}</span>
            )}
            <span className="logo-text">{getText(settings.siteTitle, language) || t('header.logo', language)}</span>
            <span className="logo-subtitle">{getText(settings.siteSubtitle, language) || t('header.subtitle', language)}</span>
            {settings.projectUrl && (
              <a
                href={settings.projectUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="github-link"
                title="GitHub"
              >
                <svg viewBox="0 0 16 16" width="18" height="18" fill="currentColor"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/></svg>
              </a>
            )}
            {settings.xeyeEnabled !== false && (
              <a
                href={protectedExternalLinks.xeye.href}
                target="_blank"
                rel="noopener"
                referrerPolicy="origin"
                className="xeye-link"
                title="Xeye 平台"
                aria-label="Xeye 平台"
              >
                {protectedExternalLinks.xeye.label}
              </a>
            )}
          </div>
        </div>

        <div className="header-center">
          <div className="search-box" role="search">
            <span className="search-icon" aria-hidden="true">⌕</span>
            <input
              type="search"
              name="content-search"
              className="search-input"
              placeholder={t('header.searchPlaceholder', language)}
              aria-label={t('header.searchPlaceholder', language)}
              value={searchQuery}
              onChange={(event) => {
                setActiveView('workspace');
                setSearchQuery(event.target.value);
              }}
            />
            {searchQuery && (
              <button type="button" className="search-clear" onClick={() => setSearchQuery('')} aria-label="清除搜索">×</button>
            )}
          </div>
          <div className="tab-switcher" role="tablist" aria-label="内容类型">
            <button
              type="button"
              role="tab"
              aria-selected={activeTab === 'payloads'}
              aria-controls="main-content"
              tabIndex={activeTab === 'payloads' ? 0 : -1}
              className={`tab-btn ${activeTab === 'payloads' ? 'active' : ''}`}
              onClick={() => switchTab('payloads')}
              onKeyDown={event => handleTabKeyDown(event, 'payloads')}
            >
              {t('header.tabPayloads', language)}
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={activeTab === 'tools'}
              aria-controls="main-content"
              tabIndex={activeTab === 'tools' ? 0 : -1}
              className={`tab-btn ${activeTab === 'tools' ? 'active' : ''}`}
              onClick={() => switchTab('tools')}
              onKeyDown={event => handleTabKeyDown(event, 'tools')}
            >
              {t('header.tabTools', language)}
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={activeTab === 'ctf'}
              aria-controls="main-content"
              tabIndex={activeTab === 'ctf' ? 0 : -1}
              className={`tab-btn ${activeTab === 'ctf' ? 'active' : ''}`}
              onClick={() => switchTab('ctf')}
              onKeyDown={event => handleTabKeyDown(event, 'ctf')}
            >
              {t('header.tabCtf', language)}
            </button>
          </div>
        </div>

        <div className="header-right">
          <button
            className="theme-toggle"
            type="button"
            onClick={toggleTheme}
            title={theme === 'dark' ? t('header.themeToggleDark', language) : t('header.themeToggleLight', language)}
            aria-label={theme === 'dark' ? t('header.themeToggleDark', language) : t('header.themeToggleLight', language)}
          >
            <span aria-hidden="true">{theme === 'dark' ? '☀' : '☾'}</span>
          </button>

          <button
            ref={mobileUtilitiesButtonRef}
            className="mobile-utilities-toggle"
            type="button"
            onClick={() => setShowMobileUtilities(previous => !previous)}
            aria-label="更多工具"
            aria-controls="mobile-utilities-menu"
            aria-expanded={showMobileUtilities}
          >
            <span aria-hidden="true">⋮</span>
          </button>

          {activeTab !== 'ctf' && (
            <button
              className="encoding-toggle"
              type="button"
              onClick={openEncoding}
              title={t('header.encodingTitle', language)}
            >
              {t('header.encoding', language)}
            </button>
          )}

          {showClientDownloads && (
            <button
              className="client-download-link"
              type="button"
              onClick={openClientDownloads}
              title={clientDownloadTitle}
              aria-label={clientDownloadTitle}
            >
              <span>{clientDownloadLabel}</span>
              {clientDownloadCount ? <small>{clientDownloadCount} builds</small> : clientDownloadSize && <small>{clientDownloadSize}</small>}
            </button>
          )}

          <div className="mode-switcher" role="group" aria-label={t('header.modeLabel', language)}>
            <span className="mode-label">{t('header.modeLabel', language)}</span>
            <button 
              type="button"
              aria-pressed={bypassMode === 'normal'}
              className={`mode-btn ${bypassMode === 'normal' ? 'active' : ''}`}
              onClick={() => setBypassMode('normal')}
            >
              {t('header.modeNormal', language)}
            </button>
            <button 
              type="button"
              aria-pressed={bypassMode === 'waf'}
              className={`mode-btn ${bypassMode === 'waf' ? 'active warning' : ''}`}
              onClick={() => setBypassMode('waf')}
            >
              {t('header.modeWaf', language)}
            </button>
          </div>

          <div className="variables-dropdown">
            <button 
              ref={variablesToggleRef}
              type="button"
              className="variables-toggle"
              onClick={() => setShowVariables(!showVariables)}
              aria-expanded={showVariables}
              aria-controls="variables-panel"
            >
              {t('header.variables', language)}
            </button>
            {showVariables && (
              <div ref={variablesPanelRef} className="variables-panel" id="variables-panel">
                <div className="variables-header">
                  <div>
                    <h3>{t('header.variablesTitle', language)}</h3>
                    <span className="variables-hint">{t('header.variablesHint', language)}</span>
                  </div>
                  <button type="button" className="variables-close" onClick={() => setShowVariables(false)} aria-label="关闭全局变量">×</button>
                </div>
                <div className="variables-tools">
                  <input
                    type="search"
                    name="variable-search"
                    value={variableSearch}
                    onChange={event => setVariableSearch(event.target.value)}
                    placeholder={language === 'zh' ? '搜索变量、说明或当前值' : 'Search variable, note, or value'}
                    className="variables-search"
                  />
                </div>
                <div className="variables-list">
                  {variableGroups.length ? variableGroups.map(({ group, variables }) => {
                    const collapsed = collapsedVariableGroups.has(group) && !variableSearch.trim();
                    const groupLabel = getText(variableGroupLabels[group] || variableGroupLabels.other, language);
                    return (
                      <section key={group} className="variable-group">
                        <button
                          type="button"
                          className="variable-group-toggle"
                          onClick={() => toggleVariableGroup(group)}
                          aria-expanded={!collapsed}
                        >
                          <span className={`variable-group-icon ${collapsed ? '' : 'expanded'}`}>▶</span>
                          <span>{groupLabel}</span>
                          <small>{variables.length}</small>
                        </button>
                        {!collapsed && (
                          <div className="variable-group-body">
                            {variables.map(variable => (
                              <div key={variable.key} className={`variable-item ${pinnedVariableKeys.has(variable.key) ? 'pinned' : ''}`}>
                                <div className="variable-info">
                                  <span className="variable-key">{`{${variable.key}}`}</span>
                                  <span className="variable-desc">{getText(variable.description, language)}</span>
                                </div>
                                <input
                                  type="text"
                                  value={variable.value}
                                  onChange={(e) => updateVariable(variable.key, e.target.value)}
                                  className="variable-input"
                                  aria-label={`${variable.key}：${getText(variable.description, language)}`}
                                />
                              </div>
                            ))}
                          </div>
                        )}
                      </section>
                    );
                  }) : (
                    <div className="variables-empty">
                      <strong>{language === 'zh' ? '没有匹配变量' : 'No variables found'}</strong>
                      <span>{language === 'zh' ? '换个关键词，或清空搜索。' : 'Try another keyword or clear the search.'}</span>
                    </div>
                  )}
                </div>
                <div className="variables-footer">
                  {language === 'zh'
                    ? '后台新增 Payload 或工具命令时，写入 {URL}、{COOKIE}、{ATTACKER_IP} 等占位符即可自动联动。'
                    : 'Admin-created payloads and tool commands can use placeholders such as {URL}, {COOKIE}, and {ATTACKER_IP}.'}
                </div>
              </div>
            )}
          </div>
        </div>

        {showMobileUtilities && (
          <div ref={mobileUtilitiesRef} className="mobile-utilities-menu" id="mobile-utilities-menu" aria-label="更多工具">
            <div className="mobile-utilities-mode" role="group" aria-label={t('header.modeLabel', language)}>
              <span>{t('header.modeLabel', language)}</span>
              <div>
                <button
                  type="button"
                  className={bypassMode === 'normal' ? 'active' : ''}
                  aria-pressed={bypassMode === 'normal'}
                  onClick={() => setBypassMode('normal')}
                >
                  {t('header.modeNormal', language)}
                </button>
                <button
                  type="button"
                  className={bypassMode === 'waf' ? 'active warning' : ''}
                  aria-pressed={bypassMode === 'waf'}
                  onClick={() => setBypassMode('waf')}
                >
                  {t('header.modeWaf', language)}
                </button>
              </div>
            </div>
            <button type="button" onClick={openVariables}>{t('header.variables', language)}</button>
            {activeTab !== 'ctf' && (
              <button type="button" onClick={openEncoding}>{t('header.encoding', language)}</button>
            )}
            {showClientDownloads && (
              <button type="button" onClick={openClientDownloads}>{clientDownloadLabel}</button>
            )}
          </div>
        )}

        

      </header>

      {showEncoding && (
        <div
          className="encoding-modal-overlay"
          onMouseDown={event => {
            if (event.target === event.currentTarget) setShowEncoding(false);
          }}
        >
          <div
            ref={encodingDialogRef}
            className="encoding-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby={encodingTitleId}
            tabIndex={-1}
          >
            <div className="encoding-modal-header">
              <h2 id={encodingTitleId}>{t('header.encodingModalTitle', language)}</h2>
              <button type="button" className="close-btn" onClick={() => setShowEncoding(false)} aria-label="关闭编解码工具">×</button>
            </div>
            <div className="encoding-modal-body">
              {encodingTools}
            </div>
            

          </div>
        </div>
      )}
    </>
  );
}

export default Header;
