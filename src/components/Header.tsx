import { useEffect, useId, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { useAppContext } from '../appContext';
import { t, getText } from '../i18n';
import { protectedExternalLinks } from '../protectedLinks';
import type { PublicClientBuildInfo } from '../types';

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
  const {
    globalVariables,
    setGlobalVariables,
    bypassMode,
    setBypassMode,
    activeTab,
    setActiveTab,
    setActiveView,
    setSelectedPayloadId,
    setSelectedToolId,
    theme,
    setTheme,
    searchQuery,
    setSearchQuery,
    settings,
    language,
  } = useAppContext();
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

  const switchTab = (tab: 'payloads' | 'tools') => {
    setActiveView('workspace');
    setActiveTab(tab);
    setSelectedPayloadId(null);
    setSelectedToolId(null);
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
              className={`tab-btn ${activeTab === 'payloads' ? 'active' : ''}`}
              onClick={() => switchTab('payloads')}
            >
              {t('header.tabPayloads', language)}
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={activeTab === 'tools'}
              className={`tab-btn ${activeTab === 'tools' ? 'active' : ''}`}
              onClick={() => switchTab('tools')}
            >
              {t('header.tabTools', language)}
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

          <button 
            className="encoding-toggle"
            type="button"
            onClick={openEncoding}
            title={t('header.encodingTitle', language)}
          >
            {t('header.encoding', language)}
          </button>

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
            <button type="button" onClick={openEncoding}>{t('header.encoding', language)}</button>
            {showClientDownloads && (
              <button type="button" onClick={openClientDownloads}>{clientDownloadLabel}</button>
            )}
          </div>
        )}

        <style>{`
          .header {
            height: var(--app-header-height);
            flex: 0 0 var(--app-header-height);
            background: linear-gradient(180deg, var(--bg-secondary) 0%, var(--bg-primary) 100%);
            border-bottom: 1px solid var(--border-color);
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0 20px;
            position: relative;
            z-index: 100;
          }

          .header::before {
            content: '';
            position: absolute;
            bottom: 0;
            left: 0;
            right: 0;
            height: 1px;
            background: linear-gradient(90deg, transparent, var(--neon-cyan), transparent);
          }

          .header-left {
            display: flex;
            align-items: center;
            gap: 16px;
            min-width: 0;
          }

          .menu-toggle {
            background: transparent;
            border: 1px solid var(--border-color);
            color: var(--text-secondary);
            width: 44px;
            height: 44px;
            border-radius: 4px;
            font-size: 18px;
            cursor: pointer;
            transition: all var(--transition-fast);
          }

          .menu-toggle:hover {
            border-color: var(--neon-cyan);
            color: var(--neon-cyan);
          }

          .logo {
            display: flex;
            align-items: center;
            gap: 10px;
            min-width: 0;
            max-width: 100%;
          }

          .logo-icon {
            font-size: 28px;
            filter: drop-shadow(0 0 10px var(--neon-cyan));
          }

          .logo-image {
            width: 32px;
            height: 32px;
            flex: 0 0 32px;
            object-fit: contain;
            border-radius: 6px;
            background: rgba(255, 255, 255, 0.05);
            filter: drop-shadow(0 0 10px var(--neon-cyan));
          }

          .logo-text {
            min-width: 0;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            font-family: var(--font-display);
            font-size: 20px;
            font-weight: 700;
            letter-spacing: 3px;
            background: var(--gradient-cyber);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
          }

          .logo-subtitle {
            font-size: 11px;
            color: var(--text-muted);
            letter-spacing: 1px;
            margin-left: 8px;
            padding-left: 8px;
            border-left: 1px solid var(--border-color);
          }

          .github-link {
            display: flex;
            align-items: center;
            justify-content: center;
            margin-left: 10px;
            color: var(--text-muted);
            transition: color var(--transition-fast);
          }

          .github-link:hover {
            color: var(--neon-cyan);
          }

          .xeye-link {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            min-height: 24px;
            margin-left: 2px;
            padding: 0 8px;
            border: 1px solid rgba(0, 240, 255, 0.28);
            border-radius: 6px;
            color: var(--neon-cyan);
            font-family: var(--font-display);
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0;
            text-decoration: none;
            background: rgba(0, 240, 255, 0.06);
            transition: all var(--transition-fast);
          }

          .xeye-link:hover {
            color: var(--bg-primary);
            background: var(--neon-cyan);
            box-shadow: 0 0 14px rgba(0, 240, 255, 0.28);
          }

          .client-download-link,
          .mobile-client-download {
            align-items: center;
            justify-content: center;
            min-height: 34px;
            border: 1px solid rgba(0, 255, 65, 0.32);
            border-radius: 6px;
            color: var(--neon-green);
            background: rgba(0, 255, 65, 0.07);
            font-family: var(--font-display);
            font-weight: 700;
            letter-spacing: 0;
            text-decoration: none;
            white-space: nowrap;
            transition: all var(--transition-fast);
          }

          .client-download-link {
            display: inline-flex;
            gap: 6px;
            padding: 0 10px;
            font-size: 12px;
          }

          .client-download-link small {
            color: var(--text-muted);
            font-family: var(--font-mono);
            font-size: 10px;
            font-weight: 500;
          }

          .mobile-client-download {
            display: none;
            padding: 0 8px;
            font-size: 12px;
          }

          .client-download-link:hover,
          .mobile-client-download:hover {
            color: var(--bg-primary);
            background: var(--neon-green);
            box-shadow: 0 0 14px rgba(0, 255, 65, 0.22);
          }

          .client-download-link:hover small {
            color: var(--bg-primary);
          }

          .header-center {
            flex: 1;
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 12px;
            min-width: 0;
          }

          /* ===== Search Box ===== */
          .search-box {
            display: flex;
            align-items: center;
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 0 10px;
            width: 260px;
            transition: all var(--transition-fast);
          }

          .search-box:focus-within {
            border-color: var(--neon-cyan);
            box-shadow: 0 0 12px rgba(0, 240, 255, 0.15);
          }

          .search-icon {
            font-size: 14px;
            margin-right: 6px;
            opacity: 0.6;
          }

          .search-input {
            background: transparent;
            border: none;
            color: var(--text-primary);
            font-size: 13px;
            padding: 8px 0;
            flex: 1;
            outline: none;
            width: 100%;
          }

          .search-input::placeholder {
            color: var(--text-muted);
            font-size: 12px;
          }

          .search-input:focus {
            box-shadow: none;
            border: none;
          }

          .search-clear {
            background: transparent;
            border: none;
            color: var(--text-muted);
            font-size: 18px;
            cursor: pointer;
            padding: 0 4px;
            transition: color var(--transition-fast);
          }

          .search-clear:hover {
            color: var(--neon-red);
          }

          .tab-switcher {
            display: flex;
            align-items: center;
            background: var(--bg-tertiary);
            border-radius: 6px;
            padding: 4px;
            border: 1px solid var(--border-color);
            min-height: 44px;
            overflow: hidden;
          }

          .tab-btn {
            display: flex;
            align-items: center;
            justify-content: center;
            background: transparent;
            border: none;
            color: var(--text-secondary);
            min-height: 36px;
            padding: 0 18px;
            border-radius: 4px;
            font-family: var(--font-body);
            font-size: 13px;
            line-height: 1;
            min-width: 0;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            cursor: pointer;
            transition: all var(--transition-fast);
          }

          .tab-btn:hover {
            color: var(--text-primary);
          }

          .tab-btn.active {
            background: var(--neon-cyan);
            color: var(--bg-primary);
            font-weight: 600;
          }

          .header-right {
            display: flex;
            align-items: center;
            gap: 12px;
            min-width: 0;
          }

          /* ===== Theme Toggle ===== */
          .lang-toggle {
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            color: var(--text-secondary);
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 600;
            cursor: pointer;
            transition: all var(--transition-fast);
          }

          .lang-toggle:hover {
            border-color: var(--neon-green);
            color: var(--neon-green);
            box-shadow: 0 0 12px rgba(0, 255, 136, 0.2);
          }

          .theme-toggle {
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            width: 44px;
            height: 44px;
            border-radius: 6px;
            font-size: 18px;
            cursor: pointer;
            transition: all var(--transition-fast);
            display: flex;
            align-items: center;
            justify-content: center;
          }

          .theme-toggle:hover {
            border-color: var(--neon-yellow);
            box-shadow: 0 0 12px rgba(255, 255, 0, 0.2);
            transform: scale(1.1);
          }

          .encoding-toggle {
            background: rgba(139, 0, 255, 0.1);
            border: 1px solid var(--neon-purple);
            color: var(--neon-purple);
            padding: 8px 14px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 500;
            cursor: pointer;
            transition: all var(--transition-fast);
          }

          .encoding-toggle:hover {
            background: rgba(139, 0, 255, 0.2);
            box-shadow: 0 0 15px rgba(139, 0, 255, 0.3);
          }

          .mode-switcher {
            display: flex;
            align-items: center;
            gap: 8px;
            background: var(--bg-tertiary);
            padding: 4px 12px;
            border-radius: 6px;
            border: 1px solid var(--border-color);
          }

          .mobile-mode-switcher {
            display: none;
            align-items: center;
            gap: 6px;
            background: var(--bg-tertiary);
            padding: 4px;
            border-radius: 6px;
            border: 1px solid var(--border-color);
          }

          .mobile-encoding-toggle {
            display: none;
            align-items: center;
            justify-content: center;
            min-height: 38px;
            padding: 0 10px;
            border: 1px solid var(--neon-purple);
            border-radius: 6px;
            background: rgba(139, 0, 255, 0.1);
            color: var(--neon-purple);
            font-size: 12px;
            font-weight: 700;
            white-space: nowrap;
          }

          .header .mode-label {
            font-size: 12px;
            color: var(--text-muted);
          }

          .header .mode-btn {
            background: transparent;
            border: 1px solid transparent;
            color: var(--text-secondary);
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 12px;
            min-width: 0;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            cursor: pointer;
            transition: all var(--transition-fast);
          }

          .header .mode-btn:hover {
            color: var(--text-primary);
          }

          .header .mode-btn.active {
            background: rgba(0, 240, 255, 0.1);
            border-color: var(--neon-cyan);
            color: var(--neon-cyan);
          }

          .header .mode-btn.active.warning {
            background: rgba(255, 102, 0, 0.1);
            border-color: var(--neon-orange);
            color: var(--neon-orange);
          }

          .header .mode-btn.active.danger {
            background: rgba(255, 0, 85, 0.1);
            border-color: var(--neon-red);
            color: var(--neon-red);
          }

          .variables-dropdown {
            position: relative;
          }

          .variables-toggle {
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            color: var(--text-secondary);
            padding: 8px 16px;
            border-radius: 6px;
            font-size: 13px;
            white-space: nowrap;
            cursor: pointer;
            transition: all var(--transition-fast);
          }

          .variables-toggle:hover {
            border-color: var(--neon-cyan);
            color: var(--neon-cyan);
          }

          .variables-panel {
            position: absolute;
            top: calc(100% + 8px);
            right: 0;
            width: min(720px, calc(100vw - 24px));
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            box-shadow: var(--shadow-card);
            z-index: 1000;
            overflow: hidden;
          }

          .variables-header {
            display: flex;
            align-items: flex-start;
            justify-content: space-between;
            gap: 12px;
            padding: 16px;
            border-bottom: 1px solid var(--border-color);
          }

          .variables-close {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 44px;
            height: 44px;
            margin: -6px -6px -6px 0;
            border-radius: 6px;
            background: transparent;
            color: var(--text-secondary);
            font-size: 22px;
          }

          .variables-close:hover {
            background: var(--bg-hover);
            color: var(--text-primary);
          }

          .variables-header h3 {
            font-size: 14px;
            font-weight: 600;
            margin-bottom: 4px;
          }

          .variables-hint {
            font-size: 11px;
            color: var(--text-muted);
            line-height: 1.5;
          }

          .variables-tools {
            padding: 12px 14px;
            border-bottom: 1px solid var(--border-color);
            background: rgba(255, 255, 255, 0.02);
          }

          .variables-search {
            width: 100%;
            min-height: 36px;
            padding: 8px 10px;
            font-size: 12px;
          }

          .variables-search::placeholder {
            color: var(--text-muted);
          }

          .variables-list {
            max-height: min(520px, calc(100dvh - var(--app-header-height) - 190px));
            overflow-y: auto;
          }

          .variable-group {
            border-bottom: 1px solid var(--border-color);
          }

          .variable-group:last-child {
            border-bottom: none;
          }

          .variable-group-toggle {
            width: 100%;
            min-height: 38px;
            display: grid;
            grid-template-columns: 16px minmax(0, 1fr) auto;
            align-items: center;
            gap: 8px;
            padding: 9px 14px;
            background: rgba(0, 229, 255, 0.05);
            border: 0;
            color: var(--text-primary);
            text-align: left;
            cursor: pointer;
          }

          .variable-group-toggle span:nth-child(2) {
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            font-size: 12px;
            font-weight: 700;
          }

          .variable-group-toggle small {
            min-width: 24px;
            padding: 2px 8px;
            border-radius: 999px;
            background: var(--bg-tertiary);
            color: var(--text-muted);
            text-align: center;
            font-size: 11px;
          }

          .variable-group-icon {
            color: var(--neon-cyan);
            font-size: 10px;
            transition: transform var(--transition-fast);
          }

          .variable-group-icon.expanded {
            transform: rotate(90deg);
          }

          .variable-group-body {
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
          }

          .variable-item {
            display: grid;
            grid-template-columns: minmax(0, 1fr);
            align-items: center;
            gap: 8px;
            padding: 12px 14px;
            border-bottom: 1px solid var(--border-color);
            border-right: 1px solid var(--border-color);
            min-width: 0;
          }

          .variable-item:nth-child(2n) {
            border-right: none;
          }

          .variable-item.pinned {
            background: rgba(0, 229, 255, 0.035);
          }

          .variable-item:last-child {
            border-bottom: none;
          }

          .variable-info {
            display: flex;
            flex-direction: column;
            gap: 2px;
            min-width: 0;
          }

          .variable-key {
            font-family: var(--font-mono);
            font-size: 12px;
            color: var(--neon-cyan);
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
          }

          .variable-desc {
            font-size: 11px;
            color: var(--text-muted);
            line-height: 1.35;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
          }

          .variable-input {
            width: 100%;
            min-width: 0;
            padding: 6px 10px;
            font-size: 12px;
            font-family: var(--font-mono);
          }

          .variables-empty,
          .variables-footer {
            padding: 14px;
            color: var(--text-muted);
            font-size: 11px;
            line-height: 1.5;
          }

          .variables-empty {
            display: flex;
            flex-direction: column;
            gap: 4px;
            text-align: center;
          }

          .variables-footer {
            border-top: 1px solid var(--border-color);
            background: rgba(255, 255, 255, 0.02);
          }

          @media (max-width: 1280px) {
            .header {
              gap: 12px;
              padding: 0 12px;
            }

            .header-center {
              justify-content: flex-start;
            }

            .search-box {
              width: 220px;
            }

            .search-box:focus-within {
              width: 220px;
            }

            .header .mode-label,
            .logo-subtitle {
              display: none;
            }
          }

          @media (max-width: 1100px) and (min-width: 901px) {
            .header {
              display: grid;
              grid-template-columns: minmax(0, 1fr) auto;
              grid-template-rows: 40px 42px;
              align-content: center;
              align-items: center;
              gap: 8px 12px;
              padding: 10px 14px;
            }

            .header-left {
              grid-column: 1 / 2;
              grid-row: 1;
              min-width: 0;
            }

            .header-center {
              grid-column: 1 / -1;
              grid-row: 2;
              display: grid;
              grid-template-columns: minmax(260px, 1fr) minmax(188px, auto) minmax(170px, auto) auto;
              align-items: center;
              gap: 8px;
            }

            .header-right {
              grid-column: 2 / 3;
              grid-row: 1;
              gap: 8px;
              justify-content: flex-end;
            }

            .search-box,
            .search-box:focus-within {
              width: 100%;
              min-width: 0;
            }

            .tab-switcher {
              width: 100%;
              min-width: 188px;
            }

            .tab-btn {
              flex: 1 1 0;
              min-width: 86px;
              padding: 0 12px;
              overflow: visible;
              text-overflow: clip;
            }

            .encoding-toggle,
            .client-download-link,
            .mode-switcher {
              display: none;
            }

            .mobile-mode-switcher,
            .mobile-encoding-toggle,
            .mobile-client-download {
              display: flex;
            }

            .mobile-mode-switcher {
              min-width: 170px;
            }

            .mobile-mode-switcher .mode-btn {
              flex: 1 1 0;
            }
          }

          @media (max-width: 900px) {
            .header {
              display: grid;
              grid-template-columns: minmax(0, 1fr) auto;
              grid-template-rows: 40px 42px;
              align-content: center;
              align-items: center;
              gap: 8px;
              padding: 10px 12px;
            }

            .header-left {
              grid-column: 1 / 2;
              grid-row: 1;
              min-width: 0;
              gap: 10px;
            }

            .header-center {
              grid-column: 1 / -1;
              grid-row: 2;
              display: grid;
              grid-template-columns: minmax(0, 1fr) auto auto auto auto;
              align-items: center;
              gap: 8px;
            }

            .header-right {
              gap: 8px;
              grid-column: 2 / 3;
              grid-row: 1;
              justify-content: flex-end;
            }

            .logo-text {
              font-size: 16px;
              letter-spacing: 0;
            }

            .github-link,
            .xeye-link,
            .client-download-link,
            .encoding-toggle,
            .mode-switcher {
              display: none;
            }

            .mobile-mode-switcher {
              display: flex;
              min-width: 132px;
            }

            .mobile-encoding-toggle,
            .mobile-client-download {
              display: flex;
            }

            .search-box,
            .search-box:focus-within {
              flex: 1;
              width: auto;
              min-width: 0;
            }

            .tab-switcher {
              min-width: 136px;
            }

            .tab-btn {
              padding: 0 10px;
              white-space: nowrap;
            }

            .variables-panel {
              position: fixed;
              top: var(--app-header-height);
              right: 12px;
              left: 12px;
              width: auto;
              max-height: calc(100dvh - var(--app-header-height) - 20px);
              overflow: auto;
            }

            .variable-group-body {
              grid-template-columns: 1fr;
            }

            .variable-item {
              border-right: none;
            }
          }

          @media (max-width: 520px) {
            .header {
              grid-template-columns: minmax(0, 1fr) auto;
              grid-template-rows: 36px auto;
              padding: 8px 10px;
              gap: 7px;
            }

            .header-center {
              grid-template-columns: minmax(0, 1fr) minmax(64px, auto) minmax(50px, auto);
              grid-template-rows: 38px 38px 38px;
              align-items: stretch;
              gap: 7px;
            }

            .search-box,
            .search-box:focus-within {
              grid-column: 1 / -1;
              width: 100%;
              min-height: 38px;
            }

            .tab-switcher {
              grid-column: 1 / -1;
              min-width: 0;
              width: 100%;
            }

            .mobile-mode-switcher {
              grid-column: 1 / 2;
              min-width: 0;
              width: 100%;
            }

            .mobile-encoding-toggle {
              grid-column: 2 / 3;
              width: 100%;
              min-width: 0;
              padding: 0 6px;
            }

            .mobile-client-download {
              grid-column: 3 / 4;
              width: 100%;
            }

            .tab-btn {
              flex: 1;
              text-align: center;
              overflow: visible;
              text-overflow: clip;
            }

            .mobile-mode-switcher .mode-btn {
              flex: 1;
              min-height: 30px;
              padding: 4px 6px;
              overflow: visible;
              text-overflow: clip;
            }

            .lang-toggle,
            .variables-toggle {
              padding: 6px 8px;
              font-size: 11px;
            }

            .lang-toggle {
              width: 46px;
              overflow: hidden;
              text-overflow: clip;
            }

            .variables-toggle {
              width: 56px;
              overflow: hidden;
              text-overflow: clip;
            }

            .header-right {
              gap: 6px;
            }

            .theme-toggle,
            .menu-toggle {
              width: 44px;
              height: 44px;
            }

            .search-input::placeholder {
              color: var(--text-muted);
              font-size: 11px;
            }

            .variables-panel {
              top: var(--app-header-height);
              max-height: calc(100dvh - var(--app-header-height) - 16px);
            }

            .variables-header {
              padding: 12px;
            }

            .variables-tools {
              padding: 10px 12px;
            }

            .variables-list {
              max-height: calc(100dvh - var(--app-header-height) - 190px);
            }

            .variable-group-toggle {
              min-height: 36px;
              padding: 8px 12px;
            }

            .variable-item {
              padding: 10px 12px;
            }

            .variable-desc {
              white-space: normal;
              display: -webkit-box;
              -webkit-line-clamp: 2;
              -webkit-box-orient: vertical;
            }

            .variable-input {
              min-height: 34px;
              font-size: 12px;
            }
          }

          @media (max-width: 360px) {
            .header {
              grid-template-rows: 36px auto;
              padding-left: 8px;
              padding-right: 8px;
            }

            .logo-icon,
            .logo-image {
              width: 28px;
              height: 28px;
              flex-basis: 28px;
              font-size: 24px;
            }

            .logo-text {
              font-size: 14px;
            }

            .lang-toggle,
            .variables-toggle {
              overflow: hidden;
              text-overflow: ellipsis;
            }

            .variables-toggle {
              width: 56px;
              max-width: none;
              overflow: visible;
              text-overflow: clip;
            }

            .mobile-encoding-toggle {
              width: 100%;
              font-size: 11px;
            }

            .mobile-client-download {
              font-size: 11px;
              min-height: 34px;
            }

            .mobile-mode-switcher .mode-btn,
            .tab-btn {
              font-size: 11px;
              padding-left: 5px;
              padding-right: 5px;
            }
          }

          @media (max-width: 340px) {
            .logo-text {
              display: none;
            }
          }

          /* Production shell: one desktop row and exactly two compact mobile rows. */
          .header {
            background: var(--bg-secondary);
          }

          .header::before {
            display: none;
          }

          .logo-text,
          .logo-subtitle {
            letter-spacing: 0;
          }

          .mobile-utilities-toggle,
          .mobile-utilities-menu {
            display: none;
          }

          .header button,
          .header a {
            flex-shrink: 0;
          }

          @media (max-width: 1100px) {
            .header {
              height: var(--app-header-height);
              grid-template-columns: minmax(0, 1fr) auto;
              grid-template-rows: 44px 44px;
              align-content: center;
              gap: 8px 10px;
              padding: 6px 10px;
            }

            .header-left {
              grid-column: 1;
              grid-row: 1;
              gap: 8px;
            }

            .header-center {
              grid-column: 1 / -1;
              grid-row: 2;
              display: grid;
              grid-template-columns: minmax(0, 1fr) minmax(140px, 42vw);
              grid-template-rows: 44px;
              gap: 8px;
              min-width: 0;
            }

            .header-right {
              grid-column: 2;
              grid-row: 1;
              display: flex;
              gap: 6px;
            }

            .menu-toggle,
            .theme-toggle,
            .mobile-utilities-toggle,
            .search-box,
            .tab-switcher,
            .tab-btn {
              min-height: 44px;
            }

            .menu-toggle,
            .theme-toggle,
            .mobile-utilities-toggle {
              width: 44px;
              height: 44px;
            }

            .mobile-utilities-toggle {
              display: inline-flex;
              align-items: center;
              justify-content: center;
              border: 1px solid var(--border-color);
              border-radius: 6px;
              background: var(--bg-tertiary);
              color: var(--text-primary);
              font-size: 22px;
            }

            .encoding-toggle,
            .client-download-link,
            .mode-switcher,
            .variables-toggle,
            .github-link,
            .xeye-link,
            .logo-subtitle {
              display: none;
            }

            .variables-dropdown {
              width: 0;
              height: 0;
            }

            .search-box,
            .search-box:focus-within {
              grid-column: auto;
              grid-row: auto;
              width: 100%;
              min-width: 0;
              height: 44px;
              border: 0;
              box-shadow: inset 0 0 0 1px var(--border-color);
            }

            .search-box:focus-within {
              box-shadow: inset 0 0 0 1px var(--neon-cyan), 0 0 12px rgba(0, 240, 255, 0.15);
            }

            .search-input {
              min-width: 0;
              height: 44px;
              padding-right: 42px;
            }

            .search-clear {
              width: 44px;
              height: 44px;
              right: 0;
            }

            .tab-switcher {
              grid-column: auto;
              grid-row: auto;
              width: 100%;
              min-width: 0;
              height: 44px;
            }

            .tab-btn {
              flex: 1 1 0;
              min-width: 0;
              padding: 0 8px;
              overflow: hidden;
              text-overflow: ellipsis;
            }

            .mobile-utilities-menu {
              position: fixed;
              top: calc(var(--app-header-height) - 2px);
              right: 10px;
              z-index: 1200;
              display: grid;
              grid-template-columns: repeat(2, minmax(0, 1fr));
              gap: 8px;
              width: min(320px, calc(100vw - 20px));
              padding: 10px;
              border: 1px solid var(--border-color);
              border-radius: 8px;
              background: var(--bg-card);
              box-shadow: var(--shadow-card);
            }

            .mobile-utilities-menu > button,
            .mobile-utilities-mode button {
              min-width: 0;
              min-height: 44px;
              padding: 8px 10px;
              border: 1px solid var(--border-color);
              border-radius: 6px;
              background: var(--bg-tertiary);
              color: var(--text-primary);
              font-weight: 700;
            }

            .mobile-utilities-mode {
              grid-column: 1 / -1;
              display: grid;
              grid-template-columns: auto minmax(0, 1fr);
              align-items: center;
              gap: 10px;
              color: var(--text-secondary);
              font-size: 12px;
            }

            .mobile-utilities-mode > div {
              display: grid;
              grid-template-columns: repeat(2, minmax(0, 1fr));
              gap: 6px;
            }

            .mobile-utilities-mode button.active {
              border-color: var(--neon-cyan);
              color: var(--neon-cyan);
              background: color-mix(in srgb, var(--neon-cyan) 10%, var(--bg-tertiary));
            }

            .mobile-utilities-mode button.warning.active {
              border-color: var(--neon-orange);
              color: var(--neon-orange);
            }

            .variables-panel {
              position: fixed;
              top: var(--app-header-height);
              right: 10px;
              left: auto;
              width: min(720px, calc(100vw - 20px));
              max-height: calc(100dvh - var(--app-header-height) - 16px);
              overflow: auto;
            }
          }

          @media (max-width: 520px) {
            .header {
              grid-template-rows: 44px 44px;
              padding: 6px 8px;
            }

            .header-center {
              grid-template-columns: minmax(0, 1fr) minmax(132px, 42vw);
              grid-template-rows: 44px;
              gap: 6px;
            }

            .search-box,
            .search-box:focus-within,
            .tab-switcher {
              grid-column: auto;
              grid-row: auto;
              min-height: 44px;
            }

            .search-icon {
              display: none;
            }

            .search-input {
              padding-left: 10px;
            }

            .tab-btn {
              min-height: 44px;
              padding-inline: 5px;
              font-size: 12px;
            }

            .logo-text {
              display: block;
              max-width: min(34vw, 126px);
              font-size: 15px;
            }

            .variables-panel {
              right: 8px;
              left: 8px;
              width: auto;
            }
          }

          @media (max-width: 340px) {
            .logo-text {
              display: none;
            }
          }
        `}</style>
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
            <style>{`
              .encoding-modal-overlay {
                position: fixed;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                background: rgba(0, 0, 0, 0.8);
                display: flex;
                align-items: center;
                justify-content: center;
                z-index: 2000;
                animation: fadeIn 0.2s ease;
              }

              @keyframes fadeIn {
                from { opacity: 0; }
                to { opacity: 1; }
              }

              .encoding-modal {
                background: var(--bg-primary);
                border: 1px solid var(--border-color);
                border-radius: 12px;
                width: 95%;
                max-width: 1100px;
                max-height: 90vh;
                overflow: hidden;
                box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
                animation: slideUp 0.3s ease;
              }

              @keyframes slideUp {
                from {
                  opacity: 0;
                  transform: translateY(20px);
                }
                to {
                  opacity: 1;
                  transform: translateY(0);
                }
              }

              .encoding-modal-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                padding: 16px 24px;
                border-bottom: 1px solid var(--border-color);
              }

              .encoding-modal-header h2 {
                font-size: 18px;
                font-weight: 600;
                color: var(--neon-purple);
              }

              .close-btn {
                background: transparent;
                border: none;
                color: var(--text-muted);
                font-size: 28px;
                cursor: pointer;
                width: 44px;
                height: 44px;
                flex: 0 0 44px;
                display: flex;
                align-items: center;
                justify-content: center;
                border-radius: 4px;
                transition: all var(--transition-fast);
              }

              .close-btn:hover {
                background: var(--bg-hover);
                color: var(--text-primary);
              }

              .encoding-modal-body {
                max-height: calc(90vh - 70px);
                overflow-y: auto;
              }

              .encoding-modal-body .encoding-tools {
                padding: 16px 24px;
              }

              .encoding-modal-body .encoding-header {
                display: none;
              }

              @media (max-width: 720px) {
                .encoding-modal-overlay {
                  align-items: stretch;
                  justify-content: stretch;
                  padding: 8px;
                }

                .encoding-modal {
                  width: 100%;
                  max-width: none;
                  max-height: calc(100dvh - 16px);
                  border-radius: 8px;
                }

                .encoding-modal-header {
                  padding: 12px 14px;
                }

                .encoding-modal-body {
                  max-height: calc(100dvh - 78px);
                }

                .encoding-modal-body .encoding-tools {
                  padding: 12px;
                }
              }

              @media (max-width: 420px) {
                .encoding-modal-overlay {
                  padding: 0;
                }

                .encoding-modal {
                  min-height: 100dvh;
                  max-height: 100dvh;
                  border-radius: 0;
                  border-left: 0;
                  border-right: 0;
                }

                .encoding-modal-body {
                  max-height: calc(100dvh - 61px);
                }
              }
            `}</style>
          </div>
        </div>
      )}
    </>
  );
}

export default Header;
