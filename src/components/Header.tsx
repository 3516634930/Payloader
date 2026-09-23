import { useCallback, useId, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { useLanguage, useNav, useSearch, useStaticData } from '../appContext';
import type { ActiveTab } from '../appContext';
import { t, getText } from '../i18n';
import { protectedExternalLinks } from '../protectedLinks';
import type { PublicClientBuildInfo } from '../types';
import { useDismissable } from './useDismissable';
import { useFocusTrap } from './useFocusTrap';
import HeaderSearch from './HeaderSearch';
import HeaderActions from './HeaderActions';
import MobileUtilitiesMenu from './MobileUtilitiesMenu';
import '../styles/header.css';

interface HeaderProps {
  sidebarCollapsed: boolean;
  setSidebarCollapsed: (collapsed: boolean) => void;
  clientBuildInfo: PublicClientBuildInfo | null;
  showClientDownloads?: boolean;
  encodingTools: ReactNode;
  onOpenClientDownloads: () => void;
}

function Header({ sidebarCollapsed, setSidebarCollapsed, clientBuildInfo, showClientDownloads = true, encodingTools, onOpenClientDownloads }: HeaderProps) {
  const { activeTab, setActiveView, setActiveTab, setSelectedPayloadId, setSelectedToolId } = useNav();
  const { searchQuery, setSearchQuery } = useSearch();
  const { settings } = useStaticData();
  const { language } = useLanguage();
  const [showVariables, setShowVariables] = useState(false);
  const [showEncoding, setShowEncoding] = useState(false);
  const [showMobileUtilities, setShowMobileUtilities] = useState(false);
  const encodingDialogRef = useRef<HTMLDivElement>(null);
  const mobileUtilitiesRef = useRef<HTMLDivElement>(null);
  const mobileUtilitiesButtonRef = useRef<HTMLButtonElement>(null);
  const variablesToggleRef = useRef<HTMLButtonElement>(null);
  const variablesPanelRef = useRef<HTMLDivElement>(null);
  const encodingTitleId = useId();
  const clientDownloadLabel = language === 'zh' ? '下载客户端' : 'Download Client';

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

  useDismissable({
    enabled: showMobileUtilities,
    containerRef: mobileUtilitiesRef,
    buttonRef: mobileUtilitiesButtonRef,
    onClose: () => setShowMobileUtilities(false),
    getEscapeFocusTarget: () => mobileUtilitiesButtonRef.current,
  });

  useDismissable({
    enabled: showVariables,
    containerRef: variablesPanelRef,
    buttonRef: variablesToggleRef,
    onClose: () => setShowVariables(false),
    getEscapeFocusTarget: () => variablesToggleRef.current || mobileUtilitiesButtonRef.current,
  });

  useFocusTrap({
    enabled: showEncoding,
    dialogRef: encodingDialogRef,
    fallbackFocusRef: mobileUtilitiesButtonRef,
    onClose: () => setShowEncoding(false),
  });

  const handleSearchChange = useCallback((value: string) => {
    setActiveView('workspace');
    setSearchQuery(value);
  }, [setActiveView, setSearchQuery]);

  const handleSearchClear = useCallback(() => setSearchQuery(''), [setSearchQuery]);

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
          <HeaderSearch value={searchQuery} onChange={handleSearchChange} onClear={handleSearchClear} />
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

        <HeaderActions
          clientBuildInfo={clientBuildInfo}
          showClientDownloads={showClientDownloads}
          clientDownloadLabel={clientDownloadLabel}
          onOpenClientDownloads={openClientDownloads}
          mobileUtilitiesButtonRef={mobileUtilitiesButtonRef}
          mobileUtilitiesOpen={showMobileUtilities}
          onToggleMobileUtilities={() => setShowMobileUtilities(previous => !previous)}
          onOpenEncoding={openEncoding}
          variablesOpen={showVariables}
          onToggleVariables={() => setShowVariables(!showVariables)}
          onCloseVariables={() => setShowVariables(false)}
          variablesToggleRef={variablesToggleRef}
          variablesPanelRef={variablesPanelRef}
        />

        {showMobileUtilities && (
          <MobileUtilitiesMenu
            mobileUtilitiesRef={mobileUtilitiesRef}
            onOpenVariables={openVariables}
            onOpenEncoding={openEncoding}
            onOpenClientDownloads={openClientDownloads}
            showClientDownloads={showClientDownloads}
            clientDownloadLabel={clientDownloadLabel}
          />
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
