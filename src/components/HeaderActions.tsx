import type { RefObject } from 'react';
import { useLanguage, useNav, useSession } from '../appContext';
import { t } from '../i18n';
import type { PublicClientBuildInfo } from '../types';
import VariablesMenu from './VariablesMenu';

const formatDownloadSize = (size: number) => {
  if (!Number.isFinite(size) || size <= 0) return '';
  if (size >= 1024 * 1024) return `${(size / 1024 / 1024).toFixed(1)} MB`;
  if (size >= 1024) return `${(size / 1024).toFixed(0)} KB`;
  return `${Math.round(size)} B`;
};

interface HeaderActionsProps {
  clientBuildInfo: PublicClientBuildInfo | null;
  showClientDownloads: boolean;
  clientDownloadLabel: string;
  onOpenClientDownloads: () => void;
  mobileUtilitiesButtonRef: RefObject<HTMLButtonElement | null>;
  mobileUtilitiesOpen: boolean;
  onToggleMobileUtilities: () => void;
  onOpenEncoding: () => void;
  variablesOpen: boolean;
  onToggleVariables: () => void;
  onCloseVariables: () => void;
  variablesToggleRef: RefObject<HTMLButtonElement | null>;
  variablesPanelRef: RefObject<HTMLDivElement | null>;
}

function HeaderActions({
  clientBuildInfo,
  showClientDownloads,
  clientDownloadLabel,
  onOpenClientDownloads,
  mobileUtilitiesButtonRef,
  mobileUtilitiesOpen,
  onToggleMobileUtilities,
  onOpenEncoding,
  variablesOpen,
  onToggleVariables,
  onCloseVariables,
  variablesToggleRef,
  variablesPanelRef,
}: HeaderActionsProps) {
  const { theme, setTheme } = useSession();
  const { activeTab, bypassMode, setBypassMode } = useNav();
  const { language } = useLanguage();

  const toggleTheme = () => {
    setTheme(prev => prev === 'dark' ? 'light' : 'dark');
  };

  const clientDownloadCount = clientBuildInfo?.items?.length || (clientBuildInfo?.latest ? 1 : 0);
  const clientDownloadSize = clientBuildInfo?.latest?.size ? formatDownloadSize(clientBuildInfo.latest.size) : '';
  const clientDownloadTitle = language === 'zh'
    ? `查看 Payloader 客户端下载列表${clientDownloadCount ? `（${clientDownloadCount} 个版本）` : ''}`
    : `Open Payloader client downloads${clientDownloadCount ? ` (${clientDownloadCount} builds)` : ''}`;

  return (
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
        onClick={onToggleMobileUtilities}
        aria-label="更多工具"
        aria-controls="mobile-utilities-menu"
        aria-expanded={mobileUtilitiesOpen}
      >
        <span aria-hidden="true">⋮</span>
      </button>

      {activeTab !== 'ctf' && (
        <button
          className="encoding-toggle"
          type="button"
          onClick={onOpenEncoding}
          title={t('header.encodingTitle', language)}
        >
          {t('header.encoding', language)}
        </button>
      )}

      {showClientDownloads && (
        <button
          className="client-download-link"
          type="button"
          onClick={onOpenClientDownloads}
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

      <VariablesMenu
        open={variablesOpen}
        onToggle={onToggleVariables}
        onClose={onCloseVariables}
        variablesToggleRef={variablesToggleRef}
        variablesPanelRef={variablesPanelRef}
      />
    </div>
  );
}

export default HeaderActions;
