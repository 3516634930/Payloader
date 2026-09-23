import type { RefObject } from 'react';
import { useLanguage, useNav } from '../appContext';
import { t } from '../i18n';

interface MobileUtilitiesMenuProps {
  mobileUtilitiesRef: RefObject<HTMLDivElement | null>;
  onOpenVariables: () => void;
  onOpenEncoding: () => void;
  onOpenClientDownloads: () => void;
  showClientDownloads: boolean;
  clientDownloadLabel: string;
}

function MobileUtilitiesMenu({ mobileUtilitiesRef, onOpenVariables, onOpenEncoding, onOpenClientDownloads, showClientDownloads, clientDownloadLabel }: MobileUtilitiesMenuProps) {
  const { activeTab, bypassMode, setBypassMode } = useNav();
  const { language } = useLanguage();

  return (
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
      <button type="button" onClick={onOpenVariables}>{t('header.variables', language)}</button>
      {activeTab !== 'ctf' && (
        <button type="button" onClick={onOpenEncoding}>{t('header.encoding', language)}</button>
      )}
      {showClientDownloads && (
        <button type="button" onClick={onOpenClientDownloads}>{clientDownloadLabel}</button>
      )}
    </div>
  );
}

export default MobileUtilitiesMenu;
