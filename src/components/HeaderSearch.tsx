import { memo } from 'react';
import { useLanguage } from '../appContext';
import { t } from '../i18n';

interface HeaderSearchProps {
  value: string;
  onChange: (value: string) => void;
  onClear: () => void;
}

function HeaderSearch({ value, onChange, onClear }: HeaderSearchProps) {
  const { language } = useLanguage();
  return (
    <div className="search-box" role="search">
      <span className="search-icon" aria-hidden="true">⌕</span>
      <input
        type="search"
        name="content-search"
        className="search-input"
        placeholder={t('header.searchPlaceholder', language)}
        aria-label={t('header.searchPlaceholder', language)}
        value={value}
        onChange={(event) => onChange(event.target.value)}
      />
      {value && (
        <button type="button" className="search-clear" onClick={onClear} aria-label="清除搜索">×</button>
      )}
    </div>
  );
}

export default memo(HeaderSearch);
