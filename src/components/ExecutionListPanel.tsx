import type { ChangeEvent, JSX } from 'react';
import { useLanguage, useNav } from '../appContext';
import { getText } from '../i18n';
import type { I18nText, PayloadExecution, SyntaxPart } from '../types';
import { countLabel, label } from './payloadDetailText';
import ExecutionItem from './ExecutionItem';

interface ExecutionListPanelProps {
  items: PayloadExecution[];
  totalCount: number;
  modeLabel: string;
  hasWafContent: boolean;
  payloadQuery: string;
  onQueryChange: (event: ChangeEvent<HTMLInputElement>) => void;
  onClearQuery: () => void;
  copiedKey: string | null;
  onCopy: (text: string, index: string) => void;
  onCopyVisible: () => void;
  onSelectSyntax: (next: { syntax: SyntaxPart[]; title: I18nText }) => void;
  renderCommand: (command: string) => JSX.Element;
}

function ExecutionListPanel({
  items,
  totalCount,
  modeLabel,
  hasWafContent,
  payloadQuery,
  onQueryChange,
  onClearQuery,
  copiedKey,
  onCopy,
  onCopyVisible,
  onSelectSyntax,
  renderCommand,
}: ExecutionListPanelProps) {
  const { bypassMode, setBypassMode } = useNav();
  const { language } = useLanguage();

  return (
    <div className="execution-section" role="tabpanel">
      <div className="execution-toolbar">
        <div className="payload-list-info">
          <span className="mode-label">{modeLabel}</span>
          <span className="item-count">{countLabel(items.length, totalCount, language)}</span>
          <span className={`waf-content-status ${hasWafContent ? 'available' : 'unavailable'}`}>
            {hasWafContent ? label('wafAvailable', language) : label('wafUnavailable', language)}
          </span>
        </div>
        <button
          className={`copy-all-btn ${copiedKey === 'all' ? 'copied' : ''}`}
          onClick={onCopyVisible}
          disabled={!items.length}
        >
          {copiedKey === 'all' ? label('copiedVisible', language) : label('copyVisible', language)}
        </button>
      </div>

      <div className="payload-controls">
        <div className="payload-search-field">
          <input
            type="search"
            name="payload-command-search"
            value={payloadQuery}
            onChange={onQueryChange}
            placeholder={label('searchPlaceholder', language)}
            aria-label={label('searchPlaceholder', language)}
          />
          {payloadQuery && (
            <button type="button" onClick={onClearQuery} aria-label={label('clearSearch', language)}>
              ×
            </button>
          )}
        </div>
      </div>

      {!items.length ? (
        <div className="payload-empty-result">
          <strong>{bypassMode === 'waf' && !hasWafContent ? label('noWafTitle', language) : label('noItemsTitle', language)}</strong>
          <span>{bypassMode === 'waf' && !hasWafContent ? label('noWafHint', language) : label('noItemsHint', language)}</span>
          {bypassMode === 'waf' && !hasWafContent && (
            <button type="button" onClick={() => setBypassMode('normal')}>{label('backToNormal', language)}</button>
          )}
        </div>
      ) : (
        <div className="execution-list">
          {items.map((exec, index) => (
            <ExecutionItem
              key={`${getText(exec.title, language)}-${index}-${exec.command}`}
              exec={exec}
              index={index}
              language={language}
              copiedKey={copiedKey}
              onCopy={onCopy}
              onSelectSyntax={onSelectSyntax}
              renderCommand={renderCommand}
            />
          ))}
        </div>
      )}
    </div>
  );
}

export default ExecutionListPanel;
