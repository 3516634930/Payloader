import type { JSX } from 'react';
import { getText } from '../i18n';
import type { I18nText, PayloadExecution, SyntaxPart } from '../types';
import { label } from './payloadDetailText';

interface ExecutionItemProps {
  exec: PayloadExecution;
  index: number;
  language: 'zh' | 'en';
  copiedKey: string | null;
  onCopy: (text: string, index: string) => void;
  onSelectSyntax: (next: { syntax: SyntaxPart[]; title: I18nText }) => void;
  renderCommand: (command: string) => JSX.Element;
}

function ExecutionItem({ exec, index, language, copiedKey, onCopy, onSelectSyntax, renderCommand }: ExecutionItemProps) {
  const platformLabel = (platform?: PayloadExecution['platform']) => {
    if (platform === 'windows') return label('platformWindows', language);
    if (platform === 'linux') return label('platformLinux', language);
    return label('platformAll', language);
  };

  const copyId = `item-${index}`;

  return (
    <article key={`${getText(exec.title, language)}-${index}-${exec.command}`} className="execution-item">
      <div className="execution-content">
        <div className="execution-header">
          <div className="execution-heading">
            <span className="item-index">{String(index + 1).padStart(2, '0')}</span>
            <h4 className="execution-title">{getText(exec.title, language)}</h4>
          </div>
          <div className="execution-badges">
            <span className={`badge platform-${exec.platform || 'all'}`}>{platformLabel(exec.platform)}</span>
            {exec.requiresAdmin && <span className="badge admin">{label('admin', language)}</span>}
          </div>
        </div>
        {exec.description && <p className="execution-desc">{getText(exec.description, language)}</p>}
        <div className="code-block-wrapper">
          <pre className="code-block">{renderCommand(exec.command)}</pre>
          <div className="code-actions">
            {exec.syntaxBreakdown?.length ? (
              <button
                className="syntax-btn"
                onClick={() => onSelectSyntax({ syntax: exec.syntaxBreakdown!, title: exec.title })}
              >
                {label('syntax', language)}
              </button>
            ) : null}
            <button className={`copy-btn ${copiedKey === copyId ? 'copied' : ''}`} onClick={() => onCopy(exec.command, copyId)}>
              {copiedKey === copyId ? label('copied', language) : label('copy', language)}
            </button>
          </div>
        </div>
      </div>
    </article>
  );
}

export default ExecutionItem;
