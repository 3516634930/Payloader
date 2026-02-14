import { useState } from 'react';
import { useAppContext } from '../App';
import { t, getText } from '../i18n';
import type { SyntaxPart, I18nText } from '../types';
import { toolCommands } from '../data/toolCommands';
import SyntaxModal from './SyntaxModal';

interface ToolDetailProps {
  toolId: string;
}

function ToolDetail({ toolId }: ToolDetailProps) {
  const { globalVariables, language } = useAppContext();
  const [copiedIndex, setCopiedIndex] = useState<string | null>(null);
  const [selectedSyntax, setSelectedSyntax] = useState<{syntax: SyntaxPart[], title: I18nText} | null>(null);

  const tool = toolCommands.find(t => t.id === toolId);

  if (!tool) {
    return (
      <div className="tool-not-found">
        <h2>{t('tool.notFound', language)}</h2>
        <p>ID: {toolId}</p>
      </div>
    );
  }

  const replaceVariables = (text: string): string => {
    let result = text;
    globalVariables.forEach(v => {
      result = result.replace(new RegExp(`\\{${v.key}\\}`, 'g'), v.value);
    });
    return result;
  };

  const copyToClipboard = async (text: string, index: string) => {
    const processedText = replaceVariables(text);
    await navigator.clipboard.writeText(processedText);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  return (
    <div className="tool-detail">
      <div className="tool-header">
        <div className="tool-title-section">
          <h1 className="tool-title">{getText(tool.name, language)}</h1>
          <p className="tool-description">{getText(tool.description, language)}</p>
        </div>
        <div className="tool-meta">
          <div className="meta-item">
            <span className="meta-label">{t('tool.category', language)}</span>
            <span className="meta-value">{getText(tool.category, language)}</span>
          </div>
        </div>
      </div>

      {tool.installation && (
        <div className="installation-section">
          <h3>{t('tool.installation', language)}</h3>
          <div className="code-block">
            <code>{getText(tool.installation, language)}</code>
            <button 
              className={`copy-btn ${copiedIndex === 'install' ? 'copied' : ''}`}
              onClick={() => copyToClipboard(getText(tool.installation, language), 'install')}
            >
              {copiedIndex === 'install' ? t('payload.copied', language) : t('payload.copy', language)}
            </button>
          </div>
        </div>
      )}

      <div className="commands-section">
        <h3>{t('tool.commands', language)}</h3>
        <div className="commands-list">
          {tool.commands.map((cmd, index) => (
            <div key={index} className="command-item">
              <div className="command-header">
                <h4 className="command-name">{getText(cmd.name, language)}</h4>
                {cmd.platform && (
                  <span className={`badge platform-${cmd.platform}`}>
                    {cmd.platform === 'all' ? t('payload.allPlatforms', language) : cmd.platform === 'windows' ? t('payload.windows', language) : t('payload.linux', language)}
                  </span>
                )}
              </div>
              <p className="command-desc">{getText(cmd.description, language)}</p>
              <div className="code-block-wrapper">
                <div className="code-block">
                  <code>{replaceVariables(cmd.command)}</code>
                </div>
                <div className="code-actions">
                  {cmd.syntaxBreakdown && cmd.syntaxBreakdown.length > 0 && (
                    <button 
                      className="syntax-btn"
                      onClick={() => setSelectedSyntax({
                        syntax: cmd.syntaxBreakdown!,
                        title: cmd.name
                      })}
                    >
                      {t('payload.syntaxAnalysis', language)}
                    </button>
                  )}
                  <button 
                    className={`copy-btn ${copiedIndex === `${index}` ? 'copied' : ''}`}
                    onClick={() => copyToClipboard(cmd.command, `${index}`)}
                  >
                    {copiedIndex === `${index}` ? t('payload.copied', language) : t('payload.copy', language)}
                  </button>
                </div>
              </div>
              {cmd.examples && cmd.examples.length > 0 && (
                <div className="examples-section">
                  <h5>{t('tool.examples', language)}</h5>
                  <ul>
                    {cmd.examples.map((example, i) => (
                      <li key={i}>{getText(example, language)}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      {tool.references && tool.references.length > 0 && (
        <div className="references-section">
          <h3>{t('tool.references', language)}</h3>
          <ul>
            {tool.references.map((ref, index) => (
              <li key={index}>
                <a href={ref} target="_blank" rel="noopener noreferrer">{ref}</a>
              </li>
            ))}
          </ul>
        </div>
      )}

      {selectedSyntax && (
        <SyntaxModal 
          syntax={selectedSyntax.syntax}
          title={selectedSyntax.title}
          onClose={() => setSelectedSyntax(null)}
        />
      )}

      <style>{`
        .tool-detail {
          padding: 24px;
          max-width: 1200px;
          margin: 0 auto;
        }

        .tool-header {
          display: flex;
          justify-content: space-between;
          gap: 24px;
          padding-bottom: 24px;
          border-bottom: 1px solid var(--border-color);
          margin-bottom: 24px;
        }

        .tool-title-section {
          flex: 1;
        }

        .tool-title {
          font-size: 28px;
          font-weight: 700;
          margin-bottom: 8px;
          background: var(--gradient-cyber);
          -webkit-background-clip: text;
          -webkit-text-fill-color: transparent;
          background-clip: text;
        }

        .tool-description {
          font-size: 14px;
          color: var(--text-secondary);
          line-height: 1.6;
        }

        .tool-meta {
          display: flex;
          flex-direction: column;
          gap: 12px;
          min-width: 200px;
        }

        .meta-item {
          display: flex;
          flex-direction: column;
          gap: 4px;
        }

        .meta-label {
          font-size: 11px;
          text-transform: uppercase;
          letter-spacing: 1px;
          color: var(--text-muted);
        }

        .meta-value {
          font-size: 14px;
          font-weight: 600;
        }

        .installation-section {
          background: var(--bg-card);
          border: 1px solid var(--border-color);
          border-radius: 8px;
          padding: 16px;
          margin-bottom: 24px;
        }

        .installation-section h3 {
          font-size: 14px;
          font-weight: 600;
          margin-bottom: 12px;
        }

        .commands-section h3 {
          font-size: 16px;
          font-weight: 600;
          margin-bottom: 16px;
        }

        .commands-list {
          display: flex;
          flex-direction: column;
          gap: 16px;
        }

        .command-item {
          background: var(--bg-card);
          border: 1px solid var(--border-color);
          border-radius: 8px;
          padding: 16px;
          transition: all var(--transition-fast);
        }

        .command-item:hover {
          border-color: var(--neon-cyan);
        }

        .command-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 8px;
        }

        .command-name {
          font-size: 14px;
          font-weight: 600;
        }

        .badge {
          font-size: 11px;
          padding: 2px 8px;
          border-radius: 4px;
          background: var(--bg-tertiary);
          color: var(--text-secondary);
        }

        .badge.platform-windows {
          background: rgba(0, 102, 255, 0.2);
          color: var(--neon-blue);
        }

        .badge.platform-linux {
          background: rgba(255, 136, 0, 0.2);
          color: var(--neon-orange);
        }

        .command-desc {
          font-size: 13px;
          color: var(--text-muted);
          margin-bottom: 12px;
        }

        .code-block-wrapper {
          display: flex;
          flex-direction: column;
          gap: 8px;
        }

        .code-block {
          background: var(--bg-tertiary);
          border: 1px solid var(--border-color);
          border-radius: 6px;
          padding: 12px 16px;
          font-family: var(--font-mono);
          font-size: 13px;
          overflow-x: auto;
          position: relative;
          display: flex;
          justify-content: space-between;
          align-items: center;
        }

        .code-block::before {
          content: '';
          position: absolute;
          left: 0;
          top: 0;
          bottom: 0;
          width: 3px;
          background: var(--neon-cyan);
          border-radius: 6px 0 0 6px;
        }

        .code-actions {
          display: flex;
          justify-content: flex-end;
          gap: 8px;
        }

        .syntax-btn, .copy-btn {
          background: var(--bg-tertiary);
          border: 1px solid var(--border-color);
          color: var(--text-secondary);
          padding: 6px 12px;
          border-radius: 4px;
          font-size: 12px;
          cursor: pointer;
          transition: all var(--transition-fast);
        }

        .syntax-btn:hover, .copy-btn:hover {
          border-color: var(--neon-cyan);
          color: var(--neon-cyan);
        }

        .copy-btn.copied {
          background: rgba(0, 255, 136, 0.1);
          border-color: var(--neon-green);
          color: var(--neon-green);
        }

        .examples-section {
          margin-top: 12px;
          padding-top: 12px;
          border-top: 1px dashed var(--border-color);
        }

        .examples-section h5 {
          font-size: 12px;
          font-weight: 600;
          color: var(--text-muted);
          margin-bottom: 8px;
        }

        .examples-section ul {
          list-style: none;
        }

        .examples-section li {
          font-size: 12px;
          color: var(--text-secondary);
          padding: 4px 0;
          padding-left: 16px;
          position: relative;
        }

        .examples-section li::before {
          content: '→';
          position: absolute;
          left: 0;
          color: var(--neon-cyan);
        }

        .references-section {
          margin-top: 24px;
          padding: 16px;
          background: var(--bg-card);
          border: 1px solid var(--border-color);
          border-radius: 8px;
        }

        .references-section h3 {
          font-size: 14px;
          font-weight: 600;
          margin-bottom: 12px;
        }

        .references-section ul {
          list-style: none;
        }

        .references-section li {
          padding: 8px 0;
        }

        .references-section a {
          color: var(--neon-cyan);
          font-size: 13px;
        }

        .references-section a:hover {
          color: var(--neon-pink);
        }

        .tool-not-found {
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          height: 100%;
          text-align: center;
        }
      `}</style>
    </div>
  );
}

export default ToolDetail;
