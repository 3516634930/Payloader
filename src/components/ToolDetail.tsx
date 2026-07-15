import { useState } from 'react';
import { useAppContext } from '../appContext';
import { t, getText } from '../i18n';
import { isProtectedExternalUrl, openProtectedExternalLink } from '../protectedLinks';
import type { SyntaxPart, I18nText } from '../types';
import { resolveVariableParts, resolveVariableText } from '../utils/variables';
import SyntaxModal from './SyntaxModal';

interface ToolDetailProps {
  toolId: string;
}

function ToolDetail({ toolId }: ToolDetailProps) {
  const { globalVariables, language, allToolCommands } = useAppContext();
  const [copiedIndex, setCopiedIndex] = useState<string | null>(null);
  const [selectedSyntax, setSelectedSyntax] = useState<{syntax: SyntaxPart[], title: I18nText} | null>(null);

  const tool = allToolCommands.find(t => t.id === toolId);

  if (!tool) {
    return (
      <div className="tool-not-found">
        <h2>{t('tool.notFound', language)}</h2>
        <p>ID: {toolId}</p>
      </div>
    );
  }

  const copyToClipboard = async (text: string, index: string) => {
    const processedText = resolveVariableText(text, globalVariables);
    try {
      await navigator.clipboard.writeText(processedText);
    } catch {
      const textarea = document.createElement('textarea');
      textarea.value = processedText;
      textarea.style.position = 'fixed';
      textarea.style.opacity = '0';
      document.body.appendChild(textarea);
      textarea.focus();
      textarea.select();
      document.execCommand('copy');
      textarea.remove();
    }
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const renderCommand = (command: string) => {
    const parts = resolveVariableParts(command, globalVariables);
    if (!parts.some(part => part.key)) return command;

    return parts.map((part, index) => (
      part.key ? (
        <span key={`${part.key}-${index}`} className="var-highlight" title={`${part.raw} -> ${part.value}`}>
          {part.text}
        </span>
      ) : (
        <span key={`text-${index}`}>{part.text}</span>
      )
    ));
  };

  const isExternalTool = Boolean(tool.externalUrl);

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

      {isExternalTool && (
        <div className="external-tool-section">
          <div>
            <h3>{language === 'zh' ? '平台入口' : 'Platform Entry'}</h3>
            <p>{language === 'zh' ? '这是默认提供的 Xeye 平台入口，部署管理员可在后台工具列表中删除。' : 'This default Xeye entry can be removed by the deployment administrator.'}</p>
          </div>
          <button
            className="external-open-btn"
            type="button"
            onClick={() => openProtectedExternalLink(tool.externalUrl)}
          >
            {language === 'zh' ? '打开 XSS 平台' : 'Open XSS Platform'}
          </button>
        </div>
      )}

      {!isExternalTool && tool.installation && (
        <div className="installation-section">
          <h3>{t('tool.installation', language)}</h3>
          <div className="code-block">
            <code>{renderCommand(getText(tool.installation, language))}</code>
            <button 
              className={`copy-btn ${copiedIndex === 'install' ? 'copied' : ''}`}
              onClick={() => copyToClipboard(getText(tool.installation, language), 'install')}
            >
              {copiedIndex === 'install' ? t('payload.copied', language) : t('payload.copy', language)}
            </button>
          </div>
        </div>
      )}

      {!isExternalTool && (
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
                  <code>{renderCommand(cmd.command)}</code>
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
                      <li key={i}>{renderCommand(getText(example, language))}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>
      )}

      {tool.references && tool.references.length > 0 && (
        <div className="references-section">
          <h3>{t('tool.references', language)}</h3>
          <ul>
            {tool.references.map((ref, index) => (
              <li key={index}>
                <a
                  href={ref}
                  target="_blank"
                  rel={isProtectedExternalUrl(ref) ? 'noopener' : 'noopener noreferrer'}
                  referrerPolicy={isProtectedExternalUrl(ref) ? 'origin' : undefined}
                >
                  {ref}
                </a>
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
          min-width: 0;
        }

        .tool-title {
          font-size: 28px;
          font-weight: 700;
          margin-bottom: 8px;
          background: var(--gradient-cyber);
          -webkit-background-clip: text;
          -webkit-text-fill-color: transparent;
          background-clip: text;
          overflow-wrap: anywhere;
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

        .external-tool-section {
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 16px;
          background: var(--bg-card);
          border: 1px solid rgba(0, 240, 255, 0.28);
          border-radius: 8px;
          padding: 18px;
          margin-bottom: 24px;
        }

        .external-tool-section h3 {
          font-size: 16px;
          font-weight: 700;
          margin-bottom: 6px;
        }

        .external-tool-section p {
          color: var(--text-secondary);
          font-size: 13px;
          line-height: 1.6;
        }

        .external-open-btn {
          flex: 0 0 auto;
          border: 1px solid var(--neon-cyan);
          border-radius: 6px;
          background: rgba(0, 240, 255, 0.12);
          color: var(--neon-cyan);
          cursor: pointer;
          font-weight: 700;
          padding: 10px 14px;
          transition: all var(--transition-fast);
        }

        .external-open-btn:hover {
          background: var(--neon-cyan);
          color: var(--bg-primary);
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
          overflow-x: hidden;
          position: relative;
          display: flex;
          justify-content: space-between;
          align-items: center;
          gap: 12px;
          min-width: 0;
        }

        .code-block code {
          min-width: 0;
          white-space: pre-wrap;
          overflow-wrap: anywhere;
          word-break: break-word;
        }

        .var-highlight {
          display: inline;
          color: var(--neon-cyan);
          background: rgba(0, 229, 255, 0.12);
          border-radius: 3px;
          padding: 0 2px;
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
          min-width: 0;
        }

        .syntax-btn, .copy-btn {
          background: var(--bg-tertiary);
          border: 1px solid var(--border-color);
          color: var(--text-secondary);
          padding: 6px 12px;
          border-radius: 4px;
          font-size: 12px;
          min-height: 34px;
          min-width: 0;
          white-space: nowrap;
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

        @media (max-width: 900px) {
          .tool-detail {
            padding: 16px;
          }

          .tool-header,
          .external-tool-section,
          .command-header,
          .code-block-wrapper,
          .code-actions {
            flex-direction: column;
            align-items: stretch;
          }

          .tool-meta {
            min-width: 0;
          }

          .installation-section .code-block {
            align-items: stretch;
            flex-direction: column;
          }
        }

        @media (max-width: 520px) {
          .tool-title {
            font-size: 22px;
          }

          .command-item,
          .installation-section,
          .references-section {
            padding: 14px;
          }

          .code-actions {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(112px, 1fr));
          }

          .syntax-btn,
          .copy-btn {
            width: 100%;
          }
        }
      `}</style>
    </div>
  );
}

export default ToolDetail;
