import { useState } from 'react';
import { useLanguage, useSession, useStaticData } from '../appContext';
import { t, getText } from '../i18n';
import { isProtectedExternalUrl, openProtectedExternalLink } from '../protectedLinks';
import type { SyntaxPart, I18nText } from '../types';
import { resolveVariableParts, resolveVariableText } from '../utils/variables';
import { useCopyFeedback } from '../utils/clipboard';
import SyntaxModal from './SyntaxModal';
import '../styles/tool-detail.css';

interface ToolDetailProps {
  toolId: string;
}

function ToolDetail({ toolId }: ToolDetailProps) {
  const { globalVariables } = useSession();
  const { language } = useLanguage();
  const { allToolCommands } = useStaticData();
  const { copiedKey: copiedIndex, copy } = useCopyFeedback();
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

  const copyToClipboard = (text: string, index: string) => {
    void copy(resolveVariableText(text, globalVariables), index);
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
    </div>
  );
}

export default ToolDetail;
