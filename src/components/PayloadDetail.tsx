import { useState } from 'react';
import type { JSX } from 'react';
import { useAppContext } from '../App';
import { t, getText } from '../i18n';
import type { PayloadItem, PayloadExecution, SyntaxPart, I18nText } from '../types';
import { webPayloads } from '../data/webPayloads';
import { intranetPayloads } from '../data/intranetPayloads';
import SyntaxModal from './SyntaxModal';

interface PayloadDetailProps {
  payloadId: string;
}

function PayloadDetail({ payloadId }: PayloadDetailProps) {
  const { globalVariables, bypassMode, language } = useAppContext();
  const [copiedIndex, setCopiedIndex] = useState<string | null>(null);
  const [selectedSyntax, setSelectedSyntax] = useState<{syntax: SyntaxPart[], title: I18nText} | null>(null);
  const [activeSection, setActiveSection] = useState<'execution' | 'tutorial' | 'analysis' | 'chain'>('execution');

  const allPayloads: PayloadItem[] = [...webPayloads, ...intranetPayloads];
  const payload = allPayloads.find(p => p.id === payloadId);

  if (!payload) {
    return (
      <div className="payload-not-found">
        <h2>{t('payload.notFound', language)}</h2>
        <p>ID: {payloadId}</p>
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

  /** Render command with variable highlights */
  const renderCommandWithHighlights = (command: string) => {
    const replaced = replaceVariables(command);
    // Find variable positions and highlight them
    let lastIdx = 0;
    const regex = /\{([A-Z_]+)\}/g;
    let match;
    // Work on original command to find variable positions
    const varPositions: { start: number; end: number; key: string; value: string }[] = [];
    while ((match = regex.exec(command)) !== null) {
      const varDef = globalVariables.find(v => v.key === match![1]);
      if (varDef) {
        varPositions.push({ start: match.index, end: match.index + match[0].length, key: match[1], value: varDef.value });
      }
    }

    if (varPositions.length === 0) {
      return <code>{replaced}</code>;
    }

    // Build replaced text with highlight spans
    let replacedIdx = 0;
    const elements: JSX.Element[] = [];
    for (const vp of varPositions) {
      // Text before variable
      const beforeOrig = command.substring(lastIdx, vp.start);
      if (beforeOrig.length > 0) {
        elements.push(<span key={`t-${replacedIdx}`}>{beforeOrig}</span>);
      }
      // Variable replacement highlighted
      elements.push(
        <span key={`v-${replacedIdx}`} className="var-highlight" title={`\{${vp.key}\} → ${vp.value}`}>
          {vp.value}
        </span>
      );
      replacedIdx++;
      lastIdx = vp.end;
    }
    // Remaining text
    const remaining = command.substring(lastIdx);
    if (remaining.length > 0) {
      elements.push(<span key={`t-end`}>{remaining}</span>);
    }

    return <code>{elements}</code>;
  };

  const copyToClipboard = async (text: string, index: string) => {
    const processedText = replaceVariables(text);
    await navigator.clipboard.writeText(processedText);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const copyAllCommands = async () => {
    const allCmds = getExecutionItems().map(e => replaceVariables(e.command)).join('\n\n');
    await navigator.clipboard.writeText(allCmds);
    setCopiedIndex('all');
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const getExecutionItems = (): PayloadExecution[] => {
    if (bypassMode === 'waf' && payload.wafBypass && payload.wafBypass.length > 0) {
      return payload.wafBypass;
    }
    if (bypassMode === 'edr' && payload.edrBypass && payload.edrBypass.length > 0) {
      return payload.edrBypass;
    }
    return payload.execution;
  };

  const getDifficultyColor = (difficulty: string) => {
    switch (difficulty) {
      case 'beginner': return 'var(--neon-green)';
      case 'intermediate': return 'var(--neon-cyan)';
      case 'advanced': return 'var(--neon-orange)';
      case 'expert': return 'var(--neon-red)';
      default: return 'var(--text-muted)';
    }
  };

  const executionItems = getExecutionItems();

  return (
    <div className="payload-detail">
      <div className="payload-header">
        <div className="payload-title-section">
          <div className="payload-tags">
            {payload.tags.map(tag => (
              <span key={tag} className="tag">{tag}</span>
            ))}
          </div>
          <h1 className="payload-title">{getText(payload.name, language)}</h1>
          <p className="payload-description">{getText(payload.description, language)}</p>
        </div>
        <div className="payload-meta">
          <div className="meta-item">
            <span className="meta-label">{t('payload.category', language)}</span>
            <span className="meta-value">{getText(payload.category, language)}</span>
          </div>
          {payload.subCategory && (
            <div className="meta-item">
              <span className="meta-label">{t('payload.subCategory', language)}</span>
              <span className="meta-value">{getText(payload.subCategory, language)}</span>
            </div>
          )}
          {payload.tutorial && (
            <div className="meta-item">
              <span className="meta-label">{t('payload.difficulty', language)}</span>
              <span 
                className="meta-value difficulty"
                style={{ color: getDifficultyColor(payload.tutorial.difficulty) }}
              >
                {payload.tutorial.difficulty.toUpperCase()}
              </span>
            </div>
          )}
        </div>
      </div>

      {payload.prerequisites && payload.prerequisites.length > 0 && (
        <div className="prerequisites-section">
          <h3>{t('payload.prerequisites', language)}</h3>
          <ul className="prerequisites-list">
            {payload.prerequisites.map((prereq, index) => (
              <li key={index}>{getText(prereq, language)}</li>
            ))}
          </ul>
        </div>
      )}

      <div className="section-tabs">
        <button 
          className={`section-tab ${activeSection === 'execution' ? 'active' : ''}`}
          onClick={() => setActiveSection('execution')}
        >
          {t('payload.tabExecution', language)}
        </button>
        <button 
          className={`section-tab ${activeSection === 'chain' ? 'active' : ''}`}
          onClick={() => setActiveSection('chain')}
        >
          {t('payload.tabChain', language)}
        </button>
        <button 
          className={`section-tab ${activeSection === 'analysis' ? 'active' : ''}`}
          onClick={() => setActiveSection('analysis')}
        >
          {t('payload.tabAnalysis', language)}
        </button>
        <button 
          className={`section-tab ${activeSection === 'tutorial' ? 'active' : ''}`}
          onClick={() => setActiveSection('tutorial')}
        >
          {t('payload.tabTutorial', language)}
        </button>
      </div>

      {activeSection === 'execution' && (
        <div className="execution-section">
          {bypassMode !== 'normal' && (
            <div className={`bypass-notice ${bypassMode}`}>
              <span className="bypass-icon">
                {bypassMode === 'waf' ? '🛡️' : '🦠'}
              </span>
              <span>
                {bypassMode === 'waf' 
                  ? t('payload.wafNotice', language)
                  : t('payload.edrNotice', language)}
              </span>
            </div>
          )}

          <div className="execution-toolbar">
            <button 
              className={`copy-all-btn ${copiedIndex === 'all' ? 'copied' : ''}`}
              onClick={copyAllCommands}
            >
              {copiedIndex === 'all' ? t('payload.copiedAll', language) : t('payload.copyAll', language)}
            </button>
            <span className="step-count">{t('payload.steps', language, { count: executionItems.length })}</span>
          </div>

          <div className="execution-list">
            {executionItems.map((exec, index) => (
              <div key={index} className="execution-item">
                <div className="execution-step-badge">
                  <span className="step-number">{index + 1}</span>
                </div>
                <div className="execution-content">
                  <div className="execution-header">
                    <h4 className="execution-title">{getText(exec.title, language)}</h4>
                    <div className="execution-badges">
                      {exec.platform && (
                        <span className={`badge platform-${exec.platform}`}>
                          {exec.platform === 'all' ? t('payload.allPlatforms', language) : exec.platform === 'windows' ? t('payload.windows', language) : t('payload.linux', language)}
                        </span>
                      )}
                      {exec.requiresAdmin && (
                        <span className="badge admin">{t('payload.requiresAdmin', language)}</span>
                      )}
                    </div>
                  </div>
                  {exec.description && (
                    <p className="execution-desc">{getText(exec.description, language)}</p>
                  )}
                  <div className="code-block-wrapper">
                    <div className="code-block">
                      {renderCommandWithHighlights(exec.command)}
                    </div>
                    <div className="code-actions">
                      {exec.syntaxBreakdown && exec.syntaxBreakdown.length > 0 && (
                        <button 
                          className="syntax-btn"
                          onClick={() => setSelectedSyntax({
                            syntax: exec.syntaxBreakdown!,
                            title: exec.title
                          })}
                        >
                          {t('payload.syntaxAnalysis', language)}
                        </button>
                      )}
                      <button 
                        className={`copy-btn ${copiedIndex === `${index}` ? 'copied' : ''}`}
                        onClick={() => copyToClipboard(exec.command, `${index}`)}
                      >
                        {copiedIndex === `${index}` ? t('payload.copied', language) : t('payload.copy', language)}
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ===== Attack Chain Visualization ===== */}
      {activeSection === 'chain' && (
        <div className="chain-section">
          <div className="chain-header-info">
            <h3>{t('payload.chainTitle', language)}</h3>
            <p>{t('payload.chainDesc', language)}</p>
          </div>
          <div className="chain-visualization">
            {executionItems.map((exec, index) => (
              <div key={index} className="chain-node-wrapper">
                <div className={`chain-node ${index === 0 ? 'first' : ''} ${index === executionItems.length - 1 ? 'last' : ''}`}>
                  <div className="chain-node-header">
                    <span className="chain-step">STEP {index + 1}</span>
                    {exec.platform && (
                      <span className={`chain-platform ${exec.platform}`}>
                        {exec.platform === 'all' ? '🌐' : exec.platform === 'windows' ? '🪟' : '🐧'}
                      </span>
                    )}
                  </div>
                  <h4 className="chain-node-title">{getText(exec.title, language)}</h4>
                  {exec.description && (
                    <p className="chain-node-desc">{getText(exec.description, language)}</p>
                  )}
                  <div className="chain-command-preview">
                    <code>{replaceVariables(exec.command).substring(0, 80)}{exec.command.length > 80 ? '...' : ''}</code>
                  </div>
                  <div className="chain-node-actions">
                    <button 
                      className={`chain-copy-btn ${copiedIndex === `chain-${index}` ? 'copied' : ''}`}
                      onClick={() => copyToClipboard(exec.command, `chain-${index}`)}
                    >
                      {copiedIndex === `chain-${index}` ? '✓' : '📋'}
                    </button>
                    {exec.syntaxBreakdown && exec.syntaxBreakdown.length > 0 && (
                      <button 
                        className="chain-syntax-btn"
                        onClick={() => setSelectedSyntax({
                          syntax: exec.syntaxBreakdown!,
                          title: exec.title
                        })}
                      >
                        📖
                      </button>
                    )}
                  </div>
                </div>
                {index < executionItems.length - 1 && (
                  <div className="chain-connector">
                    <div className="chain-arrow" />
                    <span className="chain-connector-label">→</span>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {activeSection === 'analysis' && (
        <div className="analysis-section">
          <div className="analysis-card">
            <h3>{t('payload.analysisTitle', language)}</h3>
            <p>{getText(payload.analysis, language) || t('payload.noAnalysis', language)}</p>
          </div>
          
          {payload.opsecTips && payload.opsecTips.length > 0 && (
            <div className="analysis-card warning">
              <h3>{t('payload.opsecTitle', language)}</h3>
              <ul>
                {payload.opsecTips.map((tip, index) => (
                  <li key={index}>{getText(tip, language)}</li>
                ))}
              </ul>
            </div>
          )}

          {payload.references && payload.references.length > 0 && (
            <div className="analysis-card">
              <h3>{t('payload.referencesTitle', language)}</h3>
              <ul className="references-list">
                {payload.references.map((ref, index) => (
                  <li key={index}>
                    <a href={ref} target="_blank" rel="noopener noreferrer">{ref}</a>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {activeSection === 'tutorial' && payload.tutorial && (
        <div className="tutorial-section">
          <div className="tutorial-card">
            <h3>{t('payload.tutOverview', language)}</h3>
            <p>{getText(payload.tutorial.overview, language)}</p>
          </div>
          <div className="tutorial-card">
            <h3>{t('payload.tutVulnerability', language)}</h3>
            <p>{getText(payload.tutorial.vulnerability, language)}</p>
          </div>
          <div className="tutorial-card">
            <h3>{t('payload.tutExploitation', language)}</h3>
            <p>{getText(payload.tutorial.exploitation, language)}</p>
          </div>
          <div className="tutorial-card">
            <h3>{t('payload.tutMitigation', language)}</h3>
            <p>{getText(payload.tutorial.mitigation, language)}</p>
          </div>
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
        .payload-detail {
          padding: 24px;
          max-width: 1200px;
          margin: 0 auto;
        }

        .payload-header {
          display: flex;
          justify-content: space-between;
          gap: 24px;
          padding-bottom: 24px;
          border-bottom: 1px solid var(--border-color);
          margin-bottom: 24px;
        }

        .payload-title-section {
          flex: 1;
        }

        .payload-tags {
          display: flex;
          flex-wrap: wrap;
          gap: 8px;
          margin-bottom: 12px;
        }

        .payload-title {
          font-size: 28px;
          font-weight: 700;
          margin-bottom: 8px;
          background: var(--gradient-cyber);
          -webkit-background-clip: text;
          -webkit-text-fill-color: transparent;
          background-clip: text;
        }

        .payload-description {
          font-size: 14px;
          color: var(--text-secondary);
          line-height: 1.6;
        }

        .payload-meta {
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

        .meta-value.difficulty {
          font-family: var(--font-display);
        }

        .prerequisites-section {
          background: var(--bg-card);
          border: 1px solid var(--border-color);
          border-radius: 8px;
          padding: 16px;
          margin-bottom: 24px;
        }

        .prerequisites-section h3 {
          font-size: 14px;
          font-weight: 600;
          margin-bottom: 12px;
        }

        .prerequisites-list {
          list-style: none;
        }

        .prerequisites-list li {
          position: relative;
          padding-left: 20px;
          font-size: 13px;
          color: var(--text-secondary);
          margin-bottom: 8px;
        }

        .prerequisites-list li::before {
          content: '✓';
          position: absolute;
          left: 0;
          color: var(--neon-green);
        }

        .section-tabs {
          display: flex;
          gap: 8px;
          margin-bottom: 24px;
          padding-bottom: 16px;
          border-bottom: 1px solid var(--border-color);
        }

        .section-tab {
          background: var(--bg-tertiary);
          border: 1px solid var(--border-color);
          color: var(--text-secondary);
          padding: 10px 20px;
          border-radius: 6px;
          font-size: 13px;
          cursor: pointer;
          transition: all var(--transition-fast);
        }

        .section-tab:hover {
          border-color: var(--neon-cyan);
          color: var(--text-primary);
        }

        .section-tab.active {
          background: rgba(0, 240, 255, 0.1);
          border-color: var(--neon-cyan);
          color: var(--neon-cyan);
        }

        /* ===== Execution Toolbar ===== */
        .execution-toolbar {
          display: flex;
          align-items: center;
          justify-content: space-between;
          margin-bottom: 16px;
        }

        .copy-all-btn {
          background: var(--bg-tertiary);
          border: 1px solid var(--neon-cyan);
          color: var(--neon-cyan);
          padding: 8px 16px;
          border-radius: 6px;
          font-size: 13px;
          font-weight: 500;
          cursor: pointer;
          transition: all var(--transition-fast);
        }

        .copy-all-btn:hover {
          background: rgba(0, 240, 255, 0.15);
          box-shadow: 0 0 12px rgba(0, 240, 255, 0.2);
        }

        .copy-all-btn.copied {
          background: rgba(0, 255, 136, 0.1);
          border-color: var(--neon-green);
          color: var(--neon-green);
        }

        .step-count {
          font-size: 12px;
          color: var(--text-muted);
        }

        .bypass-notice {
          display: flex;
          align-items: center;
          gap: 12px;
          padding: 12px 16px;
          border-radius: 6px;
          margin-bottom: 16px;
          font-size: 13px;
        }

        .bypass-notice.waf {
          background: rgba(255, 102, 0, 0.1);
          border: 1px solid rgba(255, 102, 0, 0.3);
          color: var(--neon-orange);
        }

        .bypass-notice.edr {
          background: rgba(255, 0, 85, 0.1);
          border: 1px solid rgba(255, 0, 85, 0.3);
          color: var(--neon-red);
        }

        .execution-list {
          display: flex;
          flex-direction: column;
          gap: 16px;
        }

        .execution-item {
          display: flex;
          gap: 16px;
          align-items: flex-start;
        }

        .execution-step-badge {
          display: flex;
          align-items: center;
          justify-content: center;
          width: 32px;
          height: 32px;
          min-width: 32px;
          border-radius: 50%;
          background: rgba(0, 240, 255, 0.15);
          border: 1px solid var(--neon-cyan);
          margin-top: 16px;
        }

        .step-number {
          font-family: var(--font-display);
          font-size: 12px;
          font-weight: 700;
          color: var(--neon-cyan);
        }

        .execution-content {
          flex: 1;
          background: var(--bg-card);
          border: 1px solid var(--border-color);
          border-radius: 8px;
          padding: 16px;
          transition: all var(--transition-fast);
        }

        .execution-content:hover {
          border-color: var(--neon-cyan);
        }

        .execution-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 8px;
        }

        .execution-title {
          font-size: 14px;
          font-weight: 600;
        }

        .execution-badges {
          display: flex;
          gap: 8px;
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

        .badge.admin {
          background: rgba(255, 0, 85, 0.2);
          color: var(--neon-red);
        }

        .execution-desc {
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

        /* Variable highlight in commands */
        .var-highlight {
          background: rgba(0, 255, 136, 0.15);
          color: var(--neon-green);
          padding: 1px 4px;
          border-radius: 3px;
          border-bottom: 1px dashed var(--neon-green);
          cursor: help;
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

        /* ===== Attack Chain Visualization ===== */
        .chain-section {
          padding: 8px 0;
        }

        .chain-header-info {
          margin-bottom: 24px;
        }

        .chain-header-info h3 {
          font-size: 16px;
          font-weight: 600;
          color: var(--neon-cyan);
          margin-bottom: 6px;
        }

        .chain-header-info p {
          font-size: 13px;
          color: var(--text-muted);
        }

        .chain-visualization {
          display: flex;
          flex-direction: column;
          gap: 0;
          position: relative;
        }

        .chain-node-wrapper {
          display: flex;
          flex-direction: column;
          align-items: center;
        }

        .chain-node {
          width: 100%;
          max-width: 600px;
          background: var(--bg-card);
          border: 1px solid var(--border-color);
          border-radius: 12px;
          padding: 20px;
          position: relative;
          transition: all var(--transition-fast);
        }

        .chain-node:hover {
          border-color: var(--neon-cyan);
          box-shadow: var(--shadow-neon);
          transform: translateY(-2px);
        }

        .chain-node.first {
          border-color: var(--neon-green);
        }

        .chain-node.first .chain-step {
          background: rgba(0, 255, 136, 0.15);
          color: var(--neon-green);
          border-color: var(--neon-green);
        }

        .chain-node.last {
          border-color: var(--neon-red);
        }

        .chain-node.last .chain-step {
          background: rgba(255, 0, 85, 0.15);
          color: var(--neon-red);
          border-color: var(--neon-red);
        }

        .chain-node-header {
          display: flex;
          align-items: center;
          justify-content: space-between;
          margin-bottom: 8px;
        }

        .chain-step {
          font-family: var(--font-display);
          font-size: 10px;
          font-weight: 700;
          letter-spacing: 2px;
          padding: 3px 10px;
          border-radius: 4px;
          background: rgba(0, 240, 255, 0.1);
          color: var(--neon-cyan);
          border: 1px solid rgba(0, 240, 255, 0.3);
        }

        .chain-platform {
          font-size: 14px;
        }

        .chain-node-title {
          font-size: 15px;
          font-weight: 600;
          margin-bottom: 6px;
          color: var(--text-primary);
        }

        .chain-node-desc {
          font-size: 12px;
          color: var(--text-muted);
          margin-bottom: 10px;
          line-height: 1.5;
        }

        .chain-command-preview {
          background: var(--bg-tertiary);
          border: 1px solid var(--border-color);
          border-radius: 6px;
          padding: 8px 12px;
          margin-bottom: 10px;
        }

        .chain-command-preview code {
          font-family: var(--font-mono);
          font-size: 11px;
          color: var(--neon-cyan);
          word-break: break-all;
        }

        .chain-node-actions {
          display: flex;
          gap: 6px;
          justify-content: flex-end;
        }

        .chain-copy-btn, .chain-syntax-btn {
          background: var(--bg-tertiary);
          border: 1px solid var(--border-color);
          color: var(--text-secondary);
          width: 30px;
          height: 30px;
          border-radius: 4px;
          font-size: 14px;
          cursor: pointer;
          display: flex;
          align-items: center;
          justify-content: center;
          transition: all var(--transition-fast);
        }

        .chain-copy-btn:hover, .chain-syntax-btn:hover {
          border-color: var(--neon-cyan);
          color: var(--neon-cyan);
        }

        .chain-copy-btn.copied {
          background: rgba(0, 255, 136, 0.1);
          border-color: var(--neon-green);
          color: var(--neon-green);
        }

        .chain-connector {
          display: flex;
          flex-direction: column;
          align-items: center;
          padding: 4px 0;
        }

        .chain-arrow {
          width: 2px;
          height: 20px;
          background: linear-gradient(180deg, var(--neon-cyan), var(--neon-purple));
        }

        .chain-connector-label {
          font-size: 16px;
          color: var(--neon-cyan);
          font-weight: 700;
          transform: rotate(90deg);
          line-height: 1;
        }

        /* ===== Analysis & Tutorial ===== */
        .analysis-section, .tutorial-section {
          display: flex;
          flex-direction: column;
          gap: 16px;
        }

        .analysis-card, .tutorial-card {
          background: var(--bg-card);
          border: 1px solid var(--border-color);
          border-radius: 8px;
          padding: 20px;
        }

        .analysis-card.warning {
          background: rgba(255, 102, 0, 0.05);
          border-color: rgba(255, 102, 0, 0.3);
        }

        .analysis-card h3, .tutorial-card h3 {
          font-size: 14px;
          font-weight: 600;
          margin-bottom: 12px;
          color: var(--neon-cyan);
        }

        .analysis-card p, .tutorial-card p {
          font-size: 13px;
          color: var(--text-secondary);
          line-height: 1.8;
        }

        .analysis-card ul, .tutorial-card ul {
          list-style: none;
        }

        .analysis-card li {
          font-size: 13px;
          color: var(--text-secondary);
          padding: 8px 0;
          padding-left: 20px;
          position: relative;
        }

        .analysis-card.warning li::before {
          content: '⚠';
          position: absolute;
          left: 0;
        }

        .references-list li {
          padding: 8px 0;
        }

        .references-list a {
          color: var(--neon-cyan);
          font-size: 13px;
        }

        .references-list a:hover {
          color: var(--neon-pink);
        }

        .payload-not-found {
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

export default PayloadDetail;
