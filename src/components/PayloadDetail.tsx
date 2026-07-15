import { useMemo, useState } from 'react';
import type { JSX } from 'react';
import { useAppContext } from '../appContext';
import { getText } from '../i18n';
import type { AttackChainStep, I18nText, PayloadExecution, SyntaxPart, TutorialContent } from '../types';
import { resolveVariableParts, resolveVariableText } from '../utils/variables';
import SyntaxModal from './SyntaxModal';

interface PayloadDetailProps {
  payloadId: string;
}

type DetailSection = 'payloads' | 'chain' | 'tutorial';

const uiText = {
  notFound: { zh: 'Payload 未找到', en: 'Payload not found' },
  category: { zh: '分类', en: 'Category' },
  subCategory: { zh: '子分类', en: 'Sub-category' },
  difficulty: { zh: '难度', en: 'Difficulty' },
  prerequisites: { zh: '使用前确认', en: 'Before use' },
  tabPayloads: { zh: 'Payload 列表', en: 'Payload list' },
  tabAttackChain: { zh: '攻击链', en: 'Attack chain' },
  tabTutorial: { zh: '教程', en: 'Tutorial' },
  normalMode: { zh: '标准 Payload', en: 'Standard payloads' },
  wafMode: { zh: 'WAF 绕过 Payload', en: 'WAF bypass payloads' },
  copyVisible: { zh: '复制当前列表', en: 'Copy visible' },
  copiedVisible: { zh: '已复制当前列表', en: 'Visible copied' },
  copy: { zh: '复制', en: 'Copy' },
  copied: { zh: '已复制', en: 'Copied' },
  syntax: { zh: '语法解析', en: 'Syntax' },
  platformAll: { zh: '全平台', en: 'All platforms' },
  platformWindows: { zh: 'Windows', en: 'Windows' },
  platformLinux: { zh: 'Linux', en: 'Linux' },
  admin: { zh: '需要管理员权限', en: 'Requires admin' },
  chainPayload: { zh: '关联 Payload', en: 'Related payload' },
  chainFallbackTitle: { zh: '按当前模式验证', en: 'Validate with the selected mode' },
  chainFallbackDesc: { zh: '先确认授权范围和上传点，再从 Payload 列表复制当前模式下的条目，在测试环境中验证响应、落点和防护效果。', en: 'Confirm authorization and the upload point, copy an item from the current mode, then validate the response, storage path, and defensive effect in a test environment.' },
  notesTitle: { zh: '结果分析', en: 'Result analysis' },
  noNotes: { zh: '暂无结果分析。', en: 'No result analysis.' },
  opsec: { zh: '注意事项', en: 'Tips' },
  refs: { zh: '参考资料', en: 'References' },
  overview: { zh: '概述', en: 'Overview' },
  vulnerability: { zh: '原理', en: 'Principle' },
  exploitation: { zh: '使用方法', en: 'Usage' },
  mitigation: { zh: '防护建议', en: 'Mitigation' },
  searchPlaceholder: { zh: '筛选当前 Payload...', en: 'Filter this payload...' },
  clearSearch: { zh: '清除', en: 'Clear' },
  noItemsTitle: { zh: '没有匹配的 Payload', en: 'No matching payloads' },
  noItemsHint: { zh: '换个关键词试试。', en: 'Try another keyword.' },
  noWafTitle: { zh: '当前条目暂无 WAF 绕过内容', en: 'No WAF bypass content for this item' },
  noWafHint: { zh: '这里不会用标准 Payload 冒充绕过方案，可切回标准模式查看已有内容。', en: 'Standard payloads are not presented as bypasses. Switch to standard mode to view available content.' },
  backToNormal: { zh: '切回标准模式', en: 'Use standard mode' },
  wafAvailable: { zh: 'WAF 内容可用', en: 'WAF content available' },
  wafUnavailable: { zh: '无 WAF 内容', en: 'No WAF content' },
};

const label = (key: keyof typeof uiText, language: 'zh' | 'en') => uiText[key][language];

const countLabel = (count: number, total: number, language: 'zh' | 'en') => (
  language === 'zh' ? `${count}/${total} 条可复制` : `${count}/${total} copyable`
);

const payloadIdAliases: Record<string, string> = {
  'jwt-none-alg': 'jwt-none-attack',
  'jwt-none-algo': 'jwt-none-attack',
  'jwt-weak-secret': 'jwt-secret-bruteforce',
  'jwt-kid-injection': 'jwt-key-confusion',
  'jwt-jku-spoofing': 'jwt-jku-x5u-injection',
};

const tutorialPlaceholders = new Set([
  '选择对应payload测试',
  '选择对应 payload 测试',
  '选择绕过技术',
  'select the corresponding payload to test',
  'select a bypass technique',
]);

const tutorialFieldIsSubstantive = (value: I18nText) => {
  const values = typeof value === 'string' ? [value] : [value.zh, value.en];
  return values.some(candidate => {
    const normalized = String(candidate || '').trim().toLowerCase();
    return normalized.length >= 20 && !tutorialPlaceholders.has(normalized);
  });
};

const tutorialIsSubstantive = (tutorial?: TutorialContent) => Boolean(
  tutorial
  && tutorialFieldIsSubstantive(tutorial.overview)
  && tutorialFieldIsSubstantive(tutorial.vulnerability)
  && tutorialFieldIsSubstantive(tutorial.exploitation)
  && tutorialFieldIsSubstantive(tutorial.mitigation)
);

function PayloadDetail({ payloadId }: PayloadDetailProps) {
  const { globalVariables, bypassMode, setBypassMode, language, allPayloads } = useAppContext();
  const [copiedIndex, setCopiedIndex] = useState<string | null>(null);
  const [selectedSyntax, setSelectedSyntax] = useState<{ syntax: SyntaxPart[]; title: I18nText } | null>(null);
  const [sectionSelection, setSectionSelection] = useState<{ payloadId: string; section: DetailSection }>({
    payloadId,
    section: 'payloads',
  });
  const [payloadQueryState, setPayloadQueryState] = useState({ payloadId, value: '' });

  const resolvedPayloadId = payloadIdAliases[payloadId] || payloadId;
  const payload = allPayloads.find(item => item.id === payloadId) || allPayloads.find(item => item.id === resolvedPayloadId);
  const hasSubstantiveTutorial = tutorialIsSubstantive(payload?.tutorial);
  const hasWafContent = Boolean(payload?.wafBypass?.length);
  const requestedSection = sectionSelection.payloadId === payloadId ? sectionSelection.section : 'payloads';
  const activeSection = requestedSection === 'tutorial' && !hasSubstantiveTutorial ? 'payloads' : requestedSection;
  const setActiveSection = (section: DetailSection) => setSectionSelection({ payloadId, section });

  const payloadQuery = payloadQueryState.payloadId === payloadId ? payloadQueryState.value : '';

  const executionItems = useMemo<PayloadExecution[]>(() => {
    if (!payload) return [];
    if (bypassMode === 'waf') return payload.wafBypass || [];
    return payload.execution;
  }, [bypassMode, payload]);

  const attackChainItems = useMemo<AttackChainStep[]>(() => {
    if (!payload) return [];
    if (payload.attackChain?.length) return payload.attackChain;
    return [
      {
        title: { zh: '确认适用场景', en: 'Confirm the scenario' },
        description: payload.description,
      },
      {
        title: label('chainFallbackTitle', language),
        description: label('chainFallbackDesc', language),
        payload: executionItems[0]?.command,
      },
      {
        title: { zh: '记录结果', en: 'Record results' },
        description: payload.analysis || { zh: '记录上传响应、保存文件名、访问路径、服务端是否解析以及防护设备命中情况。', en: 'Record the upload response, saved filename, access path, server-side parsing behavior, and defensive detections.' },
      },
      {
        title: { zh: '加固复盘', en: 'Review mitigation' },
        description: payload.tutorial?.mitigation || { zh: '根据验证结果收敛上传类型、存储目录、脚本执行权限、鉴权、审计和告警策略。', en: 'Use the validation result to tighten type checks, storage paths, script execution permissions, authorization, auditing, and alerting.' },
      },
    ];
  }, [executionItems, language, payload]);

  const filteredExecutionItems = useMemo(() => {
    const query = payloadQuery.trim().toLowerCase();

    return executionItems.filter(item => {
      if (!query) return true;

      const searchable = [
        getText(item.title, language),
        getText(item.description, language),
        item.command,
      ].join(' ').toLowerCase();

      return searchable.includes(query);
    });
  }, [executionItems, language, payloadQuery]);

  if (!payload) {
    return (
      <div className="payload-not-found">
        <h2>{label('notFound', language)}</h2>
        <p>ID: {payloadId}</p>
      </div>
    );
  }

  const modeLabel = (() => {
    if (bypassMode === 'waf') return label('wafMode', language);
    return label('normalMode', language);
  })();

  const copyText = async (text: string, index: string) => {
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
    window.setTimeout(() => setCopiedIndex(null), 1800);
  };

  const copyVisible = async () => {
    if (!filteredExecutionItems.length) return;
    await copyText(filteredExecutionItems.map(item => item.command).join('\n\n'), 'all');
  };

  const renderCommandWithHighlights = (command: string) => {
    const parts = resolveVariableParts(command, globalVariables);
    const hasVariables = parts.some(part => part.key);

    if (!hasVariables) return <code>{parts.map(part => part.text).join('')}</code>;

    const elements: JSX.Element[] = parts.map((part, index) => {
      if (!part.key) return <span key={`text-${index}`}>{part.text}</span>;
      return (
        <span key={`var-${index}`} className="var-highlight" title={`${part.raw} -> ${part.value}`}>
          {part.text}
        </span>
      );
    });
    return <code>{elements}</code>;
  };

  const platformLabel = (platform?: PayloadExecution['platform']) => {
    if (platform === 'windows') return label('platformWindows', language);
    if (platform === 'linux') return label('platformLinux', language);
    return label('platformAll', language);
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
            <span className="meta-label">{label('category', language)}</span>
            <span className="meta-value">{getText(payload.category, language)}</span>
          </div>
          {payload.subCategory && (
            <div className="meta-item">
              <span className="meta-label">{label('subCategory', language)}</span>
              <span className="meta-value">{getText(payload.subCategory, language)}</span>
            </div>
          )}
          {hasSubstantiveTutorial && payload.tutorial && (
            <div className="meta-item">
              <span className="meta-label">{label('difficulty', language)}</span>
              <span className="meta-value difficulty" style={{ color: getDifficultyColor(payload.tutorial.difficulty) }}>
                {payload.tutorial.difficulty.toUpperCase()}
              </span>
            </div>
          )}
        </div>
      </div>

      {payload.prerequisites?.length ? (
        <div className="prerequisites-section">
          <h3>{label('prerequisites', language)}</h3>
          <ul className="prerequisites-list">
            {payload.prerequisites.map((prereq, index) => (
              <li key={index}>{getText(prereq, language)}</li>
            ))}
          </ul>
        </div>
      ) : null}

      <div className="section-tabs" role="tablist" aria-label="Payload 内容">
        <button type="button" role="tab" aria-selected={activeSection === 'payloads'} className={`section-tab ${activeSection === 'payloads' ? 'active' : ''}`} onClick={() => setActiveSection('payloads')}>
          {label('tabPayloads', language)}
        </button>
        <button type="button" role="tab" aria-selected={activeSection === 'chain'} className={`section-tab ${activeSection === 'chain' ? 'active' : ''}`} onClick={() => setActiveSection('chain')}>
          {label('tabAttackChain', language)}
        </button>
        {hasSubstantiveTutorial && (
          <button type="button" role="tab" aria-selected={activeSection === 'tutorial'} className={`section-tab ${activeSection === 'tutorial' ? 'active' : ''}`} onClick={() => setActiveSection('tutorial')}>
            {label('tabTutorial', language)}
          </button>
        )}
      </div>

      <span className="sr-only" aria-live="polite">
        {copiedIndex ? (copiedIndex === 'all' ? label('copiedVisible', language) : label('copied', language)) : ''}
      </span>

      {activeSection === 'payloads' && (
        <div className="execution-section" role="tabpanel">
          <div className="execution-toolbar">
            <div className="payload-list-info">
              <span className="mode-label">{modeLabel}</span>
              <span className="item-count">{countLabel(filteredExecutionItems.length, executionItems.length, language)}</span>
              <span className={`waf-content-status ${hasWafContent ? 'available' : 'unavailable'}`}>
                {hasWafContent ? label('wafAvailable', language) : label('wafUnavailable', language)}
              </span>
            </div>
            <button
              className={`copy-all-btn ${copiedIndex === 'all' ? 'copied' : ''}`}
              onClick={copyVisible}
              disabled={!filteredExecutionItems.length}
            >
              {copiedIndex === 'all' ? label('copiedVisible', language) : label('copyVisible', language)}
            </button>
          </div>

          <div className="payload-controls">
            <div className="payload-search-field">
              <input
                type="search"
                name="payload-command-search"
                value={payloadQuery}
                onChange={event => setPayloadQueryState({ payloadId, value: event.target.value })}
                placeholder={label('searchPlaceholder', language)}
                aria-label={label('searchPlaceholder', language)}
              />
              {payloadQuery && (
                <button type="button" onClick={() => setPayloadQueryState({ payloadId, value: '' })} aria-label={label('clearSearch', language)}>
                  ×
                </button>
              )}
            </div>
          </div>

          {!filteredExecutionItems.length ? (
            <div className="payload-empty-result">
              <strong>{bypassMode === 'waf' && !hasWafContent ? label('noWafTitle', language) : label('noItemsTitle', language)}</strong>
              <span>{bypassMode === 'waf' && !hasWafContent ? label('noWafHint', language) : label('noItemsHint', language)}</span>
              {bypassMode === 'waf' && !hasWafContent && (
                <button type="button" onClick={() => setBypassMode('normal')}>{label('backToNormal', language)}</button>
              )}
            </div>
          ) : (
            <div className="execution-list">
              {filteredExecutionItems.map((exec, index) => {
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
                        <pre className="code-block">{renderCommandWithHighlights(exec.command)}</pre>
                        <div className="code-actions">
                          {exec.syntaxBreakdown?.length ? (
                            <button
                              className="syntax-btn"
                              onClick={() => setSelectedSyntax({ syntax: exec.syntaxBreakdown!, title: exec.title })}
                            >
                              {label('syntax', language)}
                            </button>
                          ) : null}
                          <button className={`copy-btn ${copiedIndex === copyId ? 'copied' : ''}`} onClick={() => copyText(exec.command, copyId)}>
                            {copiedIndex === copyId ? label('copied', language) : label('copy', language)}
                          </button>
                        </div>
                      </div>
                    </div>
                  </article>
                );
              })}
            </div>
          )}
        </div>
      )}

      {activeSection === 'chain' && (
        <div className="attack-chain-section" role="tabpanel">
          <div className="chain-timeline">
            {attackChainItems.map((step, index) => {
              const copyId = `chain-${index}`;
              return (
                <article key={`${getText(step.title, language)}-${index}`} className="chain-step">
                  <div className="chain-index">{String(index + 1).padStart(2, '0')}</div>
                  <div className="chain-body">
                    <h3>{getText(step.title, language)}</h3>
                    <p>{getText(step.description, language)}</p>
                    {step.payload ? (
                      <div className="code-block-wrapper chain-payload">
                        <span>{label('chainPayload', language)}</span>
                        <pre className="code-block">{renderCommandWithHighlights(step.payload)}</pre>
                        <div className="code-actions">
                          <button className={`copy-btn ${copiedIndex === copyId ? 'copied' : ''}`} onClick={() => copyText(step.payload!, copyId)}>
                            {copiedIndex === copyId ? label('copied', language) : label('copy', language)}
                          </button>
                        </div>
                      </div>
                    ) : null}
                  </div>
                </article>
              );
            })}
          </div>
        </div>
      )}

      {activeSection === 'tutorial' && hasSubstantiveTutorial && payload.tutorial && (
        <div className="tutorial-section" role="tabpanel">
          <div className="tutorial-card">
            <h3>{label('overview', language)}</h3>
            <p>{getText(payload.tutorial.overview, language)}</p>
          </div>
          <div className="tutorial-card">
            <h3>{label('vulnerability', language)}</h3>
            <p>{getText(payload.tutorial.vulnerability, language)}</p>
          </div>
          <div className="tutorial-card">
            <h3>{label('exploitation', language)}</h3>
            <p>{getText(payload.tutorial.exploitation, language)}</p>
          </div>
          <div className="tutorial-card">
            <h3>{label('mitigation', language)}</h3>
            <p>{getText(payload.tutorial.mitigation, language)}</p>
          </div>
          <div className="analysis-card">
            <h3>{label('notesTitle', language)}</h3>
            <p>{payload.analysis ? getText(payload.analysis, language) : label('noNotes', language)}</p>
          </div>
          {payload.opsecTips?.length ? (
            <div className="analysis-card warning">
              <h3>{label('opsec', language)}</h3>
              <ul>
                {payload.opsecTips.map((tip, index) => <li key={index}>{getText(tip, language)}</li>)}
              </ul>
            </div>
          ) : null}
          {payload.references?.length ? (
            <div className="analysis-card">
              <h3>{label('refs', language)}</h3>
              <ul className="references-list">
                {payload.references.map((ref, index) => (
                  <li key={index}><a href={ref} target="_blank" rel="noopener noreferrer">{ref}</a></li>
                ))}
              </ul>
            </div>
          ) : null}
        </div>
      )}

      {selectedSyntax && (
        <SyntaxModal syntax={selectedSyntax.syntax} title={selectedSyntax.title} onClose={() => setSelectedSyntax(null)} />
      )}

      <style>{`
        .payload-detail {
          width: min(100%, 1180px);
          margin: 0 auto;
          padding: 22px;
        }

        .payload-header {
          display: grid;
          grid-template-columns: minmax(0, 1fr) 220px;
          gap: 20px;
          padding-bottom: 18px;
          border-bottom: 1px solid var(--border-color);
          margin-bottom: 18px;
        }

        .payload-title-section {
          min-width: 0;
        }

        .payload-tags {
          display: flex;
          flex-wrap: wrap;
          gap: 6px;
          margin-bottom: 10px;
        }

        .payload-title {
          font-size: 26px;
          font-weight: 700;
          line-height: 1.25;
          margin-bottom: 8px;
          background: var(--gradient-cyber);
          -webkit-background-clip: text;
          -webkit-text-fill-color: transparent;
          background-clip: text;
          overflow-wrap: anywhere;
        }

        .payload-description {
          font-size: 14px;
          color: var(--text-secondary);
          line-height: 1.65;
        }

        .payload-meta {
          display: flex;
          flex-direction: column;
          gap: 10px;
        }

        .meta-item {
          display: flex;
          flex-direction: column;
          gap: 3px;
          min-width: 0;
        }

        .meta-label {
          font-size: 11px;
          text-transform: uppercase;
          color: var(--text-muted);
        }

        .meta-value {
          font-size: 14px;
          font-weight: 600;
          overflow-wrap: anywhere;
        }

        .prerequisites-section {
          background: var(--bg-card);
          border: 1px solid var(--border-color);
          border-radius: 8px;
          padding: 14px;
          margin-bottom: 18px;
        }

        .prerequisites-section h3 {
          font-size: 14px;
          margin-bottom: 10px;
        }

        .prerequisites-list {
          list-style: none;
          display: grid;
          gap: 6px;
        }

        .prerequisites-list li {
          font-size: 13px;
          color: var(--text-secondary);
          line-height: 1.55;
        }

        .section-tabs {
          display: flex;
          gap: 8px;
          margin-bottom: 16px;
          overflow-x: auto;
          padding-bottom: 4px;
        }

        .section-tab {
          flex: 0 0 auto;
          min-width: 0;
          background: var(--bg-tertiary);
          border: 1px solid var(--border-color);
          color: var(--text-secondary);
          padding: 9px 14px;
          border-radius: 6px;
          font-size: 13px;
          white-space: nowrap;
          overflow: hidden;
          text-overflow: ellipsis;
          cursor: pointer;
          transition: all var(--transition-fast);
        }

        .section-tab:hover,
        .section-tab.active {
          border-color: var(--neon-cyan);
          color: var(--neon-cyan);
          background: rgba(0, 240, 255, 0.08);
        }

        .execution-toolbar {
          display: flex;
          justify-content: space-between;
          align-items: center;
          gap: 12px;
          margin-bottom: 12px;
        }

        .payload-list-info {
          display: flex;
          align-items: center;
          gap: 10px;
          min-width: 0;
        }

        .mode-label {
          font-size: 14px;
          font-weight: 700;
          color: var(--text-primary);
          overflow-wrap: anywhere;
        }

        .item-count {
          font-size: 12px;
          color: var(--text-muted);
          white-space: nowrap;
        }

        .waf-content-status {
          padding: 2px 7px;
          border: 1px solid var(--border-color);
          border-radius: 4px;
          color: var(--text-muted);
          font-size: 11px;
          white-space: nowrap;
        }

        .waf-content-status.available {
          border-color: color-mix(in srgb, var(--neon-green) 42%, var(--border-color));
          color: var(--neon-green);
        }

        .payload-controls {
          display: grid;
          grid-template-columns: minmax(220px, 1fr);
          gap: 10px;
          margin-bottom: 14px;
        }

        .payload-mode-filter {
          display: flex;
          align-items: center;
          gap: 4px;
          padding: 4px;
          background: var(--bg-tertiary);
          border: 1px solid var(--border-color);
          border-radius: 6px;
        }

        .payload-mode-filter button {
          min-height: 34px;
          padding: 7px 10px;
          border-radius: 5px;
          background: transparent;
          color: var(--text-secondary);
          font-size: 12px;
          white-space: nowrap;
        }

        .payload-mode-filter button:hover:not(:disabled),
        .payload-mode-filter button.active {
          background: rgba(0, 240, 255, 0.1);
          color: var(--neon-cyan);
        }

        .payload-mode-filter button:disabled {
          cursor: not-allowed;
          opacity: 0.42;
        }

        .payload-search-field {
          display: flex;
          align-items: center;
          min-width: 0;
          background: var(--bg-tertiary);
          border: 1px solid var(--border-color);
          border-radius: 6px;
          overflow: hidden;
        }

        .payload-search-field:focus-within {
          border-color: var(--neon-cyan);
          box-shadow: 0 0 12px rgba(0, 240, 255, 0.14);
        }

        .payload-search-field input {
          flex: 1;
          min-width: 0;
          border: 0;
          background: transparent;
          box-shadow: none;
          padding: 9px 12px;
          font-size: 13px;
        }

        .payload-search-field button {
          flex: 0 0 auto;
          width: 36px;
          height: 36px;
          background: transparent;
          color: var(--text-muted);
          font-size: 18px;
        }

        .payload-search-field button:hover {
          color: var(--neon-red);
        }

        .copy-all-btn,
        .copy-btn,
        .syntax-btn {
          background: var(--bg-tertiary);
          border: 1px solid var(--border-color);
          color: var(--text-secondary);
          border-radius: 6px;
          cursor: pointer;
          transition: all var(--transition-fast);
          white-space: nowrap;
        }

        .copy-all-btn {
          border-color: var(--neon-cyan);
          color: var(--neon-cyan);
          padding: 8px 14px;
          font-size: 13px;
          font-weight: 600;
        }

        .copy-all-btn:disabled {
          cursor: not-allowed;
          opacity: 0.45;
          border-color: var(--border-color);
          color: var(--text-muted);
        }

        .copy-btn,
        .syntax-btn {
          min-height: 36px;
          padding: 7px 12px;
          font-size: 12px;
        }

        .copy-all-btn:not(:disabled):hover,
        .copy-btn:hover,
        .syntax-btn:hover {
          border-color: var(--neon-cyan);
          color: var(--neon-cyan);
          background: rgba(0, 240, 255, 0.1);
        }

        .copy-all-btn.copied,
        .copy-btn.copied {
          border-color: var(--neon-green);
          color: var(--neon-green);
          background: rgba(0, 255, 136, 0.1);
        }

        .execution-list {
          display: flex;
          flex-direction: column;
          gap: 12px;
        }

        .execution-item {
          min-width: 0;
        }

        .execution-content {
          background: var(--bg-card);
          border: 1px solid var(--border-color);
          border-radius: 8px;
          padding: 14px;
          transition: border-color var(--transition-fast);
        }

        .execution-content:hover {
          border-color: rgba(0, 240, 255, 0.55);
        }

        .execution-header {
          display: flex;
          justify-content: space-between;
          align-items: flex-start;
          gap: 12px;
          margin-bottom: 8px;
        }

        .execution-heading {
          display: flex;
          align-items: center;
          gap: 9px;
          min-width: 0;
        }

        .item-index {
          flex: 0 0 auto;
          font-family: var(--font-mono);
          font-size: 11px;
          color: var(--neon-cyan);
          border: 1px solid rgba(0, 240, 255, 0.35);
          border-radius: 5px;
          padding: 2px 6px;
        }

        .execution-title {
          font-size: 15px;
          line-height: 1.35;
          overflow-wrap: anywhere;
        }

        .execution-badges {
          display: flex;
          flex-wrap: wrap;
          gap: 6px;
          justify-content: flex-end;
        }

        .badge {
          font-size: 11px;
          padding: 2px 7px;
          border-radius: 5px;
          background: var(--bg-tertiary);
          color: var(--text-secondary);
          white-space: nowrap;
        }

        .badge.platform-windows { color: var(--neon-blue); }
        .badge.platform-linux { color: var(--neon-orange); }
        .badge.admin { color: var(--neon-red); }

        .execution-desc {
          font-size: 13px;
          color: var(--text-muted);
          line-height: 1.55;
          margin-bottom: 10px;
        }

        .code-block-wrapper {
          display: flex;
          flex-direction: column;
          gap: 8px;
        }

        .code-block {
          margin: 0;
          background: var(--bg-tertiary);
          border: 1px solid var(--border-color);
          border-radius: 6px;
          padding: 12px 14px;
          overflow-x: hidden;
          position: relative;
          max-width: 100%;
        }

        .code-block code {
          display: block;
          font-family: var(--font-mono);
          font-size: 13px;
          line-height: 1.55;
          color: var(--text-primary);
          white-space: pre-wrap;
          overflow-wrap: anywhere;
          word-break: break-word;
          min-width: 0;
        }

        .var-highlight {
          background: rgba(0, 255, 136, 0.15);
          color: var(--neon-green);
          padding: 1px 3px;
          border-radius: 3px;
          border-bottom: 1px dashed var(--neon-green);
        }

        .code-actions {
          display: flex;
          justify-content: flex-end;
          gap: 8px;
          min-width: 0;
        }

        .payload-empty-result {
          display: flex;
          flex-direction: column;
          gap: 4px;
          align-items: center;
          justify-content: center;
          min-height: 150px;
          padding: 22px;
          border: 1px dashed var(--border-color);
          border-radius: 8px;
          color: var(--text-muted);
          text-align: center;
        }

        .payload-empty-result strong {
          color: var(--text-primary);
          font-size: 15px;
        }

        .payload-empty-result button {
          min-height: 44px;
          margin-top: 10px;
          padding: 8px 14px;
          border: 1px solid var(--neon-cyan);
          border-radius: 6px;
          background: transparent;
          color: var(--neon-cyan);
          font-weight: 700;
        }

        .analysis-section,
        .attack-chain-section,
        .tutorial-section {
          display: flex;
          flex-direction: column;
          gap: 14px;
        }

        .chain-timeline {
          display: flex;
          flex-direction: column;
          gap: 12px;
        }

        .chain-step {
          display: grid;
          grid-template-columns: 44px minmax(0, 1fr);
          gap: 12px;
          min-width: 0;
        }

        .chain-index {
          width: 36px;
          height: 36px;
          border: 1px solid rgba(0, 240, 255, 0.35);
          border-radius: 6px;
          display: flex;
          align-items: center;
          justify-content: center;
          font-family: var(--font-mono);
          font-size: 12px;
          color: var(--neon-cyan);
          background: rgba(0, 240, 255, 0.06);
        }

        .chain-body {
          min-width: 0;
          background: var(--bg-card);
          border: 1px solid var(--border-color);
          border-radius: 8px;
          padding: 15px;
        }

        .chain-body h3 {
          font-size: 15px;
          color: var(--text-primary);
          margin-bottom: 8px;
          overflow-wrap: anywhere;
        }

        .chain-body p {
          font-size: 13px;
          color: var(--text-secondary);
          line-height: 1.7;
        }

        .chain-payload {
          margin-top: 12px;
        }

        .chain-payload > span {
          font-size: 12px;
          color: var(--text-muted);
        }

        .analysis-card,
        .tutorial-card {
          background: var(--bg-card);
          border: 1px solid var(--border-color);
          border-radius: 8px;
          padding: 16px;
        }

        .analysis-card.warning {
          border-color: rgba(255, 102, 0, 0.35);
        }

        .analysis-card h3,
        .tutorial-card h3 {
          font-size: 14px;
          color: var(--neon-cyan);
          margin-bottom: 10px;
        }

        .analysis-card p,
        .tutorial-card p,
        .analysis-card li {
          font-size: 13px;
          color: var(--text-secondary);
          line-height: 1.75;
        }

        .analysis-card ul,
        .tutorial-card ul {
          list-style: none;
        }

        .references-list li {
          padding: 5px 0;
          overflow-wrap: anywhere;
        }

        .payload-not-found {
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          height: 100%;
          text-align: center;
        }

        @media (max-width: 900px) {
          .payload-detail {
            padding: 14px;
          }

          .payload-header {
            grid-template-columns: 1fr;
            gap: 14px;
          }

          .payload-meta {
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
          }

          .execution-toolbar,
          .execution-header {
            align-items: stretch;
            flex-direction: column;
          }

          .payload-list-info {
            align-items: flex-start;
            justify-content: space-between;
          }

          .payload-controls {
            grid-template-columns: 1fr;
          }

          .payload-mode-filter {
            overflow-x: auto;
          }

          .payload-mode-filter button {
            flex: 1 0 auto;
            min-height: 38px;
          }

          .execution-badges {
            justify-content: flex-start;
          }

          .code-actions {
            justify-content: stretch;
          }

          .copy-btn,
          .syntax-btn,
          .copy-all-btn {
            flex: 1;
          }
        }

        @media (max-width: 520px) {
          .payload-detail {
            padding: 10px;
          }

          .section-tabs {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(92px, 1fr));
            gap: 6px;
            overflow: visible;
          }

          .section-tab {
            width: 100%;
            min-height: 44px;
            padding: 9px 7px;
            text-align: center;
          }

          .payload-title {
            font-size: 21px;
          }

          .payload-description,
          .execution-desc {
            font-size: 12px;
          }

          .payload-meta {
            grid-template-columns: 1fr;
          }

          .execution-content,
          .chain-body,
          .analysis-card,
          .tutorial-card,
          .prerequisites-section {
            padding: 12px;
          }

          .execution-heading {
            align-items: flex-start;
          }

          .payload-list-info {
            flex-wrap: wrap;
          }

          .execution-toolbar {
            gap: 10px;
          }

          .copy-all-btn {
            width: 100%;
            min-height: 40px;
          }

          .code-actions {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(112px, 1fr));
          }

          .code-block {
            padding: 10px 11px;
          }

          .code-block code {
            font-size: 12px;
            line-height: 1.55;
          }
        }
      `}</style>
    </div>
  );
}

export default PayloadDetail;
