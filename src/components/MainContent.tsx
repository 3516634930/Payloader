import { useMemo } from 'react';
import { useAppContext } from '../appContext';
import { getText, t } from '../i18n';
import { openProtectedExternalLink } from '../protectedLinks';
import PayloadDetail from './PayloadDetail';
import ToolDetail from './ToolDetail';
import ClientDownloads from './ClientDownloads';
import SimpleTextDetail from './SimpleTextDetail';
import type { PublicClientBuildInfo } from '../types';

interface MainContentProps {
  clientBuildInfo: PublicClientBuildInfo | null;
}

function MainContent({ clientBuildInfo }: MainContentProps) {
  const {
    selectedPayloadId,
    selectedToolId,
    setSelectedPayloadId,
    setSelectedToolId,
    activeTab,
    language,
    dataLoading,
    dataError,
    deferredSearchQuery,
    searchMatches,
    setSearchQuery,
    allPayloads,
    allToolCommands,
    allPayloadNavigation,
    allToolNavigation,
    activeView,
    setActiveView,
  } = useAppContext();

  const query = deferredSearchQuery.trim();

  const payloadResults = useMemo(() => {
    if (!query) return [];
    return allPayloads
      .filter(payload => searchMatches.payloadIds.has(payload.id))
      .map(payload => ({
        payload,
        commandCount: payload.execution.length,
        bypassCount: payload.wafBypass?.length || 0,
      }))
      .slice(0, 80);
  }, [allPayloads, query, searchMatches.payloadIds]);

  const toolResults = useMemo(() => {
    if (!query) return [];
    return allToolCommands
      .filter(tool => searchMatches.toolIds.has(tool.id))
      .slice(0, 80);
  }, [allToolCommands, query, searchMatches.toolIds]);

  const homeActions = useMemo(() => {
    const findDestination = (item: (typeof allPayloadNavigation)[number]): { payloadId?: string; toolId?: string } | null => {
      if (item.payloadId) return { payloadId: item.payloadId };
      if (item.toolId) return { toolId: item.toolId };
      for (const child of item.children || []) {
        const destination = findDestination(child);
        if (destination) return destination;
      }
      return null;
    };

    const navigation = activeTab === 'payloads' ? allPayloadNavigation : allToolNavigation;
    return navigation
      .map(item => ({ label: getText(item.name, language), destination: findDestination(item) }))
      .filter(action => action.destination)
      .slice(0, 8);
  }, [activeTab, allPayloadNavigation, allToolNavigation, language]);

  const openPayload = (payloadId: string) => {
    setActiveView('workspace');
    setSelectedPayloadId(payloadId);
    setSelectedToolId(null);
    setSearchQuery('');
  };

  const openTool = (toolId: string) => {
    setActiveView('workspace');
    const tool = allToolCommands.find(candidate => candidate.id === toolId);
    if (tool?.externalUrl && openProtectedExternalLink(tool.externalUrl)) {
      setSearchQuery('');
      return;
    }
    setSelectedToolId(toolId);
    setSelectedPayloadId(null);
    setSearchQuery('');
  };

  const openHomeAction = (destination: { payloadId?: string; toolId?: string }) => {
    if (destination.payloadId) openPayload(destination.payloadId);
    else if (destination.toolId) openTool(destination.toolId);
  };

  const renderSearchResults = () => {
    const isPayloadSearch = activeTab === 'payloads';
    const resultCount = isPayloadSearch ? payloadResults.length : toolResults.length;
    const title = language === 'zh'
      ? `搜索结果：${deferredSearchQuery.trim()}`
      : `Search results: ${deferredSearchQuery.trim()}`;
    const hint = language === 'zh'
      ? '点开结果后即可查看可复制列表。'
      : 'Open a result to view the copyable list.';

    return (
      <div className="search-results-view">
        <div className="search-results-head">
          <div>
            <h2>{title}</h2>
            <p>{resultCount ? hint : (language === 'zh' ? '没有匹配的数据，换个关键词试试。' : 'No matches. Try another keyword.')}</p>
          </div>
          <button type="button" onClick={() => setSearchQuery('')}>{language === 'zh' ? '清除搜索' : 'Clear'}</button>
        </div>

        {resultCount ? (
          <div className="result-list">
            {isPayloadSearch ? (
              payloadResults.map(result => result && (
                <button key={result.payload.id} type="button" className="result-item" onClick={() => openPayload(result.payload.id)}>
                  <span className="result-title">{getText(result.payload.name, language)}</span>
                  <span className="result-desc">{getText(result.payload.description, language)}</span>
                  <span className="result-meta">
                    {getText(result.payload.category, language)}
                    <span>{language === 'zh' ? `${result.commandCount} 条标准` : `${result.commandCount} standard`}</span>
                    {result.bypassCount ? <span>{language === 'zh' ? `${result.bypassCount} 条绕过` : `${result.bypassCount} bypass`}</span> : null}
                  </span>
                </button>
              ))
            ) : (
              toolResults.map(tool => (
                <button key={tool.id} type="button" className="result-item" onClick={() => openTool(tool.id)}>
                  <span className="result-title">{getText(tool.name, language)}</span>
                  <span className="result-desc">{getText(tool.description, language)}</span>
                  <span className="result-meta">
                    {getText(tool.category, language)}
                    <span>{tool.externalUrl ? (language === 'zh' ? '外链跳转' : 'External link') : (language === 'zh' ? `${tool.commands.length} 条命令` : `${tool.commands.length} commands`)}</span>
                  </span>
                </button>
              ))
            )}
          </div>
        ) : (
          <div className="empty-search">
            <strong>{language === 'zh' ? '没有匹配结果' : 'No matches'}</strong>
            <span>{language === 'zh' ? '可以搜索漏洞名、Payload 片段、命令、工具名或标签。' : 'Search by name, payload snippet, command, tool, or tag.'}</span>
          </div>
        )}
      </div>
    );
  };

  const renderContent = () => {
    if (dataLoading) {
      return (
        <div className="empty-state" role="status" aria-live="polite">
          <h2>正在加载数据</h2>
          <p>Payloader 正在读取本地 SQLite 数据库</p>
        </div>
      );
    }

    if (dataError) {
      return (
        <div className="empty-state" role="alert">
          <h2>数据加载失败</h2>
          <p>{dataError}</p>
        </div>
      );
    }

    if (activeView === 'clientDownloads') {
      return <ClientDownloads clientBuildInfo={clientBuildInfo} />;
    }

    if (query) {
      return renderSearchResults();
    }

    if (activeTab === 'payloads') {
      if (selectedPayloadId) {
        const p = allPayloads.find(x => x.id === selectedPayloadId);
        const cat = p ? (typeof p.category === 'string' ? p.category : p.category.zh) : '';
        if (cat === '自定义') return <SimpleTextDetail payloadId={selectedPayloadId} />;
        return <PayloadDetail payloadId={selectedPayloadId} />;
      }
      return (
        <section className="empty-state" aria-labelledby="payload-empty-title">
          <h2 id="payload-empty-title">{t('main.selectPayload', language)}</h2>
          <p>{t('main.selectPayloadHint', language)}</p>
          <div className="empty-actions" aria-label="常用 Payload 分类">
            {homeActions.map(action => (
              <button key={action.label} type="button" onClick={() => openHomeAction(action.destination!)}>
                <span>{action.label}</span>
                <small>打开分类</small>
              </button>
            ))}
          </div>
        </section>
      );
    }

    if (selectedToolId) {
      return <ToolDetail toolId={selectedToolId} />;
    }

    // custom payload selected while on tools tab
    if (selectedPayloadId) {
      const p = allPayloads.find(x => x.id === selectedPayloadId);
      const cat = p ? (typeof p.category === 'string' ? p.category : p.category.zh) : '';
      if (cat === '自定义') return <SimpleTextDetail payloadId={selectedPayloadId} />;
    }

    return (
      <section className="empty-state" aria-labelledby="tool-empty-title">
        <h2 id="tool-empty-title">{t('main.selectTool', language)}</h2>
        <p>{t('main.selectToolHint', language)}</p>
        <div className="empty-actions" aria-label="常用工具分类">
          {homeActions.map(action => (
            <button key={action.label} type="button" onClick={() => openHomeAction(action.destination!)}>
              <span>{action.label}</span>
              <small>打开分类</small>
            </button>
          ))}
        </div>
      </section>
    );
  };

  return (
    <main className="main-content" id="main-content" tabIndex={-1}>
      {renderContent()}
      <style>{`
        .main-content {
          flex: 1;
          height: calc(100vh - var(--app-header-height));
          height: calc(100dvh - var(--app-header-height));
          overflow-y: auto;
          overflow-x: hidden;
          background: var(--bg-primary);
          min-width: 0;
          min-height: 0;
        }

        .empty-state {
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          min-height: 100%;
          padding: 40px;
          text-align: center;
        }

        .empty-state h2 {
          font-size: 24px;
          font-weight: 600;
          margin-bottom: 12px;
          color: var(--text-primary);
        }

        .empty-state > p {
          font-size: 14px;
          color: var(--text-secondary);
          margin-bottom: 24px;
        }

        .empty-actions {
          display: grid;
          grid-template-columns: repeat(2, minmax(0, 1fr));
          gap: 8px;
          width: min(100%, 560px);
        }

        .empty-actions button {
          display: grid;
          grid-template-columns: minmax(0, 1fr) auto;
          align-items: center;
          gap: 10px;
          min-width: 0;
          min-height: 48px;
          padding: 10px 12px;
          border: 1px solid var(--border-color);
          border-radius: 6px;
          background: transparent;
          color: var(--text-primary);
          text-align: left;
        }

        .empty-actions button:hover {
          border-color: var(--neon-cyan);
          background: var(--bg-hover);
        }

        .empty-actions span {
          min-width: 0;
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
          font-weight: 700;
        }

        .empty-actions small {
          color: var(--text-muted);
          font-size: 11px;
        }

        .search-results-view {
          width: min(100%, 1180px);
          margin: 0 auto;
          padding: 22px;
        }

        .search-results-head {
          display: flex;
          align-items: flex-start;
          justify-content: space-between;
          gap: 16px;
          margin-bottom: 16px;
          padding-bottom: 14px;
          border-bottom: 1px solid var(--border-color);
        }

        .search-results-head h2 {
          font-size: 22px;
          line-height: 1.3;
          margin-bottom: 6px;
          overflow-wrap: anywhere;
        }

        .search-results-head p {
          color: var(--text-muted);
          font-size: 13px;
        }

        .search-results-head button {
          flex: 0 0 auto;
          min-height: 36px;
          padding: 8px 12px;
          border-radius: 6px;
          border: 1px solid var(--border-color);
          background: var(--bg-tertiary);
          color: var(--text-secondary);
        }

        .search-results-head button:hover {
          border-color: var(--neon-cyan);
          color: var(--neon-cyan);
        }

        .result-list {
          display: grid;
          grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
          gap: 10px;
        }

        .result-item {
          display: flex;
          flex-direction: column;
          align-items: stretch;
          gap: 7px;
          min-width: 0;
          padding: 14px;
          border-radius: 8px;
          border: 1px solid var(--border-color);
          background: var(--bg-card);
          color: var(--text-primary);
          text-align: left;
          transition: border-color var(--transition-fast), background var(--transition-fast);
        }

        .result-item:hover {
          border-color: var(--neon-cyan);
          background: var(--bg-hover);
        }

        .result-title {
          font-size: 15px;
          font-weight: 700;
          line-height: 1.35;
          overflow-wrap: anywhere;
        }

        .result-desc {
          color: var(--text-secondary);
          font-size: 13px;
          line-height: 1.55;
          overflow-wrap: anywhere;
        }

        .result-meta {
          display: flex;
          flex-wrap: wrap;
          gap: 6px;
          color: var(--text-muted);
          font-size: 12px;
        }

        .result-meta span {
          color: var(--neon-cyan);
        }

        .empty-search {
          display: flex;
          flex-direction: column;
          align-items: center;
          gap: 6px;
          min-height: 220px;
          padding: 28px;
          border: 1px dashed var(--border-color);
          border-radius: 8px;
          color: var(--text-muted);
          text-align: center;
        }

        .empty-search strong {
          color: var(--text-primary);
          font-size: 16px;
        }

        @media (max-width: 900px) {
          .empty-state {
            padding: 24px 16px;
            justify-content: flex-start;
          }

          .search-results-view {
            padding: 14px;
          }

          .search-results-head {
            flex-direction: column;
            align-items: stretch;
          }

          .search-results-head button {
            width: 100%;
          }

          .result-list {
            grid-template-columns: 1fr;
          }
        }

        @media (max-width: 520px) {
          .empty-state {
            padding: 18px 12px;
          }

          .empty-state h2,
          .search-results-head h2 {
            font-size: 20px;
          }

          .empty-actions {
            grid-template-columns: 1fr;
          }
        }
      `}</style>
    </main>
  );
}

export default MainContent;
