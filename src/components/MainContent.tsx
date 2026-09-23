import { lazy, Suspense, useMemo } from 'react';
import { useLanguage, useNav, useSearch, useStaticData } from '../appContext';
import { getText, t } from '../i18n';
import { openProtectedExternalLink } from '../protectedLinks';
import PayloadDetail from './PayloadDetail';
import ToolDetail from './ToolDetail';
import ClientDownloads from './ClientDownloads';
import SimpleTextDetail from './SimpleTextDetail';
import type { PublicClientBuildInfo } from '../types';
import '../styles/main-content.css';

const LazyCtfToolkit = lazy(() => import('./CtfToolkit'));

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
    activeView,
    setActiveView,
  } = useNav();
  const { dataLoading, dataError, allPayloads, allToolCommands, allPayloadNavigation, allToolNavigation } = useStaticData();
  const { deferredSearchQuery, searchMatches, setSearchQuery } = useSearch();
  const { language } = useLanguage();

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
    // CTF 标签页下全局搜索沿用 Payload 库结果（工具命令属于渗透工作流）。
    const isPayloadSearch = activeTab !== 'tools';
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

    if (activeTab === 'ctf' && !query) {
      return (
        <Suspense fallback={<div className="lazy-loading" role="status" aria-live="polite">正在加载 CTF 解题工具箱...</div>}>
          <LazyCtfToolkit />
        </Suspense>
      );
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
    </main>
  );
}

export default MainContent;
