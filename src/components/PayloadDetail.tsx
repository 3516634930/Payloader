import { useMemo, useState } from 'react';
import type { JSX } from 'react';
import { useLanguage, useNav, useSession, useStaticData } from '../appContext';
import { getText } from '../i18n';
import type { AttackChainStep, I18nText, PayloadExecution, SyntaxPart } from '../types';
import { resolveVariableParts, resolveVariableText } from '../utils/variables';
import { useCopyFeedback } from '../utils/clipboard';
import SyntaxModal from './SyntaxModal';
import { label, payloadIdAliases, tutorialIsSubstantive } from './payloadDetailText';
import type { DetailSection } from './payloadDetailText';
import PayloadDetailHeader from './PayloadDetailHeader';
import ExecutionListPanel from './ExecutionListPanel';
import AttackChainPanel from './AttackChainPanel';
import TutorialPanel from './TutorialPanel';
import '../styles/payload-detail.css';

interface PayloadDetailProps {
  payloadId: string;
}

function PayloadDetail({ payloadId }: PayloadDetailProps) {
  const { globalVariables } = useSession();
  const { bypassMode } = useNav();
  const { language } = useLanguage();
  const { allPayloads } = useStaticData();
  const { copiedKey: copiedIndex, copy } = useCopyFeedback();
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

  const copyText = (text: string, index: string) => {
    void copy(resolveVariableText(text, globalVariables), index);
  };

  const copyVisible = () => {
    if (!filteredExecutionItems.length) return;
    copyText(filteredExecutionItems.map(item => item.command).join('\n\n'), 'all');
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

  return (
    <div className="payload-detail">
      <PayloadDetailHeader
        payload={payload}
        hasSubstantiveTutorial={hasSubstantiveTutorial}
        language={language}
        activeSection={activeSection}
        onSelectSection={setActiveSection}
        copiedKey={copiedIndex}
      />

      {activeSection === 'payloads' && (
        <ExecutionListPanel
          items={filteredExecutionItems}
          totalCount={executionItems.length}
          modeLabel={modeLabel}
          hasWafContent={hasWafContent}
          payloadQuery={payloadQuery}
          onQueryChange={event => setPayloadQueryState({ payloadId, value: event.target.value })}
          onClearQuery={() => setPayloadQueryState({ payloadId, value: '' })}
          copiedKey={copiedIndex}
          onCopy={copyText}
          onCopyVisible={copyVisible}
          onSelectSyntax={setSelectedSyntax}
          renderCommand={renderCommandWithHighlights}
        />
      )}

      {activeSection === 'chain' && (
        <AttackChainPanel
          steps={attackChainItems}
          language={language}
          copiedKey={copiedIndex}
          onCopy={copyText}
          renderCommand={renderCommandWithHighlights}
        />
      )}

      {activeSection === 'tutorial' && hasSubstantiveTutorial && payload.tutorial && (
        <TutorialPanel payload={payload} tutorial={payload.tutorial} language={language} />
      )}

      {selectedSyntax && (
        <SyntaxModal syntax={selectedSyntax.syntax} title={selectedSyntax.title} onClose={() => setSelectedSyntax(null)} />
      )}
    </div>
  );
}

export default PayloadDetail;
