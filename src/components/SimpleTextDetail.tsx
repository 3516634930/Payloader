import { useMemo, useCallback, useState } from 'react';
import { useAppContext } from '../appContext';
import { getText } from '../i18n';

function SimpleTextDetail({ payloadId }: { payloadId: string }) {
  const { allPayloads, language } = useAppContext();
  const payload = useMemo(() => allPayloads.find(p => p.id === payloadId), [allPayloads, payloadId]);
  const [copied, setCopied] = useState(false);

  const content = useMemo(() => payload?.execution[0]?.command ?? '', [payload]);
  const name = useMemo(() => payload ? getText(payload.name, language) : '', [payload, language]);

  const copy = useCallback(() => {
    navigator.clipboard.writeText(content).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  }, [content]);

  if (!payload) return null;

  return (
    <div style={{ padding: '24px 28px', height: '100%', boxSizing: 'border-box', display: 'flex', flexDirection: 'column', gap: '12px' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexShrink: 0 }}>
        <h1 style={{ margin: 0, fontSize: '20px', fontWeight: 700 }}>{name}</h1>
        <button
          onClick={copy}
          style={{ padding: '6px 16px', borderRadius: '6px', border: '1px solid var(--border-color)', background: 'transparent', color: 'inherit', cursor: 'pointer', fontSize: '13px' }}
        >
          {copied ? '✓ 已复制' : '复制全文'}
        </button>
      </div>
      <pre style={{
        flex: 1,
        margin: 0,
        padding: '16px',
        background: 'var(--bg-secondary)',
        border: '1px solid var(--border-color)',
        borderRadius: '8px',
        fontFamily: 'monospace',
        fontSize: '13px',
        lineHeight: '1.65',
        whiteSpace: 'pre-wrap',
        wordBreak: 'break-word',
        overflowY: 'auto',
        /* perf: contain layout/paint, use GPU layer for scrolling */
        contain: 'strict',
        willChange: 'scroll-position',
      }}>
        {content}
      </pre>
    </div>
  );
}

export default SimpleTextDetail;
