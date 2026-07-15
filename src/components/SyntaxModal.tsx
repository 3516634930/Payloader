import type { SyntaxPart, I18nText } from '../types';
import { useEffect, useId, useRef } from 'react';
import { useAppContext } from '../appContext';
import { t, getText } from '../i18n';
import { resolveVariableText } from '../utils/variables';

interface SyntaxModalProps {
  syntax: SyntaxPart[];
  title: I18nText;
  onClose: () => void;
}

function SyntaxModal({ syntax, title, onClose }: SyntaxModalProps) {
  const { globalVariables, language } = useAppContext();
  const dialogRef = useRef<HTMLDivElement>(null);
  const previousFocus = useRef<HTMLElement | null>(null);
  const onCloseRef = useRef(onClose);
  const titleId = useId();

  useEffect(() => {
    onCloseRef.current = onClose;
  }, [onClose]);

  useEffect(() => {
    previousFocus.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const dialog = dialogRef.current;
    const focusableSelector = 'a[href], button:not([disabled]), input:not([disabled]), [tabindex]:not([tabindex="-1"])';
    const focusDialog = window.requestAnimationFrame(() => {
      (dialog?.querySelector<HTMLElement>(focusableSelector) || dialog)?.focus();
    });

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.preventDefault();
        onCloseRef.current();
        return;
      }
      if (event.key !== 'Tab' || !dialog) return;

      const focusable = Array.from(dialog.querySelectorAll<HTMLElement>(focusableSelector))
        .filter(element => element.offsetParent !== null);
      if (!focusable.length) {
        event.preventDefault();
        dialog.focus();
        return;
      }
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => {
      window.cancelAnimationFrame(focusDialog);
      document.removeEventListener('keydown', handleKeyDown);
      previousFocus.current?.focus();
    };
  }, []);

  // 19种SyntaxPart type的完整颜色映射 (name now from i18n)
  const typeColorMap: Record<string, { color: string; group: string }> = {
    // 基础语法类
    command:    { color: 'var(--neon-cyan)',    group: 'basic' },
    parameter:  { color: 'var(--neon-orange)',  group: 'basic' },
    value:      { color: 'var(--neon-green)',   group: 'basic' },
    operator:   { color: 'var(--neon-pink)',    group: 'basic' },
    variable:   { color: 'var(--neon-yellow)',  group: 'basic' },
    // Web安全类
    header:     { color: '#ff9f43',             group: 'web' },
    method:     { color: '#ee5a24',             group: 'web' },
    domain:     { color: '#7ed6df',             group: 'web' },
    path:       { color: '#badc58',             group: 'web' },
    tag:        { color: '#e056fd',             group: 'web' },
    json:       { color: '#22a6b3',             group: 'web' },
    // 编码与技术类
    encoding:   { color: '#f9ca24',             group: 'tech' },
    technique:  { color: '#6c5ce7',             group: 'tech' },
    format:     { color: '#fd79a8',             group: 'tech' },
    function:   { color: '#00cec9',             group: 'tech' },
    keyword:    { color: '#e17055',             group: 'tech' },
    concept:    { color: '#a29bfe',             group: 'tech' },
    char:       { color: '#55efc4',             group: 'tech' },
    'tool-mode':{ color: '#fab1a0',             group: 'tech' },
  };

  const getTypeColor = (type: string) => {
    return typeColorMap[type]?.color || 'var(--text-secondary)';
  };

  const getTypeName = (type: string) => {
    const key = `syntax.${type}` as Parameters<typeof t>[0];
    const result = t(key, language);
    // If key not found, t() returns the key itself - fall back to 'Other'
    return result === key ? t('syntax.other', language) : result;
  };

  // 从当前语法数据中收集使用到的type，用于动态图例
  const usedTypes = [...new Set(syntax.map(s => s.type).filter(Boolean))] as string[];

  return (
    <div className="modal-overlay" onMouseDown={event => {
      if (event.target === event.currentTarget) onClose();
    }}>
      <div
        ref={dialogRef}
        className="modal-content"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
      >
        <div className="modal-header">
          <h3 id={titleId}>{t('syntax.title', language)}{getText(title, language)}</h3>
          <button type="button" className="modal-close" onClick={onClose} aria-label="关闭语法解析">×</button>
        </div>
        <div className="modal-body">
          <div className="syntax-legend">
            {usedTypes.map(tp => (
              <span key={tp} className="legend-item">
                <span className="dot" style={{ background: getTypeColor(tp) }}></span>
                {getTypeName(tp)}
              </span>
            ))}
          </div>
          <div className="syntax-list">
            {syntax.map((item, index) => (
              <div key={index} className="syntax-item">
                <div className="syntax-part-wrapper">
                  <code 
                    className="syntax-part"
                    style={{ 
                      borderColor: getTypeColor(item.type || ''),
                      color: getTypeColor(item.type || '')
                    }}
                  >
                    {resolveVariableText(item.part, globalVariables)}
                  </code>
                  {item.type && (
                    <span 
                      className="syntax-type"
                      style={{ backgroundColor: getTypeColor(item.type) }}
                    >
                      {getTypeName(item.type)}
                    </span>
                  )}
                </div>
                <div className="syntax-explanation">
                  {resolveVariableText(getText(item.explanation, language), globalVariables)}
                </div>
              </div>
            ))}
          </div>
        </div>
        <style>{`
          .modal-overlay {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0, 0, 0, 0.8);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 1000;
            animation: fadeIn 0.2s ease;
          }

          @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
          }

          .modal-content {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            width: 90%;
            max-width: 700px;
            max-height: 80vh;
            overflow: hidden;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
            animation: slideUp 0.3s ease;
          }

          @keyframes slideUp {
            from {
              opacity: 0;
              transform: translateY(20px);
            }
            to {
              opacity: 1;
              transform: translateY(0);
            }
          }

          .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 20px 24px;
            border-bottom: 1px solid var(--border-color);
          }

          .modal-header h3 {
            min-width: 0;
            font-size: 16px;
            font-weight: 600;
            color: var(--neon-cyan);
            overflow-wrap: anywhere;
          }

          .modal-close {
            background: transparent;
            border: none;
            color: var(--text-muted);
            font-size: 24px;
            cursor: pointer;
            width: 44px;
            height: 44px;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 4px;
            transition: all var(--transition-fast);
          }

          .modal-close:hover {
            background: var(--bg-hover);
            color: var(--text-primary);
          }

          .modal-body {
            padding: 24px;
            overflow-y: auto;
            max-height: calc(80vh - 80px);
          }

          .syntax-legend {
            display: flex;
            flex-wrap: wrap;
            gap: 16px;
            margin-bottom: 20px;
            padding-bottom: 16px;
            border-bottom: 1px solid var(--border-color);
          }

          .legend-item {
            display: flex;
            align-items: center;
            gap: 6px;
            font-size: 12px;
            color: var(--text-muted);
          }

          .dot {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            flex-shrink: 0;
          }

          .syntax-list {
            display: flex;
            flex-direction: column;
            gap: 12px;
          }

          .syntax-item {
            display: flex;
            gap: 16px;
            padding: 12px;
            background: var(--bg-tertiary);
            border-radius: 8px;
            align-items: flex-start;
            min-width: 0;
          }

          .syntax-part-wrapper {
            display: flex;
            flex-direction: column;
            align-items: flex-start;
            gap: 6px;
            min-width: 120px;
          }

          .syntax-part {
            font-family: var(--font-mono);
            font-size: 13px;
            padding: 6px 10px;
            background: var(--bg-secondary);
            border-radius: 4px;
            border: 1px solid;
            word-break: break-all;
            max-width: 100%;
          }

          .syntax-type {
            font-size: 10px;
            padding: 2px 6px;
            border-radius: 3px;
            color: var(--bg-primary);
            font-weight: 600;
            text-transform: uppercase;
          }

          .syntax-explanation {
            flex: 1;
            min-width: 0;
            font-size: 13px;
            color: var(--text-secondary);
            line-height: 1.6;
            padding-top: 6px;
            overflow-wrap: anywhere;
          }

          @media (max-width: 640px) {
            .modal-overlay {
              align-items: stretch;
              justify-content: stretch;
              padding: 8px;
            }

            .modal-content {
              width: 100%;
              max-width: none;
              max-height: calc(100dvh - 16px);
              border-radius: 8px;
            }

            .modal-header {
              padding: 14px 16px;
            }

            .modal-body {
              padding: 14px;
              max-height: calc(100dvh - 78px);
            }

            .syntax-legend {
              gap: 8px;
              margin-bottom: 14px;
              padding-bottom: 12px;
            }

            .syntax-item {
              display: grid;
              grid-template-columns: 1fr;
              gap: 10px;
            }

            .syntax-part-wrapper {
              min-width: 0;
              width: 100%;
            }
          }

          @media (max-width: 420px) {
            .modal-overlay {
              padding: 0;
            }

            .modal-content {
              min-height: 100dvh;
              max-height: 100dvh;
              border-radius: 0;
              border-left: 0;
              border-right: 0;
            }

            .modal-body {
              max-height: calc(100dvh - 65px);
            }
          }
        `}</style>
      </div>
    </div>
  );
}

export default SyntaxModal;
