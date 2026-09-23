import type { SyntaxPart, I18nText } from '../types';
import { useEffect, useId, useRef } from 'react';
import { useLanguage, useSession } from '../appContext';
import { t, getText } from '../i18n';
import { resolveVariableText } from '../utils/variables';
import '../styles/syntax-modal.css';

interface SyntaxModalProps {
  syntax: SyntaxPart[];
  title: I18nText;
  onClose: () => void;
}

function SyntaxModal({ syntax, title, onClose }: SyntaxModalProps) {
  const { globalVariables } = useSession();
  const { language } = useLanguage();
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
      </div>
    </div>
  );
}

export default SyntaxModal;
