import type { RefObject } from 'react';
import { useId } from 'react';
import { useAppContext } from '../../appContext';
import { detectFlagFormats } from '../../utils/codec';
import type { Detection, OperationId } from '../../utils/codec';
import { formatTextStats } from '../codec/outputPanelUtils';
import { WorkbenchOutputPanel } from '../codec/WorkbenchOutputPanel';

type FlagHits = ReturnType<typeof detectFlagFormats>;

interface CtfHeroProps {
  input: string;
  output: string;
  error: string;
  running: boolean;
  autoDisabled: boolean;
  autoDecodeLimit: number;
  detections: Detection[];
  flagHits: FlagHits;
  displayOutput: string;
  showFileEntry: boolean;
  // 文件入口按钮的按域文案（批次 L）：不传时用杂项取证域的默认文案。
  fileEntryLabel?: { zh: string; en: string };
  fileEntryHint?: { zh: string; en: string };
  heroRef: RefObject<HTMLDivElement | null>;
  onInputChange: (value: string) => void;
  onDetection: (id: OperationId) => void;
  onFileEntry: () => void;
  onUseAsInput: () => void;
  onClear: () => void;
}

// 智能识别 hero（批次 J 自单一工作台抽出）：全域置顶，粘贴即自动解码。
// 批次 M：全局密钥栏（与密码工作台共享同一把钥匙）+ 富输出面板（搜索/flag 高亮/候选导航/字数统计/回灌）。
function CtfHero({
  input,
  output,
  error,
  running,
  autoDisabled,
  autoDecodeLimit,
  detections,
  flagHits,
  displayOutput,
  showFileEntry,
  fileEntryLabel,
  fileEntryHint,
  heroRef,
  onInputChange,
  onDetection,
  onFileEntry,
  onUseAsInput,
  onClear,
}: CtfHeroProps) {
  const { language, globalSecret, setGlobalSecret } = useAppContext();
  const secretFieldId = useId();
  return (
    <>
      <section className="ctf-hero" ref={heroRef} aria-label={language === 'zh' ? '智能识别' : 'Smart identify'}>
        <div className="ctf-hero-head">
          <strong>{language === 'zh' ? '智能识别' : 'Smart Identify'}</strong>
          <small>{language === 'zh' ? '粘贴即自动解码，支持多层嵌套编码' : 'Auto-decodes on paste, including nested layers'}</small>
          {showFileEntry ? (
            <button
              type="button"
              className="ctf-file-entry"
              onClick={onFileEntry}
              title={fileEntryHint
                ? fileEntryHint[language]
                : language === 'zh' ? '选择或拖入文件，在杂项取证域本地分析（上限 20MB，不上传）' : 'Pick or drop a file for local analysis in Misc & Forensics (20MB limit, never uploaded)'}
            >
              📎 {fileEntryLabel ? fileEntryLabel[language] : language === 'zh' ? '文件分析' : 'File analysis'}
            </button>
          ) : null}
        </div>
        <textarea
          className="ctf-hero-input"
          value={input}
          onChange={event => onInputChange(event.target.value)}
          aria-label={language === 'zh' ? '智能识别输入' : 'Smart identify input'}
          placeholder={language === 'zh'
            ? '在此粘贴密文 / 编码内容 / flag 线索...\n支持 Base、Hex、摩斯、古典密码、XOR 等自动识别'
            : 'Paste ciphertext, encoded content, or flag hints here...\nBase, hex, Morse, classical ciphers, XOR, and more are auto-detected'}
          spellCheck={false}
        />
        <div className="ctf-hero-stats" aria-label={language === 'zh' ? '输入字数统计' : 'Input statistics'}>
          <span>{formatTextStats(input, language)}</span>
          {autoDisabled && input.trim() ? (
            <span>{language === 'zh' ? `输入超过 ${autoDecodeLimit} 字符，已暂停自动识别，请在下方选择具体算法处理。` : `Input exceeds ${autoDecodeLimit} chars; auto-identify paused. Pick a specific tool below.`}</span>
          ) : null}
        </div>
        <div className="global-secret-bar">
          <label htmlFor={secretFieldId}>{language === 'zh' ? '🔑 全局密钥' : '🔑 Global key'}</label>
          <input
            id={secretFieldId}
            value={globalSecret}
            onChange={event => setGlobalSecret(event.target.value)}
            placeholder={language === 'zh'
              ? '多步解密共用一把钥匙；下方工作台自动读取，填了私有密钥则优先用私有值'
              : 'One key for the whole chain; the workbench below reads it, per-operation keys take precedence'}
            spellCheck={false}
            autoComplete="off"
          />
        </div>
        {detections.length ? (
          <div className="detect-strip" aria-label={language === 'zh' ? '自动识别结果' : 'Detected formats'}>
            <span>{language === 'zh' ? '识别' : 'Detected'}</span>
            {detections.map(detection => (
              <button key={`${detection.id}-${detection.label}`} type="button" onClick={() => onDetection(detection.id)}>
                {detection.label}
              </button>
            ))}
          </div>
        ) : null}
        {flagHits.length ? (
          <div className="ctf-flag-strip" aria-label={language === 'zh' ? '识别到 flag 格式' : 'Flag formats found'}>
            {flagHits.map(hit => (
              <span key={hit.prefix} className="ctf-flag-badge" title={hit.sample}>
                🚩 {language === 'zh' ? 'flag 格式' : 'flag format'}：<code>{hit.prefix}{'{...}'}</code>
              </span>
            ))}
          </div>
        ) : null}
        <WorkbenchOutputPanel
          value={displayOutput}
          rawOutput={output}
          error={error}
          running={running}
          minHeight="compact"
          onUseAsInput={onUseAsInput}
          onClear={onClear}
        />
      </section>
      <style>{`
        .ctf-hero {
          min-width: 0;
          display: grid;
          gap: 10px;
          border: 1px solid rgba(0, 240, 255, 0.35);
          border-radius: 8px;
          background: var(--bg-card);
          padding: 14px;
          scroll-margin-top: 16px;
        }

        .ctf-hero-head {
          display: flex;
          flex-wrap: wrap;
          align-items: baseline;
          gap: 8px;
        }

        .ctf-hero-head strong {
          color: var(--neon-cyan);
          font-size: 14px;
          font-weight: 800;
        }

        .ctf-hero-head small {
          color: var(--text-muted);
          font-size: 11px;
        }

        .ctf-file-entry {
          margin-left: auto;
          min-height: 30px;
          min-width: 0;
          padding: 5px 9px;
          border: 1px solid var(--border-color);
          border-radius: 6px;
          background: rgba(255, 255, 255, 0.035);
          color: var(--text-secondary);
          font-size: 12px;
          font-weight: 700;
          cursor: pointer;
          transition: border-color var(--transition-fast), color var(--transition-fast);
        }

        .ctf-file-entry:hover {
          border-color: var(--neon-cyan);
          color: var(--neon-cyan);
        }

        .ctf-hero-input {
          min-width: 0;
          width: 100%;
          min-height: 120px;
          resize: vertical;
          border: 1px solid var(--border-color);
          border-radius: 8px;
          background: var(--bg-secondary);
          color: var(--text-primary);
          padding: 13px;
          outline: none;
          font-family: var(--font-mono);
          font-size: 13px;
          line-height: 1.6;
          white-space: pre-wrap;
          overflow-wrap: anywhere;
        }

        .ctf-hero-input:focus {
          border-color: var(--neon-cyan);
          box-shadow: 0 0 0 3px rgba(0, 240, 255, 0.12);
        }

        .ctf-hero-input::placeholder {
          color: var(--text-muted);
        }

        .ctf-flag-strip {
          display: flex;
          flex-wrap: wrap;
          gap: 8px;
        }

        .ctf-flag-badge {
          display: inline-flex;
          align-items: center;
          gap: 6px;
          min-height: 30px;
          padding: 4px 10px;
          border: 1px solid var(--neon-green);
          border-radius: 999px;
          background: rgba(0, 255, 136, 0.08);
          color: var(--neon-green);
          font-size: 12px;
          font-weight: 700;
        }

        .ctf-flag-badge code {
          font-family: var(--font-mono);
          font-size: 12px;
        }

        .ctf-hero-stats {
          min-width: 0;
          display: flex;
          flex-wrap: wrap;
          gap: 4px 12px;
          color: var(--text-muted);
          font-size: 11px;
          font-variant-numeric: tabular-nums;
        }

        /* 全局密钥栏（批次 M）：与密码工作台共享同一把钥匙（appContext.globalSecret） */
        .ctf-hero .global-secret-bar {
          min-width: 0;
          display: grid;
          grid-template-columns: auto minmax(0, 1fr);
          gap: 10px;
          align-items: center;
          border: 1px dashed rgba(0, 240, 255, 0.3);
          border-radius: 8px;
          background: rgba(0, 240, 255, 0.04);
          padding: 9px 11px;
        }

        .ctf-hero .global-secret-bar label {
          color: var(--neon-cyan);
          font-size: 12px;
          font-weight: 800;
          white-space: nowrap;
        }

        .ctf-hero .global-secret-bar input {
          min-width: 0;
          width: 100%;
          min-height: 34px;
          border: 1px solid var(--border-color);
          border-radius: 6px;
          background: var(--bg-secondary);
          color: var(--text-primary);
          padding: 7px 10px;
          outline: none;
          font-family: var(--font-mono);
          font-size: 12px;
        }

        .ctf-hero .global-secret-bar input:focus {
          border-color: var(--neon-cyan);
          box-shadow: 0 0 0 3px rgba(0, 240, 255, 0.12);
        }

        .ctf-hero .detect-strip {
          min-width: 0;
          display: flex;
          flex-wrap: wrap;
          align-items: center;
          gap: 7px;
          color: var(--text-muted);
          font-size: 12px;
        }

        .ctf-hero .detect-strip span {
          font-weight: 700;
        }

        .ctf-hero .detect-strip button {
          min-height: 30px;
          min-width: 0;
          padding: 5px 9px;
          border: 1px solid var(--border-color);
          border-radius: 6px;
          background: rgba(255, 255, 255, 0.035);
          color: var(--text-secondary);
          font-size: 12px;
          font-weight: 700;
          transition: all var(--transition-fast);
        }

        .ctf-hero .detect-strip button:hover {
          border-color: var(--neon-cyan);
          color: var(--neon-cyan);
        }

        @media (max-width: 680px) {
          .ctf-hero {
            padding: 10px;
          }

          .ctf-hero-input {
            min-height: 96px;
            font-size: 12px;
          }

          .ctf-hero .global-secret-bar {
            grid-template-columns: 1fr;
          }

          .ctf-hero .detect-strip {
            display: grid;
            grid-template-columns: 1fr 1fr;
          }

          .ctf-hero .detect-strip span {
            grid-column: 1 / -1;
          }
        }
      `}</style>
    </>
  );
}

export default CtfHero;
