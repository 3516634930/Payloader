import { useState } from 'react';
import type { RefObject } from 'react';
import { useId } from 'react';
import { useAppContext } from '../../appContext';
import { detectFlagFormats } from '../../utils/codec/smartDecode';
import type { Detection, OperationId } from '../../utils/codec/types';
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
  // hero 形态（注册表 heroMode 声明，缺省 full）：collapsed 时首屏只渲染单行紧凑条，
  // 展开后才是完整 hero；展开状态在组件内部记忆（hero 为框架层单实例，跨域切换自然保留）。
  heroMode?: 'full' | 'collapsed';
  // 折叠条上的"需要解编码？"引导：点击切回密码与编码域（速查域折叠条专用）。
  onSwitchToCipher?: () => void;
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
// hero 按域变形：cipher 保持完整形态；misc/traffic 与速查域折叠为单行条，文件/速查工作区升为该域首屏。
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
  heroMode = 'full',
  onSwitchToCipher,
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
  const [expanded, setExpanded] = useState(false);
  const collapsed = heroMode === 'collapsed' && !expanded;
  const isZh = language === 'zh';

  // 折叠条状态摘要：一眼看到当前识别进展，决定要不要展开。
  let stripStatus: string;
  if (running) {
    stripStatus = isZh ? '识别中…' : 'Identifying…';
  } else if (!input.trim()) {
    stripStatus = isZh ? '粘贴密文或编码内容，自动识别' : 'Paste ciphertext or encoded text to identify';
  } else if (autoDisabled) {
    stripStatus = isZh ? `超过 ${autoDecodeLimit} 字符，已暂停自动识别` : `Over ${autoDecodeLimit} chars; auto-identify paused`;
  } else if (flagHits.length) {
    stripStatus = isZh ? '🚩 已识别 flag 格式' : '🚩 Flag format detected';
  } else if (detections.length) {
    const labels = detections.slice(0, 3).map(detection => detection.label).join('、');
    stripStatus = isZh ? `识别到 ${detections.length} 种：${labels}` : `${detections.length} detected: ${labels}`;
  } else if (displayOutput.trim()) {
    stripStatus = isZh ? '已有解码结果' : 'Decode result ready';
  } else {
    stripStatus = isZh ? '暂无识别结果' : 'No result yet';
  }

  // 折叠条（heroMode === 'collapsed' 且未展开时替换整个 hero，文件/速查工作区升为该域首屏）。
  const foldedHero = collapsed ? (
    <section className="ctf-hero ctf-hero-folded" ref={heroRef} aria-label={isZh ? '智能识别' : 'Smart identify'}>
      <div className="ctf-hero-strip">
        <button
          type="button"
          className="ctf-hero-strip-main"
          onClick={() => setExpanded(true)}
          aria-expanded={false}
          title={isZh ? '展开完整智能识别（粘贴即自动解码）' : 'Expand full Smart Identify (auto-decodes on paste)'}
        >
          <strong>⚡ {isZh ? '快速文本识别' : 'Quick Identify'}</strong>
          <span className="ctf-hero-strip-status">{stripStatus}</span>
          <span className="ctf-hero-strip-toggle" aria-hidden="true">{isZh ? '展开 ▾' : 'Expand ▾'}</span>
        </button>
        {onSwitchToCipher ? (
          <button
            type="button"
            className="ctf-hero-strip-guide"
            onClick={onSwitchToCipher}
            title={isZh ? '切到密码与编码域使用完整智能识别' : 'Switch to Ciphers & Encoding for full Smart Identify'}
          >
            {isZh ? '需要解编码？→' : 'Need decoding? →'}
          </button>
        ) : null}
      </div>
    </section>
  ) : null;

  return (
    <>
      {foldedHero ?? (
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
          {heroMode === 'collapsed' ? (
            <button
              type="button"
              className="ctf-hero-fold"
              onClick={() => setExpanded(false)}
              title={language === 'zh' ? '收起为一行，把首屏让给当前工作区' : 'Collapse to one line and give the workspace the top spot'}
            >
              {language === 'zh' ? '收起' : 'Collapse'}
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
      )}
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

        /* 折叠条（hero 按域变形）：单行紧凑条，总高 ≤48px，点击展开完整 hero */
        .ctf-hero.ctf-hero-folded {
          display: block;
          padding: 6px;
        }

        .ctf-hero-strip {
          display: flex;
          align-items: stretch;
          gap: 6px;
        }

        .ctf-hero-strip-main {
          flex: 1;
          min-width: 0;
          display: flex;
          align-items: center;
          gap: 8px;
          min-height: 34px;
          border: none;
          border-radius: 6px;
          background: transparent;
          color: var(--text-secondary);
          padding: 4px 6px;
          font-size: 12px;
          cursor: pointer;
          text-align: left;
        }

        .ctf-hero-strip-main:hover {
          background: rgba(255, 255, 255, 0.045);
        }

        .ctf-hero-strip-main strong {
          color: var(--neon-cyan);
          font-size: 13px;
          font-weight: 800;
          white-space: nowrap;
          flex-shrink: 0;
        }

        .ctf-hero-strip-status {
          flex: 1;
          min-width: 0;
          color: var(--text-muted);
          font-size: 12px;
          white-space: nowrap;
          overflow: hidden;
          text-overflow: ellipsis;
        }

        .ctf-hero-strip-toggle {
          color: var(--text-muted);
          font-size: 11px;
          white-space: nowrap;
          flex-shrink: 0;
        }

        .ctf-hero-strip-guide {
          flex-shrink: 0;
          min-height: 34px;
          padding: 4px 10px;
          border: 1px solid var(--border-color);
          border-radius: 6px;
          background: rgba(255, 255, 255, 0.035);
          color: var(--text-secondary);
          font-size: 12px;
          font-weight: 700;
          white-space: nowrap;
          cursor: pointer;
          transition: border-color var(--transition-fast), color var(--transition-fast);
        }

        .ctf-hero-strip-guide:hover {
          border-color: var(--neon-cyan);
          color: var(--neon-cyan);
        }

        .ctf-hero-fold {
          min-height: 30px;
          padding: 5px 9px;
          border: 1px solid var(--border-color);
          border-radius: 6px;
          background: rgba(255, 255, 255, 0.035);
          color: var(--text-muted);
          font-size: 12px;
          white-space: nowrap;
          cursor: pointer;
          transition: color var(--transition-fast);
        }

        .ctf-hero-fold:hover {
          color: var(--text-primary);
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

          .ctf-hero.ctf-hero-folded {
            padding: 5px;
          }

          /* 窄屏收起"展开"字样省空间：整条仍是展开按钮，状态摘要截断兜底 */
          .ctf-hero-strip-toggle {
            display: none;
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
