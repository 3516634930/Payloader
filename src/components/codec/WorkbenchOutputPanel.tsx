import { useEffect, useMemo, useRef, useState } from 'react';
import { useAppContext } from '../../appContext';
import { detectFlagFormats } from '../../utils/codec';
import type { FlagFormatHit } from '../../utils/codec';
import { candidateHighlightKey, formatTextStats, parseCandidateLayers } from './outputPanelUtils';
import { CodecCandidateList } from './CodecCandidates';

// 批次 M 富输出面板：工作台与智能识别 hero 共用。
// 能力：正则/明文搜索（默认按正则解析，编译失败自动退回字面）+ 命中高亮与 ↑↓ 导航、
// flag 命中常亮高亮、输入/输出字数与字节统计、输出回灌输入、候选间 ↑↓ 导航、
// 富文本/原始视图切换；超过 RICH_VIEW_LIMIT 自动退纯文本防卡顿。

const RICH_VIEW_LIMIT = 200_000;
const MAX_MATCHES = 2000;

interface MatchRange {
  start: number;
  end: number;
}

interface SearchResult {
  matches: MatchRange[];
  // re = 正则命中；text = 正则编译失败按字面命中；empty = 无查询
  mode: 're' | 'text' | 'empty';
}

const buildSearchResult = (text: string, query: string): SearchResult => {
  const trimmed = query.trim();
  if (!trimmed || !text) return { matches: [], mode: 'empty' };
  let pattern: RegExp;
  try {
    pattern = new RegExp(trimmed, 'g');
  } catch {
    // 正则非法：退回字面大小写不敏感搜索
    const haystack = text.toLowerCase();
    const needle = trimmed.toLowerCase();
    const matches: MatchRange[] = [];
    let cursor = haystack.indexOf(needle);
    while (cursor >= 0 && matches.length < MAX_MATCHES) {
      matches.push({ start: cursor, end: cursor + needle.length });
      cursor = haystack.indexOf(needle, cursor + Math.max(1, needle.length));
    }
    return { matches, mode: 'text' };
  }
  const matches: MatchRange[] = [];
  let guard = 0;
  let current: RegExpExecArray | null;
  while ((current = pattern.exec(text)) && matches.length < MAX_MATCHES) {
    if (current[0].length === 0) {
      pattern.lastIndex += 1;
      continue;
    }
    matches.push({ start: current.index, end: current.index + current[0].length });
    if (++guard >= MAX_MATCHES) break;
  }
  return { matches, mode: 're' };
};

// flag 常亮区间：复用引擎 detectFlagFormats 的前缀清单，对同一文本重建位置级匹配。
const buildFlagRanges = (text: string, hits: FlagFormatHit[]): MatchRange[] => {
  if (!text || !hits.length) return [];
  let pattern: RegExp;
  try {
    pattern = new RegExp(`\\b(?:${hits.map(hit => hit.prefix.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|')})\\{[^{}\\n]{4,}\\}`, 'gi');
  } catch {
    return [];
  }
  return [...text.matchAll(pattern)].map(match => ({ start: match.index, end: match.index + match[0].length }));
};

const KIND_PLAIN = 0;
const KIND_SEARCH = 1;
const KIND_FLAG = 2;
// 当前导航目标单独成段：保证 data-current 节点与 hitIndex 一一对应，导航定位不会因相邻命中合并而漂移。
const KIND_CURRENT = 3;

interface Segment {
  text: string;
  kind: number;
}

const buildSegments = (text: string, search: SearchResult, flagRanges: MatchRange[], hitIndex: number): Segment[] => {
  const kinds = new Uint8Array(text.length);
  for (const range of search.matches) kinds.fill(KIND_SEARCH, range.start, range.end);
  for (const range of flagRanges) kinds.fill(KIND_FLAG, range.start, range.end);
  const currentMatch = search.matches[hitIndex];
  if (currentMatch) kinds.fill(KIND_CURRENT, currentMatch.start, currentMatch.end);
  const segments: Segment[] = [];
  let cursor = 0;
  while (cursor < text.length) {
    const kind = kinds[cursor];
    let end = cursor + 1;
    while (end < text.length && kinds[end] === kind) end += 1;
    segments.push({ text: text.slice(cursor, end), kind });
    cursor = end;
  }
  return segments;
};

export interface WorkbenchOutputPanelProps {
  // 展示文本（候选段已剥）；rawOutput 保留候选段供候选导航解析。
  value: string;
  rawOutput: string;
  error: string;
  running: boolean;
  minHeight?: 'compact' | 'normal';
  onUseAsInput: () => void;
  useAsInputDisabled?: boolean;
  onClear?: () => void;
}

export function WorkbenchOutputPanel({ value, rawOutput, error, running, minHeight = 'normal', onUseAsInput, useAsInputDisabled, onClear }: WorkbenchOutputPanelProps) {
  const { language } = useAppContext();
  const [query, setQuery] = useState('');
  const [hitIndex, setHitIndex] = useState(0);
  const [rawMode, setRawMode] = useState(false);
  const [copied, setCopied] = useState(false);
  const [candidateIndex, setCandidateIndex] = useState(-1);
  const viewRef = useRef<HTMLDivElement | null>(null);
  const candidatesRef = useRef<HTMLDetailsElement | null>(null);

  const search = useMemo(() => (error ? { matches: [] as MatchRange[], mode: 'empty' as const } : buildSearchResult(value, query)), [value, query, error]);
  const flagRanges = useMemo(() => (error ? [] : buildFlagRanges(value, detectFlagFormats(value))), [value, error]);
  const overLimit = value.length > RICH_VIEW_LIMIT;
  const richRenderable = !rawMode && !error && !overLimit;
  const segments = useMemo(
    () => (richRenderable && value ? buildSegments(value, search, flagRanges, hitIndex) : null),
    [richRenderable, value, search, flagRanges, hitIndex],
  );
  const searchCount = search.matches.length;

  const candidateLayers = useMemo(() => parseCandidateLayers(rawOutput), [rawOutput]);
  const flatCandidates = useMemo(
    () => (candidateLayers ?? []).flatMap(layer => layer.options.map(option => ({ layer, option }))),
    [candidateLayers],
  );

  // 搜索词或输出变化时重置导航指针：渲染期比较上一次输入（React 认可的派生状态重置模式，避免 effect 级联渲染）。
  const [navSource, setNavSource] = useState({ query, value });
  if (navSource.query !== query || navSource.value !== value) {
    setNavSource({ query, value });
    setHitIndex(0);
    setCandidateIndex(-1);
  }

  // 导航滚动：当前命中唯一（data-current），候选展开后定位到对应行；block: nearest 避免整页跳动。
  useEffect(() => {
    if (!searchCount) return;
    viewRef.current?.querySelector('.wb-out-search-hit[data-current="true"]')?.scrollIntoView({ block: 'nearest' });
  }, [hitIndex, searchCount, segments]);

  useEffect(() => {
    if (candidateIndex < 0 || candidateIndex >= flatCandidates.length) return;
    const entry = flatCandidates[candidateIndex];
    candidatesRef.current?.setAttribute('open', '');
    const node = candidatesRef.current?.querySelector(`[data-candidate-key="${CSS.escape(candidateHighlightKey(entry.layer.layer, entry.option.name))}"]`);
    node?.scrollIntoView({ block: 'nearest' });
  }, [candidateIndex, flatCandidates]);

  const stepHit = (delta: number) => {
    if (!searchCount) return;
    setHitIndex(index => (index + delta + searchCount) % searchCount);
  };

  const stepCandidate = (delta: number) => {
    if (!flatCandidates.length) return;
    setCandidateIndex(index => {
      const base = index < 0 ? 0 : index;
      return (base + delta + flatCandidates.length) % flatCandidates.length;
    });
  };

  const copyOutput = async () => {
    try {
      await navigator.clipboard.writeText(error || value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1600);
    } catch {
      // 非安全上下文（如 http 内网部署）下剪贴板 API 不可用：静默降级，按钮保持可手动选中文本复制。
    }
  };

  const currentCandidate = candidateIndex >= 0 ? flatCandidates[candidateIndex] : null;
  const statsText = useMemo(() => formatTextStats(error || value, language), [error, value, language]);
  const searchModeLabel = search.mode === 're' ? (language === 'zh' ? '正则' : 'regex') : search.mode === 'text' ? (language === 'zh' ? '字面' : 'literal') : '';

  return (
    <div className="wb-out-panel" data-min={minHeight}>
      <div className="panel-header">
        <label>{language === 'zh' ? '输出' : 'Output'}</label>
        <small className="wb-out-stats" title={language === 'zh' ? '字符数（Unicode 码点）与 UTF-8 字节数' : 'Characters (Unicode code points) and UTF-8 bytes'}>{statsText}</small>
        <div className="panel-actions">
          {value && !error ? (
            <button type="button" className="copy-btn" onClick={() => setRawMode(mode => !mode)} title={language === 'zh' ? '在高亮视图与可选择的原始文本之间切换' : 'Toggle between highlighted view and raw selectable text'}>
              {rawMode ? (language === 'zh' ? '高亮视图' : 'Rich view') : (language === 'zh' ? '原始文本' : 'Raw')}
            </button>
          ) : null}
          <button type="button" className="copy-btn" onClick={onUseAsInput} disabled={useAsInputDisabled || !value} title={language === 'zh' ? '把输出放回输入框，继续下一步处理' : 'Feed the output back as input for the next step'}>
            {language === 'zh' ? '输出回灌输入' : 'Use as input'}
          </button>
          <button type="button" className={`copy-btn ${copied ? 'copied' : ''}`} onClick={() => { void copyOutput(); }} disabled={!value && !error}>
            {copied ? (language === 'zh' ? '已复制' : 'Copied') : (language === 'zh' ? '复制' : 'Copy')}
          </button>
          {onClear ? (
            <button type="button" className="clear-btn" onClick={onClear}>{language === 'zh' ? '清空' : 'Clear'}</button>
          ) : null}
        </div>
      </div>

      {candidateLayers ? (
        <div className="wb-out-candidate-nav" aria-label={language === 'zh' ? '候选导航' : 'Candidate navigation'}>
          <span className="wb-nav-label">{language === 'zh' ? '候选' : 'Candidates'}</span>
          <button type="button" onClick={() => stepCandidate(-1)} disabled={!flatCandidates.length} aria-label={language === 'zh' ? '上一个候选' : 'Previous candidate'}>↑</button>
          <span className="wb-nav-count">{flatCandidates.length ? `${candidateIndex + 1}/${flatCandidates.length}` : '0/0'}</span>
          <button type="button" onClick={() => stepCandidate(1)} disabled={!flatCandidates.length} aria-label={language === 'zh' ? '下一个候选' : 'Next candidate'}>↓</button>
          <span className="wb-nav-current" title={currentCandidate ? currentCandidate.option.preview : undefined}>
            {currentCandidate
              ? `${language === 'zh' ? '第' : 'L'}${currentCandidate.layer.layer}${language === 'zh' ? '层' : ''} · ${currentCandidate.option.name} (${currentCandidate.option.score}) · ${currentCandidate.option.preview}`
              : language === 'zh' ? '按 ↑/↓ 在解码候选间跳转' : 'Use ↑/↓ to browse decode candidates'}
          </span>
        </div>
      ) : null}

      {!error ? (
        <div className="wb-out-search-row">
          <span aria-hidden="true">🔍</span>
          <input
            value={query}
            onChange={event => setQuery(event.target.value)}
            onKeyDown={event => {
              if (event.key === 'Enter') {
                event.preventDefault();
                stepHit(event.shiftKey ? -1 : 1);
              }
            }}
            placeholder={language === 'zh' ? '搜索输出：flag\\{.*?\\} 或任意正则（非法正则自动按字面），Enter 下一处' : 'Search output: flag\\{.*?\\} or any regex (falls back to literal), Enter for next'}
            aria-label={language === 'zh' ? '输出搜索' : 'Search output'}
            spellCheck={false}
          />
          {query ? (
            <span className="wb-out-search-meta" aria-live="polite">
              {searchCount ? `${hitIndex + 1}/${searchCount}` : language === 'zh' ? '无命中' : 'no match'}
              {searchModeLabel ? ` · ${searchModeLabel}` : ''}
            </span>
          ) : null}
          <button type="button" onClick={() => stepHit(-1)} disabled={!searchCount} aria-label={language === 'zh' ? '上一个命中' : 'Previous match'}>↑</button>
          <button type="button" onClick={() => stepHit(1)} disabled={!searchCount} aria-label={language === 'zh' ? '下一个命中' : 'Next match'}>↓</button>
        </div>
      ) : null}

      <div className="wb-out-view-wrap" ref={viewRef}>
        {error ? (
          <textarea className="wb-out-raw error" value={error} readOnly aria-label={language === 'zh' ? '错误信息' : 'Error'} />
        ) : segments ? (
          <div className="wb-out-rich" role="document" aria-label={language === 'zh' ? '解码结果' : 'Decoded result'} tabIndex={0}>
            {segments.map((segment, index) => {
              if (segment.kind === KIND_PLAIN) return <span key={index}>{segment.text}</span>;
              if (segment.kind === KIND_FLAG) return <mark key={index} className="wb-out-flag-hit" title={language === 'zh' ? 'flag 格式命中' : 'flag format hit'}>{segment.text}</mark>;
              if (segment.kind === KIND_CURRENT) return <mark key={index} className="wb-out-search-hit" data-current="true">{segment.text}</mark>;
              return <mark key={index} className="wb-out-search-hit">{segment.text}</mark>;
            })}
          </div>
        ) : (
          <textarea
            className="wb-out-raw"
            value={value}
            readOnly
            aria-label={language === 'zh' ? '解码结果' : 'Decoded result'}
            placeholder={running
              ? (language === 'zh' ? '处理中...' : 'Processing...')
              : (language === 'zh' ? '转换结果会显示在这里...' : 'The result will appear here...')}
            spellCheck={false}
          />
        )}
        {overLimit ? (
          <small className="wb-out-limit-hint">{language === 'zh' ? `输出超过 ${RICH_VIEW_LIMIT} 字符，已停用高亮与搜索定位以保持流畅。` : `Output exceeds ${RICH_VIEW_LIMIT} chars; highlighting and search positioning disabled for smoothness.`}</small>
        ) : null}
      </div>

      <CodecCandidateList
        output={rawOutput}
        language={language}
        detailsRef={candidatesRef}
        highlightKey={currentCandidate ? candidateHighlightKey(currentCandidate.layer.layer, currentCandidate.option.name) : null}
      />

      <style>{`
        .wb-out-panel {
          min-width: 0;
          display: grid;
          gap: 8px;
        }

        .wb-out-panel .panel-header {
          min-width: 0;
          display: flex;
          flex-wrap: wrap;
          align-items: center;
          justify-content: space-between;
          gap: 8px;
        }

        .wb-out-panel .panel-header label {
          color: var(--text-muted);
          font-size: 12px;
          font-weight: 800;
        }

        .wb-out-stats {
          min-width: 0;
          color: var(--text-muted);
          font-size: 11px;
          font-variant-numeric: tabular-nums;
          white-space: nowrap;
          overflow: hidden;
          text-overflow: ellipsis;
        }

        .wb-out-panel .panel-actions {
          min-width: 0;
          display: flex;
          flex-wrap: wrap;
          justify-content: flex-end;
          gap: 6px;
        }

        .wb-out-panel .copy-btn,
        .wb-out-panel .clear-btn {
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

        .wb-out-panel .copy-btn:hover:not(:disabled),
        .wb-out-panel .clear-btn:hover {
          border-color: var(--neon-cyan);
          color: var(--neon-cyan);
        }

        .wb-out-panel .copy-btn.copied {
          border-color: var(--neon-green);
          background: rgba(0, 255, 136, 0.1);
          color: var(--neon-green);
        }

        .wb-out-panel .copy-btn:disabled,
        .wb-out-panel .clear-btn:disabled {
          opacity: 0.45;
          cursor: not-allowed;
        }

        .wb-out-candidate-nav,
        .wb-out-search-row {
          min-width: 0;
          display: flex;
          flex-wrap: wrap;
          align-items: center;
          gap: 7px;
          color: var(--text-muted);
          font-size: 12px;
        }

        .wb-out-candidate-nav .wb-nav-label,
        .wb-out-search-row > span[aria-hidden] {
          font-weight: 800;
        }

        .wb-out-search-row input {
          min-width: 0;
          flex: 1 1 180px;
          min-height: 32px;
          border: 1px solid var(--border-color);
          border-radius: 6px;
          background: var(--bg-secondary);
          color: var(--text-primary);
          padding: 6px 10px;
          outline: none;
          font-family: var(--font-mono);
          font-size: 12px;
        }

        .wb-out-search-row input:focus {
          border-color: var(--neon-cyan);
          box-shadow: 0 0 0 3px rgba(0, 240, 255, 0.12);
        }

        .wb-out-search-meta {
          font-variant-numeric: tabular-nums;
          white-space: nowrap;
        }

        .wb-out-candidate-nav button,
        .wb-out-search-row button {
          min-width: 32px;
          min-height: 32px;
          border: 1px solid var(--border-color);
          border-radius: 6px;
          background: rgba(255, 255, 255, 0.035);
          color: var(--text-secondary);
          font-size: 13px;
          font-weight: 800;
          cursor: pointer;
          transition: all var(--transition-fast);
        }

        .wb-out-candidate-nav button:hover:not(:disabled),
        .wb-out-search-row button:hover:not(:disabled) {
          border-color: var(--neon-cyan);
          color: var(--neon-cyan);
        }

        .wb-out-candidate-nav button:disabled,
        .wb-out-search-row button:disabled {
          opacity: 0.45;
          cursor: not-allowed;
        }

        .wb-nav-current {
          min-width: 0;
          flex: 1 1 220px;
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
          color: var(--text-secondary);
        }

        .wb-out-view-wrap {
          min-width: 0;
          display: grid;
          gap: 6px;
        }

        .wb-out-rich {
          min-height: 110px;
          max-height: 480px;
          overflow: auto;
          border: 1px solid var(--border-color);
          border-radius: 8px;
          background: var(--bg-secondary);
          color: var(--text-primary);
          padding: 13px;
          font-family: var(--font-mono);
          font-size: 13px;
          line-height: 1.6;
          white-space: pre-wrap;
          overflow-wrap: anywhere;
          user-select: text;
          cursor: text;
        }

        .wb-out-rich:focus-visible {
          border-color: var(--neon-cyan);
          box-shadow: 0 0 0 3px rgba(0, 240, 255, 0.12);
          outline: none;
        }

        .wb-out-rich mark {
          background: transparent;
          color: inherit;
          padding: 0;
        }

        .wb-out-search-hit {
          background: rgba(255, 214, 0, 0.28) !important;
          box-shadow: 0 0 0 1px rgba(255, 214, 0, 0.35);
          border-radius: 2px;
        }

        .wb-out-search-hit[data-current="true"] {
          background: rgba(255, 106, 0, 0.55) !important;
          box-shadow: 0 0 0 1px rgba(255, 106, 0, 0.7);
        }

        .wb-out-flag-hit {
          background: rgba(0, 255, 136, 0.16) !important;
          color: var(--neon-green);
          box-shadow: 0 0 0 1px rgba(0, 255, 136, 0.45);
          border-radius: 2px;
          font-weight: 700;
        }

        .wb-out-raw {
          min-width: 0;
          width: 100%;
          min-height: 110px;
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

        .wb-out-raw.error {
          border-color: var(--neon-red);
          color: var(--neon-red);
        }

        .wb-out-raw::placeholder {
          color: var(--text-muted);
        }

        .wb-out-limit-hint {
          color: var(--text-muted);
          font-size: 11px;
        }

        .wb-out-panel .candidate-list[data-candidate-current] {
          border-color: var(--neon-cyan);
        }

        .wb-out-panel .candidate-option.candidate-current {
          outline: 1px solid var(--neon-cyan);
          background: rgba(0, 240, 255, 0.12);
        }

        @media (max-width: 680px) {
          .wb-out-panel .panel-header {
            align-items: stretch;
            flex-direction: column;
          }

          .wb-out-panel .panel-actions {
            display: grid;
            grid-template-columns: 1fr 1fr;
          }

          .wb-out-panel .copy-btn,
          .wb-out-panel .clear-btn {
            width: 100%;
            min-height: 44px;
          }

          .wb-nav-current {
            flex-basis: 100%;
            white-space: normal;
          }
        }
      `}</style>
    </div>
  );
}
