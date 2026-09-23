import { memo, useEffect, useMemo, useRef, useState } from 'react';
import { useLanguage } from '../../appContext';
import { useCopyFeedback } from '../../utils/clipboard';
import { findFlagAutoRanges } from '../../utils/codec/smartDecode';
import type { FlagAutoRange } from '../../utils/codec/smartDecode';
import { candidateHighlightKey, formatTextStats, parseCandidateLayers } from './outputPanelUtils';
import { CodecCandidateList } from './CodecCandidates';
import '../../styles/workbench-output-panel.css';

// 批次 M 富输出面板：工作台与智能识别 hero 共用。
// 能力：正则/明文搜索（默认按正则解析，编译失败自动退回字面）+ 命中高亮与 ↑↓ 导航、
// flag 自动标红（完整格式深红 / flag·ctf·key 关键词红，搜索命中以描边环叠加互不覆盖）、
// 输入/输出字数与字节统计、输出回灌输入、候选间 ↑↓ 导航、富文本/原始视图切换；
// 超过 RICH_VIEW_LIMIT 自动退纯文本防卡顿。

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

// 自动标红级别（外层，0 = 无）：完整格式（前缀{...}）深红、flag/ctf/key 关键词红；搜索命中是内层叠加。
const AUTO_KEYWORD = 1;
const AUTO_FORMAT = 2;

interface HighlightAtom {
  start: number;
  end: number;
  auto: number;
  search: boolean;
  current: boolean;
}

// 边界原子分段：按自动标红区间 / 搜索命中 / 当前命中三类边界切分文本，三元组相同的相邻原子合并。
// 外层（auto）与内层（search/current）分开渲染——红区内的搜索命中画描边环而不是换底色，两层互不覆盖。
const buildHighlightAtoms = (text: string, autoRanges: FlagAutoRange[], search: SearchResult, hitIndex: number): HighlightAtom[] => {
  if (!text) return [];
  const auto = new Uint8Array(text.length);
  for (const range of autoRanges) auto.fill(range.level === 'format' ? AUTO_FORMAT : AUTO_KEYWORD, range.start, range.end);
  const searchHit = new Uint8Array(text.length);
  for (const match of search.matches) searchHit.fill(1, match.start, match.end);
  const currentMatch = search.matches[hitIndex];

  const bounds = new Set<number>([0, text.length]);
  for (const range of autoRanges) {
    bounds.add(range.start);
    bounds.add(range.end);
  }
  for (const match of search.matches) {
    bounds.add(match.start);
    bounds.add(match.end);
  }
  if (currentMatch) {
    bounds.add(currentMatch.start);
    bounds.add(currentMatch.end);
  }
  const sorted = [...bounds].sort((a, b) => a - b);

  const atoms: HighlightAtom[] = [];
  // data-current 只挂在当前命中的第一个原子上：命中与 auto 区间跨界相交时会切成多个原子，
  // 多个 data-current 会让导航滚动定位与橙环断成两截（复核 P2-1）。
  let currentAssigned = false;
  for (let index = 0; index < sorted.length - 1; index += 1) {
    const start = sorted[index];
    const end = sorted[index + 1];
    if (start >= end) continue;
    const previous = atoms[atoms.length - 1];
    const autoLevel = auto[start];
    const inSearch = searchHit[start] === 1;
    const inCurrent = Boolean(currentMatch && !currentAssigned && start >= currentMatch.start && start < currentMatch.end);
    if (inCurrent) currentAssigned = true;
    if (previous && previous.end === start && previous.auto === autoLevel && previous.search === inSearch && previous.current === inCurrent) {
      previous.end = end;
      continue;
    }
    atoms.push({ start, end, auto: autoLevel, search: inSearch, current: inCurrent });
  }
  return atoms;
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

export const WorkbenchOutputPanel = memo(function WorkbenchOutputPanel({ value, rawOutput, error, running, minHeight = 'normal', onUseAsInput, useAsInputDisabled, onClear }: WorkbenchOutputPanelProps) {
  const { language } = useLanguage();
  const [query, setQuery] = useState('');
  const [hitIndex, setHitIndex] = useState(0);
  const [rawMode, setRawMode] = useState(false);
  const { copiedKey, copy } = useCopyFeedback();
  const [candidateIndex, setCandidateIndex] = useState(-1);
  const viewRef = useRef<HTMLDivElement | null>(null);
  const candidatesRef = useRef<HTMLDetailsElement | null>(null);

  const search = useMemo(() => (error ? { matches: [] as MatchRange[], mode: 'empty' as const } : buildSearchResult(value, query)), [value, query, error]);
  const overLimit = value.length > RICH_VIEW_LIMIT;
  // 超限已退纯文本无标红，跳过标红扫描（复核 P2-2：200K 密集关键词文本实测可到秒级）
  const autoRanges = useMemo(() => (error || overLimit ? [] : findFlagAutoRanges(value)), [value, error, overLimit]);
  const richRenderable = !rawMode && !error && !overLimit;
  const segments = useMemo(
    () => (richRenderable && value ? buildHighlightAtoms(value, autoRanges, search, hitIndex) : null),
    [richRenderable, value, autoRanges, search, hitIndex],
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
    viewRef.current?.querySelector('[data-current="true"]')?.scrollIntoView({ block: 'nearest' });
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

  const copyOutput = () => {
    // copy 内部含 execCommand 降级；失败时 copiedKey 保持不变，按钮不误报"已复制"。
    void copy(error || value);
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
          <button type="button" className={`copy-btn ${copiedKey !== null ? 'copied' : ''}`} onClick={() => { void copyOutput(); }} disabled={!value && !error}>
            {copiedKey !== null ? (language === 'zh' ? '已复制' : 'Copied') : (language === 'zh' ? '复制' : 'Copy')}
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
            {segments.map((atom, index) => {
              const atomText = value.slice(atom.start, atom.end);
              // 红区外的搜索命中：黄底（当前导航目标橙底）
              if (!atom.auto) {
                if (!atom.search) return <span key={index}>{atomText}</span>;
                return atom.current
                  ? <mark key={index} className="wb-out-search-hit" data-current="true">{atomText}</mark>
                  : <mark key={index} className="wb-out-search-hit">{atomText}</mark>;
              }
              const outerClass = atom.auto === AUTO_FORMAT ? 'wb-out-flag-hit' : 'wb-out-kw-hit';
              // 红区内的搜索命中：描边环叠加，不换掉红底（两层共存）
              if (atom.search) {
                return (
                  <mark key={index} className={outerClass}>
                    <span className="wb-out-search-ring" data-current={atom.current ? 'true' : undefined}>{atomText}</span>
                  </mark>
                );
              }
              return <mark key={index} className={outerClass}>{atomText}</mark>;
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
    </div>
  );
});
