import { useMemo } from 'react';
import type { Ref } from 'react';
import { candidateHighlightKey, parseCandidateLayers } from './outputPanelUtils';

// 批次 M 候选列表（自 CodecWorkbench 迁出为公共组件，工作台与智能识别 hero 共用）：
// 展示 smart-decode 的机读候选段落；导航定位：展开由宿主经 detailsRef 控制，高亮按 层::候选名。
interface CodecCandidateListProps {
  output: string;
  detailsRef?: Ref<HTMLDetailsElement>;
  highlightKey?: string | null;
}

export function CodecCandidateList({ output, language, detailsRef, highlightKey }: { output: string; language: 'zh' | 'en' } & CodecCandidateListProps) {
  const candidateLayers = useMemo(() => (output ? parseCandidateLayers(output) : null), [output]);
  if (!candidateLayers) return null;
  return (
    <details ref={detailsRef} className="candidate-list">
      <summary>{language === 'zh' ? `候选列表（${candidateLayers.length} 层存在歧义，点击展开）` : `Candidates (${candidateLayers.length} ambiguous layers, click to expand)`}</summary>
      {candidateLayers.map(layer => (
        <div key={layer.layer} className="candidate-layer">
          <div className="candidate-layer-title">{language === 'zh' ? `第 ${layer.layer} 层 · 已选用 ${layer.chosen}` : `Layer ${layer.layer} · chose ${layer.chosen}`}</div>
          {layer.options.map(option => {
            const key = candidateHighlightKey(layer.layer, option.name);
            const highlighted = highlightKey === key;
            return (
              <div
                key={`${option.name}-${option.score}`}
                className={`candidate-option ${option.name === layer.chosen ? 'chosen' : ''} ${highlighted ? 'candidate-current' : ''}`}
                data-candidate-key={key}
              >
                <span className="candidate-name">{option.name === layer.chosen ? '✓ ' : ''}{option.name}</span>
                <span className="candidate-score">{option.score}</span>
                <span className="candidate-preview">{option.preview}</span>
              </div>
            );
          })}
        </div>
      ))}
    </details>
  );
}
