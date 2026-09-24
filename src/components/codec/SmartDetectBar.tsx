import { useState } from 'react';
import { useLanguage } from '../../appContext';
import { DetectStrip } from './DetectStrip';
import { WorkbenchOutputPanel } from './WorkbenchOutputPanel';
import { useSmartIdentify } from './useSmartIdentify';
import type { OperationId } from '../../utils/codec/types';

interface SmartDetectBarProps {
  // 输入源 = 工作台输入框（单一舞台：识别能力内嵌进工作台，不再有独立 hero 输入）。
  input: string;
  // 芯片点击：与菜单点击同语义（选中操作 + 以当前输入立即执行）。
  onDetection: (id: OperationId) => void;
  // 智能解码纯结果回灌进工作台输入框（多层链第二步）。
  onUseAsInput: (pureResult: string) => void;
  onClear: () => void;
}

// 智能识别条（UI 编排优化批）：CyberChef Magic 模式——识别是输入区的附属能力而非独立舞台。
// 折叠 = 单行（状态摘要 + 识别芯片 + flag 徽章）；展开 = 完整输出面板（搜索/标红/回灌）。
// 无输入时只渲染一行弱提示，不占工作区空间。
function SmartDetectBar({ input, onDetection, onUseAsInput, onClear }: SmartDetectBarProps) {
  const { language } = useLanguage();
  const [expanded, setExpanded] = useState(false);
  const isZh = language === 'zh';
  const { detections, flagHits, output, displayOutput, pureResult, error, running, autoDisabled } = useSmartIdentify(input);

  if (!input.trim()) return null;

  let status: string;
  if (running) {
    status = isZh ? '识别中…' : 'Identifying…';
  } else if (autoDisabled) {
    status = isZh ? '超过 20000 字符，已暂停自动识别' : 'Over 20,000 chars; auto-identify paused';
  } else if (flagHits.length) {
    status = isZh ? '🚩 已识别 flag 格式' : '🚩 Flag format detected';
  } else if (detections.length) {
    const labels = detections.slice(0, 3).map(detection => detection.label).join('、');
    status = isZh ? `识别到 ${detections.length} 种：${labels}` : `${detections.length} detected: ${labels}`;
  } else if (displayOutput.trim()) {
    status = isZh ? '已有解码结果' : 'Decode result ready';
  } else {
    status = isZh ? '暂无识别结果' : 'No result yet';
  }

  return (
    <section className="smart-detect-bar" aria-label={isZh ? '智能识别' : 'Smart identify'}>
      <div className="smart-detect-row">
        <button
          type="button"
          className="smart-detect-toggle"
          onClick={() => setExpanded(value => !value)}
          aria-expanded={expanded}
          title={isZh ? '展开/收起智能识别结果' : 'Expand or collapse smart identify result'}
        >
          <strong>⚡ {status}</strong>
          <span aria-hidden="true">{expanded ? '▴' : '▾'}</span>
        </button>
        {detections.length ? <DetectStrip detections={detections} onDetect={onDetection} /> : null}
        {flagHits.length ? (
          <span className="smart-detect-flags" aria-label={isZh ? '识别到 flag 格式' : 'Flag formats found'}>
            {flagHits.map(hit => (
              <span key={hit.prefix} className="ctf-flag-badge" title={hit.sample}>
                🚩<code>{hit.prefix}{'{...}'}</code>
              </span>
            ))}
          </span>
        ) : null}
      </div>
      {expanded ? (
        <WorkbenchOutputPanel
          value={displayOutput}
          rawOutput={output}
          error={error}
          running={running}
          minHeight="compact"
          onUseAsInput={() => {
            if (pureResult) onUseAsInput(pureResult);
          }}
          onClear={onClear}
        />
      ) : null}
    </section>
  );
}

export { SmartDetectBar };
