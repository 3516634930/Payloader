import { useState } from 'react';
import { notifications } from '@mantine/notifications';
import type { CatalogTool, ChallengeCategory } from '../../utils/ctf/challengeCatalog';
import { challengeCatalog } from '../../utils/ctf/challengeCatalog';

// 题型选择卡（杂项取证域）：下拉选 misc 子类 → 满编展示该类工具行（带说明与入口徽标）。
// 交互铁律（调研 ctf-tool-navigation-2026-09-24.md）：文件类工具未上传时点击直接弹文件选择器
// 而非禁用；已上传则滚动到对应卡。纯输入工具跳密码域定位操作；跨域条目切域。
interface ChallengePickerCardProps {
  language: 'zh' | 'en';
  hasFile: boolean;
  onPickFile: () => void;
  onScrollToCard: (cardId: string) => boolean;
  onOpenCipherOperation: (operationId: string) => void;
  onSwitchModule: (moduleId: string) => void;
  // 已上传文件随行移交（traffic 类条目带文件走魔数路由，与推荐条 handoffFile 行为一致）；无文件时不传。
  onHandOffCurrentFile?: () => void;
}

const KIND_BADGE: Record<CatalogTool['kind'], { zh: string; en: string }> = {
  file: { zh: '需文件', en: 'file' },
  cipher: { zh: '纯输入', en: 'input' },
  module: { zh: '切域', en: 'switch' },
};

function ChallengePickerCard({
  language,
  hasFile,
  onPickFile,
  onScrollToCard,
  onOpenCipherOperation,
  onSwitchModule,
  onHandOffCurrentFile,
}: ChallengePickerCardProps) {
  const zh = language === 'zh';
  const [categoryId, setCategoryId] = useState<string>(challengeCatalog[0].id);
  const category: ChallengeCategory = challengeCatalog.find(item => item.id === categoryId) ?? challengeCatalog[0];

  const runTool = (tool: CatalogTool) => {
    if (tool.soon) {
      notifications.show({ message: zh ? '该工具在后续版本提供。' : 'This tool is coming in a later release.' });
      return;
    }
    // 数据配置错误早暴露：缺定位字段的条目不许静默降级成"弹文件选择器"（reviewer P2）。
    if (tool.kind === 'cipher' && !tool.operationId) {
      notifications.show({ message: zh ? `条目 ${tool.id} 缺少操作定位（目录配置错误）` : `Entry ${tool.id} is missing its operation target`, color: 'red' });
      return;
    }
    if (tool.kind === 'file' && !tool.cardId) {
      notifications.show({ message: zh ? `条目 ${tool.id} 缺少卡片锚点（目录配置错误）` : `Entry ${tool.id} is missing its card anchor`, color: 'red' });
      return;
    }
    if (tool.kind === 'cipher' && tool.operationId) {
      onOpenCipherOperation(tool.operationId);
      return;
    }
    if (tool.kind === 'module' && tool.targetModuleId) {
      // 带文件移交的切域条目（pcap → 流量域）：文件跟人走，避免用户在目标域重传。
      if (tool.handoffFileOnNavigate && hasFile && onHandOffCurrentFile) {
        onHandOffCurrentFile();
        return;
      }
      onSwitchModule(tool.targetModuleId);
      return;
    }
    // kind=file：已上传 → 锚点滚动（目标卡未渲染时提示换文件）；未上传 → 直接弹选择器。
    if (hasFile && tool.cardId) {
      const reached = onScrollToCard(tool.cardId);
      if (!reached) {
        notifications.show({
          message: zh
            ? '当前文件没有命中该工具（卡片未出现）——分析可能仍在进行，或该文件类型不匹配，稍候重试或换文件。'
            : 'This file does not match that tool (the card is not showing yet); wait for analysis or try another file.',
        });
      }
      return;
    }
    onPickFile();
  };

  // 紧凑折叠形态（批次 FF-UX）：默认只占标题一行，展开才显示题型下拉与工具行——
  // 未载文件时首屏让位给 dropzone 空态与左列工具菜单，不再一屏三层选工具入口。
  return (
    <details id="ff-card-challenge-picker" className="ff-card ff-challenge-picker" aria-label={zh ? '按题型选工具' : 'Pick tools by category'}>
      <summary className="ff-card-head ff-challenge-picker-summary">
        <strong>{zh ? '按题型选工具' : 'Tools by category'}</strong>
        <span className="ff-note">{zh ? '不确定类型就直接拖文件进来自动识别，点此展开' : 'Not sure? Drop the file in — click to expand'}</span>
      </summary>
      <div className="ff-challenge-picker-body">
        <div className="ff-row">
          <select
            className="ff-select"
            value={categoryId}
            aria-label={zh ? '题目类型' : 'Challenge category'}
            onChange={event => setCategoryId(event.target.value)}
          >
            {challengeCatalog.map(item => (
              <option key={item.id} value={item.id}>{item.icon} {item.label[language]}</option>
            ))}
          </select>
        </div>
        <p className="ff-note">{category.hint[language]}</p>
        <div className="ff-catalog-list">
        {category.tools.map(tool => (
          <div key={tool.id} className={`ff-catalog-row${tool.soon ? ' ff-catalog-soon' : ''}`}>
            <div className="ff-catalog-info">
              <span className="ff-catalog-name">{tool.label[language]}</span>
              <span className={`ff-badge${tool.kind === 'file' ? '' : ' ff-badge-ok'}`}>
                {KIND_BADGE[tool.kind][language]}
              </span>
              {tool.soon && <span className="ff-badge ff-badge-warn">{zh ? '即将上线' : 'soon'}</span>}
              <p className="ff-note">{tool.description[language]}</p>
            </div>
            <button
              type="button"
              className={`ff-button${tool.soon ? '' : ' ff-button-primary'}`}
              onClick={() => runTool(tool)}
              title={tool.kind === 'file' && !hasFile
                ? (zh ? '选择文件后该工具自动可用' : 'Pick a file to enable this tool')
                : tool.label[language]}
            >
              {tool.kind === 'file'
                ? (hasFile ? (zh ? '打开工具' : 'Open tool') : (zh ? '选择文件' : 'Choose file'))
                : tool.kind === 'cipher'
                  ? (zh ? '去解码' : 'Decode')
                  : (zh ? '前往' : 'Go')}
            </button>
          </div>
        ))}
        </div>
      </div>
    </details>
  );
}

export default ChallengePickerCard;
