import { useCallback } from 'react';
import { useAppContext } from '../../appContext';
import { openProtectedExternalLink } from '../../protectedLinks';
import { ctfCheatSheets } from '../../utils/ctf/cheatsheets';
import type { CheatEntry } from '../../utils/ctf/cheatsheets';
import type { CtfWorkspaceProps } from '../../utils/ctf/modules';
import ModulePlaceholder from './ModulePlaceholder';

// 题型速查工作区（批次 M）：Web/逆向/Pwn/AI 四域的最小可用内容。
// 速查条目来自 src/utils/ctf/cheatsheets/ 静态种子，跳转落主 tab 对应条目；
// 专属工具仍在建设中——如实提示，注册表缺失时回退占位页，保证点击不空、不报错。
function CheatsheetWorkspace({ module }: CtfWorkspaceProps) {
  const {
    language,
    setActiveTab,
    setSelectedPayloadId,
    setSelectedToolId,
    allToolCommands,
  } = useAppContext();
  const sheet = ctfCheatSheets[module.id];
  const zh = language === 'zh';

  const openEntry = useCallback((entry: CheatEntry) => {
    if (!entry.jump) return;
    if (entry.jump.kind === 'payload') {
      setSelectedToolId(null);
      setSelectedPayloadId(entry.jump.id);
      setActiveTab('payloads');
      return;
    }
    const tool = allToolCommands.find(candidate => candidate.id === entry.jump?.id);
    if (!tool) return;
    // 与侧边栏同规则：外链工具走保护性外链，其余进工具详情。
    if (tool.externalUrl && openProtectedExternalLink(tool.externalUrl)) return;
    setSelectedPayloadId(null);
    setSelectedToolId(tool.id);
    setActiveTab('tools');
  }, [allToolCommands, setActiveTab, setSelectedPayloadId, setSelectedToolId]);

  if (!sheet || sheet.entries.length === 0) {
    return <ModulePlaceholder module={module} />;
  }

  return (
    <section className="cheatsheet" aria-label={module.name[language]}>
      <div className="cs-hint" role="note">
        <strong>{zh ? '专属工具建设中，先用题型速查' : 'Dedicated tools are in development — start with the cheat sheet'}</strong>
        <p>
          {zh
            ? '以下条目从项目知识库精选，点击卡片按钮直达载荷库 / 工具命令库对应条目；snippet 点击即复制。'
            : 'Curated from the knowledge base. Card buttons jump to the payload / tool reference; snippets copy on click.'}
        </p>
        {module.note && <p className="cs-hint-note">{module.note[language]}</p>}
      </div>

      <div className="cs-grid">
        {sheet.entries.map(entry => (
          <article key={entry.id} className="cs-card">
            <header className="cs-card-head">
              <h4>{entry.title[language]}</h4>
              {entry.jump && (
                <button
                  type="button"
                  className="cs-jump"
                  title={entry.jump.kind === 'payload'
                    ? (zh ? '跳转到载荷库该条目' : 'Open this entry in the payload library')
                    : (zh ? '跳转到工具命令库该命令集' : 'Open this command set in the tool reference')}
                  onClick={() => openEntry(entry)}
                >
                  {entry.jump.kind === 'payload'
                    ? (zh ? '载荷库 ↗' : 'Payloads ↗')
                    : (zh ? '工具命令 ↗' : 'Tools ↗')}
                </button>
              )}
            </header>
            <p className="cs-summary">{entry.summary[language]}</p>
            {entry.snippet && (
              <button
                type="button"
                className="cs-snippet"
                title={zh ? '点击复制' : 'Click to copy'}
                onClick={() => { void navigator.clipboard.writeText(entry.snippet!); }}
              >
                {entry.snippet}
              </button>
            )}
            {entry.tip && <p className="cs-tip">{entry.tip[language]}</p>}
          </article>
        ))}
      </div>

      <style>{cheatsheetStyles}</style>
    </section>
  );
}

const cheatsheetStyles = `
  .cheatsheet {
    min-width: 0;
    display: grid;
    gap: 12px;
  }

  .cs-hint {
    border: 1px dashed rgba(0, 240, 255, 0.3);
    border-radius: 8px;
    background: var(--bg-card);
    padding: 12px 14px;
    display: grid;
    gap: 5px;
  }

  .cs-hint strong {
    color: var(--neon-cyan);
    font-size: 13px;
    font-weight: 800;
  }

  .cs-hint p {
    margin: 0;
    color: var(--text-secondary);
    font-size: 12px;
    line-height: 1.7;
  }

  .cs-hint-note {
    color: var(--text-muted);
  }

  .cs-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
    gap: 12px;
  }

  .cs-card {
    min-width: 0;
    display: grid;
    gap: 8px;
    align-content: start;
    border: 1px solid var(--border-color);
    border-radius: 8px;
    background: var(--bg-card);
    padding: 13px;
  }

  .cs-card-head {
    display: flex;
    flex-wrap: wrap;
    align-items: baseline;
    gap: 8px;
  }

  .cs-card-head h4 {
    margin: 0;
    color: var(--text-primary);
    font-size: 13px;
    font-weight: 800;
  }

  .cs-jump {
    margin-left: auto;
    min-height: 26px;
    padding: 3px 10px;
    border: 1px solid rgba(0, 240, 255, 0.45);
    border-radius: 999px;
    background: transparent;
    color: var(--neon-cyan);
    font-size: 11px;
    font-weight: 700;
    cursor: pointer;
    white-space: nowrap;
    transition: background var(--transition-fast), color var(--transition-fast);
  }

  .cs-jump:hover {
    background: rgba(0, 240, 255, 0.12);
  }

  .cs-summary {
    margin: 0;
    color: var(--text-secondary);
    font-size: 12px;
    line-height: 1.7;
  }

  .cs-snippet {
    margin: 0;
    padding: 8px 10px;
    border: 1px solid var(--border-color);
    border-radius: 6px;
    background: var(--bg-secondary);
    color: var(--text-secondary);
    font-family: var(--font-mono, monospace);
    font-size: 11px;
    line-height: 1.6;
    text-align: left;
    white-space: pre-wrap;
    word-break: break-all;
    cursor: pointer;
    transition: border-color var(--transition-fast), color var(--transition-fast);
  }

  .cs-snippet:hover {
    border-color: var(--neon-cyan);
    color: var(--neon-cyan);
  }

  .cs-tip {
    margin: 0;
    color: var(--text-muted);
    font-size: 12px;
    line-height: 1.7;
  }

  @media (max-width: 680px) {
    .cs-grid {
      grid-template-columns: 1fr;
    }
  }
`;

export default CheatsheetWorkspace;
