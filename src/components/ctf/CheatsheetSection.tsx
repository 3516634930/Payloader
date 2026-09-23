import { useCallback } from 'react';
import { notifications } from '@mantine/notifications';
import { useAppContext } from '../../appContext';
import { openProtectedExternalLink } from '../../protectedLinks';
import { ctfCheatSheets } from '../../utils/ctf/cheatsheets';
import type { CheatEntry } from '../../utils/ctf/cheatsheets';

interface CheatsheetSectionProps {
  moduleId: string;
  // footer = 工作台底部的"题型速查"区块（带区块标题）；placeholder = 速查占位域的主体网格。
  variant: 'footer' | 'placeholder';
}

// 题型速查网格（逆向/Pwn 工作台底部与速查占位域共享）：条目来自 src/utils/ctf/cheatsheets/ 静态种子，
// 点击卡片按钮直达载荷库 / 工具命令库对应条目，snippet 点击复制。
function CheatsheetSection({ moduleId, variant }: CheatsheetSectionProps) {
  const {
    language,
    setActiveTab,
    setSelectedPayloadId,
    setSelectedToolId,
    allToolCommands,
  } = useAppContext();
  const sheet = ctfCheatSheets[moduleId];
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

  if (!sheet || sheet.entries.length === 0) return null;

  return (
    <section className="cheatsheet" aria-label={zh ? '题型速查' : 'Cheat sheet'}>
      {variant === 'footer' && (
        <div className="cs-footer-head">
          <strong>{zh ? '题型速查' : 'Cheat sheet'}</strong>
          <span>{zh ? '从知识库精选的第一手打法，点击直达对应条目。' : 'Curated first moves from the knowledge base — click to jump.'}</span>
        </div>
      )}
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
                onClick={() => {
                  void navigator.clipboard.writeText(entry.snippet!).then(
                    () => notifications.show({ message: zh ? '片段已复制。' : 'Snippet copied.', color: 'teal', autoClose: 1400 }),
                    () => notifications.show({ message: zh ? '复制失败，请手动选择文本复制。' : 'Copy failed; select the text manually.', color: 'red' }),
                  );
                }}
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

  .cs-footer-head {
    display: flex;
    flex-wrap: wrap;
    align-items: baseline;
    gap: 10px;
    padding-top: 4px;
    border-top: 1px solid var(--border-color);
  }

  .cs-footer-head strong {
    color: var(--neon-cyan);
    font-size: 13px;
    font-weight: 800;
  }

  .cs-footer-head span {
    color: var(--text-muted);
    font-size: 12px;
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

export default CheatsheetSection;
