import { useCallback } from 'react';
import { notifications } from '@mantine/notifications';
import { useLanguage, useNav, useStaticData } from '../../appContext';
import { openProtectedExternalLink } from '../../protectedLinks';
import type { CheatEntry } from '../../utils/ctf/cheatsheets';
import { copyToClipboard } from '../../utils/clipboard';
import '../../styles/cheatsheet-section.css';

interface CheatsheetSectionProps {
  moduleId: string;
  // footer = 工作台底部的"题型速查"区块（带区块标题）；placeholder = 速查占位域的主体网格。
  variant: 'footer' | 'placeholder';
}

// 题型速查网格（逆向/Pwn 工作台底部与速查占位域共享）：条目来自 src/utils/ctf/cheatsheets/ 静态种子，
// 点击卡片按钮直达载荷库 / 工具命令库对应条目，snippet 点击复制。
function CheatsheetSection({ moduleId, variant }: CheatsheetSectionProps) {
  const { language } = useLanguage();
  const { setActiveTab, setSelectedPayloadId, setSelectedToolId } = useNav();
  const { allToolCommands } = useStaticData();
  const { ctfCheatsheets } = useStaticData();
  const sheet = ctfCheatsheets?.[moduleId];
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
                  void copyToClipboard(entry.snippet!).then(ok => {
                    if (!ok) notifications.show({ message: zh ? '复制失败，请手动选择文本复制。' : 'Copy failed; select the text manually.', color: 'red' });
                    else notifications.show({ message: zh ? '片段已复制。' : 'Snippet copied.', color: 'teal', autoClose: 1400 });
                  });
                }}
              >
                {entry.snippet}
              </button>
            )}
            {entry.tip && <p className="cs-tip">{entry.tip[language]}</p>}
          </article>
        ))}
      </div>
    </section>
  );
}

export default CheatsheetSection;
