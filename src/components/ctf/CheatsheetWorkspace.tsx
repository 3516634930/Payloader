import { memo } from 'react';
import { useLanguage } from '../../appContext';
import { ctfCheatSheets } from '../../utils/ctf/cheatsheets';
import type { CtfWorkspaceProps } from '../../utils/ctf/modules';
import CheatsheetSection from './CheatsheetSection';
import ModulePlaceholder from './ModulePlaceholder';

// 题型速查工作区（批次 M，逆向/Pwn 专属工作台上线后收薄为占位壳）：
// 仅服务仍以速查为主体的域（Web/AI）。速查网格与跳转逻辑由 CheatsheetSection 承载；
// .cs-hint 样式由 styles/cheatsheet-section.css 提供，本壳不再重复。
const CheatsheetWorkspace = memo(function CheatsheetWorkspace({ module }: CtfWorkspaceProps) {
  const { language } = useLanguage();
  const zh = language === 'zh';

  const sheet = ctfCheatSheets[module.id];
  if (!sheet || sheet.entries.length === 0) {
    return <ModulePlaceholder module={module} />;
  }

  return (
    // .cheatsheet 的 grid/gap/min-width 样式由 styles/cheatsheet-section.css 提供。
    <div className="cheatsheet">
      <div className="cs-hint" role="note">
        <strong>{zh ? '专属工具建设中，先用题型速查' : 'Dedicated tools are in development — start with the cheat sheet'}</strong>
        <p>
          {zh
            ? '以下条目从项目知识库精选，点击卡片按钮直达载荷库 / 工具命令库对应条目；snippet 点击即复制。'
            : 'Curated from the knowledge base. Card buttons jump to the payload / tool reference; snippets copy on click.'}
        </p>
        {module.note && <p className="cs-hint-note">{module.note[language]}</p>}
      </div>
      <CheatsheetSection moduleId={module.id} variant="placeholder" />
    </div>
  );
});

export default CheatsheetWorkspace;
