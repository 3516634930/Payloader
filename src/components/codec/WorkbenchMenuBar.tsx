import { Menu } from '@mantine/core';
import { useAppContext } from '../../appContext';
import { label } from '../../utils/codec/bases';

export interface WorkbenchMenuEntry {
  key: string;
  // 预渲染文案（含【名解密】方向标记），由调用方按语言生成
  label: string;
  title?: string;
  active?: boolean;
  onSelect: () => void;
}

export interface WorkbenchMenuDef {
  id: string;
  name: { zh: string; en: string };
  groups: Array<{ label: { zh: string; en: string } | null; entries: WorkbenchMenuEntry[] }>;
}

interface WorkbenchMenuBarProps {
  menus: WorkbenchMenuDef[];
  ariaLabel: string;
  // 条尾「当前」激活操作名（可选）
  current?: string;
}

// 顶部菜单栏（随波逐流形态）：顶部横排菜单 + 下拉操作列表，点击菜单项由调用方立即执行。
// withinPortal 让下拉脱离横向滚动容器渲染，移动端小屏不被裁剪；Mantine Menu 自带
// 方向键 + Enter 键盘导航与 Esc 收起。
function WorkbenchMenuBar({ menus, ariaLabel, current }: WorkbenchMenuBarProps) {
  const { language } = useAppContext();
  return (
    <div className="wb-menubar" role="toolbar" aria-label={ariaLabel}>
      <div className="wb-menubar-track">
        {menus.map(menuDef => (
          <Menu key={menuDef.id} withinPortal trigger="click" position="bottom-start" shadow="md" radius="md">
            <Menu.Target>
              <button type="button" className="wb-menubar-trigger">{label(menuDef.name, language)}</button>
            </Menu.Target>
            <Menu.Dropdown className="wb-menubar-dropdown" data-menubar-menu={menuDef.id}>
              {menuDef.groups.map((group, groupIndex) => (
                <FragmentMenuGroup key={groupIndex} label={group.label} entries={group.entries} language={language} />
              ))}
            </Menu.Dropdown>
          </Menu>
        ))}
        {current ? (
          <span className="wb-menubar-current" aria-live="polite">
            {language === 'zh' ? '当前：' : 'Active: '}
            {current}
          </span>
        ) : null}
      </div>

      <style>{`
        .wb-menubar {
          min-width: 0;
        }

        .wb-menubar-track {
          min-width: 0;
          display: flex;
          align-items: center;
          gap: 6px;
          overflow-x: auto;
          scrollbar-width: thin;
          -webkit-overflow-scrolling: touch;
          padding-bottom: 2px;
        }

        .wb-menubar-trigger {
          flex-shrink: 0;
          min-height: 34px;
          min-width: 0;
          border: 1px solid var(--border-color);
          border-radius: 6px;
          background: var(--bg-secondary);
          color: var(--text-secondary);
          padding: 6px 11px;
          font-size: 12px;
          font-weight: 800;
          white-space: nowrap;
          cursor: pointer;
          transition: border-color var(--transition-fast), color var(--transition-fast);
        }

        .wb-menubar-trigger:hover {
          border-color: var(--neon-cyan);
          color: var(--neon-cyan);
        }

        .wb-menubar-current {
          flex-shrink: 0;
          margin-left: auto;
          min-width: 0;
          max-width: 46%;
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
          color: var(--neon-cyan);
          font-size: 12px;
          font-weight: 700;
        }

        .wb-menubar-dropdown {
          max-height: min(62vh, 520px);
          overflow-y: auto;
        }

        .wb-menubar-dropdown .wb-menubar-item {
          font-size: 12px;
          font-weight: 700;
        }

        .wb-menubar-dropdown .wb-menubar-item-active {
          background: rgba(0, 240, 255, 0.12);
          color: var(--neon-cyan);
        }

        @media (max-width: 680px) {
          .wb-menubar-trigger {
            min-height: 44px;
          }
        }
      `}</style>
    </div>
  );
}

// 下拉内分组（小节标签 + 条目）：用 Fragment 包装避免额外 DOM 干扰 Mantine 菜单键盘导航。
function FragmentMenuGroup({
  label: groupLabel,
  entries,
  language,
}: {
  label: { zh: string; en: string } | null;
  entries: WorkbenchMenuEntry[];
  language: 'zh' | 'en';
}) {
  return (
    <>
      {groupLabel ? <Menu.Label>{groupLabel[language]}</Menu.Label> : null}
      {entries.map(entry => (
        <Menu.Item
          key={entry.key}
          className={`wb-menubar-item ${entry.active ? 'wb-menubar-item-active' : ''}`}
          title={entry.title}
          onClick={entry.onSelect}
        >
          {entry.label}
        </Menu.Item>
      ))}
    </>
  );
}

export default WorkbenchMenuBar;
export { WorkbenchMenuBar };
