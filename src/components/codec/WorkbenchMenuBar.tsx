import { memo } from 'react';
import { Menu } from '@mantine/core';
import { useLanguage } from '../../appContext';
import { label } from '../../utils/codec/bases';
import '../../styles/workbench-menu-bar.css';

export interface WorkbenchMenuEntry {
  key: string;
  // 预渲染文案（含【名 + 类别动词】方向标记：加/解密、编/解码、压/解压），由调用方按语言生成
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
const WorkbenchMenuBar = memo(function WorkbenchMenuBar({ menus, ariaLabel, current }: WorkbenchMenuBarProps) {
  const { language } = useLanguage();
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
    </div>
  );
});

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
