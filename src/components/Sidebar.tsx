import { memo, useCallback, useEffect, useMemo, useState } from 'react';
import { useLanguage, useNav, useSearch, useStaticData } from '../appContext';
import { t, getText } from '../i18n';
import { openProtectedExternalLink } from '../protectedLinks';
import { groupDenseLeaves } from '../utils/navigationGrouping';
import type { I18nText, NavItem } from '../types';
import '../styles/sidebar.css';

interface TreeNodeProps {
  item: NavItem;
  level: number;
  matchedIds: ReadonlySet<string>;
  forceExpand: boolean;
  isSelected: boolean;
  // 本节点子树内是否包含当前选中叶子：选择跨枝移动时祖先链借此感知并重渲染，
  // 未受影响子树在 memo 比较器处整体 bail（原始选中 id 只供递归计算，不进比较面）。
  branchSelected: boolean;
  onSelect: (item: NavItem) => void;
  isFirst?: boolean;
  onNavigate?: () => void;
  selectedPayloadId: string | null;
  selectedToolId: string | null;
  // 当前选中叶子的统一 id（payload 优先）：比较器用它感知"同枝内移动选中"——
  // 该场景下祖先链 branchSelected 恒为 true、自身 isSelected 不变，没有它祖先会整体 bail。
  selectedLeafId: string | null;
}

// 递归判断子树是否包含选中叶子（Nav 数据为静态引用，按值比较即可）。
function subtreeContains(item: NavItem, selectedPayloadId: string | null, selectedToolId: string | null): boolean {
  if ((item.payloadId != null && item.payloadId === selectedPayloadId)
    || (item.toolId != null && item.toolId === selectedToolId)) {
    return true;
  }
  return Boolean(item.children?.some(child => subtreeContains(child, selectedPayloadId, selectedToolId)));
}

const visibleTreeItems = (tree: Element | null) => (
  tree
    ? Array.from(tree.querySelectorAll<HTMLButtonElement>('button[role="treeitem"]'))
        .filter(element => element.offsetParent !== null)
    : []
);

function handleTreeKeyDown(event: KeyboardEvent) {
  const current = event.target;
  if (!(current instanceof HTMLButtonElement) || current.getAttribute('role') !== 'treeitem') return;

  const items = visibleTreeItems(current.closest('[role="tree"]'));
  const currentIndex = items.indexOf(current);
  const focusAt = (index: number) => {
    if (!items.length) return;
    items[Math.max(0, Math.min(index, items.length - 1))]?.focus();
  };

  if (event.key === 'ArrowDown') {
    event.preventDefault();
    focusAt(currentIndex + 1);
  } else if (event.key === 'ArrowUp') {
    event.preventDefault();
    focusAt(currentIndex - 1);
  } else if (event.key === 'Home') {
    event.preventDefault();
    focusAt(0);
  } else if (event.key === 'End') {
    event.preventDefault();
    focusAt(items.length - 1);
  } else if (event.key === 'ArrowRight' && current.hasAttribute('aria-expanded')) {
    event.preventDefault();
    if (current.getAttribute('aria-expanded') === 'false') {
      current.click();
    } else {
      const childGroup = current.parentElement?.children[1];
      childGroup?.getElementsByTagName('button')[0]?.focus();
    }
  } else if (event.key === 'ArrowLeft') {
    if (current.getAttribute('aria-expanded') === 'true') {
      event.preventDefault();
      current.click();
      return;
    }
    const parentGroup = current.parentElement?.parentElement;
    const parentItem = parentGroup?.getAttribute('role') === 'group'
      ? parentGroup.parentElement?.children[0]
      : null;
    if (parentItem instanceof HTMLElement) {
      event.preventDefault();
      parentItem.focus();
    }
  }
}

const TreeNode = memo(function TreeNode({
  item,
  level,
  matchedIds,
  forceExpand,
  isSelected,
  onSelect,
  isFirst = false,
  onNavigate,
  selectedPayloadId,
  selectedToolId,
  selectedLeafId,
}: TreeNodeProps) {
  // branchSelected 不解构：它是 memo 比较器的传播信号（见比较器），组件体无需读取。
  const [isExpanded, setIsExpanded] = useState(false);
  const { language } = useLanguage();

  const hasChildren = item.children && item.children.length > 0;
  // 叶子过多的层级插入虚拟分组节点（二级菜单），避免几十个条目平铺在一层。
  const displayChildren = useMemo(
    () => (hasChildren
      ? groupDenseLeaves(
        item,
        item.children!,
        item.children!.some(child => child.payloadId) ? 'payload' : 'tool',
      )
      : []),
    [item, hasChildren],
  );
  const isMatched = matchedIds.has(item.payloadId || item.toolId || '');
  const hasMatchedDescendant = hasChildren && hasDescendantMatch(item, matchedIds);

  // Auto-expand when searching
  const effectiveExpanded = forceExpand ? (hasMatchedDescendant || isMatched) : isExpanded;

  if (forceExpand && !isMatched && !hasMatchedDescendant && !hasChildren) {
    return null;
  }

  if (forceExpand && hasChildren && !hasMatchedDescendant) {
    return null;
  }

  const handleClick = () => {
    if (hasChildren) {
      setIsExpanded(!isExpanded);
    } else {
      onSelect(item);
    }
  };

  return (
    <div className="tree-node" role="none">
      <button
        type="button"
        role="treeitem"
        aria-level={level + 1}
        aria-expanded={hasChildren ? effectiveExpanded : undefined}
        aria-selected={isSelected}
        aria-current={isSelected ? 'page' : undefined}
        tabIndex={isFirst ? 0 : -1}
        className={`tree-item ${isSelected ? 'selected' : ''} ${hasChildren ? 'has-children' : ''} ${isMatched && forceExpand ? 'search-match' : ''}`}
        style={{ paddingLeft: `${level * 16 + 12}px` }}
        onClick={handleClick}
      >
        {hasChildren && (
          <span className={`tree-expand-icon ${effectiveExpanded ? 'expanded' : ''}`} aria-hidden="true">
            ▶
          </span>
        )}
        {!hasChildren && <span className="tree-leaf-spacer" aria-hidden="true" />}
        <span className="tree-label">{getText(item.name, language)}</span>
        {(item.payloadId || item.toolId) && (
          <span className="tree-badge" aria-hidden="true">
            {item.payloadId ? 'P' : 'T'}
          </span>
        )}
      </button>
      {hasChildren && effectiveExpanded && (
        <div className="tree-children" role="group">
          {displayChildren.map(child => (
            <TreeNode
              key={child.id}
              item={child}
              level={level + 1}
              matchedIds={matchedIds}
              forceExpand={forceExpand}
              isSelected={(child.payloadId != null && child.payloadId === selectedPayloadId)
                || (child.toolId != null && child.toolId === selectedToolId)}
              branchSelected={subtreeContains(child, selectedPayloadId, selectedToolId)}
              onSelect={onSelect}
              onNavigate={onNavigate}
              selectedPayloadId={selectedPayloadId}
              selectedToolId={selectedToolId}
              selectedLeafId={selectedLeafId}
            />
          ))}
        </div>
      )}
    </div>
  );
}, (prev, next) =>
  // 规则一：选中叶子 id 变化且本枝（前或后）含选中 → 同枝内移动/进出，祖先链必须重渲染，
  // 否则新旧叶子的 isSelected 翻转永远无法下发（这是纯 branchSelected 方案的盲区）。
  // 规则二：其余情况按显示相关 props 逐项相等才 bail，未受影响子树整体跳过。
  !(prev.selectedLeafId !== next.selectedLeafId && (prev.branchSelected || next.branchSelected))
  && prev.item === next.item
  && prev.level === next.level
  && prev.matchedIds === next.matchedIds
  && prev.forceExpand === next.forceExpand
  && prev.isSelected === next.isSelected
  && prev.branchSelected === next.branchSelected
  && prev.onSelect === next.onSelect
  && prev.isFirst === next.isFirst
  && prev.onNavigate === next.onNavigate
);

function hasDescendantMatch(item: NavItem, matchedIds: ReadonlySet<string>): boolean {
  if (!item.children) return false;
  for (const child of item.children) {
    if (matchedIds.has(child.payloadId || child.toolId || '')) return true;
    if (hasDescendantMatch(child, matchedIds)) return true;
  }
  return false;
}

function isTreeItemVisible(item: NavItem, matchedIds: ReadonlySet<string>, isSearching: boolean): boolean {
  if (!isSearching) return true;
  const hasChildren = Boolean(item.children?.length);
  return hasChildren
    ? hasDescendantMatch(item, matchedIds)
    : matchedIds.has(item.payloadId || item.toolId || '');
}

function isCustomCategory(value: I18nText): boolean {
  if (typeof value === 'string') return value === '自定义' || value === 'Custom';
  return value.zh === '自定义' || value.en === 'Custom';
}

function CustomSection({ items, matchedIds, onNavigate, language, selectedPayloadId, selectedToolId, onSelect, isFirst = false }: { items: NavItem[]; matchedIds: ReadonlySet<string>; onNavigate?: () => void; language: string; selectedPayloadId: string | null; selectedToolId: string | null; onSelect: (item: NavItem) => void; isFirst?: boolean }) {
  const [expanded, setExpanded] = useState(false);
  const selectedLeafId = selectedPayloadId ?? selectedToolId;
  return (
    <div className="tree-node" role="none">
      <button
        type="button"
        role="treeitem"
        aria-level={1}
        aria-expanded={expanded}
        aria-selected={false}
        tabIndex={isFirst ? 0 : -1}
        className="tree-item has-children"
        style={{ paddingLeft: '12px' }}
        onClick={() => setExpanded(current => !current)}
      >
        <span className={`tree-expand-icon ${expanded ? 'expanded' : ''}`} aria-hidden="true">▶</span>
        <span className="tree-label">{language === 'zh' ? '自定义文本' : 'Custom Text'}</span>
      </button>
      {expanded && (
        <div className="tree-children" role="group">
          {items.map(item => (
            <TreeNode
              key={item.id}
              item={item}
              level={1}
              matchedIds={matchedIds}
              forceExpand={false}
              isSelected={(item.payloadId != null && item.payloadId === selectedPayloadId)
                || (item.toolId != null && item.toolId === selectedToolId)}
              branchSelected={subtreeContains(item, selectedPayloadId, selectedToolId)}
              onSelect={onSelect}
              onNavigate={onNavigate}
              selectedPayloadId={selectedPayloadId}
              selectedToolId={selectedToolId}
              selectedLeafId={selectedLeafId}
            />
          ))}
        </div>
      )}
    </div>
  );
}

interface SidebarProps {
  collapsed: boolean;
  onClose?: () => void;
  onNavigate?: () => void;
}

function Sidebar({ collapsed, onClose, onNavigate }: SidebarProps) {
  const { activeTab, selectedPayloadId, selectedToolId, setSelectedPayloadId, setSelectedToolId } = useNav();
  const selectedLeafId = selectedPayloadId ?? selectedToolId;
  const { deferredSearchQuery, searchMatches } = useSearch();
  const { language } = useLanguage();
  const { allPayloads, allToolCommands, allPayloadNavigation, allToolNavigation } = useStaticData();

  const customNavItems: NavItem[] = useMemo(() => {
    if (activeTab === 'payloads') {
      return allPayloads
        .filter(item => isCustomCategory(item.category))
        .map(item => ({
          id: `custom-payload-nav-${item.id}`,
          name: item.name,
          payloadId: item.id,
        }));
    }
    if (activeTab === 'tools') {
      return allToolCommands
        .filter(item => isCustomCategory(item.category))
        .map(item => ({
          id: `custom-tool-nav-${item.id}`,
          name: item.name,
          toolId: item.id,
        }));
    }
    return [];
  }, [activeTab, allPayloads, allToolCommands]);

  const data = useMemo(
    () => activeTab === 'payloads' ? allPayloadNavigation : activeTab === 'tools' ? allToolNavigation : [],
    [activeTab, allPayloadNavigation, allToolNavigation],
  );

  // 选中处理（TreeNode 原 context 直读迁移而来）：叶子点击统一走这里。
  // useCallback 保证引用稳定，TreeNode 的 memo 比较器因此可通过。
  const handleSelect = useCallback((item: NavItem) => {
    if (item.payloadId) {
      setSelectedPayloadId(item.payloadId);
      setSelectedToolId(null);
      onNavigate?.();
      return;
    }
    if (item.toolId) {
      const tool = allToolCommands.find(candidate => candidate.id === item.toolId);
      if (tool?.externalUrl && openProtectedExternalLink(tool.externalUrl)) {
        onNavigate?.();
        return;
      }
      setSelectedToolId(item.toolId);
      setSelectedPayloadId(null);
      onNavigate?.();
    }
  }, [allToolCommands, onNavigate, setSelectedPayloadId, setSelectedToolId]);

  const matchedIds = activeTab === 'payloads' ? searchMatches.payloadIds : searchMatches.toolIds;
  const matchCount = matchedIds.size;
  const isSearching = deferredSearchQuery.trim().length > 0;
  const firstVisibleRootId = useMemo(
    () => data.find(item => isTreeItemVisible(item, matchedIds, isSearching))?.id ?? null,
    [data, isSearching, matchedIds],
  );

  useEffect(() => {
    document.addEventListener('keydown', handleTreeKeyDown);
    return () => document.removeEventListener('keydown', handleTreeKeyDown);
  }, []);

  useEffect(() => {
    if (collapsed) return;

    const handleEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && window.matchMedia('(max-width: 900px)').matches) {
        onClose?.();
      }
    };
    document.addEventListener('keydown', handleEscape);
    return () => document.removeEventListener('keydown', handleEscape);
  }, [collapsed, onClose]);

  return (
    <aside
      id="primary-navigation"
      className={`sidebar ${collapsed ? 'collapsed' : ''}`}
      aria-label={activeTab === 'payloads' ? 'Payload 分类导航' : '工具分类导航'}
      aria-hidden={collapsed}
      inert={collapsed}
    >
      <div className="sidebar-content">
        <div className="sidebar-header">
          <h2>{activeTab === 'payloads' ? t('sidebar.attackCategories', language) : activeTab === 'tools' ? t('sidebar.toolCategories', language) : (language === 'zh' ? '自定义 Payload' : 'Custom Payload')}</h2>
          {isSearching && (
            <span className="search-result-count" role="status" aria-live="polite">
              {t('sidebar.searchFound', language, { count: matchCount })}
            </span>
          )}
        </div>
        <div className="tree-container" role="tree" aria-label={activeTab === 'payloads' ? 'Payload 分类' : '工具分类'}>
          {isSearching && matchCount === 0 ? (
            <div className="no-search-results">
              <p>{t('sidebar.noResults', language)}</p>
              <span className="no-results-hint">{t('sidebar.noResultsHint', language)}</span>
            </div>
          ) : (
            <>
              {data.map(item => (
                <TreeNode
                  key={item.id}
                  item={item}
                  level={0}
                  matchedIds={matchedIds}
                  forceExpand={isSearching}
                  isSelected={(item.payloadId != null && item.payloadId === selectedPayloadId)
                    || (item.toolId != null && item.toolId === selectedToolId)}
                  branchSelected={subtreeContains(item, selectedPayloadId, selectedToolId)}
                  onSelect={handleSelect}
                  isFirst={item.id === firstVisibleRootId}
                  onNavigate={onNavigate}
                  selectedPayloadId={selectedPayloadId}
                  selectedToolId={selectedToolId}
                  selectedLeafId={selectedLeafId}
                />
              ))}
              {(activeTab === 'payloads' || activeTab === 'tools') && customNavItems.length > 0 && !isSearching && (
                <CustomSection
                  items={customNavItems}
                  matchedIds={matchedIds}
                  onNavigate={onNavigate}
                  language={language}
                  selectedPayloadId={selectedPayloadId}
                  selectedToolId={selectedToolId}
                  onSelect={handleSelect}
                  isFirst={data.length === 0}
                />
              )}
            </>
          )}
        </div>
      </div>
    </aside>
  );
}

export default Sidebar;
