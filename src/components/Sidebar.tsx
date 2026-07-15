import { useEffect, useMemo, useState } from 'react';
import { useAppContext } from '../appContext';
import { t, getText } from '../i18n';
import { openProtectedExternalLink } from '../protectedLinks';
import type { I18nText, NavItem } from '../types';

interface TreeNodeProps {
  item: NavItem;
  level: number;
  matchedIds: ReadonlySet<string>;
  forceExpand: boolean;
  isFirst?: boolean;
  onNavigate?: () => void;
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

function TreeNode({ item, level, matchedIds, forceExpand, isFirst = false, onNavigate }: TreeNodeProps) {
  const [isExpanded, setIsExpanded] = useState(false);
  const { selectedPayloadId, setSelectedPayloadId, selectedToolId, setSelectedToolId, allToolCommands, language } = useAppContext();

  const hasChildren = item.children && item.children.length > 0;
  const isSelected = item.payloadId === selectedPayloadId || item.toolId === selectedToolId;

  // Check if this node or any descendant matches the search
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
    } else if (item.payloadId) {
      setSelectedPayloadId(item.payloadId);
      setSelectedToolId(null);
      onNavigate?.();
    } else if (item.toolId) {
      const tool = allToolCommands.find(candidate => candidate.id === item.toolId);
      if (tool?.externalUrl && openProtectedExternalLink(tool.externalUrl)) {
        onNavigate?.();
        return;
      }
      setSelectedToolId(item.toolId);
      setSelectedPayloadId(null);
      onNavigate?.();
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
          {item.children!.map(child => (
            <TreeNode key={child.id} item={child} level={level + 1} matchedIds={matchedIds} forceExpand={forceExpand} onNavigate={onNavigate} />
          ))}
        </div>
      )}
    </div>
  );
}

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

function CustomSection({ items, matchedIds, onNavigate, language, isFirst = false }: { items: NavItem[]; matchedIds: ReadonlySet<string>; onNavigate?: () => void; language: string; isFirst?: boolean }) {
  const [expanded, setExpanded] = useState(false);
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
            <TreeNode key={item.id} item={item} level={1} matchedIds={matchedIds} forceExpand={false} onNavigate={onNavigate} />
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
  const {
    activeTab,
    deferredSearchQuery,
    searchMatches,
    language,
    allPayloads,
    allToolCommands,
    allPayloadNavigation,
    allToolNavigation,
  } = useAppContext();

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
                <TreeNode key={item.id} item={item} level={0} matchedIds={matchedIds} forceExpand={isSearching} isFirst={item.id === firstVisibleRootId} onNavigate={onNavigate} />
              ))}
              {(activeTab === 'payloads' || activeTab === 'tools') && customNavItems.length > 0 && !isSearching && (
                <CustomSection items={customNavItems} matchedIds={matchedIds} onNavigate={onNavigate} language={language} isFirst={data.length === 0} />
              )}
            </>
          )}
        </div>
      </div>

      <style>{`
        .sidebar {
          width: 280px;
          height: calc(100vh - var(--app-header-height));
          height: calc(100dvh - var(--app-header-height));
          background: var(--bg-secondary);
          border-right: 1px solid var(--border-color);
          transition: transform var(--transition-normal), visibility var(--transition-fast);
          overflow: hidden;
          position: relative;
          flex: 0 0 auto;
        }

        .sidebar::after {
          content: '';
          position: absolute;
          top: 0;
          right: 0;
          width: 1px;
          height: 100%;
          background: linear-gradient(180deg, var(--neon-cyan), transparent);
          opacity: 0.3;
        }

        .sidebar.collapsed {
          width: 0;
          border-right: 0;
        }

        .sidebar-content {
          width: 280px;
          height: 100%;
          display: flex;
          flex-direction: column;
        }

        .sidebar-header {
          padding: 16px;
          border-bottom: 1px solid var(--border-color);
          display: flex;
          align-items: center;
          justify-content: space-between;
        }

        .sidebar-header h2 {
          font-size: 12px;
          font-weight: 600;
          text-transform: uppercase;
          letter-spacing: 2px;
          color: var(--text-muted);
        }

        .search-result-count {
          font-size: 11px;
          color: var(--neon-green);
          font-weight: 500;
        }

        .tree-container {
          flex: 1;
          overflow-y: auto;
          padding: 8px 0;
        }

        .no-search-results {
          display: flex;
          flex-direction: column;
          align-items: center;
          padding: 40px 20px;
          text-align: center;
        }

        .no-results-icon {
          font-size: 32px;
          margin-bottom: 12px;
          opacity: 0.5;
        }

        .no-search-results p {
          font-size: 13px;
          color: var(--text-muted);
          margin-bottom: 4px;
        }

        .no-results-hint {
          font-size: 11px;
          color: var(--text-muted);
          opacity: 0.7;
        }

        .tree-node {
          user-select: none;
        }

        .tree-item {
          display: flex;
          align-items: center;
          width: 100%;
          min-height: 40px;
          padding: 8px 12px;
          border: 0;
          border-left: 2px solid transparent;
          border-radius: 0;
          background: transparent;
          color: inherit;
          text-align: left;
          cursor: pointer;
          transition: all var(--transition-fast);
        }

        .tree-item:hover {
          background: var(--bg-hover);
        }

        .tree-item.selected {
          background: rgba(0, 240, 255, 0.1);
          border-left-color: var(--neon-cyan);
        }

        .tree-item.selected .tree-label {
          color: var(--neon-cyan);
        }

        .tree-item.search-match {
          background: rgba(0, 255, 136, 0.08);
          border-left-color: var(--neon-green);
        }

        .tree-item.search-match .tree-label {
          color: var(--neon-green);
          font-weight: 600;
        }

        .tree-expand-icon {
          width: 16px;
          font-size: 8px;
          color: var(--text-muted);
          transition: transform var(--transition-fast);
          margin-right: 4px;
        }

        .tree-expand-icon.expanded {
          transform: rotate(90deg);
        }

        .tree-leaf-spacer {
          width: 20px;
        }

        .tree-label {
          flex: 1;
          font-size: 13px;
          color: var(--text-secondary);
          white-space: nowrap;
          overflow: hidden;
          text-overflow: ellipsis;
        }

        .tree-item:hover .tree-label {
          color: var(--text-primary);
        }

        .tree-badge {
          min-width: 20px;
          padding: 1px 4px;
          border: 1px solid var(--border-color);
          border-radius: 4px;
          color: var(--text-muted);
          font-family: var(--font-mono);
          font-size: 10px;
          line-height: 1.4;
          text-align: center;
        }

        .tree-children {
          animation: slideDown 0.2s ease;
        }

        @media (max-width: 900px) {
          .sidebar {
            position: fixed;
            top: var(--app-header-height);
            left: 0;
            bottom: 0;
            height: calc(100dvh - var(--app-header-height));
            width: var(--app-drawer-width);
            z-index: 90;
            box-shadow: 12px 0 30px rgba(0, 0, 0, 0.35);
            transform: translateX(0);
            visibility: visible;
            will-change: transform;
          }

          .sidebar.collapsed {
            width: var(--app-drawer-width);
            transform: translateX(calc(-1 * var(--app-drawer-width)));
            visibility: hidden;
            pointer-events: none;
            box-shadow: none;
            border-right: 0;
          }

          .sidebar-content {
            width: var(--app-drawer-width);
          }

          .tree-item {
            min-height: 44px;
          }
        }

        @keyframes slideDown {
          from {
            opacity: 0;
            transform: translateY(-10px);
          }
          to {
            opacity: 1;
            transform: translateY(0);
          }
        }
      `}</style>
    </aside>
  );
}

export default Sidebar;
