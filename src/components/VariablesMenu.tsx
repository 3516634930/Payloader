import { useState } from 'react';
import type { RefObject } from 'react';
import { useLanguage, useSession } from '../appContext';
import { t, getText } from '../i18n';

const variableGroupLabels: Record<string, { zh: string; en: string }> = {
  target: { zh: '目标信息', en: 'Target' },
  request: { zh: '请求参数', en: 'Request' },
  auth: { zh: '认证会话', en: 'Auth' },
  callback: { zh: '回连与带外', en: 'Callback' },
  file: { zh: '文件与字典', en: 'Files' },
  cloud: { zh: '云资源', en: 'Cloud' },
  infra: { zh: '内网与基础设施', en: 'Infra' },
  other: { zh: '其它', en: 'Other' },
};

const pinnedVariableKeys = new Set(['URL', 'TARGET', 'PATH', 'PARAM', 'PARAM_VALUE', 'COOKIE', 'HEADER_AUTH', 'ATTACKER_IP', 'LPORT']);

interface VariablesMenuProps {
  open: boolean;
  onToggle: () => void;
  onClose: () => void;
  variablesToggleRef: RefObject<HTMLButtonElement | null>;
  variablesPanelRef: RefObject<HTMLDivElement | null>;
}

function VariablesMenu({ open, onToggle, onClose, variablesToggleRef, variablesPanelRef }: VariablesMenuProps) {
  const { globalVariables, setGlobalVariables } = useSession();
  const { language } = useLanguage();
  const [variableSearch, setVariableSearch] = useState('');
  const [collapsedVariableGroups, setCollapsedVariableGroups] = useState<Set<string>>(() => new Set(['cloud', 'infra']));

  const updateVariable = (key: string, value: string) => {
    setGlobalVariables(prev => 
      prev.map(v => v.key === key ? { ...v, value } : v)
    );
  };

  const toggleVariableGroup = (group: string) => {
    setCollapsedVariableGroups(prev => {
      const next = new Set(prev);
      if (next.has(group)) next.delete(group);
      else next.add(group);
      return next;
    });
  };

  const variableGroups = (() => {
    const query = variableSearch.trim().toLowerCase();
    const groups = new Map<string, typeof globalVariables>();

    for (const variable of globalVariables) {
      const group = variable.group || 'other';
      const searchable = [
        variable.key,
        variable.value,
        getText(variable.description, language),
        getText(variableGroupLabels[group] || variableGroupLabels.other, language),
      ].join(' ').toLowerCase();

      if (query && !searchable.includes(query)) continue;
      const existing = groups.get(group) || [];
      existing.push(variable);
      groups.set(group, existing);
    }

    return Array.from(groups.entries()).map(([group, variables]) => ({
      group,
      variables: variables.sort((a, b) => {
        const pinnedA = pinnedVariableKeys.has(a.key) ? 0 : 1;
        const pinnedB = pinnedVariableKeys.has(b.key) ? 0 : 1;
        if (pinnedA !== pinnedB) return pinnedA - pinnedB;
        return a.key.localeCompare(b.key);
      }),
    }));
  })();

  return (
    <div className="variables-dropdown">
      <button 
        ref={variablesToggleRef}
        type="button"
        className="variables-toggle"
        onClick={onToggle}
        aria-expanded={open}
        aria-controls="variables-panel"
      >
        {t('header.variables', language)}
      </button>
      {open && (
        <div ref={variablesPanelRef} className="variables-panel" id="variables-panel">
          <div className="variables-header">
            <div>
              <h3>{t('header.variablesTitle', language)}</h3>
              <span className="variables-hint">{t('header.variablesHint', language)}</span>
            </div>
            <button type="button" className="variables-close" onClick={onClose} aria-label="关闭全局变量">×</button>
          </div>
          <div className="variables-tools">
            <input
              type="search"
              name="variable-search"
              value={variableSearch}
              onChange={event => setVariableSearch(event.target.value)}
              placeholder={language === 'zh' ? '搜索变量、说明或当前值' : 'Search variable, note, or value'}
              className="variables-search"
            />
          </div>
          <div className="variables-list">
            {variableGroups.length ? variableGroups.map(({ group, variables }) => {
              const collapsed = collapsedVariableGroups.has(group) && !variableSearch.trim();
              const groupLabel = getText(variableGroupLabels[group] || variableGroupLabels.other, language);
              return (
                <section key={group} className="variable-group">
                  <button
                    type="button"
                    className="variable-group-toggle"
                    onClick={() => toggleVariableGroup(group)}
                    aria-expanded={!collapsed}
                  >
                    <span className={`variable-group-icon ${collapsed ? '' : 'expanded'}`}>▶</span>
                    <span>{groupLabel}</span>
                    <small>{variables.length}</small>
                  </button>
                  {!collapsed && (
                    <div className="variable-group-body">
                      {variables.map(variable => (
                        <div key={variable.key} className={`variable-item ${pinnedVariableKeys.has(variable.key) ? 'pinned' : ''}`}>
                          <div className="variable-info">
                            <span className="variable-key">{`{${variable.key}}`}</span>
                            <span className="variable-desc">{getText(variable.description, language)}</span>
                          </div>
                          <input
                            type="text"
                            value={variable.value}
                            onChange={(e) => updateVariable(variable.key, e.target.value)}
                            className="variable-input"
                            aria-label={`${variable.key}：${getText(variable.description, language)}`}
                          />
                        </div>
                      ))}
                    </div>
                  )}
                </section>
              );
            }) : (
              <div className="variables-empty">
                <strong>{language === 'zh' ? '没有匹配变量' : 'No variables found'}</strong>
                <span>{language === 'zh' ? '换个关键词，或清空搜索。' : 'Try another keyword or clear the search.'}</span>
              </div>
            )}
          </div>
          <div className="variables-footer">
            {language === 'zh'
              ? '后台新增 Payload 或工具命令时，写入 {URL}、{COOKIE}、{ATTACKER_IP} 等占位符即可自动联动。'
              : 'Admin-created payloads and tool commands can use placeholders such as {URL}, {COOKIE}, and {ATTACKER_IP}.'}
          </div>
        </div>
      )}
    </div>
  );
}

export default VariablesMenu;
