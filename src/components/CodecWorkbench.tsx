import { useCallback, useEffect, useImperativeHandle, useMemo, useRef, useState } from 'react';
import { useLanguage, useSession } from '../appContext';
import {
  buildCtfMenus,
  defaultParams,
  detectInput,
  extractPureDecodeResult,
  hydrateCodecHeavyData,
  label,
  operations,
  stripCandidateSection,
  transform,
} from '../utils/codec';
import type {
  CodecGroupData,
  Direction,
  Operation,
  OperationId,
  ParamKey,
} from '../utils/codec';
import { DetectStrip } from './codec/DetectStrip';
import { GlobalSecretBar } from './codec/GlobalSecretBar';
import { OperationParamsPanel } from './codec/OperationParamsPanel';
import { formatTextStats } from './codec/outputPanelUtils';
import { WorkbenchMenuBar } from './codec/WorkbenchMenuBar';
import { actionsOfOperation, hashAlgorithmValueOf, primaryActionOfOperation, variantValueOf } from './codec/workbenchActions';
import type { WorkbenchAction } from './codec/workbenchActions';
import type { WorkbenchMenuDef, WorkbenchMenuEntry } from './codec/WorkbenchMenuBar';
import { WorkbenchOutputPanel } from './codec/WorkbenchOutputPanel';
import '../styles/codec-workbench.css';

export interface CodecWorkbenchHandle {
  // seedInput：宿主（智能识别 hero 检测芯片跳转）希望一并带入的输入文本；undefined 时保留工作台现有输入。
  focusOperation: (id: OperationId, seedInput?: string) => void;
}

interface CodecWorkbenchProps {
  ref?: React.Ref<CodecWorkbenchHandle | null>;
  groups: CodecGroupData[];
  heading?: { zh: string; en: string };
  description?: { zh: string; en: string };
  registerTestApi?: boolean;
  // pentest（默认）= 渗透编解码视图（侧栏分类 + 动作网格，保持既有形态）；
  // ctf = CTF 解题工具箱（顶部菜单栏主导航，动作网格折叠为备选）。
  mode?: 'pentest' | 'ctf';
}

function CodecWorkbench({ ref, groups, heading, description, registerTestApi = false, mode = 'pentest' }: CodecWorkbenchProps) {
  const { language } = useLanguage();
  const { globalSecret, setGlobalSecret } = useSession();
  const [input, setInput] = useState('');
  const [output, setOutput] = useState('');
  const [activeGroupId, setActiveGroupId] = useState<string>(() => groups[0]?.id ?? '');
  const [activeOperationId, setActiveOperationId] = useState<OperationId | null>(null);
  const [activeActionKey, setActiveActionKey] = useState<string | null>(null);
  const [params, setParams] = useState<Record<ParamKey, string>>(defaultParams);
  const [error, setError] = useState('');
  const [running, setRunning] = useState(false);
  const [showOptions, setShowOptions] = useState(false);
  const workbenchRef = useRef<HTMLDivElement>(null);

  const activeGroup = groups.find(group => group.id === activeGroupId) ?? groups[0];
  const groupOperations = useMemo(() => activeGroup?.operations ?? [], [activeGroup]);
  const operation = groupOperations.find(item => item.id === activeOperationId) ?? groupOperations[0];
  const visibleOperationIds = useMemo(
    () => new Set<OperationId>(groups.flatMap(group => group.operations.map(item => item.id))),
    [groups],
  );
  const hashAlgorithmValue = hashAlgorithmValueOf(params, operation?.id ?? '');
  const variantValue = variantValueOf(params, operation?.id ?? '');
  const detections = useMemo(
    // 形状检测只依赖前缀特征：超长输入截断后再跑正则组，避免每次键入对全量文本做 60+ 次匹配。
    () => detectInput(input.slice(0, 4096)).filter(detection => visibleOperationIds.has(detection.id)),
    [input, visibleOperationIds],
  );
  const activeOperationIdForTest = operation?.id;

  // 重数据预热：工作台挂载即并行拉起古典密码评分表 chunk（609KB，独立异步 chunk），不阻塞首屏。
  useEffect(() => {
    void hydrateCodecHeavyData();
  }, []);

  useEffect(() => {
    if (!registerTestApi) return;
    if (typeof window === 'undefined' || !/^(localhost|127\.0\.0\.1|::1)$/i.test(window.location.hostname)) return;
    const devWindow = window as Window & {
      __PAYLOADER_CODEC_TEST_API?: {
        defaultParams: Record<ParamKey, string>;
        operations: Array<Pick<Operation, 'id' | 'supportsEncode' | 'supportsDecode' | 'params'>>;
        transform: typeof transform;
      };
    };
    devWindow.__PAYLOADER_CODEC_TEST_API = {
      defaultParams,
      operations: operations.map(operation => ({
        id: operation.id,
        supportsEncode: operation.supportsEncode,
        supportsDecode: operation.supportsDecode,
        params: operation.params,
      })),
      transform,
    };
    return () => {
      delete devWindow.__PAYLOADER_CODEC_TEST_API;
    };
  }, [registerTestApi]);

  const selectGroup = (groupId: string) => {
    const group = groups.find(item => item.id === groupId);
    setActiveGroupId(groupId);
    setActiveActionKey(null);
    if (group?.operations[0]) setActiveOperationId(group.operations[0].id);
    setError('');
    setOutput('');
  };

  // 全局密钥回退（批次 M）：操作私有 secret 为空时使用全局密钥栏的值；私有值优先。
  const effectiveParams = useMemo(
    () => (!params.secret && globalSecret ? { ...params, secret: globalSecret } : params),
    [params, globalSecret],
  );

  // inputOverride：focusOperation 携带 seed 直跑时用（setInput 是异步的，闭包 input 还是旧值）。
  const run = useCallback(async (direction: Direction, operationId: OperationId = activeOperationIdForTest, inputOverride?: string) => {
    if (!operationId) return;
    setError('');
    setRunning(true);
    try {
      // 古典密码评分表（609KB 异步 chunk）就绪后再执行：幂等，mount 预热后此处几乎总是立即返回。
      await hydrateCodecHeavyData();
      const result = await transform(operationId, direction, inputOverride ?? input, effectiveParams);
      setOutput(result);
    } catch (reason) {
      setOutput('');
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setRunning(false);
    }
  }, [input, effectiveParams, activeOperationIdForTest]);

  // 动作入口：一次点击 = 选中操作（含所属分类同步）+ 立即执行（显式传 id，不受 setState 异步影响）。
  // 菜单栏跨分类直达时同步 activeGroupId，保证工具栏下拉/摘要/参数区与当前操作一致。
  const runAction = (action: WorkbenchAction) => {
    const group = groups.find(item => item.operations.some(candidate => candidate.id === action.id));
    if (group) setActiveGroupId(group.id);
    setActiveOperationId(action.id);
    setActiveActionKey(`${action.id}-${action.direction}`);
    void run(action.direction, action.id);
  };

  const clearAll = () => {
    setInput('');
    setOutput('');
    setError('');
  };

  const applyDetection = (operationId: OperationId) => {
    const group = groups.find(item => item.operations.some(candidate => candidate.id === operationId));
    if (!group) return;
    const target = group.operations.find(item => item.id === operationId);
    const autoRun = Boolean(target && target.supportsDecode !== false);
    setActiveGroupId(group.id);
    setActiveOperationId(operationId);
    setActiveActionKey(autoRun ? `${operationId}-decode` : null);
    setError('');
    setOutput('');
    // 识别芯片与菜单条目行为对齐：点击即执行解密方向，即时出结果。
    if (autoRun) void run('decode', operationId);
  };

  useImperativeHandle(ref, () => ({
    focusOperation: (id: OperationId, seedInput?: string) => {
      const group = groups.find(item => item.operations.some(candidate => candidate.id === id));
      if (!group) return;
      const target = group.operations.find(item => item.id === id);
      const autoRun = Boolean(target && target.supportsDecode !== false);
      setActiveGroupId(group.id);
      setActiveOperationId(id);
      setActiveActionKey(autoRun ? `${id}-decode` : null);
      if (seedInput !== undefined) setInput(seedInput);
      setError('');
      setOutput('');
      workbenchRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
      // 芯片点击 = 聚焦 + 立即执行（与菜单 runAction 对齐）；带 seed 以 seed 为输入（闭包 input 是旧值）。
      if (autoRun) void run('decode', id, seedInput);
    },
  }), [groups, run]);

  if (!operation) return null;

  // 顶部菜单栏（CTF 态）：buildCtfMenus 的 9 菜单映射为下拉条目，onSelect 走 runAction 立即执行。
  // 刻意不 useMemo：runAction 闭包捕获最新 input/effectiveParams，memo 化会让菜单跑旧输入；
  // 条目对象量级与动作网格按钮相当，每次渲染重建成本可忽略。
  const isCtfMode = mode === 'ctf';
  const menuDefs: WorkbenchMenuDef[] = isCtfMode
    ? buildCtfMenus().map(menu => ({
      id: menu.id,
      name: menu.name,
      groups: menu.sections.map(section => ({
        label: section.label,
        entries: section.operations.flatMap(item => (menu.id === 'modern' ? [primaryActionOfOperation(item, language)] : actionsOfOperation(item, language))).map(action => ({
          key: `${action.id}-${action.direction}`,
          label: action.mark,
          title: label(action.summary, language),
          active: activeActionKey === `${action.id}-${action.direction}`,
          onSelect: () => runAction(action),
        } satisfies WorkbenchMenuEntry)),
      })),
    }))
    : [];

  // 分类内（操作 × 方向）动作区：仅渗透编解码模态使用平铺网格；CTF 态操作导航一律走顶部菜单栏。
  const actionPanel = (
    <div className="action-panel" aria-label={language === 'zh' ? '操作动作列表' : 'Operation actions'}>
      {activeGroup?.subgroups ? (
        activeGroup.subgroups.filter(subgroup => subgroup.operations.length).map(subgroup => (
          <div key={subgroup.name.zh} className="action-section">
            <div className="action-section-title">{label(subgroup.name, language)}</div>
            <div className="action-grid">
              {subgroup.operations.flatMap(item => actionsOfOperation(item, language)).map(action => (
                <button
                  key={`${action.id}-${action.direction}`}
                  type="button"
                  className={`action-btn ${operation?.id === action.id ? 'active' : ''}`}
                  onClick={() => runAction(action)}
                  title={label(action.summary, language)}
                >
                  {action.mark}
                </button>
              ))}
            </div>
          </div>
        ))
      ) : (
        <div className="action-grid">
          {groupOperations.flatMap(item => actionsOfOperation(item, language)).map(action => (
            <button
              key={`${action.id}-${action.direction}`}
              type="button"
              className={`action-btn ${operation?.id === action.id ? 'active' : ''}`}
              onClick={() => runAction(action)}
              title={label(action.summary, language)}
            >
              {action.mark}
            </button>
          ))}
        </div>
      )}
    </div>
  );

  return (
    <div className="encoding-tools">
      {heading && (
        <div className="encoding-header">
          <h2>{label(heading, language)}</h2>
          {description && <p>{label(description, language)}</p>}
        </div>
      )}

      <div className={`encoding-workbench ${isCtfMode ? 'ctf-nav-mode' : ''}`} ref={workbenchRef}>
        {!isCtfMode && (
          <aside className="encoding-category-panel" aria-label={language === 'zh' ? '编解码分类' : 'Codec categories'}>
            <select
              className="category-select"
              value={activeGroup?.id ?? ''}
              onChange={event => selectGroup(event.target.value)}
              aria-label={language === 'zh' ? '选择分类' : 'Select category'}
            >
              {groups.map(group => (
                <option key={group.id} value={group.id}>{label(group.name, language)}</option>
              ))}
            </select>
            <div className="category-list" role="list">
              {groups.map(group => (
                <button
                  key={group.id}
                  type="button"
                  className={`category-row ${activeGroup?.id === group.id ? 'active' : ''}`}
                  onClick={() => selectGroup(group.id)}
                >
                  <span>{label(group.name, language)}</span>
                  <small>{label(group.note, language)}</small>
                </button>
              ))}
            </div>
          </aside>
        )}

        <section className="encoding-main-panel">
          {isCtfMode ? (
            <WorkbenchMenuBar
              menus={menuDefs}
              ariaLabel={language === 'zh' ? '解题操作菜单栏' : 'Solver operation menu'}
              current={label(operation.name, language)}
            />
          ) : null}

          <div className="codec-toolbar">
            <label className="operation-select-field">
              <span>{language === 'zh' ? '算法 / 场景' : 'Operation'}</span>
              <select
                value={operation.id}
                onChange={event => {
                  setActiveOperationId(event.target.value as OperationId);
                  setError('');
                  setOutput('');
                }}
              >
                {activeGroup?.subgroups ? (
                  activeGroup.subgroups.map(subgroup => (
                    subgroup.operations.length ? (
                      <optgroup key={subgroup.name.zh} label={label(subgroup.name, language)}>
                        {subgroup.operations.map(item => (
                          <option key={item.id} value={item.id}>{label(item.name, language)}</option>
                        ))}
                      </optgroup>
                    ) : null
                  ))
                ) : (
                  groupOperations.map(item => (
                    <option key={item.id} value={item.id}>{label(item.name, language)}</option>
                  ))
                )}
              </select>
            </label>

            <div className="mode-actions" aria-label={language === 'zh' ? '执行操作' : 'Actions'}>
              <button
                type="button"
                className="mode-btn primary"
                onClick={() => run('encode')}
                disabled={running || operation.supportsEncode === false}
              >
                {label(operation.encodeLabel || { zh: '编码/生成', en: 'Encode / Generate' }, language)}
              </button>
              <button
                type="button"
                className="mode-btn"
                onClick={() => run('decode')}
                disabled={running || operation.supportsDecode === false}
              >
                {label(operation.decodeLabel || { zh: '解码/解析', en: 'Decode / Parse' }, language)}
              </button>
              <button type="button" className="mode-btn subtle" onClick={() => run('decode')} disabled={running || operation.id === 'smart-decode'}>
                {language === 'zh' ? '快速解码' : 'Quick decode'}
              </button>
            </div>
          </div>

          {/* 全局密钥栏：仅渗透视图常驻（该视图无 hero，这里是唯一入口）；CTF 视图与 hero 全局密钥栏重复，不再渲染 */}
          {!isCtfMode && (
            <GlobalSecretBar
              value={globalSecret}
              onChange={setGlobalSecret}
              placeholder={{
                zh: '多步解密共用一把钥匙；在下方参数里填了私有密钥则优先用私有值',
                en: 'One key for the whole chain; a per-operation key in the options takes precedence',
              }}
            />
          )}

          {isCtfMode ? null : actionPanel}

          <OperationParamsPanel
            operation={operation}
            language={language}
            showOptions={showOptions}
            setShowOptions={setShowOptions}
            params={params}
            setParams={setParams}
            variantValue={variantValue}
            hashAlgorithmValue={hashAlgorithmValue}
          />

          <DetectStrip detections={detections} onDetect={applyDetection} />

          <div className="encoding-content">
            <div className="encoding-panel">
              <div className="panel-header">
                <label>{language === 'zh' ? '输入' : 'Input'}</label>
                <div className="panel-actions">
                  <small className="wb-in-stats" title={language === 'zh' ? '字符数（Unicode 码点）与 UTF-8 字节数' : 'Characters (Unicode code points) and UTF-8 bytes'}>{formatTextStats(input, language)}</small>
                  <button className="clear-btn" onClick={clearAll} type="button">{language === 'zh' ? '清空' : 'Clear'}</button>
                </div>
              </div>
              <textarea
                value={input}
                onChange={event => setInput(event.target.value)}
                placeholder={language === 'zh' ? '粘贴要处理的文本、Token、编码内容或 JSON...' : 'Paste text, tokens, encoded content, or JSON...'}
                spellCheck={false}
              />
            </div>

            <div className="encoding-panel">
              <WorkbenchOutputPanel
                value={error ? '' : stripCandidateSection(output)}
                rawOutput={output}
                error={error}
                running={running}
                minHeight="normal"
                onUseAsInput={() => { setInput(extractPureDecodeResult(output)); setOutput(''); setError(''); }}
                onClear={clearAll}
              />
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}

export default CodecWorkbench;
