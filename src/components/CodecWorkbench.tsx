import { useCallback, useEffect, useId, useImperativeHandle, useMemo, useRef, useState } from 'react';
import { useAppContext } from '../appContext';
import {
  buildCtfMenus,
  cryptoJsBlockCipherOperationIds,
  defaultParams,
  detectInput,
  extractPureDecodeResult,
  isCryptoJsCipherOperation,
  isNobleAesOperation,
  isNobleNonceOperation,
  isOtpOperation,
  jwtHmacHashAlgorithms,
  label,
  operations,
  otpHashAlgorithms,
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
import { formatTextStats } from './codec/outputPanelUtils';
import { WorkbenchMenuBar } from './codec/WorkbenchMenuBar';
import type { WorkbenchMenuDef, WorkbenchMenuEntry } from './codec/WorkbenchMenuBar';
import { WorkbenchOutputPanel } from './codec/WorkbenchOutputPanel';

// 批次 O 新操作的 variant 下拉选项与默认值归一：variant 是全局共享参数键（默认 'special'），
// 这些操作首次进入工作台时 params.variant 尚未落到自己的取值域，用 defaults 表归一显示与提交值。
const parityVariantOptions: Record<string, Array<{ value: string; zh: string; en: string }>> = {
  'manchester': [
    { value: 'ieee-8023', zh: 'IEEE 802.3（1→01）', en: 'IEEE 802.3 (1→01)' },
    { value: 'ge-thomas', zh: 'G.E. Thomas（1→10）', en: 'G.E. Thomas (1→10)' },
  ],
  'ieee754': [
    { value: 'float64', zh: '双精度 float64', en: 'double float64' },
    { value: 'float32', zh: '单精度 float32', en: 'single float32' },
  ],
  'twos-complement': [
    { value: '8', zh: '8 位', en: '8-bit' },
    { value: '16', zh: '16 位', en: '16-bit' },
    { value: '32', zh: '32 位', en: '32-bit' },
  ],
  'ones-complement': [
    { value: '8', zh: '8 位', en: '8-bit' },
    { value: '16', zh: '16 位', en: '16-bit' },
    { value: '32', zh: '32 位', en: '32-bit' },
  ],
  'radix-xor': [
    { value: '16', zh: '十六进制', en: 'Hex' },
    { value: '10', zh: '十进制', en: 'Decimal' },
    { value: '8', zh: '八进制', en: 'Octal' },
    { value: '2', zh: '二进制', en: 'Binary' },
  ],
  'bit-split': [
    { value: '2', zh: '每 2 字符一组', en: '2 chars per group' },
    { value: '3', zh: '每 3 字符一组', en: '3 chars per group' },
    { value: '4', zh: '每 4 字符一组', en: '4 chars per group' },
    { value: '7', zh: '每 7 字符一组', en: '7 chars per group' },
  ],
  'rc2': [
    { value: 'pkcs7', zh: 'PKCS#7 自动填充', en: 'PKCS#7 padding' },
    { value: 'raw', zh: 'raw（8 字节整块，不填充）', en: 'raw (aligned 8-byte blocks, no padding)' },
  ],
  'rc6': [
    { value: 'pkcs7', zh: 'PKCS#7 自动填充', en: 'PKCS#7 padding' },
    { value: 'raw', zh: 'raw（16 字节整块，不填充）', en: 'raw (aligned 16-byte blocks, no padding)' },
  ],
};

const parityVariantDefaults: Record<string, string> = Object.fromEntries(
  Object.entries(parityVariantOptions).map(([id, optionList]) => [id, optionList[0].value]),
);

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

// 动作项的（操作 × 方向）标记：随波逐流【xx解密】方括号标记法，decode 优先（CTF 主链路），
// 仅支持一侧的操作只出一个动作；smart-decode 无方向语义，直接用名称。
interface WorkbenchAction {
  id: OperationId;
  direction: Direction;
  mark: string;
  summary: { zh: string; en: string };
}

const actionsOfOperation = (operation: Operation, language: 'zh' | 'en'): WorkbenchAction[] => {
  const actions: WorkbenchAction[] = [];
  const name = label(operation.name, language);
  if (operation.supportsDecode !== false) {
    const mark = operation.id === 'smart-decode'
      ? (language === 'zh' ? '【智能识别】' : '[Smart identify]')
      : language === 'zh' ? `【${name}解密】` : `[${name} dec]`;
    actions.push({ id: operation.id, direction: 'decode', mark, summary: operation.summary });
  }
  if (operation.supportsEncode !== false) {
    actions.push({ id: operation.id, direction: 'encode', mark: language === 'zh' ? `【${name}加密】` : `[${name} enc]`, summary: operation.summary });
  }
  return actions;
};

// 现代密码菜单的单方向条目：解密优先（CTF 主链路），仅支持编码侧的操作（hash/hmac/aes-cmac 等）
// 回退唯一方向——条目数减半，方向切换保留在工作台的编码/解码按钮。
const primaryActionOfOperation = (operation: Operation, language: 'zh' | 'en'): WorkbenchAction => {
  const actions = actionsOfOperation(operation, language);
  return actions.find(action => action.direction === 'decode') ?? actions[0];
};

function CodecWorkbench({ ref, groups, heading, description, registerTestApi = false, mode = 'pentest' }: CodecWorkbenchProps) {
  const { language, globalSecret, setGlobalSecret } = useAppContext();
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
  const secretFieldId = useId();

  const activeGroup = groups.find(group => group.id === activeGroupId) ?? groups[0];
  const groupOperations = useMemo(() => activeGroup?.operations ?? [], [activeGroup]);
  const operation = groupOperations.find(item => item.id === activeOperationId) ?? groupOperations[0];
  const visibleOperationIds = useMemo(
    () => new Set<OperationId>(groups.flatMap(group => group.operations.map(item => item.id))),
    [groups],
  );
  const hashAlgorithmValue = isOtpOperation(operation?.id ?? '') && !otpHashAlgorithms.has(params.hashAlgorithm)
    ? 'sha1'
    : operation?.id === 'jwt-hmac' && !jwtHmacHashAlgorithms.has(params.hashAlgorithm)
      ? 'sha256'
    : params.hashAlgorithm;
  const variantValue = operation?.id === 'rabbit' && params.variant === 'hex'
    ? 'special'
    : operation?.id === 'hexagram' && params.variant !== 'names' && params.variant !== 'symbols'
      ? 'names'
    : parityVariantDefaults[operation?.id ?? ''] && !parityVariantOptions[operation?.id ?? '']?.some(option => option.value === params.variant)
      ? parityVariantDefaults[operation?.id ?? '']
    : params.variant;
  const detections = useMemo(
    // 形状检测只依赖前缀特征：超长输入截断后再跑正则组，避免每次键入对全量文本做 60+ 次匹配。
    () => detectInput(input.slice(0, 4096)).filter(detection => visibleOperationIds.has(detection.id)),
    [input, visibleOperationIds],
  );
  const activeOperationIdForTest = operation?.id;

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
            <div className="global-secret-bar">
              <label htmlFor={secretFieldId}>{language === 'zh' ? '🔑 全局密钥' : '🔑 Global key'}</label>
              <input
                id={secretFieldId}
                value={globalSecret}
                onChange={event => setGlobalSecret(event.target.value)}
                placeholder={language === 'zh'
                  ? '多步解密共用一把钥匙；在下方参数里填了私有密钥则优先用私有值'
                  : 'One key for the whole chain; a per-operation key in the options takes precedence'}
                spellCheck={false}
                autoComplete="off"
              />
            </div>
          )}

          {isCtfMode ? null : actionPanel}

          <div className="operation-summary">
            <div>
              <strong>{label(operation.name, language)}</strong>
              <span>{label(operation.summary, language)}</span>
            </div>
            {operation.params?.length ? (
              <button type="button" className="options-toggle" onClick={() => setShowOptions(value => !value)}>
                {showOptions ? (language === 'zh' ? '收起参数' : 'Hide options') : (language === 'zh' ? '展开参数' : 'Show options')}
              </button>
            ) : null}
          </div>

          {operation.params?.length ? (
            <div className={`codec-options ${showOptions ? 'open' : ''}`}>
              {operation.params.includes('variant') && (
                <label>
                  <span>{language === 'zh' ? '输出 / 算法变体' : 'Variant'}</span>
                  <select value={variantValue} onChange={event => setParams({ ...params, variant: event.target.value })}>
                    {(operation.id === 'html-entity' || operation.id === 'xml-entity') && (
                      <>
                        <option value="special">{language === 'zh' ? '命名实体' : 'Named entities'}</option>
                        <option value="decimal">{language === 'zh' ? '十进制实体' : 'Decimal entities'}</option>
                        <option value="hex">{language === 'zh' ? '十六进制实体' : 'Hex entities'}</option>
                      </>
                    )}
                    {operation.id === 'unicode-escape' && (
                      <>
                        <option value="special">{language === 'zh' ? '\\uXXXX' : '\\uXXXX'}</option>
                        <option value="hex">{language === 'zh' ? '\\xHH' : '\\xHH'}</option>
                        <option value="brace">{language === 'zh' ? '\\u{...} 格式' : '\\u{...} format'}</option>
                      </>
                    )}
                    {operation.id === 'base32' && (
                      <>
                        <option value="special">RFC 4648 Base32</option>
                        <option value="hex">Base32hex</option>
                        <option value="decimal">Crockford Base32</option>
                      </>
                    )}
                    {parityVariantOptions[operation.id]?.map(option => (
                      <option key={option.value} value={option.value}>{language === 'zh' ? option.zh : option.en}</option>
                    ))}
                    {operation.id === 'bech32' && (
                      <>
                        <option value="special">Bech32</option>
                        <option value="hex">Bech32m</option>
                      </>
                    )}
                    {operation.id === 'hexagram' && (
                      <>
                        <option value="names">{language === 'zh' ? '卦名（坤剥比观…）' : 'Names (坤剥比观…)'}</option>
                        <option value="symbols">{language === 'zh' ? '卦符（䷀-䷿）' : 'Symbols (䷀-䷿)'}</option>
                      </>
                    )}
                    {operation.id === 'otpauth-uri' && (
                      <>
                        <option value="special">TOTP</option>
                        <option value="hex">HOTP</option>
                      </>
                    )}
                    {isCryptoJsCipherOperation(operation.id) && (
                      <>
                        <option value="special">{operation.id === 'rabbit' ? 'Raw key + IV' : 'CBC raw key + IV'}</option>
                        {cryptoJsBlockCipherOperationIds.has(operation.id) && <option value="hex">ECB raw key</option>}
                        <option value="decimal">OpenSSL Salted__ passphrase</option>
                      </>
                    )}
                    {(operation.id === 'aes-ecb' || operation.id === 'aes-cbc-raw') && (
                      <>
                        <option value="special">PKCS#7 padding</option>
                        <option value="hex">No padding exact block</option>
                      </>
                    )}
                    {operation.id === 'sm4' && (
                      <>
                        <option value="special">CBC raw key + IV</option>
                        <option value="hex">ECB raw key</option>
                      </>
                    )}
                    {operation.id === 'ascii85' && (
                      <>
                        <option value="special">ASCII85 / Adobe</option>
                        <option value="hex">Z85</option>
                      </>
                    )}
                    {operation.id === 'hex' && (
                      <>
                        <option value="special">{language === 'zh' ? '纯 Hex' : 'Plain hex'}</option>
                        <option value="decimal">{language === 'zh' ? '0x 前缀' : '0x prefix'}</option>
                        <option value="hex">{language === 'zh' ? '\\x 前缀' : '\\x prefix'}</option>
                      </>
                    )}
                    {operation.id === 'rot' && (
                      <>
                        <option value="special">ROT13 / Caesar</option>
                        <option value="hex">ROT47</option>
                      </>
                    )}
                    {operation.id === 'utf16-bytes' && (
                      <>
                        <option value="special">UTF-16 LE</option>
                        <option value="hex">UTF-16 BE</option>
                      </>
                    )}
                    {operation.id === 'dna-code' && (
                      <>
                        <option value="special">00=A 01=C 10=G 11=T</option>
                        <option value="decimal">00=A 01=G 10=C 11=T</option>
                        <option value="hex">00=C 01=A 10=T 11=G</option>
                      </>
                    )}
                    {operation.id === 'keyboard-shift' && (
                      <>
                        <option value="special">{language === 'zh' ? '向右还原' : 'Shift right'}</option>
                        <option value="hex">{language === 'zh' ? '向左还原' : 'Shift left'}</option>
                      </>
                    )}
                    {operation.id === 'albam' && (
                      <>
                        <option value="special">{language === 'zh' ? 'A↔N 半表互换（+13 对合）' : 'A↔N half-table swap (+13)'}</option>
                        <option value="shift11">CacheSleuth +11</option>
                      </>
                    )}
                  </select>
                </label>
              )}
              {operation.params.includes('hashAlgorithm') && (
                <label>
                  <span>{language === 'zh' ? '摘要算法' : 'Digest algorithm'}</span>
                  <select value={hashAlgorithmValue} onChange={event => setParams({ ...params, hashAlgorithm: event.target.value })}>
                    {isOtpOperation(operation.id) ? (
                      <>
                        <option value="sha1">SHA-1</option>
                        <option value="sha256">SHA-256</option>
                        <option value="sha512">SHA-512</option>
                      </>
                    ) : operation.id === 'jwt-hmac' ? (
                      <>
                        <option value="sha256">SHA-256 / HS256</option>
                        <option value="sha384">SHA-384 / HS384</option>
                        <option value="sha512">SHA-512 / HS512</option>
                      </>
                    ) : (
                      <>
                        {operation.id !== 'hmac' && <option value="md5">MD5</option>}
                        <option value="sha1">SHA-1</option>
                        <option value="sha256">SHA-256</option>
                        <option value="sha384">SHA-384</option>
                        <option value="sha512">SHA-512</option>
                        {operation.id !== 'hmac' && <option value="sha3-224">SHA3-224</option>}
                        {operation.id !== 'hmac' && <option value="sha3-256">SHA3-256</option>}
                        {operation.id !== 'hmac' && <option value="sha3-384">SHA3-384</option>}
                        {operation.id !== 'hmac' && <option value="sha3-512">SHA3-512</option>}
                        {operation.id !== 'hmac' && <option value="keccak-256">Keccak-256</option>}
                        {operation.id !== 'hmac' && <option value="keccak-512">Keccak-512</option>}
                        {operation.id !== 'hmac' && <option value="md4">MD4</option>}
                        {operation.id !== 'hmac' && <option value="ntlm">NTLM</option>}
                        {operation.id !== 'hmac' && <option value="ripemd160">RIPEMD-160</option>}
                        {operation.id !== 'hmac' && <option value="blake2b-256">BLAKE2b-256</option>}
                        {operation.id !== 'hmac' && <option value="blake2b-512">BLAKE2b-512</option>}
                        {operation.id !== 'hmac' && <option value="blake2s-256">BLAKE2s-256</option>}
                        {operation.id !== 'hmac' && <option value="blake3">BLAKE3</option>}
                        {operation.id !== 'hmac' && <option value="sm3">SM3</option>}
                        {operation.id !== 'hmac' && <option value="whirlpool">Whirlpool</option>}
                        {operation.id !== 'hmac' && <option value="xxhash32">xxHash32</option>}
                        {operation.id !== 'hmac' && <option value="xxhash64">xxHash64</option>}
                        {operation.id !== 'hmac' && <option value="crc16">CRC16</option>}
                        {operation.id !== 'hmac' && <option value="crc32">CRC32</option>}
                        {operation.id !== 'hmac' && <option value="adler32">Adler32</option>}
                      </>
                    )}
                  </select>
                </label>
              )}
              {operation.params.includes('secret') && (
                <label className={operation.id === 'jwt-public' ? 'wide-option' : undefined}>
                  <span>{operation.id === 'brainfuck'
                    ? (language === 'zh' ? 'Brainfuck 输入' : 'Brainfuck stdin')
                    : operation.id === 'lcg-helper'
                      ? (language === 'zh' ? '可选 modulus' : 'Optional modulus')
                      : operation.id === 'hash-length-extension-helper'
                        ? (language === 'zh' ? '追加数据' : 'Append data')
                      : isCryptoJsCipherOperation(operation.id)
                        ? (variantValue === 'decimal' ? 'Passphrase' : 'Key')
                      : operation.id === 'openssl-aes-256-cbc'
                        ? 'OpenSSL passphrase'
                      : isNobleNonceOperation(operation.id) || isNobleAesOperation(operation.id) || operation.id === 'sm4'
                        ? 'Key'
                      : isOtpOperation(operation.id)
                        ? 'Base32 secret'
                      : operation.id === 'enigma'
                        ? 'Enigma settings'
                      : operation.id === 'jwt-hmac'
                        ? 'JWT HMAC secret'
                      : operation.id === 'jwt-public'
                        ? 'Public key material'
                      : operation.id === 'fernet'
                        ? 'Fernet key'
                      : (language === 'zh' ? '密钥 / 口令' : 'Secret / password')}</span>
                  {operation.id === 'jwt-public' ? (
                    <textarea
                      value={params.secret}
                      onChange={event => setParams({ ...params, secret: event.target.value })}
                      rows={6}
                      spellCheck={false}
                      placeholder={'-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n\nor paste JWK / JWKS JSON'}
                    />
                  ) : (
                    <input value={params.secret} onChange={event => setParams({ ...params, secret: event.target.value })} placeholder={operation.id === 'lcg-helper' ? 'm=2^31 / m=2147483648' : operation.id === 'hash-length-extension-helper' ? 'admin=true' : isCryptoJsCipherOperation(operation.id) ? (params.variant === 'decimal' ? 'OpenSSL passphrase' : 'hex key or UTF-8 key') : operation.id === 'openssl-aes-256-cbc' ? 'OpenSSL passphrase' : isNobleNonceOperation(operation.id) || isNobleAesOperation(operation.id) || operation.id === 'sm4' ? 'hex key or UTF-8 key' : isOtpOperation(operation.id) ? 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ' : operation.id === 'enigma' ? 'rotors=I II III; reflector=B; rings=AAA; positions=AAA; plugboard=AV BS' : operation.id === 'jwt-hmac' ? 'secret' : operation.id === 'fernet' ? 'URL-safe Base64 32-byte key' : (language === 'zh' ? '仅在本地浏览器使用' : 'Used locally in this browser')} />
                  )}
                </label>
              )}
              {operation.params.includes('iv') && (!operation.params.includes('variant') || operation.id === 'aes-cbc-raw' || (variantValue !== 'hex' && variantValue !== 'decimal')) && (
                <label>
                  <span>{isNobleNonceOperation(operation.id) ? 'Nonce' : operation.id === 'rabbit' ? 'IV / nonce' : 'IV'}</span>
                  <input value={params.iv} onChange={event => setParams({ ...params, iv: event.target.value })} placeholder={isNobleNonceOperation(operation.id) ? 'hex nonce or UTF-8 nonce' : operation.id === 'rabbit' ? 'optional hex or UTF-8 IV' : 'hex IV or UTF-8 IV'} />
                </label>
              )}
              {operation.params.includes('hrp') && (
                <label>
                  <span>{language === 'zh' ? 'HRP 前缀' : 'HRP prefix'}</span>
                  <input value={params.hrp} onChange={event => setParams({ ...params, hrp: event.target.value })} placeholder="bc / tb / lnbc" />
                </label>
              )}
              {operation.params.includes('versionHex') && (
                <label>
                  <span>{language === 'zh' ? '版本字节 Hex' : 'Version bytes hex'}</span>
                  <input value={params.versionHex} onChange={event => setParams({ ...params, versionHex: event.target.value })} placeholder="00 / 05 / 80" />
                </label>
              )}
              {operation.params.includes('digits') && (
                <label>
                  <span>{language === 'zh' ? 'OTP 位数' : 'OTP digits'}</span>
                  <input type="number" min="4" max="10" step="1" value={params.digits} onChange={event => setParams({ ...params, digits: event.target.value })} />
                </label>
              )}
              {operation.params.includes('counter') && (operation.id !== 'otpauth-uri' || params.variant === 'hex') && (
                <label>
                  <span>{language === 'zh' ? 'HOTP counter' : 'HOTP counter'}</span>
                  <input type="number" min="0" step="1" value={params.counter} onChange={event => setParams({ ...params, counter: event.target.value })} />
                </label>
              )}
              {operation.params.includes('timeStep') && (operation.id !== 'otpauth-uri' || params.variant !== 'hex') && (
                <label>
                  <span>{language === 'zh' ? 'TOTP 步长秒数' : 'TOTP time step'}</span>
                  <input type="number" min="1" step="1" value={params.timeStep} onChange={event => setParams({ ...params, timeStep: event.target.value })} />
                </label>
              )}
              {operation.params.includes('otpTimestamp') && (
                <label>
                  <span>{language === 'zh' ? 'Unix 秒级时间' : 'Unix timestamp seconds'}</span>
                  <input inputMode="numeric" value={params.otpTimestamp} onChange={event => setParams({ ...params, otpTimestamp: event.target.value })} placeholder={language === 'zh' ? '留空表示当前时间' : 'Empty = current time'} />
                </label>
              )}
              {operation.params.includes('keyword2') && (
                <label>
                  <span>{language === 'zh' ? '第二关键词' : 'Second keyword'}</span>
                  <input value={params.keyword2} onChange={event => setParams({ ...params, keyword2: event.target.value })} placeholder="CIPHER / SECONDKEY" />
                </label>
              )}
              {operation.params.includes('associatedData') && (
                <label>
                  <span>{language === 'zh' ? 'AAD 关联数据' : 'AAD / associated data'}</span>
                  <input value={params.associatedData} onChange={event => setParams({ ...params, associatedData: event.target.value })} placeholder="optional UTF-8 or hex AAD" />
                </label>
              )}
              {operation.params.includes('period') && (
                <label>
                  <span>{language === 'zh' ? '周期' : 'Period'}</span>
                  <input type="number" min="1" max="64" value={params.period} onChange={event => setParams({ ...params, period: event.target.value })} />
                </label>
              )}
              {operation.params.includes('iterations') && (
                <label>
                  <span>{operation.id === 'brainfuck' ? (language === 'zh' ? '最大步数' : 'Max steps') : (language === 'zh' ? 'PBKDF2 迭代次数' : 'PBKDF2 iterations')}</span>
                  <input type="number" min="10000" step="1000" value={params.iterations} onChange={event => setParams({ ...params, iterations: event.target.value })} />
                </label>
              )}
              {operation.params.includes('dropBytes') && (
                <label>
                  <span>{language === 'zh' ? '丢弃字节' : 'Drop bytes'}</span>
                  <input type="number" min="0" max="4096" step="1" value={params.dropBytes} onChange={event => setParams({ ...params, dropBytes: event.target.value })} />
                </label>
              )}
              {operation.params.includes('shift') && (
                <label>
                  <span>{language === 'zh' ? 'Caesar 位移' : 'Caesar shift'}</span>
                  <input type="number" value={params.shift} onChange={event => setParams({ ...params, shift: event.target.value })} />
                </label>
              )}
              {operation.params.includes('separator') && (
                <label>
                  <span>{language === 'zh' ? '分隔符' : 'Separator'}</span>
                  <select value={params.separator} onChange={event => setParams({ ...params, separator: event.target.value })}>
                    <option value="space">{language === 'zh' ? '空格' : 'Space'}</option>
                    <option value="comma">{language === 'zh' ? '逗号' : 'Comma'}</option>
                    <option value="newline">{language === 'zh' ? '换行' : 'New line'}</option>
                  </select>
                </label>
              )}
              {operation.params.includes('affineA') && (
                <label>
                  <span>{language === 'zh' ? 'Affine a' : 'Affine a'}</span>
                  <input type="number" value={params.affineA} onChange={event => setParams({ ...params, affineA: event.target.value })} />
                </label>
              )}
              {operation.params.includes('affineB') && (
                <label>
                  <span>{language === 'zh' ? 'Affine b' : 'Affine b'}</span>
                  <input type="number" value={params.affineB} onChange={event => setParams({ ...params, affineB: event.target.value })} />
                </label>
              )}
              {operation.params.includes('rails') && (
                <label>
                  <span>{language === 'zh' ? '轨道数' : 'Rails'}</span>
                  <input type="number" min="2" max="32" value={params.rails} onChange={event => setParams({ ...params, rails: event.target.value })} />
                </label>
              )}
              {operation.params.includes('knownPlaintext') && (
                <label>
                  <span>{language === 'zh' ? '已知明文' : 'Known plaintext'}</span>
                  <input value={params.knownPlaintext} onChange={event => setParams({ ...params, knownPlaintext: event.target.value })} placeholder="flag{ / PNG header / PK" />
                </label>
              )}
              {operation.params.includes('mimeType') && (
                <label>
                  <span>MIME</span>
                  <input value={params.mimeType} onChange={event => setParams({ ...params, mimeType: event.target.value })} />
                </label>
              )}
              {operation.params.includes('blockLabel') && (
                <label>
                  <span>{language === 'zh' ? 'PEM 块类型' : 'PEM block label'}</span>
                  <input value={params.blockLabel} onChange={event => setParams({ ...params, blockLabel: event.target.value })} placeholder="PUBLIC KEY / CERTIFICATE / PRIVATE KEY" />
                </label>
              )}
            </div>
          ) : null}

          {detections.length ? (
            <div className="detect-strip" aria-label={language === 'zh' ? '自动识别结果' : 'Detected formats'}>
              <span>{language === 'zh' ? '识别' : 'Detected'}</span>
              {detections.map(detection => (
                <button key={`${detection.id}-${detection.label}`} type="button" onClick={() => applyDetection(detection.id)}>
                  {detection.label}
                </button>
              ))}
            </div>
          ) : null}

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

      <style>{`
        .encoding-tools {
          width: min(100%, 1180px);
          min-width: 0;
          margin: 0 auto;
          padding: 20px;
          display: grid;
          gap: 16px;
        }

        .encoding-header {
          display: grid;
          gap: 6px;
        }

        .encoding-header h2 {
          margin: 0;
          font-size: 22px;
          line-height: 1.25;
          font-weight: 760;
          color: var(--text-primary);
        }

        .encoding-header p {
          margin: 0;
          max-width: 820px;
          font-size: 13px;
          line-height: 1.55;
          color: var(--text-muted);
        }

        .encoding-workbench {
          min-width: 0;
          display: grid;
          grid-template-columns: 230px minmax(0, 1fr);
          gap: 14px;
          align-items: start;
        }

        /* CTF 态：菜单栏替代左侧分类栏，主面板占满整行 */
        .encoding-workbench.ctf-nav-mode {
          grid-template-columns: minmax(0, 1fr);
        }

        .encoding-category-panel,
        .encoding-main-panel {
          min-width: 0;
          border: 1px solid var(--border-color);
          border-radius: 8px;
          background: var(--bg-card);
        }

        .encoding-category-panel {
          padding: 8px;
          position: sticky;
          top: 0;
        }

        .category-select {
          display: none;
          width: 100%;
        }

        .category-list {
          display: grid;
          gap: 4px;
        }

        .category-row {
          width: 100%;
          min-width: 0;
          border: 1px solid transparent;
          border-radius: 6px;
          background: transparent;
          color: var(--text-secondary);
          padding: 10px;
          display: grid;
          gap: 3px;
          text-align: left;
          transition: all var(--transition-fast);
        }

        .category-row:hover {
          background: var(--bg-hover);
          color: var(--text-primary);
        }

        .category-row.active {
          border-color: rgba(0, 240, 255, 0.45);
          background: rgba(0, 240, 255, 0.1);
          color: var(--neon-cyan);
        }

        .category-row span {
          min-width: 0;
          overflow-wrap: anywhere;
          font-size: 13px;
          font-weight: 700;
          line-height: 1.25;
        }

        .category-row small {
          min-width: 0;
          overflow-wrap: anywhere;
          color: var(--text-muted);
          font-size: 11px;
          line-height: 1.35;
        }

        .encoding-main-panel {
          padding: 14px;
          display: grid;
          gap: 12px;
        }

        .codec-toolbar {
          min-width: 0;
          display: grid;
          grid-template-columns: minmax(220px, 1fr) auto;
          gap: 12px;
          align-items: end;
        }

        /* 全局密钥栏（批次 M）：常驻工具栏下方，跨操作/跨工作台共享 */
        .global-secret-bar {
          min-width: 0;
          display: grid;
          grid-template-columns: auto minmax(0, 1fr);
          gap: 10px;
          align-items: center;
          border: 1px dashed rgba(0, 240, 255, 0.3);
          border-radius: 8px;
          background: rgba(0, 240, 255, 0.04);
          padding: 9px 11px;
        }

        .global-secret-bar label {
          color: var(--neon-cyan);
          font-size: 12px;
          font-weight: 800;
          white-space: nowrap;
        }

        .global-secret-bar input {
          min-width: 0;
          width: 100%;
          min-height: 34px;
          border: 1px solid var(--border-color);
          border-radius: 6px;
          background: var(--bg-secondary);
          color: var(--text-primary);
          padding: 7px 10px;
          outline: none;
          font-family: var(--font-mono);
          font-size: 12px;
        }

        .global-secret-bar input:focus {
          border-color: var(--neon-cyan);
          box-shadow: 0 0 0 3px rgba(0, 240, 255, 0.12);
        }

        /* 动作网格（批次 M）：分类内操作平铺为（操作×方向）按钮，一次点击立即执行 */
        .action-panel {
          min-width: 0;
          display: grid;
          gap: 10px;
        }

        .action-section {
          min-width: 0;
          display: grid;
          gap: 6px;
        }

        .action-section-title {
          color: var(--text-muted);
          font-size: 11px;
          font-weight: 800;
          letter-spacing: 0.02em;
        }

        .action-grid {
          min-width: 0;
          display: grid;
          grid-template-columns: repeat(auto-fill, minmax(168px, 1fr));
          gap: 6px;
        }

        .action-btn {
          min-width: 0;
          min-height: 34px;
          border: 1px solid var(--border-color);
          border-radius: 6px;
          background: var(--bg-secondary);
          color: var(--text-secondary);
          padding: 6px 9px;
          font-size: 12px;
          font-weight: 700;
          line-height: 1.3;
          text-align: left;
          overflow-wrap: anywhere;
          cursor: pointer;
          transition: all var(--transition-fast);
        }

        .action-btn:hover {
          border-color: var(--neon-cyan);
          color: var(--neon-cyan);
        }

        .action-btn.active {
          border-color: var(--neon-cyan);
          background: rgba(0, 240, 255, 0.12);
          color: var(--neon-cyan);
        }

        .wb-in-stats {
          min-width: 0;
          color: var(--text-muted);
          font-size: 11px;
          font-variant-numeric: tabular-nums;
          white-space: nowrap;
        }

        .operation-select-field,
        .codec-options label {
          min-width: 0;
          display: grid;
          gap: 6px;
        }

        .operation-select-field span,
        .codec-options span {
          color: var(--text-muted);
          font-size: 12px;
          font-weight: 700;
        }

        .operation-select-field select,
        .codec-options select,
        .codec-options input,
        .codec-options textarea,
        .category-select {
          min-width: 0;
          width: 100%;
          min-height: 38px;
          border: 1px solid var(--border-color);
          border-radius: 6px;
          background: var(--bg-secondary);
          color: var(--text-primary);
          padding: 8px 10px;
          outline: none;
        }

        .operation-select-field select:focus,
        .codec-options select:focus,
        .codec-options input:focus,
        .codec-options textarea:focus,
        .category-select:focus {
          border-color: var(--neon-cyan);
          box-shadow: 0 0 0 3px rgba(0, 240, 255, 0.12);
        }

        .codec-options textarea {
          min-height: 120px;
          resize: vertical;
          font-family: 'JetBrains Mono', 'Fira Code', monospace;
          line-height: 1.45;
        }

        .codec-options .wide-option {
          grid-column: 1 / -1;
        }

        .mode-actions {
          min-width: 0;
          display: flex;
          flex-wrap: wrap;
          justify-content: flex-end;
          gap: 7px;
        }

        .mode-btn,
        .options-toggle,
        .detect-strip button,
        .clear-btn,
        .copy-btn {
          min-height: 36px;
          min-width: 0;
          border: 1px solid var(--border-color);
          border-radius: 6px;
          background: var(--bg-secondary);
          color: var(--text-secondary);
          padding: 8px 11px;
          font-size: 12px;
          font-weight: 700;
          white-space: nowrap;
          transition: all var(--transition-fast);
        }

        .mode-btn:hover:not(:disabled),
        .options-toggle:hover,
        .detect-strip button:hover,
        .clear-btn:hover,
        .copy-btn:hover:not(:disabled) {
          border-color: var(--neon-cyan);
          color: var(--neon-cyan);
        }

        .mode-btn.primary {
          border-color: var(--neon-cyan);
          background: rgba(0, 240, 255, 0.12);
          color: var(--neon-cyan);
        }

        .mode-btn.subtle {
          color: var(--text-muted);
        }

        .mode-btn:disabled,
        .copy-btn:disabled {
          opacity: 0.45;
          cursor: not-allowed;
        }

        .operation-summary {
          min-width: 0;
          border: 1px solid rgba(255, 255, 255, 0.08);
          border-radius: 8px;
          background: rgba(255, 255, 255, 0.025);
          padding: 11px;
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 10px;
        }

        .operation-summary div {
          min-width: 0;
          display: grid;
          gap: 4px;
        }

        .operation-summary strong {
          min-width: 0;
          overflow-wrap: anywhere;
          color: var(--text-primary);
          font-size: 13px;
        }

        .operation-summary span {
          min-width: 0;
          overflow-wrap: anywhere;
          color: var(--text-muted);
          font-size: 12px;
          line-height: 1.5;
        }

        .codec-options {
          display: none;
          grid-template-columns: repeat(3, minmax(0, 1fr));
          gap: 10px;
          border: 1px solid var(--border-color);
          border-radius: 8px;
          background: rgba(0, 0, 0, 0.12);
          padding: 12px;
        }

        .codec-options.open {
          display: grid;
        }

        .detect-strip {
          min-width: 0;
          display: flex;
          flex-wrap: wrap;
          align-items: center;
          gap: 7px;
          color: var(--text-muted);
          font-size: 12px;
        }

        .detect-strip span {
          font-weight: 700;
        }

        .detect-strip button {
          min-height: 30px;
          padding: 5px 9px;
          background: rgba(255, 255, 255, 0.035);
        }

        .encoding-content {
          min-width: 0;
          display: grid;
          grid-template-columns: repeat(2, minmax(0, 1fr));
          gap: 12px;
          align-items: stretch;
        }

        .encoding-panel {
          min-width: 0;
          display: grid;
          grid-template-rows: auto minmax(220px, 1fr);
          gap: 8px;
        }

        /* Top-N 多候选可折叠列表 */
        .encoding-panel .candidate-list {
          grid-column: 1 / -1;
          border: 1px solid var(--border-color, rgba(128, 128, 128, 0.35));
          border-radius: 8px;
          padding: 6px 10px;
          font-size: 12px;
          background: rgba(128, 128, 128, 0.06);
        }
        .encoding-panel .candidate-list summary {
          cursor: pointer;
          color: var(--text-muted);
          font-weight: 700;
          user-select: none;
        }
        .encoding-panel .candidate-layer {
          margin-top: 8px;
          display: grid;
          gap: 4px;
        }
        .encoding-panel .candidate-layer-title {
          font-weight: 800;
          color: var(--text-muted);
        }
        .encoding-panel .candidate-option {
          display: grid;
          grid-template-columns: minmax(90px, auto) 42px minmax(0, 1fr);
          gap: 8px;
          align-items: baseline;
          padding: 3px 6px;
          border-radius: 6px;
        }
        .encoding-panel .candidate-option.chosen {
          background: rgba(66, 206, 208, 0.12);
        }
        .encoding-panel .candidate-name {
          font-weight: 800;
        }
        .encoding-panel .candidate-score {
          color: var(--text-muted);
          font-variant-numeric: tabular-nums;
        }
        .encoding-panel .candidate-preview {
          min-width: 0;
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
          opacity: 0.85;
        }

        .panel-header {
          min-width: 0;
          display: flex;
          justify-content: space-between;
          align-items: center;
          gap: 8px;
        }

        .panel-header label {
          color: var(--text-muted);
          font-size: 12px;
          font-weight: 800;
        }

        .panel-actions {
          min-width: 0;
          display: flex;
          flex-wrap: wrap;
          justify-content: flex-end;
          gap: 6px;
        }

        .copy-btn.copied {
          border-color: var(--neon-green);
          background: rgba(0, 255, 136, 0.1);
          color: var(--neon-green);
        }

        .encoding-panel textarea {
          min-width: 0;
          width: 100%;
          min-height: 220px;
          resize: vertical;
          border: 1px solid var(--border-color);
          border-radius: 8px;
          background: var(--bg-secondary);
          color: var(--text-primary);
          padding: 13px;
          outline: none;
          font-family: var(--font-mono);
          font-size: 13px;
          line-height: 1.6;
          white-space: pre-wrap;
          overflow-wrap: anywhere;
          writing-mode: horizontal-tb;
        }

        .encoding-panel textarea:focus {
          border-color: var(--neon-cyan);
          box-shadow: 0 0 0 3px rgba(0, 240, 255, 0.12);
        }

        .encoding-panel textarea.error {
          border-color: var(--neon-red);
          color: var(--neon-red);
        }

        .encoding-panel textarea::placeholder {
          color: var(--text-muted);
        }

        @media (max-width: 900px) {
          .encoding-tools {
            padding: 14px;
          }

          .encoding-workbench {
            grid-template-columns: 1fr;
          }

          .encoding-category-panel {
            position: static;
          }

          .category-select {
            display: block;
          }

          .category-list {
            display: none;
          }

          .codec-toolbar {
            grid-template-columns: 1fr;
          }

          .mode-actions {
            justify-content: stretch;
          }

          .mode-btn {
            flex: 1 1 130px;
          }

          .codec-options {
            grid-template-columns: repeat(2, minmax(0, 1fr));
          }

          .action-grid {
            grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
          }

          .global-secret-bar {
            grid-template-columns: 1fr;
          }
        }

        @media (max-width: 680px) {
          .encoding-tools {
            padding: 10px;
          }

          .encoding-header h2 {
            font-size: 18px;
          }

          .encoding-main-panel {
            padding: 10px;
          }

          .operation-select-field select,
          .codec-options select,
          .codec-options input,
          .category-select,
          .mode-btn,
          .options-toggle,
          .detect-strip button,
          .clear-btn,
          .copy-btn {
            min-height: 44px;
          }

          .operation-summary {
            align-items: stretch;
            flex-direction: column;
          }

          .options-toggle {
            width: 100%;
          }

          .codec-options,
          .encoding-content {
            grid-template-columns: 1fr;
          }

          .action-btn {
            min-height: 44px;
          }

          .action-grid {
            grid-template-columns: repeat(2, minmax(0, 1fr));
          }

          .encoding-panel {
            grid-template-rows: auto minmax(170px, 1fr);
          }

          .encoding-panel textarea {
            min-height: 170px;
            font-size: 12px;
          }
        }

        @media (max-width: 420px) {
          .mode-actions,
          .panel-actions {
            display: grid;
            grid-template-columns: 1fr;
            width: 100%;
          }

          .panel-header {
            align-items: stretch;
            flex-direction: column;
          }

          .mode-btn,
          .clear-btn,
          .copy-btn {
            width: 100%;
            min-height: 44px;
            white-space: normal;
          }

          .detect-strip {
            display: grid;
            grid-template-columns: 1fr 1fr;
          }

          .detect-strip span {
            grid-column: 1 / -1;
          }
        }
      `}</style>
    </div>
  );
}

export default CodecWorkbench;
