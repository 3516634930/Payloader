import { memo, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { DragEvent as ReactDragEvent } from 'react';
import { SegmentedControl } from '@mantine/core';
import { useLanguage } from '../appContext';
import { isOperationVisible } from '../utils/codec/audience';
import { hydrateCodecHeavyData } from '../utils/codec/heavyData';
import type { OperationId } from '../utils/codec/types';
import { ctfModules } from './ctf/registry';
import { detectFileTypes, ROUTE_EXT_GROUPS } from '../utils/ctf/fileDetect';
import CtfHero from './ctf/CtfHero';
import { useSmartIdentify } from './codec/useSmartIdentify';
import '../styles/ctf-toolkit.css';

const CIPHER_MODULE_ID = 'cipher';

// CTF 解题工具箱框架壳（批次 J）：题域导航 + 模块插件化。
// 各题型域由 src/components/ctf/registry.tsx 注册表组装（契约数据在 utils/ctf/moduleContracts.ts），
// 加新域 = 追加一条契约并注册工作区组件，不改本框架。
// UI 编排优化批（CyberChef「工具即首页」）：标题收敛为一行；密码域不渲染 hero——
// 智能识别内嵌进工作台输入区（SmartDetectBar），首屏即主工作区；
// 文件/速查域保留折叠条 hero（需要时可展开完整识别）。
const CtfToolkit = memo(function CtfToolkit() {
  const { language } = useLanguage();
  const [activeModuleId, setActiveModuleId] = useState<string>(ctfModules[0]?.id ?? CIPHER_MODULE_ID);
  // pendingFile 定向投递：targetModuleId 标记路由目标域，框架只把它投给目标面板——
  // 常驻（keepMounted）的其它文件域不会误消费并弹出"解析失败"假告警。
  const [pendingFile, setPendingFile] = useState<{ file: File; token: number; targetModuleId: string } | null>(null);
  // hero 输入仅服务于非密码域的折叠 hero（展开后粘贴识别）；密码域识别走工作台内嵌 SmartDetectBar。
  const [heroInput, setHeroInput] = useState('');
  const heroRef = useRef<HTMLDivElement | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const focusApiRef = useRef<((id: OperationId, seedInput?: string) => void) | null>(null);
  const pendingFocusRef = useRef<{ id: OperationId; seed?: string } | null>(null);

  const hero = useSmartIdentify(heroInput);

  // 重数据预热：进 CTF tab 即并行拉起评分表 chunk，不阻塞首屏渲染。
  useEffect(() => {
    void hydrateCodecHeavyData();
  }, []);

  const registerFocus = useCallback((focus: ((id: OperationId, seedInput?: string) => void) | null) => {
    focusApiRef.current = focus;
  }, []);

  // 跨域检测芯片（非密码域展开 hero 时出现）：先切回密码与编码域，
  // 待工作台重新可见后再聚焦目标操作（隐藏容器内 scrollIntoView 不生效，需等渲染提交后执行）。
  useEffect(() => {
    if (activeModuleId !== CIPHER_MODULE_ID) return;
    const pending = pendingFocusRef.current;
    if (!pending) return;
    pendingFocusRef.current = null;
    focusApiRef.current?.(pending.id, pending.seed);
  }, [activeModuleId]);

  // 引用稳定（heroNode useMemo 与 keepMounted 工作区消费这些回调，裸函数每渲染换引用会击穿 memo）。
  // clear 已在 hook 内 useCallback 稳定，提出局部变量做依赖，避免整只 hero 对象进依赖数组。
  const heroClear = hero.clear;
  const handleHeroInput = useCallback((value: string) => {
    setHeroInput(value);
    if (!value.trim()) heroClear();
  }, [heroClear]);

  // 种子输入走 latest-ref：applyDetection 还喂给全部 keepMounted 工作区（onOpenCipherOperation），
  // 若直接闭包 heroInput 则每次击键换引用、击穿工作区 memo；调用时读取 ref 即为当前输入。
  const heroInputRef = useRef('');
  heroInputRef.current = heroInput;
  const applyDetection = useCallback((operationId: OperationId) => {
    if (operationId === 'smart-decode') {
      heroRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
      return;
    }
    if (!isOperationVisible(operationId, 'ctf')) return;
    if (activeModuleId === CIPHER_MODULE_ID) {
      // 芯片跳转把 hero 当前输入一并带进工作台（空输入不覆盖工作台现场）。
      focusApiRef.current?.(operationId, heroInputRef.current || undefined);
      return;
    }
    pendingFocusRef.current = { id: operationId, seed: heroInputRef.current || undefined };
    setActiveModuleId(CIPHER_MODULE_ID);
  }, [activeModuleId]);

  const activeModule = ctfModules.find(module => module.id === activeModuleId) ?? ctfModules[0];
  const showFileEntry = activeModule?.entryKinds.includes('file') ?? false;
  // 密码域不再渲染 hero（识别能力在工作台内）；其余域折叠条形态。
  const showHero = activeModuleId !== CIPHER_MODULE_ID;

  // 工作区消费文件后回调清空：pendingFile 只投递给路由目标域（targetModuleId 过滤），
  // 消费即清空防残留；token 单调递增保证同一文件不会被再次投递。
  const clearPendingFile = useCallback(() => setPendingFile(null), []);

  // 文件入口（批次 K 起，批次 L 增加魔数路由，逆向域批次扩展 ELF/PE/MachO → 逆向域）：
  // hero 按钮与页面级拖拽统一走这里。头部字节命中抓包格式 → 流量分析域；命中可执行格式 → 逆向域；
  // 其余情况下当前域接受文件则留在当前域，否则切到杂项取证。
  // 只在拖拽载荷含文件时接管，避免吞掉纯文本拖放。
  const fileTokenRef = useRef(0);
  const handleFileSelected = useCallback(async (file: File | null | undefined) => {
    if (!file) return;
    let exts: string[] = [];
    try {
      const head = new Uint8Array(await file.slice(0, 12).arrayBuffer());
      exts = detectFileTypes(head).map(type => type.ext);
    } catch {
      // 读不出头部就按普通文件走原路由，不阻断入口。
    }
    const active = ctfModules.find(module => module.id === activeModuleId);
    // 魔数路由：抓包格式 → 流量分析域，可执行格式 → 逆向域（扩展名集合以 fileDetect.ROUTE_EXT_GROUPS 为权威）。
    const targetId = exts.some(ext => ROUTE_EXT_GROUPS.traffic.includes(ext)) ? 'traffic'
      : exts.some(ext => ROUTE_EXT_GROUPS.reverse.includes(ext)) ? 'reverse'
        : active?.entryKinds.includes('file') ? active.id : 'misc';
    fileTokenRef.current += 1;
    setPendingFile({ file, token: fileTokenRef.current, targetModuleId: targetId });
    setActiveModuleId(targetId);
  }, [activeModuleId]);

  const handleContainerDrop = useCallback((event: ReactDragEvent<HTMLDivElement>) => {
    if (!Array.from(event.dataTransfer.types).includes('Files')) return;
    event.preventDefault();
    void handleFileSelected(event.dataTransfer.files?.[0]);
  }, [handleFileSelected]);

  const handleContainerDragOver = useCallback((event: ReactDragEvent<HTMLDivElement>) => {
    if (!Array.from(event.dataTransfer.types).includes('Files')) return;
    event.preventDefault();
  }, []);

  // 引用稳定：内联箭头每次渲染换引用，会击穿 5 个 keepMounted 工作区的 memo。
  const handOffFile = useCallback((file: File) => { void handleFileSelected(file); }, [handleFileSelected]);

  const heroNode = useMemo(() => showHero ? (
    <CtfHero
      input={heroInput}
      output={hero.output}
      error={hero.error}
      running={hero.running}
      autoDisabled={hero.autoDisabled}
      autoDecodeLimit={20000}
      detections={hero.detections}
      flagHits={hero.flagHits}
      displayOutput={hero.displayOutput}
      showFileEntry={showFileEntry}
      fileEntryLabel={activeModuleId === 'traffic'
        ? { zh: '抓包分析', en: 'Capture analysis' }
        : activeModuleId === 'reverse'
          ? { zh: '逆向分析', en: 'Reverse analysis' }
          : undefined}
      fileEntryHint={activeModuleId === 'traffic'
        ? {
          zh: '选择或拖入 pcap / pcapng，在流量分析域本地解析包列表、协议统计、TCP 流与 HTTP 对象（上限 20MB，不上传）',
          en: 'Pick or drop a pcap / pcapng for local parsing in Traffic Analysis: packet list, protocol stats, TCP streams, and HTTP objects (20MB limit, never uploaded)',
        }
        : activeModuleId === 'reverse'
          ? {
            zh: '选择或拖入 ELF / PE / Mach-O，自动做常量指纹扫描、块级熵图与字符串分析（上限 20MB，不上传）',
            en: 'Pick or drop an ELF / PE / Mach-O for constant fingerprints, block entropy, and strings (20MB limit, never uploaded)',
          }
          : undefined}
      heroRef={heroRef}
      heroMode="collapsed"
      // "需要解编码？"引导只在速查域折叠条出现（文件域首屏是文件工作区，无需引导）。
      onSwitchToCipher={activeModule?.entryKinds.includes('cheatsheet')
        ? () => setActiveModuleId(CIPHER_MODULE_ID)
        : undefined}
      onInputChange={handleHeroInput}
      onDetection={applyDetection}
      onFileEntry={() => fileInputRef.current?.click()}
      onUseAsInput={() => { setHeroInput(hero.pureResult); hero.clear(); }}
      onClear={() => { handleHeroInput(''); }}
    />
  ) : null, [showHero, heroInput, hero, showFileEntry, activeModuleId, activeModule, handleHeroInput, applyDetection]);

  return (
    <div
      className="ctf-toolkit"
      onDragOver={handleContainerDragOver}
      onDrop={handleContainerDrop}
    >
      <input
        ref={fileInputRef}
        type="file"
        aria-hidden="true"
        tabIndex={-1}
        style={{ display: 'none' }}
        onChange={event => {
          void handleFileSelected(event.target.files?.[0]);
          event.target.value = '';
        }}
      />
      <div className="encoding-header encoding-header-compact">
        <h2 title={language === 'zh'
          ? '按题型域组织：密码与编码、杂项取证、流量分析、逆向、Pwn 已就绪，Web/AI 提供题型速查；粘贴即自动识别'
          : 'Organized by category: Ciphers & Encoding, Misc & Forensics, Traffic Analysis, Reverse, and Pwn are ready; Web and AI offer cheat sheets. Paste to auto-identify.'}>
          {language === 'zh' ? 'CTF 解题工具箱' : 'CTF Toolkit'}
        </h2>
      </div>

      <nav className="ctf-domain-nav-wrap" aria-label={language === 'zh' ? '题型域导航' : 'Challenge categories'}>
        <SegmentedControl
          className="ctf-domain-nav"
          value={activeModuleId}
          onChange={setActiveModuleId}
          data={ctfModules.map(module => ({ value: module.id, label: `${module.icon} ${module.name[language]}` }))}
          aria-label={language === 'zh' ? '题型域导航' : 'Challenge categories'}
        />
      </nav>

      {heroNode}

      {ctfModules.map(module => {
        const workspaceProps = {
          module,
          registerFocus,
          // 定向投递：文件只发给路由目标域的面板，其它常驻文件域（hidden）不感知。
          pendingFile: module.id === pendingFile?.targetModuleId ? pendingFile : undefined,
          onFileConsumed: clearPendingFile,
          // 推荐工具条的跨域动作：handoff 走 handleFileSelected 复用魔数路由（PCAP → 流量分析域），
          // 纯导航直接切域（ELF 常量扫描引导 → 逆向速查域）。
          onHandOffFile: handOffFile,
          onSwitchModule: setActiveModuleId,
          // 题型选择卡：纯输入工具（CRC32 反推/零宽解码）跳密码域并定位操作——复用检测芯片的
          // pendingFocus 管线（隐藏容器内 scrollIntoView 不生效，切域后补聚焦）。
          onOpenCipherOperation: applyDetection,
        };
        if (module.keepMounted) {
          const Workspace = module.Workspace;
          return (
            <div key={module.id} className="ctf-module-panel" hidden={module.id !== activeModuleId}>
              <Workspace {...workspaceProps} />
            </div>
          );
        }
        if (module.id !== activeModuleId) return null;
        const Workspace = module.Workspace;
        return <Workspace key={module.id} {...workspaceProps} />;
      })}
    </div>
  );
});

export default CtfToolkit;
