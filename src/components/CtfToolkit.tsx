import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { DragEvent as ReactDragEvent } from 'react';
import { SegmentedControl } from '@mantine/core';
import { useAppContext } from '../appContext';
import {
  buildCtfGroups,
  detectFlagFormats,
  detectInput,
  extractPureDecodeResult,
  isOperationVisible,
  smartDecode,
  stripCandidateSection,
} from '../utils/codec';
import type { OperationId } from '../utils/codec';
import { ctfModules } from '../utils/ctf/modules';
import { detectFileTypes } from '../utils/ctf/fileDetect';
import CtfHero from './ctf/CtfHero';

const AUTO_DECODE_LIMIT = 20000;
const CIPHER_MODULE_ID = 'cipher';
// 魔数路由表（批次 L 起，逆向域批次扩展）：抓包格式 → 流量分析域，可执行格式 → 逆向域。
const PCAP_EXTS = new Set(['pcap', 'pcapbe', 'pcapng']);
const BINARY_EXTS = new Set(['elf', 'exe', 'macho', 'machobe']);

// CTF 解题工具箱框架壳（批次 J）：题域导航 + 模块插件化。
// 各题型域由 src/utils/ctf/modules.ts 注册表声明，加新域 = 注册一个模块对象，不改本框架。
// 智能识别 hero 按域变形（heroMode 声明，缺省 full）：cipher 完整置顶；文件/速查域折叠为单行条，
// 工作区升为该域首屏。检测芯片沿用密码与编码域（buildCtfGroups）的操作集合，行为与重构前一致。
function CtfToolkit() {
  const { language } = useAppContext();
  const [activeModuleId, setActiveModuleId] = useState<string>(ctfModules[0]?.id ?? CIPHER_MODULE_ID);
  // pendingFile 定向投递：targetModuleId 标记路由目标域，框架只把它投给目标面板——
  // 常驻（keepMounted）的其它文件域不会误消费并弹出"解析失败"假告警。
  const [pendingFile, setPendingFile] = useState<{ file: File; token: number; targetModuleId: string } | null>(null);
  const [input, setInput] = useState('');
  const [output, setOutput] = useState('');
  const [error, setError] = useState('');
  const [running, setRunning] = useState(false);
  const runTokenRef = useRef(0);
  const heroRef = useRef<HTMLDivElement | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const focusApiRef = useRef<((id: OperationId, seedInput?: string) => void) | null>(null);
  const pendingFocusRef = useRef<{ id: OperationId; seed?: string } | null>(null);

  const cipherOperationIds = useMemo(
    () => new Set<OperationId>(buildCtfGroups().flatMap(group => group.operations.map(item => item.id))),
    [],
  );
  const detections = useMemo(
    // 与工作台识别条一致：只对前 4096 字符做形状检测（检测依赖前缀特征）。
    () => detectInput(input.slice(0, 4096)).filter(detection => cipherOperationIds.has(detection.id)),
    [input, cipherOperationIds],
  );
  const displayOutput = useMemo(() => (error ? '' : stripCandidateSection(output)), [output, error]);
  const flagHits = useMemo(() => (error ? [] : detectFlagFormats(displayOutput)), [displayOutput, error]);

  const runSmartDecode = useCallback(async () => {
    const token = runTokenRef.current + 1;
    runTokenRef.current = token;
    setRunning(true);
    setError('');
    try {
      const result = await smartDecode(input);
      if (runTokenRef.current !== token) return;
      setOutput(result);
    } catch (reason) {
      if (runTokenRef.current !== token) return;
      setOutput('');
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      if (runTokenRef.current === token) setRunning(false);
    }
  }, [input]);

  // 智能识别置顶体验：粘贴后 350ms 防抖自动解码；超长输入不自动跑（结果区给出手动提示）。
  useEffect(() => {
    if (!input.trim() || input.length > AUTO_DECODE_LIMIT) return;
    const timer = window.setTimeout(() => {
      void runSmartDecode();
    }, 350);
    return () => window.clearTimeout(timer);
  }, [input, runSmartDecode]);

  const registerFocus = useCallback((focus: ((id: OperationId, seedInput?: string) => void) | null) => {
    focusApiRef.current = focus;
  }, []);

  // 跨域检测芯片：先切回密码与编码域，待工作台重新可见后再聚焦目标操作
  //（隐藏容器内 scrollIntoView 不生效，需等渲染提交后执行）；seed 一并透传，与同域路径行为一致。
  useEffect(() => {
    if (activeModuleId !== CIPHER_MODULE_ID) return;
    const pending = pendingFocusRef.current;
    if (!pending) return;
    pendingFocusRef.current = null;
    focusApiRef.current?.(pending.id, pending.seed);
  }, [activeModuleId]);

  const handleHeroInput = (value: string) => {
    setInput(value);
    if (!value.trim()) {
      runTokenRef.current += 1;
      setOutput('');
      setError('');
      setRunning(false);
    }
  };

  const applyDetection = (operationId: OperationId) => {
    if (operationId === 'smart-decode') {
      heroRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
      return;
    }
    if (!isOperationVisible(operationId, 'ctf')) return;
    if (activeModuleId === CIPHER_MODULE_ID) {
      // 芯片跳转把 hero 当前输入一并带进工作台（空输入不覆盖工作台现场）。
      focusApiRef.current?.(operationId, input || undefined);
      return;
    }
    pendingFocusRef.current = { id: operationId, seed: input || undefined };
    setActiveModuleId(CIPHER_MODULE_ID);
  };

  const activeModule = ctfModules.find(module => module.id === activeModuleId) ?? ctfModules[0];
  const showFileEntry = activeModule?.entryKinds.includes('file') ?? false;
  // hero 按域变形：注册表未声明 heroMode 的域（如 cipher）缺省完整形态。
  const heroMode = activeModule?.heroMode ?? 'full';

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
    const targetId = exts.some(ext => PCAP_EXTS.has(ext)) ? 'traffic'
      : exts.some(ext => BINARY_EXTS.has(ext)) ? 'reverse'
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
      <div className="encoding-header">
        <h2>{language === 'zh' ? 'CTF 解题工具箱' : 'CTF Toolkit'}</h2>
        <p>{language === 'zh'
          ? '按题型域组织：智能识别置顶全域可用，粘贴即自动识别；密码与编码、杂项取证、流量分析、逆向、Pwn 已就绪，Web/AI 提供题型速查。'
          : 'Organized by category: smart identify stays on top and works everywhere. Ciphers & Encoding, Misc & Forensics, Traffic Analysis, Reverse, and Pwn are ready; Web and AI offer curated cheat sheets.'}</p>
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

      <CtfHero
        input={input}
        output={output}
        error={error}
        running={running}
        autoDisabled={input.length > AUTO_DECODE_LIMIT}
        autoDecodeLimit={AUTO_DECODE_LIMIT}
        detections={detections}
        flagHits={flagHits}
        displayOutput={displayOutput}
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
        heroMode={heroMode}
        // "需要解编码？"引导只在速查域折叠条出现（文件域首屏是文件工作区，无需引导）。
        onSwitchToCipher={activeModule?.entryKinds.includes('cheatsheet')
          ? () => setActiveModuleId(CIPHER_MODULE_ID)
          : undefined}
        onInputChange={handleHeroInput}
        onDetection={applyDetection}
        onFileEntry={() => fileInputRef.current?.click()}
        onUseAsInput={() => { setInput(extractPureDecodeResult(output)); setOutput(''); setError(''); }}
        onClear={() => { handleHeroInput(''); }}
      />

      {ctfModules.map(module => {
        const workspaceProps = {
          module,
          registerFocus,
          // 定向投递：文件只发给路由目标域的面板，其它常驻文件域（hidden）不感知。
          pendingFile: module.id === pendingFile?.targetModuleId ? pendingFile : undefined,
          onFileConsumed: clearPendingFile,
          // 推荐工具条的跨域动作：handoff 走 handleFileSelected 复用魔数路由（PCAP → 流量分析域），
          // 纯导航直接切域（ELF 常量扫描引导 → 逆向速查域）。
          onHandOffFile: (file: File) => { void handleFileSelected(file); },
          onSwitchModule: setActiveModuleId,
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

      <style>{`
        .ctf-toolkit {
          width: min(100%, 1180px);
          min-width: 0;
          margin: 0 auto;
          padding: 20px;
          display: grid;
          gap: 16px;
        }

        .ctf-domain-nav-wrap {
          min-width: 0;
          display: flex;
        }

        .ctf-domain-nav {
          width: max-content;
          max-width: 100%;
          flex-shrink: 0;
          border: 1px solid var(--border-color);
          background: var(--bg-secondary);
        }

        .ctf-domain-nav label {
          white-space: nowrap;
        }

        .ctf-module-panel[hidden] {
          display: none;
        }

        @media (max-width: 900px) {
          .ctf-toolkit {
            padding: 14px;
          }
        }

        @media (max-width: 680px) {
          .ctf-toolkit {
            padding: 10px;
          }

          .encoding-header h2 {
            font-size: 18px;
          }
        }

        @media (max-width: 520px) {
          .ctf-domain-nav-wrap {
            overflow-x: auto;
            scrollbar-width: thin;
            -webkit-overflow-scrolling: touch;
            padding-bottom: 2px;
          }

          .ctf-domain-nav {
            max-width: none;
          }
        }
      `}</style>
    </div>
  );
}

export default CtfToolkit;
