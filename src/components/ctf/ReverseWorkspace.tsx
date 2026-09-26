import { memo, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { notifications } from '@mantine/notifications';
import { useLanguage } from '../../appContext';
import StringsCard from './StringsCard';
import HexdumpCard from './HexdumpCard';
import EntropyMapCard from './EntropyMapCard';
import CheatsheetSection from './CheatsheetSection';
import BinaryStructurePanel from './BinaryStructurePanel';
import UpxCard from './UpxCard';
import {
  MAX_FILE_BYTES,
  blockEntropy,
  detectFileTypes,
  entropyLevel,
  entropyVerdictText,
  extractStrings,
  highEntropyRanges,
  shannonEntropy,
} from '../../utils/ctf/fileDetect';
import type { EntropyBlock, HighEntropyRange } from '../../utils/ctf/fileDetect';
import { FINGERPRINT_SCAN_LIMIT, scanConstFingerprints } from '../../utils/ctf/constFingerprints';
import type { FingerprintCategory, FingerprintHit } from '../../utils/ctf/constFingerprints';
import { recommendTools } from '../../utils/ctf/recommendTools';
import type { ToolAnchor } from '../../utils/ctf/recommendTools';
import { parseElf } from '../../utils/ctf/elfParse';
import { parsePe } from '../../utils/ctf/peParse';
import type { PeInfo } from '../../utils/ctf/peParse';
import type { CtfWorkspaceProps } from '../../utils/ctf/moduleContracts';
import '../../styles/ctf-forensics.css';
import '../../styles/reverse-workspace.css';

interface ReverseAnalysis {
  name: string;
  size: number;
  bytes: Uint8Array;
}

interface ReverseReport {
  types: ReturnType<typeof detectFileTypes>;
  entropy: number;
  level: ReturnType<typeof entropyLevel>;
  fingerprints: FingerprintHit[];
  entropyBlocks: EntropyBlock[];
  highRanges: HighEntropyRange[];
  stringsTotal: number;
  elf: import('../../utils/ctf/elfParse').ElfInfo | null;
  pe: PeInfo | null;
  isUpx: boolean;
}

const formatBytes = (value: number): string => {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / (1024 * 1024)).toFixed(2)} MB`;
};

const toHex = (value: number): string => `0x${value.toString(16).toUpperCase()}`;

const CATEGORY_LABEL: Record<FingerprintCategory, { zh: string; en: string }> = {
  cipher: { zh: '对称密码', en: 'Cipher' },
  hash: { zh: '散列', en: 'Hash' },
  checksum: { zh: '校验', en: 'Checksum' },
  encoding: { zh: '编码', en: 'Encoding' },
  structure: { zh: '内嵌结构', en: 'Structure' },
  packer: { zh: '加壳', en: 'Packer' },
  library: { zh: '库特征', en: 'Library' },
};

// 逆向域工作台（逆向域批次）：拿二进制 → 常量指纹/熵图/strings 第一公里。
// 文件仅在本浏览器内分析（前 8MB），不上传、不执行；反编译（Ghidra 类）保持指导页形态不在本批次。
function ReverseWorkspace({ pendingFile, onFileConsumed, onSwitchModule }: CtfWorkspaceProps) {
  const { language } = useLanguage();
  const zh = language === 'zh';
  const [analysis, setAnalysis] = useState<ReverseAnalysis | null>(null);
  const [report, setReport] = useState<ReverseReport | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const inputRef = useRef<HTMLInputElement | null>(null);
  const lastTokenRef = useRef(0);
  const [activeTool, setActiveTool] = useState('overview');

  const loadFile = useCallback(async (file: File) => {
    if (file.size > MAX_FILE_BYTES) {
      notifications.show({
        title: zh ? '文件过大' : 'File too large',
        message: zh
          ? `「${file.name}」有 ${formatBytes(file.size)}，超过 20MB 上限。请先在本地裁剪或压缩后再试。`
          : `"${file.name}" is ${formatBytes(file.size)}, over the 20MB limit. Trim or compress it locally first.`,
        color: 'red',
      });
      return;
    }
    setAnalyzing(true);
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      setAnalysis({ name: file.name, size: file.size, bytes });
      // 先渲染概要一帧，再做同步扫描（8MB 内常量指纹 + 块熵合计约 0.3-1s）。
      await new Promise(resolve => setTimeout(resolve, 0));
      const types = detectFileTypes(bytes);
      const entropy = shannonEntropy(bytes);
      const entropyBlocks = blockEntropy(bytes);
      // ELF/PE 结构解析（逆向域批次 RV）：解析失败（非 ELF/PE）时为 null，不阻断其他分析。
      const elfParseResult = parseElf(bytes);
      const elf = elfParseResult.ok ? elfParseResult : null;
      const peParseResult = parsePe(bytes);
      const pe = peParseResult.ok ? peParseResult : null;
      setReport({
        types,
        entropy,
        level: entropyLevel(entropy, bytes.length),
        fingerprints: scanConstFingerprints(bytes),
        entropyBlocks,
        highRanges: highEntropyRanges(entropyBlocks),
        stringsTotal: extractStrings(bytes, { limit: 1 }).total,
        elf,
        pe,
        isUpx: (() => {
          for (let i = 0; i + 4 <= bytes.length; i++) {
            if (bytes[i] === 0x55 && bytes[i + 1] === 0x50 && bytes[i + 2] === 0x58 && bytes[i + 3] === 0x21) return true;
          }
          return false;
        })(),
      });
    } catch {
      notifications.show({
        title: zh ? '读取失败' : 'Read failed',
        message: zh ? '无法读取该文件的内容，请确认文件仍存在且可访问。' : 'The file could not be read; make sure it still exists and is accessible.',
        color: 'red',
      });
      setAnalysis(null);
      setReport(null);
    } finally {
      setAnalyzing(false);
    }
  }, [zh]);

  // 载入成功后回到概览视图（异步回调里 setState，避开 set-state-in-effect 红线）
  const loadAndShow = useCallback((file: File) => {
    void loadFile(file).then(() => setActiveTool('overview'));
  }, [loadFile]);

  useEffect(() => {
    if (!pendingFile || pendingFile.token === lastTokenRef.current) return;
    lastTokenRef.current = pendingFile.token;
    onFileConsumed?.();
    loadAndShow(pendingFile.file);
  }, [pendingFile, onFileConsumed, loadAndShow]);

  const onDrop = (event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    // 阻止冒泡到 CtfToolkit 的页面级 drop，避免同一文件被两处重复读取。
    event.stopPropagation();
    const file = event.dataTransfer.files?.[0];
    if (file) loadAndShow(file);
  };

  // 推荐工具条：复用杂项域映射；其中"常量扫描（逆向域）"锚点在本域内改为域内滚动到指纹卡。
  const recommendedTools = useMemo<ToolAnchor[]>(() => {
    if (!report) return [];
    return recommendTools(report.types).map(tool => (
      tool.targetModuleId === 'reverse'
        ? { ...tool, targetModuleId: undefined, cardId: 'rv-card-fingerprints', label: { zh: '常量指纹', en: 'Constant scan' } }
        : tool
    ));
  }, [report]);

  // 推荐工具跳转：域内锚点 → 切视图 + 滚动（批次 NAV 起二级视图取代平铺锚点）
  const openCard = (cardId: string) => {
    if (cardId === 'rv-card-fingerprints' || cardId === 'ff-card-summary') {
      setActiveTool('overview');
    }
    document.getElementById(cardId)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  return (
    <div className="file-forensics reverse-workspace" onDragOver={event => event.preventDefault()} onDrop={onDrop}>
      <input
        ref={inputRef}
        type="file"
        aria-hidden="true"
        tabIndex={-1}
        style={{ display: 'none' }}
        onChange={event => {
          const file = event.target.files?.[0];
          if (file) loadAndShow(file);
          event.target.value = '';
        }}
      />

      {!analysis ? (
        <div className="ff-dropzone">
          <div className="ff-dropzone-icon" aria-hidden="true">🔍</div>
          <strong>{zh ? '把逆向题二进制拖到这里，或点击选择' : 'Drop a challenge binary here, or click to browse'}</strong>
          <small>
            {zh
              ? '自动识别 ELF/PE/Mach-O，扫描加密算法常量指纹（TEA/AES/MD5/Base64/UPX 等）与块级熵图，附可读字符串与 hexdump。文件仅在本浏览器内分析（前 8MB），不会上传。上限 20MB。'
              : 'Detects ELF/PE/Mach-O, scans crypto constant fingerprints (TEA/AES/MD5/Base64/UPX…) and a block entropy map, plus strings and hexdump. Analyzed locally (first 8MB), never uploaded. 20MB limit.'}
          </small>
          <button type="button" className="ff-button ff-button-primary" onClick={() => inputRef.current?.click()}>
            {zh ? '选择文件' : 'Choose file'}
          </button>
        </div>
      ) : (
        <div className="ctf-toolnav">
          <nav className="ctf-toolnav-menu" aria-label={zh ? '逆向工具选择' : 'Reverse tools'}>
            <div className="ctf-toolnav-group">
              <div className="ctf-toolnav-group-title">{zh ? '目标分析' : 'Target'}</div>
              <button type="button" className={`ctf-toolnav-item ${activeTool === 'overview' ? 'active' : ''}`} aria-current={activeTool === 'overview' ? 'true' : undefined} onClick={() => setActiveTool('overview')}>
                {zh ? '概览与指纹' : 'Overview'}
              </button>
              <button type="button" className={`ctf-toolnav-item ${activeTool === 'structure' ? 'active' : ''}`} aria-current={activeTool === 'structure' ? 'true' : undefined} onClick={() => setActiveTool('structure')}>
                {zh ? 'ELF/PE 结构' : 'Structure'}
              </button>
              {report?.isUpx && (
                <button type="button" className={`ctf-toolnav-item ${activeTool === 'upx' ? 'active' : ''}`} aria-current={activeTool === 'upx' ? 'true' : undefined} onClick={() => setActiveTool('upx')}>
                  {zh ? 'UPX 脱壳' : 'UPX unpack'}
                </button>
              )}
              <button type="button" className={`ctf-toolnav-item ${activeTool === 'entropy' ? 'active' : ''}`} aria-current={activeTool === 'entropy' ? 'true' : undefined} onClick={() => setActiveTool('entropy')}>
                {zh ? '熵图' : 'Entropy map'}
              </button>
              <button type="button" className={`ctf-toolnav-item ${activeTool === 'strings' ? 'active' : ''}`} aria-current={activeTool === 'strings' ? 'true' : undefined} onClick={() => setActiveTool('strings')}>
                {zh ? '字符串' : 'Strings'}
              </button>
              <button type="button" className={`ctf-toolnav-item ${activeTool === 'hexdump' ? 'active' : ''}`} aria-current={activeTool === 'hexdump' ? 'true' : undefined} onClick={() => setActiveTool('hexdump')}>
                {zh ? 'Hexdump' : 'Hexdump'}
              </button>
            </div>
            <div className="ctf-toolnav-group">
              <div className="ctf-toolnav-group-title">{zh ? '速查' : 'Reference'}</div>
              <button type="button" className={`ctf-toolnav-item ${activeTool === 'cheatsheet' ? 'active' : ''}`} aria-current={activeTool === 'cheatsheet' ? 'true' : undefined} onClick={() => setActiveTool('cheatsheet')}>
                {zh ? '速查表' : 'Cheatsheet'}
              </button>
            </div>
          </nav>
          <div className="ctf-toolnav-body">
            {/* hidden 保挂载：切换视图不丢结构/字符串等重组件状态 */}
            <div className="ctf-toolpanel" hidden={activeTool !== 'overview'}>
              {recommendedTools.length > 0 && (
                <nav className="ff-recommend" aria-label={zh ? '推荐工具' : 'Recommended tools'}>
                  <span className="ff-recommend-label">{zh ? '推荐工具' : 'Recommended'}</span>
                  <div className="ff-recommend-tools">
                    {recommendedTools.map(tool => (
                      <button
                        key={tool.id}
                        type="button"
                        className={tool.soon ? 'ff-button ff-recommend-soon' : 'ff-button ff-recommend-hit'}
                        onClick={() => { if (tool.cardId) openCard(tool.cardId); }}
                        title={tool.label[language]}
                      >
                        {tool.label[language]}
                        {tool.soon && <span className="ff-recommend-soon-tag">{zh ? '即将上线' : 'soon'}</span>}
                      </button>
                    ))}
                  </div>
                </nav>
              )}

              <section id="ff-card-summary" className="ff-card" aria-label={zh ? '文件概要' : 'File summary'}>
                <div className="ff-card-head">
                  <strong>{zh ? '文件概要' : 'Summary'}</strong>
                  <button type="button" className="ff-button" onClick={() => inputRef.current?.click()}>{zh ? '换一个文件' : 'Replace'}</button>
                </div>
                <div className="ff-summary">
                  <span className="ff-name" title={analysis.name}>{analysis.name}</span>
                  <span className="ff-size">{formatBytes(analysis.size)}</span>
                </div>
                {report && (
                  <>
                    <div className="ff-row">
                      <span className="ff-label">{zh ? '探测类型' : 'Detected type'}</span>
                      {report.types.length
                        ? report.types.map(type => <span key={type.ext} className="ff-badge" title={type.name}>{type.name}</span>)
                        : <span className="ff-badge ff-badge-warn">{zh ? '未知类型（无已知魔数）' : 'Unknown (no magic match)'}</span>}
                      <span className="ff-label">{zh ? '信息熵' : 'Entropy'}</span>
                      <span className="ff-mono">{report.entropy.toFixed(3)} / 8</span>
                    </div>
                    <p className="ff-note">{entropyVerdictText(report.level, language)}</p>
                  </>
                )}
              </section>

              <section id="rv-card-fingerprints" className="ff-card" aria-label={zh ? '常量指纹扫描' : 'Constant fingerprint scan'}>
                <div className="ff-card-head">
                  <strong>{zh ? `常量指纹扫描（前 ${formatBytes(FINGERPRINT_SCAN_LIMIT)}）` : `Constant fingerprint scan (first ${formatBytes(FINGERPRINT_SCAN_LIMIT)})`}</strong>
                </div>
                {report && report.fingerprints.length > 0 ? (
                  report.fingerprints.map(hit => (
                    <article key={hit.id} className="rv-fingerprint">
                      <div className="ff-row">
                        <span className="ff-badge">{CATEGORY_LABEL[hit.category][language]}</span>
                        <span className="rv-fingerprint-name">{hit.name}</span>
                        <span className="ff-mono">@ {toHex(hit.offset)}</span>
                        {hit.hits > 1 && <span className="ff-badge">{zh ? `${hit.hits} 处命中` : `${hit.hits} hits`}</span>}
                        {hit.label && <span className="ff-badge">{hit.label[language]}</span>}
                      </div>
                      <p className="ff-note">{hit.meaning[language]}</p>
                      <div className="ff-row">
                        <span className="rv-fingerprint-suggest">➜ {hit.suggestion[language]}</span>
                        {hit.switchModuleId && (
                          <button
                            type="button"
                            className="ff-button ff-button-primary"
                            onClick={() => onSwitchModule?.(hit.switchModuleId!)}
                          >
                            {zh ? '去密码与编码域' : 'Open Ciphers & Encoding'}
                          </button>
                        )}
                      </div>
                    </article>
                  ))
                ) : (
                  <p className="ff-note">
                    {report
                      ? (zh
                        ? '未命中已知常量——不代表没有加密：结合熵图与字符串判断，自定义算法或混淆样本需要动态调试（见速查）。'
                        : 'No known constants hit — that does not rule out crypto: combine the entropy map and strings; custom algorithms need dynamic analysis (see the cheat sheet).')
                      : (zh ? '正在扫描…' : 'Scanning…')}
                  </p>
                )}
              </section>
            </div>

            <div className="ctf-toolpanel" hidden={activeTool !== 'structure'}>
              {report ? (
                <BinaryStructurePanel
                  key={`structure-${analysis.name}:${analysis.size}`}
                  elf={report.elf}
                  pe={report.pe}
                  bytes={analysis.bytes}
                  language={language}
                />
              ) : (
                <p className="ff-note">{zh ? '正在解析结构…' : 'Parsing structure…'}</p>
              )}
            </div>

            <div className="ctf-toolpanel" hidden={activeTool !== 'upx'}>
              {report?.isUpx ? (
                <UpxCard
                  key={`upx-${analysis.name}:${analysis.size}`}
                  bytes={analysis.bytes}
                  fileName={analysis.name}
                  language={language}
                />
              ) : (
                <p className="ff-note">{zh ? '当前文件未检测到 UPX 壳。' : 'No UPX packing detected.'}</p>
              )}
            </div>

            <div className="ctf-toolpanel" hidden={activeTool !== 'entropy'}>
              {report ? (
                <EntropyMapCard
                  key={`entropy-${analysis.name}:${analysis.size}`}
                  blocks={report.entropyBlocks}
                  ranges={report.highRanges}
                  language={language}
                />
              ) : (
                <p className="ff-note">{zh ? '正在计算熵…' : 'Computing entropy…'}</p>
              )}
            </div>

            <div className="ctf-toolpanel" hidden={activeTool !== 'strings'}>
              {report && report.stringsTotal > 0 ? (
                <StringsCard
                  key={`strings-${analysis.name}:${analysis.size}`}
                  fileName={analysis.name}
                  bytes={analysis.bytes}
                  language={language}
                />
              ) : (
                <p className="ff-note">{zh ? '未提取到可读字符串。' : 'No readable strings.'}</p>
              )}
            </div>

            <div className="ctf-toolpanel" hidden={activeTool !== 'hexdump'}>
              {report ? (
                <HexdumpCard
                  key={`hexdump-${analysis.name}:${analysis.size}`}
                  bytes={analysis.bytes}
                  size={analysis.size}
                  language={language}
                />
              ) : (
                <p className="ff-note">{zh ? '正在准备 hexdump…' : 'Preparing hexdump…'}</p>
              )}
            </div>

            <div className="ctf-toolpanel" hidden={activeTool !== 'cheatsheet'}>
              <CheatsheetSection moduleId="reverse" variant="footer" />
            </div>
          </div>
        </div>
      )}

      {analyzing && <div className="ff-busy" role="status">{zh ? '正在扫描常量指纹与熵…' : 'Scanning constants and entropy…'}</div>}
    </div>
  );
}

export default memo(ReverseWorkspace);
