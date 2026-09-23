import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { notifications } from '@mantine/notifications';
import { useAppContext } from '../../appContext';
import { FlagAutoText } from '../codec/FlagAutoText';
import { WorkbenchMenuBar } from '../codec/WorkbenchMenuBar';
import type { WorkbenchMenuDef } from '../codec/WorkbenchMenuBar';
import EmbeddedCard from './EmbeddedCard';
import type { EmbeddedReport } from './EmbeddedCard';
import ImagePlanesCard from './ImagePlanesCard';
import type { PlaneImage } from './ImagePlanesCard';
import StringsCard from './StringsCard';
import HexdumpCard from './HexdumpCard';
import { downloadBytes } from './ffDownload';
import {
  MAX_FILE_BYTES,
  detectFileTypes,
  detectZipEncryption,
  entropyLevel,
  entropyVerdictText,
  extractStrings,
  extractZeroWidthFromText,
  fixPngDimensions,
  fixZipPseudoEncryption,
  hexdumpPreview,
  parsePngIhdr,
  scanSuspiciousContent,
  shannonEntropy,
} from '../../utils/ctf/fileDetect';
import {
  enumeratePngChunks,
  findJpegTrailer,
  findPngTrailer,
  scanEmbeddedSignatures,
} from '../../utils/ctf/embedScan';
import type { PngChunkList } from "../../utils/ctf/embedScan";
import { MAX_ANALYSIS_PIXELS } from '../../utils/ctf/imagePlanes';
import { recommendTools } from '../../utils/ctf/recommendTools';
import { ffStyles } from './ffStyles';
import type { ToolAnchor } from '../../utils/ctf/recommendTools';

interface FileAnalysis {
  name: string;
  size: number;
  bytes: Uint8Array;
  // 保留原始 File 句柄：推荐工具条跨域移交（PCAP → 流量分析域）时交回框架重走魔数路由。
  file: File;
}

interface FileReport {
  types: ReturnType<typeof detectFileTypes>;
  entropy: number;
  level: ReturnType<typeof entropyLevel>;
  strings: ReturnType<typeof extractStrings>;
  suspicious: ReturnType<typeof scanSuspiciousContent>;
  hexdump: string;
  png: ReturnType<typeof parsePngIhdr>;
  zip: ReturnType<typeof detectZipEncryption> | null;
  zeroWidth: ReturnType<typeof extractZeroWidthFromText>;
  embedded: EmbeddedReport;
  chunks: PngChunkList | null;
}

export interface FileForensicsWorkspaceProps {
  // 框架层（CtfToolkit）传入的待分析文件；token 变化表示有新文件到达。
  pendingFile?: { file: File; token: number } | null;
  // 通知框架文件已被取走，框架清空 pendingFile 防止残留重放。
  onFileConsumed?: () => void;
  // 推荐工具条：把当前文件交回框架重走魔数路由（PCAP → 流量分析域，文件跟人走）。
  onHandOffFile?: (file: File) => void;
  // 推荐工具条：纯导航切域（ELF 常量扫描引导 → 逆向速查域）。
  onSwitchModule?: (moduleId: string) => void;
}

interface PngFixState {
  status: 'idle' | 'running' | 'done' | 'failed';
  width?: number;
  height?: number;
  bytes?: Uint8Array;
}

interface ZipFixState {
  cleared: number;
  bytes: Uint8Array;
}

const formatBytes = (value: number): string => {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / (1024 * 1024)).toFixed(2)} MB`;
};

// 浏览器可原生解码的图片类型：位平面/色道卡只对这些文件渲染。
const IMAGE_MIME_MAP: Record<string, string> = { png: 'image/png', jpg: 'image/jpeg', gif: 'image/gif', bmp: 'image/bmp', webp: 'image/webp', ico: 'image/x-icon' };

// strings 提取上限（与 StringsCard 内常量同值）；hexdump 每页 512B（与 HexdumpCard 同值）。
const STRINGS_EXTRACT_LIMIT = 20000;
const HEX_PAGE_BYTES = 512;

const toBinaryString = (bytes: Uint8Array): string => {
  let binary = '';
  const chunkSize = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
  }
  return binary;
};

// 杂项取证域工作区（批次 K）：文件拖入/选择 → 本地探测 → 按需分析。
// 文件只读字节、不执行、不上传；超过 20MB 直接拒绝并说明原因。
function FileForensicsWorkspace({ pendingFile, onFileConsumed, onHandOffFile, onSwitchModule }: FileForensicsWorkspaceProps) {
  const { language } = useAppContext();
  const [analysis, setAnalysis] = useState<FileAnalysis | null>(null);
  const [report, setReport] = useState<FileReport | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [pngFix, setPngFix] = useState<PngFixState>({ status: 'idle' });
  const [zipFix, setZipFix] = useState<ZipFixState | null>(null);
  const [busy, setBusy] = useState(false);
  // 位平面卡：浏览器异步解码出的 RGBA 像素（>4MP 自动降采样）。
  const [planeImage, setPlaneImage] = useState<PlaneImage | null>(null);
  const [planeStatus, setPlaneStatus] = useState<'idle' | 'loading' | 'ready' | 'failed'>('idle');
  const inputRef = useRef<HTMLInputElement | null>(null);
  const lastTokenRef = useRef(0);

  const loadFile = useCallback(async (file: File) => {
    if (file.size > MAX_FILE_BYTES) {
      notifications.show({
        title: language === 'zh' ? '文件过大' : 'File too large',
        message: language === 'zh'
          ? `「${file.name}」有 ${formatBytes(file.size)}，超过 20MB 上限。请先在本地裁剪或压缩后再试。`
          : `"${file.name}" is ${formatBytes(file.size)}, over the 20MB limit. Trim or compress it locally first.`,
        color: 'red',
      });
      return;
    }
    setBusy(true);
    setAnalyzing(false);
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      setAnalysis({ name: file.name, size: file.size, bytes, file });
      setPngFix({ status: 'idle' });
      setZipFix(null);
      // 重置位平面卡状态：其余卡片的过滤/翻页/搜索状态随 key remount 自行重置。
      setPlaneImage(null);
      setPlaneStatus('idle');
      setBusy(false);
      // 让文件概要先渲染一帧，再做同步分析（接近 20MB 的文件约 0.5-2s）；
      // 判读文案等语言相关内容在渲染层现算，切换语言不会触发重分析。
      setAnalyzing(true);
      await new Promise(resolve => setTimeout(resolve, 0));
      const types = detectFileTypes(bytes);
      const entropy = shannonEntropy(bytes);
      const latin1 = new TextDecoder('latin1').decode(bytes);
      const utf8Text = new TextDecoder('utf-8', { fatal: false }).decode(bytes.subarray(0, 512 * 1024));
      // 嵌入扫描：首字节跳转式滑窗（前 8MB），尾附检测与 chunk 枚举是 O(n) 单遍。
      const pngTrailer = findPngTrailer(bytes);
      const jpgTrailer = pngTrailer ? null : findJpegTrailer(bytes);
      setReport({
        types,
        entropy,
        level: entropyLevel(entropy, bytes.length),
        strings: extractStrings(bytes, { limit: STRINGS_EXTRACT_LIMIT }),
        suspicious: scanSuspiciousContent(latin1),
        hexdump: hexdumpPreview(bytes, { length: HEX_PAGE_BYTES }),
        png: parsePngIhdr(bytes),
        zip: types.some(type => type.ext === 'zip' || type.ext === 'jar' || type.ext === 'apk') || (bytes.length > 4 && bytes[0] === 0x50 && bytes[1] === 0x4b) ? detectZipEncryption(bytes) : null,
        zeroWidth: extractZeroWidthFromText(utf8Text),
        embedded: {
          hits: scanEmbeddedSignatures(bytes),
          pngTrailer: pngTrailer ? { offset: pngTrailer.offset, size: pngTrailer.trailing.length } : null,
          jpgTrailer: jpgTrailer ? { offset: jpgTrailer.offset, size: jpgTrailer.trailing.length } : null,
        },
        chunks: types.some(type => type.ext === 'png') ? enumeratePngChunks(bytes) : null,
      });
      setAnalyzing(false);
    } catch {
      notifications.show({
        title: language === 'zh' ? '读取失败' : 'Read failed',
        message: language === 'zh' ? '无法读取该文件的内容，请确认文件仍存在且可访问。' : 'The file could not be read; make sure it still exists and is accessible.',
        color: 'red',
      });
    } finally {
      setBusy(false);
      setAnalyzing(false);
    }
  }, [language]);

  const openPicker = () => inputRef.current?.click();

  // 顶部菜单栏（域联动）：文件与图片类菜单只在杂项取证域展示（工作区仅在本域挂载，天然满足）。
  // 未加载文件时一律先打开选择器；目标卡未渲染（该文件没有对应内容）时给出说明。
  // 注意：推荐工具条渲染在 analysis 非空分支内，因此 scrollToCard 的"无文件开选择器"分支
  // 对推荐条不可达——若把推荐条移出 ff-layout，需先给 soon 工具补显式守卫。
  const scrollToCard = useCallback((cardId: string, missingMessage: { zh: string; en: string }) => {
    if (!analysis) {
      inputRef.current?.click();
      return;
    }
    const node = document.getElementById(cardId);
    if (node) node.scrollIntoView({ behavior: 'smooth', block: 'start' });
    else notifications.show({ message: missingMessage[language] });
  }, [analysis, language]);

  // 推荐工具条（文件探测驱动）：按探测类型映射适用操作，报告头部直达；纯映射在 recommendTools.ts。
  const recommendedTools = useMemo(
    () => (report ? recommendTools(report.types) : []),
    [report],
  );

  const runToolAnchor = (tool: ToolAnchor) => {
    if (tool.handoffFile) {
      if (analysis) onHandOffFile?.(analysis.file);
      else notifications.show({ message: tool.missingMessage[language] });
      return;
    }
    if (tool.targetModuleId) {
      onSwitchModule?.(tool.targetModuleId);
      return;
    }
    if (tool.cardId) scrollToCard(tool.cardId, tool.missingMessage);
  };

  const fileMenus: WorkbenchMenuDef[] = useMemo(() => [{
    id: 'file-tools',
    name: { zh: '文件与图片', en: 'Files & Images' },
    groups: [{
      label: null,
      entries: [
        { key: 'pick', label: language === 'zh' ? '【选择文件】' : '[Choose file]', onSelect: () => inputRef.current?.click() },
        { key: 'summary', label: language === 'zh' ? '【文件概要】' : '[Summary]', onSelect: () => scrollToCard('ff-card-summary', { zh: '请先选择文件。', en: 'Choose a file first.' }) },
        { key: 'suspicious', label: language === 'zh' ? '【可疑内容】' : '[Suspicious]', onSelect: () => scrollToCard('ff-card-suspicious', { zh: '当前文件未发现可疑内容，没有可展示的部分。', en: 'No suspicious content was found in this file.' }) },
        { key: 'bitplanes', label: language === 'zh' ? '【位平面】' : '[Bit planes]', onSelect: () => scrollToCard('ff-card-bitplanes', { zh: '位平面分析仅支持图片文件，请先选择一张图片。', en: 'Bit-plane analysis applies to image files; choose an image first.' }) },
        { key: 'embedded', label: language === 'zh' ? '【嵌入数据】' : '[Embedded data]', onSelect: () => scrollToCard('ff-card-embedded', { zh: '当前文件没有检出嵌入文件或尾附数据。', en: 'No embedded files or trailing data were detected in this file.' }) },
        { key: 'chunks', label: language === 'zh' ? '【PNG chunk】' : '[PNG chunks]', onSelect: () => scrollToCard('ff-card-chunks', { zh: 'chunk 枚举仅支持 PNG 文件。', en: 'Chunk enumeration applies to PNG files only.' }) },
        { key: 'strings', label: language === 'zh' ? '【可读字符串】' : '[Strings]', onSelect: () => scrollToCard('ff-card-strings', { zh: '当前文件没有提取到可读字符串。', en: 'No readable strings were extracted from this file.' }) },
        { key: 'hexdump', label: language === 'zh' ? '【HEX 转储】' : '[Hexdump]', onSelect: () => scrollToCard('ff-card-hexdump', { zh: '当前文件没有 hexdump 预览。', en: 'No hexdump preview for this file.' }) },
      ],
    }],
  }], [language, scrollToCard]);

  useEffect(() => {
    if (!pendingFile || pendingFile.token === lastTokenRef.current) return;
    lastTokenRef.current = pendingFile.token;
    onFileConsumed?.();
    void loadFile(pendingFile.file);
  }, [pendingFile, onFileConsumed, loadFile]);

  const onDrop = (event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    // 阻止冒泡到 CtfToolkit 的页面级 drop，避免同一文件被两处重复读取。
    event.stopPropagation();
    const file = event.dataTransfer.files?.[0];
    if (file) void loadFile(file);
  };

  const extensionMatches = useMemo(() => {
    if (!analysis || !report) return null;
    const extension = analysis.name.includes('.') ? analysis.name.split('.').pop()!.toLowerCase() : '';
    if (!extension) return null;
    if (report.types.length === 0) return null;
    const detected = new Set(report.types.map(type => type.ext));
    if (detected.has(extension)) return true;
    if (detected.has('zip') && ['docx', 'xlsx', 'pptx', 'epub', 'apk', 'jar'].includes(extension)) return true;
    if (detected.has('jpg') && ['jpeg', 'jfif'].includes(extension)) return true;
    if (detected.has('exe') && ['dll', 'sys'].includes(extension)) return true;
    if (detected.has('pcapbe') && extension === 'pcap') return true;
    return false;
  }, [analysis, report]);

  const imagePreviewUrl = useMemo(() => {
    if (!analysis || !report || report.types.length === 0) return null;
    const mime = IMAGE_MIME_MAP[report.types[0].ext];
    if (!mime || analysis.size > 5 * 1024 * 1024) return null;
    return `data:${mime};base64,${btoa(toBinaryString(analysis.bytes))}`;
  }, [analysis, report]);

  // 位平面/色道卡的图片解码：createImageBitmap 统一解成 RGBA（>4MP 降采样，内存红线 16MB）。
  // 状态重置在 loadFile 换文件时完成；这里非图片文件直接不启动解码。
  // 失败（浏览器不支持该格式）时卡片给出说明，不阻塞其它卡。
  useEffect(() => {
    if (!analysis || !report || report.types.length === 0) return;
    const mime = IMAGE_MIME_MAP[report.types[0].ext];
    if (!mime) return;
    let cancelled = false;
    const decode = async () => {
      try {
        setPlaneStatus('loading');
        const blob = new Blob([analysis.bytes.slice()], { type: mime });
        let bitmap = await createImageBitmap(blob);
        const originalWidth = bitmap.width;
        const originalHeight = bitmap.height;
        let width = originalWidth;
        let height = originalHeight;
        let downsampled = false;
        if (originalWidth * originalHeight > MAX_ANALYSIS_PIXELS) {
          const scale = Math.sqrt(MAX_ANALYSIS_PIXELS / (originalWidth * originalHeight));
          width = Math.max(1, Math.floor(originalWidth * scale));
          height = Math.max(1, Math.floor(originalHeight * scale));
          bitmap.close();
          bitmap = await createImageBitmap(blob, { resizeWidth: width, resizeHeight: height, resizeQuality: 'medium' });
          downsampled = true;
        }
        const canvas = document.createElement('canvas');
        canvas.width = bitmap.width;
        canvas.height = bitmap.height;
        const ctx = canvas.getContext('2d');
        if (!ctx) throw new Error('no 2d context');
        ctx.drawImage(bitmap, 0, 0);
        // ImageBitmap.close() 后宽高按规范归零，必须先取出再关。
        const decodedWidth = bitmap.width;
        const decodedHeight = bitmap.height;
        const imageData = ctx.getImageData(0, 0, decodedWidth, decodedHeight);
        bitmap.close();
        if (cancelled) return;
        setPlaneImage({ rgba: imageData.data, width: decodedWidth, height: decodedHeight, downsampled, originalWidth, originalHeight });
        setPlaneStatus('ready');
      } catch {
        if (!cancelled) {
          setPlaneImage(null);
          setPlaneStatus('failed');
        }
      }
    };
    void decode();
    return () => {
      cancelled = true;
    };
  }, [analysis, report]);

  // strings 提取在 StringsCard 内完成；hexdump 渲染在 HexdumpCard 内完成。

  const runPngFix = async () => {
    if (!analysis) return;
    setPngFix({ status: 'running' });
    const result = await fixPngDimensions(analysis.bytes);
    if (result) setPngFix({ status: 'done', width: result.width, height: result.height, bytes: result.bytes });
    else setPngFix({ status: 'failed' });
  };

  const runZipFix = () => {
    if (!analysis) return;
    const result = fixZipPseudoEncryption(analysis.bytes);
    if (result) setZipFix({ cleared: result.cleared, bytes: result.bytes });
  };

  return (
    <div className="file-forensics" onDragOver={event => event.preventDefault()} onDrop={onDrop}>
      <input
        ref={inputRef}
        type="file"
        aria-hidden="true"
        tabIndex={-1}
        style={{ display: 'none' }}
          onChange={event => {
            const file = event.target.files?.[0];
            if (file) void loadFile(file);
            event.target.value = '';
          }}
        />

        <WorkbenchMenuBar
          menus={fileMenus}
          ariaLabel={language === 'zh' ? '文件与图片菜单' : 'Files and images menu'}
        />

      {!analysis ? (
        <div className="ff-dropzone">
          <div className="ff-dropzone-icon" aria-hidden="true">🧩</div>
          <strong>{language === 'zh' ? '把文件拖到这里，或点击选择' : 'Drop a file here, or click to browse'}</strong>
          <small>
            {language === 'zh'
              ? '自动识别文件类型、信息熵、可读字符串与可疑内容；文件仅在本浏览器内分析，不会上传。上限 20MB。'
              : 'Automatic type detection, entropy, strings, and suspicious-content scanning. Files never leave your browser. 20MB limit.'}
          </small>
          <button type="button" className="ff-button ff-button-primary" onClick={openPicker}>
            {language === 'zh' ? '选择文件' : 'Choose file'}
          </button>
        </div>
      ) : (
        <div className="ff-layout">
          {recommendedTools.length > 0 && (
            <nav className="ff-recommend" aria-label={language === 'zh' ? '推荐工具' : 'Recommended tools'}>
              <span className="ff-recommend-label">{language === 'zh' ? '推荐工具' : 'Recommended'}</span>
              <div className="ff-recommend-tools">
                {recommendedTools.map(tool => (
                  <button
                    key={tool.id}
                    type="button"
                    className={tool.soon ? 'ff-button ff-recommend-soon' : 'ff-button ff-recommend-hit'}
                    onClick={() => runToolAnchor(tool)}
                    title={tool.soon
                      ? (language === 'zh' ? '该工具在后续版本提供' : 'This tool is coming in a later release')
                      : tool.label[language]}
                  >
                    {tool.label[language]}
                    {tool.soon && <span className="ff-recommend-soon-tag">{language === 'zh' ? '即将上线' : 'soon'}</span>}
                  </button>
                ))}
              </div>
            </nav>
          )}

          <section id="ff-card-summary" className="ff-card" aria-label={language === 'zh' ? '文件概要' : 'File summary'}>
            <div className="ff-card-head">
              <strong>{language === 'zh' ? '文件概要' : 'Summary'}</strong>
              <button type="button" className="ff-button" onClick={openPicker}>{language === 'zh' ? '换一个文件' : 'Replace'}</button>
            </div>
            <div className="ff-summary">
              <span className="ff-name" title={analysis.name}>{analysis.name}</span>
              <span className="ff-size">{formatBytes(analysis.size)}</span>
            </div>
            {report && (
              <>
                <div className="ff-row">
                  <span className="ff-label">{language === 'zh' ? '探测类型' : 'Detected type'}</span>
                  {report.types.length
                    ? report.types.map(type => (
                      <span key={type.ext} className="ff-badge" title={type.name}>{type.name}</span>
                    ))
                    : <span className="ff-badge ff-badge-warn">{language === 'zh' ? '未知类型（无已知魔数）' : 'Unknown (no magic match)'}</span>}
                </div>
                {extensionMatches !== null && (
                  <div className="ff-row">
                    <span className="ff-label">{language === 'zh' ? '扩展名比对' : 'Extension check'}</span>
                    {extensionMatches
                      ? <span className="ff-badge ff-badge-ok">{language === 'zh' ? '与扩展名一致' : 'Matches extension'}</span>
                      : <span className="ff-badge ff-badge-warn">{language === 'zh' ? '与扩展名不符——可能被改名，以探测结果为准' : 'Mismatches extension — likely renamed; trust the detected type'}</span>}
                  </div>
                )}
                <div className="ff-row">
                  <span className="ff-label">{language === 'zh' ? '信息熵' : 'Entropy'}</span>
                  <span className="ff-mono">{report.entropy.toFixed(3)} / 8</span>
                </div>
                <p className="ff-note">{entropyVerdictText(report.level, language)}</p>
              </>
            )}
          </section>

          {report && report.suspicious.flags.length > 0 && (
            <section id="ff-card-flag" className="ff-card ff-card-flag" aria-label={language === 'zh' ? 'flag 命中' : 'Flag hits'}>
              <div className="ff-card-head">
                <strong>{language === 'zh' ? '🚩 发现 flag' : '🚩 Flag found'}</strong>
              </div>
              <div className="ff-row">
                {report.suspicious.flags.map(hit => (
                  <span key={hit.prefix} className="ff-badge ff-badge-flag" title={hit.sample}>{hit.sample}</span>
                ))}
              </div>
            </section>
          )}

          {report && (report.png || report.zip) && (
            <section id="ff-card-repair" className="ff-card" aria-label={language === 'zh' ? '文件修复工具' : 'Repair tools'}>
              <div className="ff-card-head">
                <strong>{language === 'zh' ? '修复工具' : 'Repair tools'}</strong>
              </div>
              {report.png && (
                <div className="ff-tool">
                  <div className="ff-row">
                    <span className="ff-label">PNG IHDR</span>
                    <span className="ff-mono">
                      {report.png.width}×{report.png.height} · {language === 'zh' ? `色深 ${report.png.bitDepth}` : `depth ${report.png.bitDepth}`}
                    </span>
                    {report.png.crcOk
                      ? <span className="ff-badge ff-badge-ok">CRC {language === 'zh' ? '校验通过' : 'OK'}</span>
                      : <span className="ff-badge ff-badge-warn">CRC {language === 'zh' ? '校验失败——宽高可能被篡改' : 'mismatch — dimensions likely tampered'}</span>}
                  </div>
                  {!report.png.crcOk && (
                    <div className="ff-row">
                      {pngFix.status === 'idle' && <button type="button" className="ff-button ff-button-primary" onClick={() => { void runPngFix(); }}>{language === 'zh' ? '尝试修复宽高（CRC 爆破）' : 'Fix dimensions (CRC bruteforce)'}</button>}
                      {pngFix.status === 'running' && <span className="ff-note">{language === 'zh' ? '正在枚举宽高组合，稍候…' : 'Enumerating dimensions…'}</span>}
                      {pngFix.status === 'done' && pngFix.bytes && (
                        <>
                          <span className="ff-badge ff-badge-ok">{language === 'zh' ? `还原为 ${pngFix.width}×${pngFix.height}` : `Recovered ${pngFix.width}×${pngFix.height}`}</span>
                          <button type="button" className="ff-button" onClick={() => downloadBytes(pngFix.bytes!, `${analysis.name.replace(/\.png$/i, '')}-fixed.png`)}>
                            {language === 'zh' ? '下载修复后文件' : 'Download fixed file'}
                          </button>
                        </>
                      )}
                      {pngFix.status === 'failed' && <span className="ff-note">{language === 'zh' ? '未能找到匹配的宽高组合：损坏可能不止宽高，或超出枚举范围。' : 'No matching dimensions found: damage may go beyond width/height or exceed the search range.'}</span>}
                    </div>
                  )}
                </div>
              )}
              {report.zip && (
                <div className="ff-tool">
                  <div className="ff-row">
                    <span className="ff-label">ZIP {language === 'zh' ? '加密标志' : 'encryption flags'}</span>
                    {report.zip.state === 'plain' && <span className="ff-badge ff-badge-ok">{language === 'zh' ? '未加密' : 'Not encrypted'}</span>}
                    {report.zip.state === 'pseudo' && <span className="ff-badge ff-badge-warn">{language === 'zh' ? '疑似伪加密（两处标志不一致）' : 'Pseudo-encrypted (flags disagree)'}</span>}
                    {report.zip.state === 'encrypted' && <span className="ff-badge ff-badge-warn">{language === 'zh' ? '标志位全 1：真加密或全量伪加密，需结合打开结果判断' : 'All flags set: real encryption or full pseudo-encryption'}</span>}
                    {report.zip.state === 'none' && <span className="ff-note">{language === 'zh' ? '未找到 ZIP 目录结构。' : 'No ZIP directory structure found.'}</span>}
                  </div>
                  {report.zip.state === 'pseudo' && !zipFix && (
                    <button type="button" className="ff-button ff-button-primary" onClick={runZipFix}>
                      {language === 'zh' ? '清除伪加密标志' : 'Clear pseudo-encryption flags'}
                    </button>
                  )}
                  {zipFix && (
                    <div className="ff-row">
                      <span className="ff-badge ff-badge-ok">{language === 'zh' ? `已清除 ${zipFix.cleared} 处标志位` : `Cleared ${zipFix.cleared} flag(s)`}</span>
                      <button type="button" className="ff-button" onClick={() => downloadBytes(zipFix.bytes, `${analysis.name.replace(/\.zip$/i, '')}-fixed.zip`)}>
                        {language === 'zh' ? '下载修复后文件' : 'Download fixed file'}
                      </button>
                    </div>
                  )}
                </div>
              )}
            </section>
          )}

          {report && (report.suspicious.flags.length > 0 || report.suspicious.base64Candidates.length > 0 || report.suspicious.keywordHits.length > 0 || report.zeroWidth.zeroWidthCount > 0) && (
            <section id="ff-card-suspicious" className="ff-card" aria-label={language === 'zh' ? '可疑内容' : 'Suspicious content'}>
              <div className="ff-card-head">
                <strong>{language === 'zh' ? '可疑内容' : 'Suspicious content'}</strong>
              </div>
              {report.suspicious.base64Candidates.length > 0 && (
                <div className="ff-tool">
                  <span className="ff-label">{language === 'zh' ? '疑似 Base64 片段（点击复制，可用「密码与编码」域解码）' : 'Base64-like fragments (click to copy; decode in Ciphers & Encoding)'}</span>
                  {report.suspicious.base64Candidates.map(candidate => (
                    <button
                      key={candidate}
                      type="button"
                      className="ff-code ff-code-click"
                      title={language === 'zh' ? '点击复制' : 'Click to copy'}
                      onClick={() => { void navigator.clipboard.writeText(candidate); }}
                    >
                      {candidate.length > 96 ? `${candidate.slice(0, 96)}…` : candidate}
                    </button>
                  ))}
                </div>
              )}
              {report.suspicious.keywordHits.length > 0 && (
                <div className="ff-row">
                  <span className="ff-label">{language === 'zh' ? '关键词命中' : 'Keyword hits'}</span>
                  {report.suspicious.keywordHits.map(keyword => <span key={keyword} className="ff-badge">{keyword}</span>)}
                </div>
              )}
              {report.zeroWidth.zeroWidthCount > 0 && (
                <div className="ff-tool">
                  <span className="ff-label">{language === 'zh' ? `发现 ${report.zeroWidth.zeroWidthCount} 个零宽字符` : `${report.zeroWidth.zeroWidthCount} zero-width characters found`}</span>
                  {report.zeroWidth.payload
                    ? <code className="ff-code"><FlagAutoText text={report.zeroWidth.payload} /></code>
                    : <span className="ff-note">{language === 'zh' ? '零宽字符未凑满完整字节序列，无法按零宽编码解码；可能只是不可见水印或分隔符。' : 'Zero-width characters do not form complete bytes; they may be watermarks or separators.'}</span>}
                </div>
              )}
            </section>
          )}

          {imagePreviewUrl && (
            <section id="ff-card-preview" className="ff-card" aria-label={language === 'zh' ? '图片预览' : 'Image preview'}>
              <div className="ff-card-head">
                <strong>{language === 'zh' ? '图片预览' : 'Image preview'}</strong>
                <button
                  type="button"
                  className="ff-button"
                  onClick={() => { void navigator.clipboard.writeText(imagePreviewUrl); }}
                >
                  {language === 'zh' ? '复制 data URL' : 'Copy data URL'}
                </button>
              </div>
              <img className="ff-preview" src={imagePreviewUrl} alt={analysis.name} />
            </section>
          )}

          {planeStatus !== 'idle' && (
            <ImagePlanesCard
              key={`planes-${analysis.name}:${analysis.size}`}
              fileName={analysis.name}
              image={planeImage}
              status={planeStatus}
              language={language}
            />
          )}

          {report && (
            <EmbeddedCard
              key={`embedded-${analysis.name}:${analysis.size}`}
              fileName={analysis.name}
              bytes={analysis.bytes}
              embedded={report.embedded}
              chunks={report.chunks}
              language={language}
            />
          )}

          {report && report.strings.total > 0 && (
            <StringsCard
              key={`strings-${analysis.name}:${analysis.size}`}
              fileName={analysis.name}
              bytes={analysis.bytes}
              language={language}
            />
          )}

          {report && report.hexdump && (
            <HexdumpCard
              key={`hexdump-${analysis.name}:${analysis.size}`}
              bytes={analysis.bytes}
              size={analysis.size}
              language={language}
            />
          )}
        </div>
      )}

      {(busy || analyzing) && <div className="ff-busy" role="status">{language === 'zh' ? (analyzing ? '正在分析文件…' : '正在读取文件…') : (analyzing ? 'Analyzing file…' : 'Reading file…')}</div>}

<style>{ffStyles}</style>
    </div>
  );
}

export default FileForensicsWorkspace;
