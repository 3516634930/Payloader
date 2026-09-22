import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { notifications } from '@mantine/notifications';
import { useAppContext } from '../../appContext';
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

interface FileAnalysis {
  name: string;
  size: number;
  bytes: Uint8Array;
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
}

export interface FileForensicsWorkspaceProps {
  // 框架层（CtfToolkit）传入的待分析文件；token 变化表示有新文件到达。
  pendingFile?: { file: File; token: number } | null;
  // 通知框架文件已被取走，框架清空 pendingFile 防止残留重放。
  onFileConsumed?: () => void;
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

const toBinaryString = (bytes: Uint8Array): string => {
  let binary = '';
  const chunkSize = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
  }
  return binary;
};

const downloadBytes = (bytes: Uint8Array, filename: string) => {
  const url = URL.createObjectURL(new Blob([bytes.slice()], { type: 'application/octet-stream' }));
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 4000);
};

// 杂项取证域工作区（批次 K）：文件拖入/选择 → 本地探测 → 按需分析。
// 文件只读字节、不执行、不上传；超过 20MB 直接拒绝并说明原因。
function FileForensicsWorkspace({ pendingFile, onFileConsumed }: FileForensicsWorkspaceProps) {
  const { language } = useAppContext();
  const [analysis, setAnalysis] = useState<FileAnalysis | null>(null);
  const [report, setReport] = useState<FileReport | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [pngFix, setPngFix] = useState<PngFixState>({ status: 'idle' });
  const [zipFix, setZipFix] = useState<ZipFixState | null>(null);
  const [busy, setBusy] = useState(false);
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
      setAnalysis({ name: file.name, size: file.size, bytes });
      setPngFix({ status: 'idle' });
      setZipFix(null);
      setBusy(false);
      // 让文件概要先渲染一帧，再做同步分析（接近 20MB 的文件约 0.5-2s）；
      // 判读文案等语言相关内容在渲染层现算，切换语言不会触发重分析。
      setAnalyzing(true);
      await new Promise(resolve => setTimeout(resolve, 0));
      const types = detectFileTypes(bytes);
      const entropy = shannonEntropy(bytes);
      const latin1 = new TextDecoder('latin1').decode(bytes);
      const utf8Text = new TextDecoder('utf-8', { fatal: false }).decode(bytes.subarray(0, 512 * 1024));
      setReport({
        types,
        entropy,
        level: entropyLevel(entropy, bytes.length),
        strings: extractStrings(bytes, { limit: 200 }),
        suspicious: scanSuspiciousContent(latin1),
        hexdump: hexdumpPreview(bytes, { length: 512 }),
        png: parsePngIhdr(bytes),
        zip: types.some(type => type.ext === 'zip' || type.ext === 'jar' || type.ext === 'apk') || (bytes.length > 4 && bytes[0] === 0x50 && bytes[1] === 0x4b) ? detectZipEncryption(bytes) : null,
        zeroWidth: extractZeroWidthFromText(utf8Text),
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
    const ext = report.types[0].ext;
    const mimeMap: Record<string, string> = { png: 'image/png', jpg: 'image/jpeg', gif: 'image/gif', bmp: 'image/bmp', webp: 'image/webp', ico: 'image/x-icon' };
    const mime = mimeMap[ext];
    if (!mime || analysis.size > 5 * 1024 * 1024) return null;
    return `data:${mime};base64,${btoa(toBinaryString(analysis.bytes))}`;
  }, [analysis, report]);

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
          <section className="ff-card" aria-label={language === 'zh' ? '文件概要' : 'File summary'}>
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
            <section className="ff-card ff-card-flag" aria-label={language === 'zh' ? 'flag 命中' : 'Flag hits'}>
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
            <section className="ff-card" aria-label={language === 'zh' ? '文件修复工具' : 'Repair tools'}>
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
            <section className="ff-card" aria-label={language === 'zh' ? '可疑内容' : 'Suspicious content'}>
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
                    ? <code className="ff-code">{report.zeroWidth.payload}</code>
                    : <span className="ff-note">{language === 'zh' ? '零宽字符未凑满完整字节序列，无法按零宽编码解码；可能只是不可见水印或分隔符。' : 'Zero-width characters do not form complete bytes; they may be watermarks or separators.'}</span>}
                </div>
              )}
            </section>
          )}

          {imagePreviewUrl && (
            <section className="ff-card" aria-label={language === 'zh' ? '图片预览' : 'Image preview'}>
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

          {report && report.strings.total > 0 && (
            <section className="ff-card" aria-label={language === 'zh' ? '可读字符串' : 'Strings'}>
              <div className="ff-card-head">
                <strong>{language === 'zh' ? `可读字符串（${report.strings.total} 条）` : `Strings (${report.strings.total})`}</strong>
              </div>
              <div className="ff-strings">
                {report.strings.values.map((value, index) => (
                  <code key={`${index}-${value}`} className="ff-code">{value.length > 160 ? `${value.slice(0, 160)}…` : value}</code>
                ))}
                {report.strings.total > report.strings.values.length && (
                  <span className="ff-note">{language === 'zh' ? `仅显示前 ${report.strings.values.length} 条。` : `Showing first ${report.strings.values.length}.`}</span>
                )}
              </div>
            </section>
          )}

          {report && report.hexdump && (
            <section className="ff-card" aria-label={language === 'zh' ? 'hexdump 预览' : 'Hexdump'}>
              <div className="ff-card-head">
                <strong>{language === 'zh' ? 'hexdump 预览（前 512 字节）' : 'Hexdump (first 512 bytes)'}</strong>
              </div>
              <pre className="ff-code ff-code-dump">{report.hexdump}</pre>
            </section>
          )}
        </div>
      )}

      {(busy || analyzing) && <div className="ff-busy" role="status">{language === 'zh' ? (analyzing ? '正在分析文件…' : '正在读取文件…') : (analyzing ? 'Analyzing file…' : 'Reading file…')}</div>}

      <style>{`
        .file-forensics {
          min-width: 0;
          display: grid;
          gap: 14px;
        }

        .ff-dropzone {
          display: grid;
          justify-items: center;
          gap: 10px;
          padding: 46px 20px;
          border: 1px dashed var(--border-color);
          border-radius: 8px;
          background: var(--bg-card);
          text-align: center;
        }

        .ff-dropzone-icon {
          font-size: 34px;
        }

        .ff-dropzone strong {
          color: var(--text-primary);
          font-size: 15px;
        }

        .ff-dropzone small {
          max-width: 460px;
          color: var(--text-muted);
          font-size: 12px;
          line-height: 1.6;
        }

        .ff-layout {
          display: grid;
          gap: 14px;
        }

        .ff-card {
          border: 1px solid var(--border-color);
          border-radius: 8px;
          background: var(--bg-card);
          padding: 13px;
          display: grid;
          gap: 9px;
          min-width: 0;
        }

        .ff-card-flag {
          border-color: var(--neon-cyan);
        }

        .ff-card-head {
          display: flex;
          flex-wrap: wrap;
          align-items: center;
          gap: 8px;
        }

        .ff-card-head strong {
          color: var(--neon-cyan);
          font-size: 13px;
          font-weight: 800;
        }

        .ff-card-head .ff-button {
          margin-left: auto;
        }

        .ff-summary {
          display: flex;
          flex-wrap: wrap;
          align-items: baseline;
          gap: 10px;
          min-width: 0;
        }

        .ff-name {
          color: var(--text-primary);
          font-weight: 700;
          word-break: break-all;
        }

        .ff-size {
          color: var(--text-muted);
          font-size: 12px;
        }

        .ff-row {
          display: flex;
          flex-wrap: wrap;
          align-items: center;
          gap: 7px;
          min-width: 0;
        }

        .ff-label {
          color: var(--text-muted);
          font-size: 12px;
          flex-shrink: 0;
        }

        .ff-badge {
          display: inline-flex;
          align-items: center;
          padding: 2px 8px;
          border: 1px solid var(--border-color);
          border-radius: 999px;
          background: rgba(255, 255, 255, 0.035);
          color: var(--text-secondary);
          font-size: 11px;
          font-weight: 700;
          word-break: break-all;
        }

        .ff-badge-ok {
          border-color: rgba(60, 220, 150, 0.55);
          color: rgb(80, 235, 170);
        }

        .ff-badge-warn {
          border-color: rgba(255, 190, 70, 0.55);
          color: rgb(255, 205, 100);
        }

        .ff-badge-flag {
          border-color: var(--neon-cyan);
          color: var(--neon-cyan);
          font-size: 12px;
        }

        .ff-note {
          margin: 0;
          color: var(--text-muted);
          font-size: 12px;
          line-height: 1.6;
        }

        .ff-mono {
          color: var(--text-secondary);
          font-family: var(--font-mono, monospace);
          font-size: 12px;
        }

        .ff-button {
          min-height: 30px;
          padding: 5px 11px;
          border: 1px solid var(--border-color);
          border-radius: 6px;
          background: rgba(255, 255, 255, 0.035);
          color: var(--text-secondary);
          font-size: 12px;
          font-weight: 700;
          cursor: pointer;
          transition: border-color var(--transition-fast), color var(--transition-fast);
        }

        .ff-button:hover {
          border-color: var(--neon-cyan);
          color: var(--neon-cyan);
        }

        .ff-button-primary {
          border-color: rgba(0, 240, 255, 0.45);
          color: var(--neon-cyan);
        }

        .ff-strings {
          display: grid;
          gap: 5px;
          max-height: 320px;
          overflow-y: auto;
        }

        .ff-code {
          display: block;
          padding: 6px 9px;
          border: 1px solid var(--border-color);
          border-radius: 6px;
          background: var(--bg-secondary);
          color: var(--text-secondary);
          font-family: var(--font-mono, monospace);
          font-size: 11px;
          word-break: break-all;
          white-space: pre-wrap;
        }

        .ff-code-click {
          cursor: pointer;
          text-align: left;
        }

        .ff-code-click:hover {
          border-color: var(--neon-cyan);
          color: var(--neon-cyan);
        }

        .ff-code-dump {
          max-height: 320px;
          overflow: auto;
        }

        .ff-preview {
          max-width: 100%;
          max-height: 320px;
          border: 1px solid var(--border-color);
          border-radius: 6px;
          object-fit: contain;
        }

        .ff-busy {
          color: var(--text-muted);
          font-size: 12px;
        }

        @media (max-width: 680px) {
          .ff-dropzone {
            padding: 30px 14px;
          }
        }
      `}</style>
    </div>
  );
}

export default FileForensicsWorkspace;
