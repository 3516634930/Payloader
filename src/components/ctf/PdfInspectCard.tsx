import { useMemo, useState } from 'react';
import { notifications } from '@mantine/notifications';
import { FlagAutoText } from '../codec/FlagAutoText';
import { inspectPdf } from '../../utils/ctf/pdfInspect';
import type { PdfInspectResult, PdfStreamInfo } from '../../utils/ctf/pdfInspect';
import { downloadBytes } from './ffDownload';

// PDF 取证卡：概览/风险指标（PDFiD 式）/注释/可疑文本/FlateDecode 流解压（组件层异步）/异常线索。
// 解析在 useMemo 同步完成（引擎限 20MB）；解压走 DecompressionStream 异步按需做；换文件父层 key remount。
interface PdfInspectCardProps {
  fileName: string;
  bytes: Uint8Array;
  language: 'zh' | 'en';
}

const PREVIEW_LIMIT = 2048;

const inflateStream = async (raw: Uint8Array): Promise<Uint8Array | null> => {
  if (typeof DecompressionStream === 'undefined') return null;
  try {
    const readable = new Blob([raw as BlobPart]).stream().pipeThrough(new DecompressionStream('deflate'));
    const buffer = await new Response(readable).arrayBuffer();
    return new Uint8Array(buffer);
  } catch {
    return null;
  }
};

const previewOf = (bytes: Uint8Array): string => {
  let text = '';
  const limit = Math.min(bytes.length, PREVIEW_LIMIT);
  for (let index = 0; index < limit; index += 1) {
    const code = bytes[index];
    text += (code === 0x0a || code === 0x0d || (code >= 0x20 && code <= 0x7e)) ? String.fromCharCode(code) : '·';
  }
  return text;
};

function PdfInspectCard({ fileName, bytes, language }: PdfInspectCardProps) {
  const zh = language === 'zh';
  const baseName = fileName.replace(/\.[^.]+$/, '');
  const result = useMemo<{ inspected?: PdfInspectResult; error?: string }>(() => {
    try {
      return { inspected: inspectPdf(bytes) };
    } catch (error) {
      return { error: (error as Error).message };
    }
  }, [bytes]);
  const [streamDecoded, setStreamDecoded] = useState<Record<number, string>>({});

  if (result.error) {
    return (
      <section id="ff-card-pdf" className="ff-card" aria-label={zh ? 'PDF 取证' : 'PDF forensics'}>
        <div className="ff-card-head"><strong>{zh ? 'PDF 取证' : 'PDF forensics'}</strong></div>
        <p className="ff-note">{result.error}</p>
      </section>
    );
  }

  const inspected = result.inspected!;
  const flateStreams = inspected.streams.filter(stream => stream.filter?.includes('FlateDecode'));

  const decodeStream = async (stream: PdfStreamInfo) => {
    const raw = bytes.subarray(stream.offset, Math.min(bytes.length, stream.offset + stream.length));
    const inflated = await inflateStream(raw);
    if (!inflated || !inflated.length) {
      notifications.show({
        message: zh
          ? `对象 ${stream.objectNumber} 解压失败：流损坏或非 zlib 格式，可下载原始字节离线分析。`
          : `Object ${stream.objectNumber} failed to inflate; download the raw bytes for offline analysis.`,
        color: 'red',
      });
      return;
    }
    setStreamDecoded(previous => ({ ...previous, [stream.objectNumber]: previewOf(inflated) }));
  };

  const metadataEntries = Object.entries(inspected.metadata);

  return (
    <section id="ff-card-pdf" className="ff-card" aria-label={zh ? 'PDF 取证' : 'PDF forensics'}>
      <div className="ff-card-head">
        <strong>{zh ? 'PDF 取证' : 'PDF forensics'}</strong>
        <span className="ff-badge">
          {inspected.version ?? 'PDF?'} · {zh ? `${inspected.objectCount} 对象` : `${inspected.objectCount} objects`}
          {inspected.streams.length ? ` · ${inspected.streams.length} stream` : ''}
        </span>
      </div>
      {metadataEntries.length > 0 && (
        <div className="ff-tool">
          <span className="ff-label">{zh ? '元数据' : 'Metadata'}</span>
          {metadataEntries.map(([key, value]) => (
            <div key={key} className="ff-row">
              <span className="ff-badge">{key}</span>
              <span className="ff-note" style={{ flex: 1 }}>{value.slice(0, 200)}</span>
            </div>
          ))}
        </div>
      )}
      <div className="ff-tool">
        <span className="ff-label">{zh ? '风险指标（PDFiD 式，对象外壳计数）' : 'Risk indicators (PDFiD-style)'}</span>
        <div className="ff-row">
          {inspected.indicators.filter(item => item.count > 0).map(item => (
            <span key={item.key} className="ff-badge ff-badge-warn" title={item.label}>{item.label} × {item.count}</span>
          ))}
          {inspected.indicators.every(item => item.count === 0) && (
            <span className="ff-badge ff-badge-ok">{zh ? '无风险指标' : 'No risky indicators'}</span>
          )}
        </div>
      </div>
      {inspected.comments.length > 0 && (
        <div className="ff-tool">
          <span className="ff-label">{zh ? '注释行（藏 flag 常见位置）' : 'Comment lines'}</span>
          {inspected.comments.map((comment, index) => (
            <code key={`comment-${index}`} className="ff-code"><FlagAutoText text={comment} /></code>
          ))}
        </div>
      )}
      {inspected.suspiciousTexts.length > 0 && (
        <div className="ff-tool">
          <span className="ff-label">{zh ? `可疑文本（${inspected.suspiciousTexts.length} 条，flag 命中在前）` : `Suspicious texts`}</span>
          {inspected.suspiciousTexts.slice(0, 12).map((text, index) => (
            <code key={`suspicious-${index}`} className="ff-code"><FlagAutoText text={text.slice(0, 400)} /></code>
          ))}
        </div>
      )}
      {flateStreams.length > 0 && (
        <div className="ff-tool">
          <span className="ff-label">{zh ? `FlateDecode 流（${flateStreams.length} 个，解压看内容）` : `FlateDecode streams (${flateStreams.length})`}</span>
          {flateStreams.map(stream => (
            <div key={`stream-${stream.objectNumber}`} className="ff-row">
              <span className="ff-badge">obj {stream.objectNumber} · {stream.length}B</span>
              <button type="button" className="ff-button" onClick={() => { void decodeStream(stream); }}>
                {zh ? '解压预览' : 'Inflate'}
              </button>
              <button
                type="button"
                className="ff-button"
                onClick={() => downloadBytes(bytes.subarray(stream.offset, Math.min(bytes.length, stream.offset + stream.length)), `${baseName}-obj${stream.objectNumber}.zlib`)}
              >
                {zh ? '下载原始流' : 'Download raw'}
              </button>
              {streamDecoded[stream.objectNumber] !== undefined && (
                <code className="ff-code" style={{ flexBasis: '100%' }}><FlagAutoText text={streamDecoded[stream.objectNumber]} /></code>
              )}
            </div>
          ))}
        </div>
      )}
      {inspected.anomalies.length > 0 && (
        <div className="ff-tool">
          <span className="ff-label">{zh ? '结构线索' : 'Structural clues'}</span>
          {inspected.anomalies.map((anomaly, index) => (
            <p key={index} className="ff-note">• {anomaly}</p>
          ))}
        </div>
      )}
    </section>
  );
}

export default PdfInspectCard;
