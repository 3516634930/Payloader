import { useEffect, useMemo, useState } from 'react';
import { FlagAutoText } from '../codec/FlagAutoText';
import { hexdumpPreview } from '../../utils/ctf/fileDetect';
import type { EmbeddedHit, PngChunkList } from '../../utils/ctf/embedScan';
import { downloadBytes } from './ffDownload';

export interface EmbeddedReport {
  hits: EmbeddedHit[];
  pngTrailer: { offset: number; size: number } | null;
  jpgTrailer: { offset: number; size: number } | null;
}

interface EmbeddedCardProps {
  fileName: string;
  bytes: Uint8Array;
  embedded: EmbeddedReport;
  chunks: PngChunkList | null;
  language: 'zh' | 'en';
}

const TRAILER_PREVIEW_BYTES = 512;
// 解压文本展示上限：zTXt/iTXt 理论可存大文件，界面上只看前 4KB。
const INFLATED_PREVIEW_CHARS = 4096;
// 与 embedScan.enumeratePngChunks 默认 maxChunks 一致；用于截断提示文案。
const MAX_CHUNKS = 256;
// 解压输入上限：超过则不尝试解压（解压炸弹自伤防护——大压缩流在主线程解压会卡 UI）。
const INFLATE_INPUT_LIMIT = 10 * 1024 * 1024;

// zlib inflate（浏览器 DecompressionStream；zTXt/iTXt 的压缩数据是 zlib 流）。
const inflateDeflate = async (data: Uint8Array): Promise<Uint8Array> => {
  const Ctor = globalThis.DecompressionStream;
  if (!Ctor) throw new Error('DecompressionStream unavailable');
  const stream = new Blob([data.slice()]).stream().pipeThrough(new Ctor('deflate'));
  return new Uint8Array(await new Response(stream).arrayBuffer());
};

const formatOffset = (offset: number): string => `0x${offset.toString(16).toUpperCase()}`;

interface ChunkTextState {
  text?: string;
  failed?: boolean;
}

// 嵌入数据卡片：嵌入文件命中（binwalk 式）+ PNG IEND / JPEG EOI 尾附 + PNG chunk 枚举。
// 全部数据来自父组件的同步扫描结果；这里只做展示与提取下载。
function EmbeddedCard({ fileName, bytes, embedded, chunks, language }: EmbeddedCardProps) {
  const zh = language === 'zh';
  const baseName = fileName.replace(/\.[^.]+$/, '');
  const [chunkTexts, setChunkTexts] = useState<Record<number, ChunkTextState>>({});

  // 压缩文本 chunk（zTXt / 压缩 iTXt）异步解压；数量少（通常 <10），全部并发解。
  const compressedChunkIndexes = useMemo(() => {
    if (!chunks) return [];
    return chunks.chunks
      .map((chunk, index) => ({ chunk, index }))
      .filter(({ chunk }) => chunk.text?.compressed && chunk.text.compressedBytes?.length);
  }, [chunks]);

  useEffect(() => {
    let cancelled = false;
    for (const { chunk, index } of compressedChunkIndexes) {
      const payload = chunk.text?.compressedBytes;
      if (!payload) continue;
      // 超限输入直接走失败路径（解压炸弹自伤防护）；统一经异步回调落状态，避免 effect 内同步 setState。
      const job = payload.length > INFLATE_INPUT_LIMIT
        ? Promise.reject(new Error('compressed payload too large'))
        : inflateDeflate(payload);
      job
        .then(inflated => {
          if (cancelled) return;
          const text = new TextDecoder('latin1').decode(inflated.subarray(0, INFLATED_PREVIEW_CHARS));
          setChunkTexts(previous => ({ ...previous, [index]: { text } }));
        })
        .catch(() => {
          if (cancelled) return;
          setChunkTexts(previous => ({ ...previous, [index]: { failed: true } }));
        });
    }
    return () => {
      cancelled = true;
    };
  }, [compressedChunkIndexes]);

  const hasTrailer = embedded.pngTrailer !== null || embedded.jpgTrailer !== null;
  const chunkList = chunks?.chunks ?? [];
  const chunksTruncated = chunks?.truncated ?? false;
  if (embedded.hits.length === 0 && !hasTrailer && chunkList.length === 0) return null;

  const trailer = embedded.pngTrailer ?? embedded.jpgTrailer;
  const trailerLabel = embedded.pngTrailer ? (zh ? 'PNG IEND 之后' : 'after PNG IEND') : (zh ? 'JPEG EOI 之后' : 'after JPEG EOI');

  return (
    <>
      {(embedded.hits.length > 0 || hasTrailer) && (
        <section id="ff-card-embedded" className="ff-card" aria-label={zh ? '嵌入数据' : 'Embedded data'}>
          <div className="ff-card-head">
            <strong>{zh ? '嵌入数据' : 'Embedded data'}</strong>
          </div>
          {embedded.hits.length > 0 && (
            <div className="ff-tool">
              <span className="ff-label">
                {zh
                  ? `检出 ${embedded.hits.length} 处嵌入文件签名（提取范围为命中处到文件尾，尾附式藏匿可直接使用）`
                  : `${embedded.hits.length} embedded signature(s) found (extraction runs to end of file, for appended payloads)`}
              </span>
              {embedded.hits.map(hit => (
                <div key={`${hit.ext}-${hit.offset}`} className="ff-row">
                  <span className="ff-badge">{hit.name}</span>
                  <span className="ff-mono">{formatOffset(hit.offset)}（{hit.offset}）</span>
                  <button
                    type="button"
                    className="ff-button"
                    onClick={() => downloadBytes(bytes.subarray(hit.offset), `${baseName}-at-${hit.offset.toString(16)}.${hit.ext}`)}
                  >
                    {zh ? '提取下载' : 'Extract'}
                  </button>
                </div>
              ))}
            </div>
          )}
          {trailer && (
            <div className="ff-tool">
              <div className="ff-row">
                <span className="ff-badge ff-badge-warn">
                  {zh ? `尾附加数据 ${trailer.size} 字节（${trailerLabel}，起始 ${formatOffset(trailer.offset)}）` : `${trailer.size} trailing byte(s) ${trailerLabel}, at ${formatOffset(trailer.offset)}`}
                </span>
                <button
                  type="button"
                  className="ff-button"
                  onClick={() => downloadBytes(bytes.subarray(trailer.offset), `${baseName}-trailer.bin`)}
                >
                  {zh ? '下载尾附数据' : 'Download'}
                </button>
              </div>
              <pre className="ff-code ff-code-dump">{hexdumpPreview(bytes.subarray(trailer.offset), { length: TRAILER_PREVIEW_BYTES })}</pre>
            </div>
          )}
        </section>
      )}

      {chunkList.length > 0 && (
        <section id="ff-card-chunks" className="ff-card" aria-label={zh ? 'PNG chunk 枚举' : 'PNG chunks'}>
          <div className="ff-card-head">
            <strong>{zh ? `PNG chunk 枚举（${chunkList.length} 个）` : `PNG chunks (${chunkList.length})`}</strong>
            {chunksTruncated && (
              <span className="ff-badge ff-badge-warn">
                {zh ? `已达枚举上限 ${MAX_CHUNKS}，超出部分未列出` : `Capped at ${MAX_CHUNKS} chunks; the rest are not listed`}
              </span>
            )}
          </div>
          <div className="ff-strings">
            {chunkList.map((chunk, index) => {
              const state = chunkTexts[index];
              return (
                <div key={`${chunk.type}-${index}`} className="ff-chunk-row">
                  <div className="ff-row">
                    <span className={chunk.crcOk ? 'ff-badge' : 'ff-badge ff-badge-warn'}>
                      {chunk.type}
                      {!chunk.crcOk && (zh ? ' · CRC 失败' : ' · CRC bad')}
                    </span>
                    <span className="ff-mono">{zh ? `长度 ${chunk.length}` : `length ${chunk.length}`} · {formatOffset(chunk.dataStart)}</span>
                  </div>
                  {chunk.text?.text && (
                    <code className="ff-code">
                      <span className="ff-label">{chunk.text.keyword}: </span>
                      <FlagAutoText text={chunk.text.text} />
                    </code>
                  )}
                  {chunk.text?.compressed && state?.text && (
                    <code className="ff-code">
                      <span className="ff-label">{chunk.text.keyword}: </span>
                      <FlagAutoText text={state.text} />
                    </code>
                  )}
                  {chunk.text?.compressed && !state && (
                    <span className="ff-note">{zh ? '正在解压…' : 'Inflating…'}</span>
                  )}
                  {chunk.text?.compressed && state?.failed && (
                    <span className="ff-note">
                      {zh
                        ? `压缩数据 ${chunk.text.compressedBytes?.length ?? 0} 字节解压失败（可能不是 zlib 流），可从上方偏移提取原始字节。`
                        : `${chunk.text.compressedBytes?.length ?? 0} compressed byte(s) failed to inflate; extract raw bytes via the offset above.`}
                    </span>
                  )}
                </div>
              );
            })}
          </div>
        </section>
      )}
    </>
  );
}

export default EmbeddedCard;
