import { useEffect, useMemo, useRef, useState } from 'react';
import { notifications } from '@mantine/notifications';
import { FlagAutoText } from '../codec/FlagAutoText';
import { decodeGifFrames, inspectGif } from '../../utils/ctf/gifInspect';
import type { GifInspectResult } from '../../utils/ctf/gifInspect';
import { decodeQrCodes } from '../../utils/ctf/qrDecode';
import { downloadBlob } from '../../utils/download';
import { copyToClipboard } from '../../utils/clipboard';

// GIF 深度解析卡：概览/注释段/帧延时三口径解读/帧缩略图（点击下载该帧 PNG）。
// 解析与帧解码都在 useMemo 同步完成（引擎自带 2000 帧/1600 万像素红线）；换文件由父层 key remount。
interface GifInspectCardProps {
  fileName: string;
  bytes: Uint8Array;
  language: 'zh' | 'en';
}

type InspectOutcome = { inspected: GifInspectResult; decodedCount: number } | { error: string };

const THUMB_MAX_FRAMES = 64;

function GifInspectCard({ fileName, bytes, language }: GifInspectCardProps) {
  const zh = language === 'zh';
  const baseName = fileName.replace(/\.[^.]+$/, '');
  const result = useMemo<InspectOutcome>(() => {
    try {
      const inspected = inspectGif(bytes);
      const decoded = decodeGifFrames(bytes, inspected, { maxFrames: THUMB_MAX_FRAMES });
      return { inspected, decodedCount: decoded };
    } catch (error) {
      return { error: (error as Error).message };
    }
  }, [bytes]);

  const frames = useMemo(() => ('inspected' in result ? result.inspected.frames : []), [result]);
  const rawDelays = useMemo(() => frames.map(frame => Math.round(frame.delayMs / 10)).slice(0, 128).join(','), [frames]);
  const thumbsRef = useRef<HTMLDivElement | null>(null);
  const [qrHits, setQrHits] = useState<Array<{ source: string; text: string }>>([]);

  // 帧拼合 QR（glance/give_you_flag 型）：单帧 + 全帧横拼 + 网格拼三路（同通关执行器口径）。
  const runFrameQr = () => {
    if (!('inspected' in result)) return;
    const inspected = result.inspected;
    const withPixels = inspected.frames.flatMap(frame => frame.imageData
      ? [{ index: frame.index, pixels: frame.imageData, width: frame.width, height: frame.height }]
      : []).slice(0, 240);
    if (withPixels.length === 0) return;
    const found: Array<{ source: string; text: string }> = [];
    for (const frame of withPixels.slice(0, 30)) {
      for (const item of decodeQrCodes(frame.pixels, frame.width, frame.height)) {
        found.push({ source: (zh ? `帧 ${frame.index + 1}` : `Frame ${frame.index + 1}`), text: item.text });
      }
    }
    const w = withPixels[0].width, h = withPixels[0].height;
    if (withPixels.length >= 2 && withPixels.every(f => f.width === w && f.height === h)) {
      const strip = new Uint8ClampedArray(withPixels.length * w * h * 4);
      withPixels.forEach((f, i) => strip.set(f.pixels, i * w * h * 4));
      for (const item of decodeQrCodes(strip, withPixels.length * w, h)) {
        found.push({ source: zh ? `横拼（${withPixels.length} 帧）` : `Strip (${withPixels.length})`, text: item.text });
      }
      const cols = Math.ceil(Math.sqrt(withPixels.length));
      const rows = Math.ceil(withPixels.length / cols);
      const grid = new Uint8ClampedArray(cols * w * rows * h * 4);
      withPixels.forEach((f, i) => {
        const gx = (i % cols) * w, gy = Math.floor(i / cols) * h;
        for (let y = 0; y < h; y += 1) {
          for (let x = 0; x < w; x += 1) {
            const src = (y * w + x) * 4, dst = ((gy + y) * cols * w + gx + x) * 4;
            grid[dst] = f.pixels[src]; grid[dst + 1] = f.pixels[src + 1];
            grid[dst + 2] = f.pixels[src + 2]; grid[dst + 3] = 255;
          }
        }
      });
      for (const item of decodeQrCodes(grid, cols * w, rows * h)) {
        found.push({ source: `${cols}×${rows} ${zh ? '网格拼' : 'grid'}`, text: item.text });
      }
    }
    setQrHits(found);
    if (!found.length) {
      notifications.show({ message: zh ? '单帧/横拼/网格拼均未识别到二维码（知识型拼图题需目检帧缩略图）。' : 'No QR found in single frames or stitchings; knowledge-based puzzles need eyeballing.' });
    }
  };

  // 帧缩略 canvas：挂载后一次性渲染（帧像素已在引擎 imageData 里）。
  useEffect(() => {
    const host = thumbsRef.current;
    const inspected = 'inspected' in result ? result.inspected : null;
    if (!host || !inspected) return;
    const canvases = host.querySelectorAll<HTMLCanvasElement>('canvas[data-frame-index]');
    canvases.forEach(canvas => {
      const frame = inspected.frames[Number(canvas.dataset.frameIndex)];
      if (!frame || !frame.imageData || !frame.width || !frame.height) return;
      const ctx = canvas.getContext('2d');
      if (!ctx) return;
      canvas.width = frame.width;
      canvas.height = frame.height;
      ctx.putImageData(new ImageData(frame.imageData, frame.width, frame.height), 0, 0);
    });
  }, [result]);

  const downloadFrame = (index: number) => {
    const canvas = thumbsRef.current?.querySelector<HTMLCanvasElement>(`canvas[data-frame-index="${index}"]`);
    if (!canvas) return;
    void canvas.toBlob(blob => {
      if (blob) downloadBlob(blob, `${baseName}-frame${String(index + 1).padStart(3, '0')}.png`);
      else notifications.show({ message: zh ? '导出失败：浏览器无法生成 PNG。' : 'Export failed: the browser could not generate a PNG.', color: 'red' });
    });
  };

  const copyText = (text: string) => {
    void copyToClipboard(text).then(ok => {
      if (!ok) notifications.show({ message: zh ? '复制失败，请手动选择文本。' : 'Copy failed; select the text manually.', color: 'red' });
      else notifications.show({ message: zh ? '已复制。' : 'Copied.', color: 'teal', autoClose: 1600 });
    });
  };

  if ('error' in result) {
    return (
      <section id="ff-card-gif" className="ff-card" aria-label={zh ? 'GIF 解析' : 'GIF inspection'}>
        <div className="ff-card-head"><strong>{zh ? 'GIF 解析' : 'GIF inspection'}</strong></div>
        <p className="ff-note">{result.error}</p>
      </section>
    );
  }

  const inspected = result.inspected!;
  const delayBits = inspected.delayBits;

  return (
    <section id="ff-card-gif" className="ff-card" aria-label={zh ? 'GIF 解析' : 'GIF inspection'}>
      <div className="ff-card-head">
        <strong>{zh ? 'GIF 解析' : 'GIF inspection'}</strong>
        <span className="ff-badge">
          {inspected.version} · {inspected.logicalWidth}×{inspected.logicalHeight} · {zh ? `${inspected.frames.length} 帧` : `${inspected.frames.length} frames`}
          {zh ? ` · 循环 ${inspected.loopCount === 0 ? '∞' : inspected.loopCount}` : ` · loop ${inspected.loopCount === 0 ? '∞' : inspected.loopCount}`}
        </span>
      </div>
      {inspected.anomalies.length > 0 && (
        <div className="ff-tool">
          <span className="ff-label">{zh ? '结构线索' : 'Structural clues'}</span>
          {inspected.anomalies.map((anomaly, index) => (
            <p key={index} className="ff-note">• {anomaly}</p>
          ))}
        </div>
      )}
      {(inspected.comments.length > 0 || inspected.plainTexts.length > 0) && (
        <div className="ff-tool">
          <span className="ff-label">{zh ? '注释 / 文本扩展段（隐写常藏处）' : 'Comment / plain-text extensions (common hiding spot)'}</span>
          {inspected.comments.map((comment, index) => (
            <code key={`comment-${index}`} className="ff-code"><FlagAutoText text={comment} /></code>
          ))}
          {inspected.plainTexts.map((text, index) => (
            <code key={`plain-${index}`} className="ff-code"><FlagAutoText text={text} /></code>
          ))}
        </div>
      )}
      {delayBits && (
        <div className="ff-tool">
          <span className="ff-label">{zh ? '帧延时隐写（三种解读并排，哪种出可读内容用哪种）' : 'Frame-delay steganography (three readings side by side)'}</span>
          <code className="ff-code">
            {`${zh ? '二进制（>50ms=1）' : 'Binary (>50ms=1)'}: ${delayBits.asBinary}\n${zh ? 'ASCII（延时值直接当码点）' : 'ASCII (delay as codepoint)'}: ${delayBits.asAscii}\n${zh ? '数字（延时值 0-9）' : 'Digits (delay 0-9)'}: ${delayBits.asSeconds}\n${zh ? '原始延时序列（前 128 帧，单位 1/100s）' : 'Raw delays (first 128, in 1/100s)'}: ${rawDelays}`}
          </code>
          <div className="ff-row">
            <button type="button" className="ff-button" onClick={() => copyText(delayBits.asBinary)}>{zh ? '复制二进制' : 'Copy binary'}</button>
            <button type="button" className="ff-button" onClick={() => copyText(delayBits.asAscii)}>{zh ? '复制 ASCII' : 'Copy ASCII'}</button>
          </div>
        </div>
      )}
      {frames.length > 0 && (
        <div className="ff-tool">
          <span className="ff-label">
            {zh
              ? `帧缩略图（点击下载该帧 PNG${result && 'inspected' in result && result.decodedCount < frames.length ? `；仅渲染前 ${result.decodedCount} 帧` : ''}）`
              : `Frame thumbnails (click to download PNG${result && 'inspected' in result && result.decodedCount < frames.length ? `; first ${result.decodedCount} rendered` : ''})`}
          </span>
          <div className="ff-row">
            <button type="button" className="ff-button ff-button-primary" onClick={runFrameQr}>
              {zh ? '帧拼合识别二维码' : 'Stitch & scan QR'}
            </button>
          </div>
          {qrHits.length > 0 && (
            <div className="ff-tool">
              {qrHits.map((hit, index) => (
                <div key={`qr-${index}`} className="ff-row">
                  <span className="ff-badge ff-badge-ok">{hit.source}</span>
                  <code className="ff-code" style={{ flex: 1 }}><FlagAutoText text={hit.text} /></code>
                  <button type="button" className="ff-button" onClick={() => { void copyToClipboard(hit.text); }}>
                    {zh ? '复制' : 'Copy'}
                  </button>
                </div>
              ))}
            </div>
          )}
          <div className="ff-plane-grid" ref={thumbsRef}>
            {frames.slice(0, result.decodedCount).map(frame => (
              <div key={frame.index} className="ff-plane-group">
                <button
                  type="button"
                  className="ff-plane-cell"
                  title={zh ? `帧 ${frame.index + 1} · ${frame.delayMs}ms · ${frame.width}×${frame.height}` : `Frame ${frame.index + 1} · ${frame.delayMs}ms · ${frame.width}×${frame.height}`}
                  onClick={() => downloadFrame(frame.index)}
                >
                  <canvas data-frame-index={frame.index} className="ff-plane-canvas" aria-label={zh ? `帧 ${frame.index + 1}` : `Frame ${frame.index + 1}`} />
                  <span className="ff-plane-cell-label">{frame.index + 1}</span>
                </button>
              </div>
            ))}
          </div>
        </div>
      )}
    </section>
  );
}

export default GifInspectCard;
