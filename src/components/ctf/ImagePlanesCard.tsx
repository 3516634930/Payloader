import { useEffect, useMemo, useRef, useState } from 'react';
import { notifications } from '@mantine/notifications';
import { FlagAutoText } from '../codec/FlagAutoText';
import {
  MAX_ANALYSIS_PIXELS,
  PLANE_CHANNELS,
  bytesToPreviewText,
  extractBitPlane,
  extractChannelPlane,
  extractLsbBytes,
  grayToRgba,
} from '../../utils/ctf/imagePlanes';
import type { RgbaChannel } from '../../utils/ctf/imagePlanes';
import { scanBitPlanes } from '../../utils/ctf/bitPlaneScan';
import type { BitPlaneHit } from '../../utils/ctf/bitPlaneScan';
import { copyToClipboard } from '../../utils/clipboard';
import { downloadBlob, downloadBytes } from '../../utils/download';

export interface PlaneImage {
  rgba: Uint8ClampedArray<ArrayBuffer>;
  width: number;
  height: number;
  downsampled: boolean;
  originalWidth: number;
  originalHeight: number;
}

interface ImagePlanesCardProps {
  fileName: string;
  image: PlaneImage | null;
  status: 'idle' | 'loading' | 'ready' | 'failed';
  language: 'zh' | 'en';
}

const LSB_PREVIEW_CHARS = 2048;
const LSB_MAX_BYTES = 64 * 1024;
// 缩略图最大边长：32 张缩略 canvas 控制显存（128px 每张 ≈ 65KB）。
const THUMB_MAX_DIM = 128;

const downloadCanvasPng = async (rgba: Uint8ClampedArray<ArrayBuffer>, width: number, height: number, filename: string): Promise<boolean> => {
  const canvas = document.createElement('canvas');
  canvas.width = width;
  canvas.height = height;
  const ctx = canvas.getContext('2d');
  if (!ctx) return false;
  ctx.putImageData(new ImageData(rgba, width, height), 0, 0);
  const blob = await new Promise<Blob | null>(resolve => canvas.toBlob(resolve, 'image/png'));
  if (!blob) return false;
  downloadBlob(blob, filename);
  return true;
};

// 把小图 rgba 最近邻放大采样不适用——这里只做缩小：按比例网格取样，输出 RGBA。
const sampleRgbaThumbnail = (rgba: Uint8ClampedArray, width: number, height: number, maxDim: number) => {
  const scale = Math.min(1, maxDim / Math.max(width, height));
  const tw = Math.max(1, Math.round(width * scale));
  const th = Math.max(1, Math.round(height * scale));
  const out = new Uint8ClampedArray(tw * th * 4);
  for (let y = 0; y < th; y += 1) {
    const sy = Math.min(height - 1, Math.floor(y / scale));
    for (let x = 0; x < tw; x += 1) {
      const sx = Math.min(width - 1, Math.floor(x / scale));
      const source = (sy * width + sx) * 4;
      const target = (y * tw + x) * 4;
      out[target] = rgba[source];
      out[target + 1] = rgba[source + 1];
      out[target + 2] = rgba[source + 2];
      out[target + 3] = rgba[source + 3];
    }
  }
  return { rgba: out, width: tw, height: th };
};

const usePlaneCanvas = (
  build: () => { rgba: Uint8ClampedArray<ArrayBuffer>; width: number; height: number } | null,
  deps: unknown[],
) => {
  const ref = useRef<HTMLCanvasElement | null>(null);
  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    const image = build();
    if (!image) return;
    // 防御：ImageData 构造对 0/NaN 宽高直接抛异常并会击穿整棵组件树（无 error boundary）。
    if (!Number.isFinite(image.width) || !Number.isFinite(image.height) || image.width <= 0 || image.height <= 0) return;
    if (image.rgba.length !== image.width * image.height * 4) return;
    canvas.width = image.width;
    canvas.height = image.height;
    ctx.putImageData(new ImageData(image.rgba, image.width, image.height), 0, 0);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  return ref;
};

interface PlaneThumbProps {
  thumb: { rgba: Uint8ClampedArray<ArrayBuffer>; width: number; height: number };
  label: string;
  selected: boolean;
  onSelect: () => void;
}

const PlaneThumb = ({ thumb, label, selected, onSelect }: PlaneThumbProps) => {
  const canvasRef = usePlaneCanvas(() => ({ rgba: thumb.rgba, width: thumb.width, height: thumb.height }), [thumb]);
  return (
    <button
      type="button"
      className={`ff-plane-cell${selected ? ' ff-plane-cell-active' : ''}`}
      onClick={onSelect}
      title={label}
    >
      <canvas ref={canvasRef} className="ff-plane-canvas" aria-label={label} />
      <span className="ff-plane-cell-label">{label}</span>
    </button>
  );
};

// 位平面 + 色道卡片：输入是已解码的 RGBA（由父组件异步 createImageBitmap 解出）。
// 平面灰度惰性现算：缩略图在采样后的小 rgba 上做（快），放大图在原图上现算一次。
// 自动扫描命中里能映射到下方手动提取器（单通道 + 行序 + MSB-first）的组合，用于"深挖"回填。
const SCAN_CHANNEL_INDEX: Record<string, RgbaChannel> = { r: 0, g: 1, b: 2, a: 3 };

function ImagePlanesCard({ fileName, image, status, language }: ImagePlanesCardProps) {
  const [selected, setSelected] = useState<{ channel: RgbaChannel; bit: number } | null>(null);
  const [lsbChannel, setLsbChannel] = useState<RgbaChannel>(0);
  const [lsbBit, setLsbBit] = useState(0);
  const [lsbResult, setLsbResult] = useState<{ text: string; bytes: Uint8Array; truncated: boolean } | null>(null);
  const [scanHits, setScanHits] = useState<BitPlaneHit[] | null>(null);

  const zh = language === 'zh';
  const baseName = fileName.replace(/\.[^.]+$/, '');

  // 缩略图（4 通道 × 8 位）在小 rgba 上现算一次，网格渲染零等待。
  const thumbs = useMemo(() => {
    if (!image) return null;
    const small = sampleRgbaThumbnail(image.rgba, image.width, image.height, THUMB_MAX_DIM);
    return PLANE_CHANNELS.map(({ channel, label }) => ({
      channel,
      label,
      bits: [7, 6, 5, 4, 3, 2, 1, 0].map(bit => ({
        bit,
        thumb: {
          rgba: grayToRgba(extractBitPlane(small.rgba, channel, bit)),
          width: small.width,
          height: small.height,
        },
      })),
    }));
  }, [image]);

  const zoomRef = usePlaneCanvas(() => {
    if (!image || !selected) return null;
    const plane = extractBitPlane(image.rgba, selected.channel, selected.bit);
    return { rgba: grayToRgba(plane), width: image.width, height: image.height };
  }, [image, selected]);

  const channelLabel = selected ? PLANE_CHANNELS.find(item => item.channel === selected.channel)?.label ?? '' : '';

  const runLsbExtract = () => {
    if (!image) return;
    const bytes = extractLsbBytes(image.rgba, { channel: lsbChannel, bit: lsbBit, maxBytes: LSB_MAX_BYTES });
    const truncated = image.width * image.height > LSB_MAX_BYTES * 8;
    setLsbResult({ bytes, text: bytesToPreviewText(bytes, LSB_PREVIEW_CHARS), truncated });
  };

  // zsteg 式全组合扫描（9 通道组 × 8 位 × 2 位序 × 2 像素序 = 288 次 256B 提取，10ms 级），
  // 只列带命中理由（zlib 魔数 / flag 格式 / 可打印率 / base64）的组合，按分降序。
  const runAutoScan = () => {
    if (!image) return;
    setScanHits(scanBitPlanes(image.rgba, image.width, image.height));
  };

  const deepDiveHit = (hit: BitPlaneHit) => {
    const channel = SCAN_CHANNEL_INDEX[hit.channel];
    if (channel === undefined || !image) return;
    setLsbChannel(channel);
    setLsbBit(hit.bit - 1);
    const bytes = extractLsbBytes(image.rgba, { channel, bit: hit.bit - 1, maxBytes: LSB_MAX_BYTES });
    const truncated = image.width * image.height > LSB_MAX_BYTES * 8;
    setLsbResult({ bytes, text: bytesToPreviewText(bytes, LSB_PREVIEW_CHARS), truncated });
  };

  const copyLsbText = () => {
    if (!lsbResult) return;
    void copyToClipboard(lsbResult.text).then(ok => {
      if (!ok) notifications.show({ message: zh ? '复制失败，请手动选择文本。' : 'Copy failed; select the text manually.', color: 'red' });
      else notifications.show({ message: zh ? '提取结果已复制。' : 'Extraction copied.', color: 'teal', autoClose: 1600 });
    });
  };

  const exportChannel = (channel: RgbaChannel, label: string) => {
    if (!image) return;
    if (image.width * image.height > MAX_ANALYSIS_PIXELS) return;
    const rgba = grayToRgba(extractChannelPlane(image.rgba, channel));
    void downloadCanvasPng(rgba, image.width, image.height, `${baseName}-${label}.png`).then(ok => {
      if (!ok) notifications.show({ message: zh ? '导出失败：浏览器无法生成 PNG 文件。' : 'Export failed: the browser could not generate the PNG.', color: 'red' });
    });
  };

  return (
    <>
      <section id="ff-card-bitplanes" className="ff-card" aria-label={zh ? '位平面浏览器' : 'Bit planes'}>
        <div className="ff-card-head">
          <strong>{zh ? '位平面浏览器' : 'Bit planes'}</strong>
          {image?.downsampled && (
            <span className="ff-badge ff-badge-warn">
              {zh
                ? `原图 ${image.originalWidth}×${image.originalHeight} 超过 4MP，已降采样为 ${image.width}×${image.height} 分析`
                : `Original ${image.originalWidth}×${image.originalHeight} exceeds 4MP; analyzing a ${image.width}×${image.height} downscale`}
            </span>
          )}
        </div>
        {status === 'loading' && <p className="ff-note">{zh ? '正在解码图片…' : 'Decoding image…'}</p>}
        {status === 'failed' && (
          <p className="ff-note">{zh ? '浏览器无法解码该图片，位平面不可用；可先用 hexdump 与字符串分析。' : 'The browser could not decode this image; use the hexdump and strings instead.'}</p>
        )}
        {thumbs && (
          <>
            <p className="ff-note">
              {zh
                ? '点击平面放大查看；隐写信息常藏在最低几位（bit 0-1）。'
                : 'Click a plane to zoom; steganography usually hides in the lowest bits (0-1).'}
            </p>
            <div className="ff-plane-grid">
              {thumbs.map(group => (
                <div key={group.label} className="ff-plane-group">
                  <span className="ff-plane-group-label">{group.label}</span>
                  <div className="ff-plane-row">
                    {group.bits.map(item => (
                      <PlaneThumb
                        key={item.bit}
                        thumb={item.thumb}
                        label={`${group.label}${item.bit}`}
                        selected={selected?.channel === group.channel && selected?.bit === item.bit}
                        onSelect={() => setSelected({ channel: group.channel, bit: item.bit })}
                      />
                    ))}
                  </div>
                </div>
              ))}
            </div>
            {selected && (
              <div className="ff-tool">
                <div className="ff-row">
                  <span className="ff-badge ff-badge-ok">{channelLabel}{selected.bit} {zh ? '放大' : 'zoom'}</span>
                  <button type="button" className="ff-button" onClick={() => setSelected(null)}>{zh ? '关闭放大' : 'Close zoom'}</button>
                </div>
                <canvas ref={zoomRef} className="ff-plane-zoom" aria-label={`${channelLabel}${selected.bit}`} />
              </div>
            )}
            <div className="ff-tool">
              <span className="ff-label">{zh ? '全组合自动扫描（zsteg 式：通道组 × 位 × 位序 × 像素序，共 288 组合）' : 'Auto-scan all combos (zsteg-style: channel group × bit × bit order × pixel order, 288 total)'}</span>
              <div className="ff-row">
                <button type="button" className="ff-button ff-button-primary" onClick={runAutoScan}>
                  {zh ? '自动扫描' : 'Auto-scan'}
                </button>
              </div>
              {scanHits && (
                scanHits.length === 0 ? (
                  <p className="ff-note">
                    {zh
                      ? '288 个组合均无命中（无 zlib 魔数 / flag 格式 / 高可打印率 / base64 特征）。可换用下方手动提取或位平面放大目检。'
                      : 'No hits across the 288 combos (no zlib magic / flag pattern / printable text / base64 traits). Try manual extraction below or inspect planes visually.'}
                  </p>
                ) : (
                  <>
                    <p className="ff-note">
                      {zh ? `命中 ${scanHits.length} 个组合（按评分降序；单通道行序命中可「深挖」导出完整字节）：` : `${scanHits.length} hits (score-descending; single-channel row hits support deep-dive export):`}
                    </p>
                    {scanHits.map(hit => {
                      const combo = `${hit.channel}/${hit.bit}/${hit.lsbFirst ? 'lsb' : 'msb'}/${hit.pixelOrder === 'row' ? (zh ? '行' : 'row') : (zh ? '列' : 'col')}`;
                      const deepDiveable = SCAN_CHANNEL_INDEX[hit.channel] !== undefined && !hit.lsbFirst && hit.pixelOrder === 'row';
                      return (
                        <div key={combo} className="ff-tool">
                          <div className="ff-row">
                            <span className="ff-badge ff-badge-ok">{combo}</span>
                            <span className="ff-badge">{hit.reasons.join(' + ')} · {hit.score}</span>
                            {deepDiveable && (
                              <button type="button" className="ff-button" onClick={() => deepDiveHit(hit)}>
                                {zh ? '深挖（64KB 完整提取）' : 'Deep-dive (64KB full extract)'}
                              </button>
                            )}
                          </div>
                          <code className="ff-code"><FlagAutoText text={hit.preview} /></code>
                        </div>
                      );
                    })}
                  </>
                )
              )}
            </div>
            <div className="ff-tool">
              <span className="ff-label">{zh ? 'LSB 顺序提取（从 (0,0) 按行取位、高位在前组字节）' : 'LSB extraction (row-major from (0,0), MSB first)'}</span>
              <div className="ff-row">
                <select
                  className="ff-select"
                  value={lsbChannel}
                  aria-label={zh ? '提取通道' : 'Channel'}
                  onChange={event => setLsbChannel(Number(event.target.value) as RgbaChannel)}
                >
                  {PLANE_CHANNELS.map(item => (
                    <option key={item.channel} value={item.channel}>{item.label}</option>
                  ))}
                </select>
                <select
                  className="ff-select"
                  value={lsbBit}
                  aria-label={zh ? '提取位' : 'Bit'}
                  onChange={event => setLsbBit(Number(event.target.value))}
                >
                  {[0, 1, 2, 3, 4, 5, 6, 7].map(bit => <option key={bit} value={bit}>bit {bit}</option>)}
                </select>
                <button type="button" className="ff-button ff-button-primary" onClick={runLsbExtract}>
                  {zh ? '提取' : 'Extract'}
                </button>
              </div>
              {lsbResult && (
                <>
                  <code className="ff-code"><FlagAutoText text={lsbResult.text} /></code>
                  <div className="ff-row">
                    {lsbResult.truncated && (
                      <span className="ff-note">
                        {zh ? `已达 ${LSB_MAX_BYTES / 1024}KB 提取上限；完整数据请用「下载原始字节」查看。` : `Hit the ${LSB_MAX_BYTES / 1024}KB preview cap; download the raw bytes for the full data.`}
                      </span>
                    )}
                    <button type="button" className="ff-button" onClick={copyLsbText}>{zh ? '复制文本' : 'Copy text'}</button>
                    <button
                      type="button"
                      className="ff-button"
                      onClick={() => downloadBytes(lsbResult.bytes, `${baseName}-lsb.bin`)}
                    >
                      {zh ? '下载原始字节' : 'Download raw bytes'}
                    </button>
                  </div>
                </>
              )}
            </div>
          </>
        )}
      </section>

      <section id="ff-card-channels" className="ff-card" aria-label={zh ? '色道分离' : 'Color channels'}>
        <div className="ff-card-head">
          <strong>{zh ? '色道分离' : 'Color channels'}</strong>
        </div>
        <p className="ff-note">
          {zh ? '把单通道导出为灰度 PNG 下载（Alpha 通道以亮度显示）。' : 'Export one channel as a grayscale PNG (alpha shown as brightness).'}
        </p>
        <div className="ff-row">
          {PLANE_CHANNELS.map(item => (
            <button key={item.channel} type="button" className="ff-button" onClick={() => exportChannel(item.channel, item.label)}>
              {zh ? `导出 ${item.label} 通道` : `Export ${item.label}`}
            </button>
          ))}
          <button
            type="button"
            className="ff-button"
            onClick={() => {
              if (!image) return;
              const rgba = new Uint8ClampedArray(image.width * image.height * 4);
              for (let index = 0; index < image.width * image.height; index += 1) {
                const source = index * 4;
                const luma = (image.rgba[source] * 299 + image.rgba[source + 1] * 587 + image.rgba[source + 2] * 114) / 1000;
                const value = Math.round(luma);
                rgba[source] = rgba[source + 1] = rgba[source + 2] = value;
                rgba[source + 3] = 255;
              }
              void downloadCanvasPng(rgba, image.width, image.height, `${baseName}-L.png`);
            }}
          >
            {zh ? '导出灰度' : 'Export grayscale'}
          </button>
        </div>
      </section>
    </>
  );
}

export default ImagePlanesCard;
