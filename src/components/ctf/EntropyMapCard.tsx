import { useEffect, useMemo, useRef, useState } from 'react';
import type { EntropyBlock, HighEntropyRange } from '../../utils/ctf/fileDetect';
import '../../styles/entropy-map-card.css';

interface EntropyMapCardProps {
  blocks: EntropyBlock[];
  ranges: HighEntropyRange[];
  language: 'zh' | 'en';
}

const CANVAS_WIDTH = 1024;
const CANVAS_HEIGHT = 96;

const toHex = (value: number): string => `0x${value.toString(16).toUpperCase()}`;

const formatSpan = (bytes: number): string => {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
};

// 熵值 → 颜色：低熵暗蓝（可读文本/填充）→ 中熵土黄（代码/混合）→ 高熵红（加密/压缩）。
const entropyColor = (entropy: number): string => {
  const t = Math.min(1, Math.max(0, entropy / 8));
  if (t < 0.5) {
    const k = t / 0.5;
    return `rgb(${Math.round(30 + k * 190)}, ${Math.round(70 + k * 90)}, ${Math.round(110 - k * 40)})`;
  }
  const k = (t - 0.5) / 0.5;
  return `rgb(${Math.round(220 + k * 35)}, ${Math.round(160 - k * 90)}, ${Math.round(70 - k * 40)})`;
};

// 块级熵图（Canvas 条形）：每像素列聚合块最大熵；高熵区段顶部刻度标注，悬停查看偏移与熵值。
function EntropyMapCard({ blocks, ranges, language }: EntropyMapCardProps) {
  const zh = language === 'zh';
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const [hover, setHover] = useState<{ label: string; entropy: number } | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    ctx.clearRect(0, 0, CANVAS_WIDTH, CANVAS_HEIGHT);
    ctx.fillStyle = 'rgba(255, 255, 255, 0.03)';
    ctx.fillRect(0, 0, CANVAS_WIDTH, CANVAS_HEIGHT);
    if (!blocks.length) return;
    const perColumn = blocks.length / CANVAS_WIDTH;
    for (let column = 0; column < CANVAS_WIDTH; column += 1) {
      const start = Math.floor(column * perColumn);
      const end = Math.min(blocks.length, Math.max(start + 1, Math.floor((column + 1) * perColumn)));
      let max = 0;
      for (let index = start; index < end; index += 1) {
        if (blocks[index].entropy > max) max = blocks[index].entropy;
      }
      const barHeight = Math.max(2, (max / 8) * CANVAS_HEIGHT);
      ctx.fillStyle = entropyColor(max);
      ctx.fillRect(column, CANVAS_HEIGHT - barHeight, 1, barHeight);
    }
    // 高熵区段顶部刻度线
    const totalEnd = blocks[blocks.length - 1].offset + blocks[blocks.length - 1].length;
    ctx.fillStyle = 'rgba(0, 240, 255, 0.9)';
    for (const range of ranges) {
      const left = Math.floor((range.startOffset / totalEnd) * CANVAS_WIDTH);
      const right = Math.max(left + 2, Math.floor((range.endOffset / totalEnd) * CANVAS_WIDTH));
      ctx.fillRect(left, 0, Math.max(2, right - left), 3);
    }
  }, [blocks, ranges]);

  const onMove = (event: React.MouseEvent<HTMLCanvasElement>) => {
    if (!blocks.length) return;
    const rect = event.currentTarget.getBoundingClientRect();
    const ratio = Math.min(1, Math.max(0, (event.clientX - rect.left) / rect.width));
    const index = Math.min(blocks.length - 1, Math.floor(ratio * blocks.length));
    const block = blocks[index];
    setHover({
      label: `${toHex(block.offset)} · ${formatSpan(block.length)}`,
      entropy: block.entropy,
    });
  };

  const rangeSummary = useMemo(
    () => ranges.map(range => ({
      key: `${range.startOffset}`,
      label: `${toHex(range.startOffset)} – ${toHex(range.endOffset)}`,
      detail: `${formatSpan(range.endOffset - range.startOffset)} · ${zh ? '平均熵' : 'avg'} ${range.average.toFixed(2)}`,
    })),
    [ranges, zh],
  );

  return (
    <section id="rv-card-entropy" className="ff-card" aria-label={zh ? '块级熵图' : 'Block entropy map'}>
      <div className="ff-card-head">
        <strong>{zh ? '块级熵图（256B/块）' : 'Block entropy map (256B each)'}</strong>
      </div>
      <canvas
        ref={canvasRef}
        width={CANVAS_WIDTH}
        height={CANVAS_HEIGHT}
        className="rv-entropy-canvas"
        aria-label={zh ? '文件分块信息熵条形图' : 'Per-block entropy bar chart'}
        onMouseMove={onMove}
        onMouseLeave={() => setHover(null)}
      />
      <p className="ff-note">
        {hover
          ? `${hover.label} · ${zh ? '熵' : 'entropy'} ${hover.entropy.toFixed(3)} / 8`
          : (zh
            ? '悬停查看偏移与熵值；顶部青色刻度 = 高熵区段（≥6.8，加密/压缩资源候选位置）。'
            : 'Hover for offset and entropy; cyan ticks mark high-entropy ranges (≥6.8, likely encrypted/compressed).')}
      </p>
      {rangeSummary.length > 0 && (
        <div className="ff-row">
          {rangeSummary.map(range => (
            <span key={range.key} className="ff-badge ff-badge-warn" title={range.detail}>
              {range.label}（{range.detail}）
            </span>
          ))}
        </div>
      )}
      {!blocks.length && (
        <p className="ff-note">{zh ? '空文件没有可绘制的内容。' : 'Nothing to draw for an empty file.'}</p>
      )}
    </section>
  );
}

export default EntropyMapCard;
