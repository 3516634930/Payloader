import { useCallback, useRef, useState } from 'react';
import { notifications } from '@mantine/notifications';
import { FlagAutoText } from '../codec/FlagAutoText';
import type { PlaneImage } from './ImagePlanesCard';
import {
  COMBINE_LABELS,
  addQrFinderPatterns,
  asciiToImage,
  bitsToImage,
  combineImages,
  concatImages,
  coordsToImage,
  floodFillMask,
  flipImage,
  imageToAscii,
  imageToRgbText,
  invertImage,
  rgbTextToImage,
  scaleNearest,
} from '../../utils/ctf/imageOps';
import { bitsToBfSource, runBrainfuck } from '../../utils/ctf/esolangs';
import { decodeQrCodes } from '../../utils/ctf/qrDecode';
import { downloadBlob } from '../../utils/download';
import { copyToClipboard } from '../../utils/clipboard';

// 图像运算与转换卡（批次 SI·D 线）：双图组合/翻转反色拼接/RGB 与字符画导出/01·XY·RGB 串转图/
// flood-fill 掩码/QR 定位角补全（随波逐流"图片隐写"菜单的图像运算族对标）。
interface ImageOpsCardProps {
  image: PlaneImage;
  language: 'zh' | 'en';
}

type AnyImage = { data: Uint8ClampedArray | ArrayLike<number>; width: number; height: number };

const canvasOf = (image: AnyImage): HTMLCanvasElement => {
  const canvas = document.createElement('canvas');
  canvas.width = image.width;
  canvas.height = image.height;
  const ctx = canvas.getContext('2d');
  if (ctx !== null) {
    const clamped = image.data instanceof Uint8ClampedArray ? image.data : new Uint8ClampedArray(image.data);
    ctx.putImageData(new ImageData(clamped as Uint8ClampedArray<ArrayBuffer>, image.width, image.height), 0, 0);
  }
  return canvas;
};

const RESULT_MAX_DIM = 360;

function ResultCanvas({ image, label, language }: { image: AnyImage; label: string; language: 'zh' | 'en' }) {
  const ref = useRef<HTMLCanvasElement | null>(null);
  const attach = useCallback(
    (node: HTMLCanvasElement | null) => {
      ref.current = node;
      if (node === null) return;
      const scale = Math.min(1, RESULT_MAX_DIM / Math.max(image.width, image.height));
      node.width = Math.max(1, Math.round(image.width * scale));
      node.height = Math.max(1, Math.round(image.height * scale));
      const ctx = node.getContext('2d');
      if (ctx === null) return;
      ctx.imageSmoothingEnabled = false;
      ctx.drawImage(canvasOf(image), 0, 0, node.width, node.height);
    },
    [image],
  );
  const download = useCallback(() => {
    const canvas = canvasOf(image);
    void canvas.toBlob(blob => {
      if (blob !== null) void downloadBlob(blob, `${label}.png`);
    });
  }, [image, label]);
  return (
    <div className="ff-tool">
      <div className="ff-row">
        <canvas ref={attach} className="ff-canvas" aria-label={label} />
        <button type="button" className="ff-button" onClick={download}>
          {language === 'zh' ? '下载 PNG' : 'Download PNG'}
        </button>
      </div>
    </div>
  );
}

const readSecondImage = async (file: File): Promise<AnyImage> => {
  const bitmap = await createImageBitmap(file);
  const width = bitmap.width;
  const height = bitmap.height;
  // 先取尺寸再 close（close 后 width/height 归零——AGENTS.md 踩坑记录）
  const canvas = document.createElement('canvas');
  canvas.width = width;
  canvas.height = height;
  const ctx = canvas.getContext('2d');
  if (ctx === null) throw new Error('canvas 2d 上下文不可用');
  ctx.drawImage(bitmap, 0, 0);
  bitmap.close();
  if (width * height > 4_000_000) throw new Error(`第二张图 ${width}×${height} 超过 400 万像素上限，请先缩小`);
  const data = ctx.getImageData(0, 0, width, height);
  return { data: data.data, width, height };
};

function ImageOpsCard({ image, language }: ImageOpsCardProps) {
  const zh = language === 'zh';
  const source: AnyImage = { data: image.rgba, width: image.width, height: image.height };
  const [result, setResult] = useState<{ image: AnyImage; label: string } | null>(null);
  const [textResult, setTextResult] = useState<string | null>(null);
  const [second, setSecond] = useState<AnyImage | null>(null);
  const [textMode, setTextMode] = useState<'bits' | 'coords' | 'rgb'>('bits');
  const [textInput, setTextInput] = useState('');
  const [textWidth, setTextWidth] = useState('');
  const [fillX, setFillX] = useState('0');
  const [fillY, setFillY] = useState('0');
  const [fillTolerance, setFillTolerance] = useState('0');
  const [moduleSize, setModuleSize] = useState('');

  const withImage = (next: AnyImage, label: string, note?: string) => {
    setResult({ image: next, label });
    setTextResult(null);
    if (note !== undefined) notifications.show({ message: note, color: 'teal', autoClose: 2500 });
  };

  const applyText = () => {
    try {
      if (textMode === 'bits') {
        const width = textWidth.trim() === '' ? undefined : Number(textWidth);
        const outcome = bitsToImage(textInput, width);
        withImage(outcome.image, 'bits-image', `${zh ? '0/1 串' : '0/1 string'}: ${outcome.bitCount} ${zh ? '位，' : ' bits, '}${outcome.widthGuess}`);
      } else if (textMode === 'coords') {
        const outcome = coordsToImage(textInput);
        withImage(outcome.image, 'coords-image', `${zh ? '坐标点' : 'Points'}: ${outcome.pointCount}`);
      } else {
        const width = textWidth.trim() === '' ? undefined : Number(textWidth);
        const outcome = rgbTextToImage(textInput, width);
        withImage(outcome.image, 'rgb-image', `${zh ? '像素' : 'Pixels'}: ${outcome.pixelCount} (${outcome.format})`);
      }
    } catch (error) {
      notifications.show({ message: (error as Error).message, color: 'red' });
    }
  };

  const tryQr = (target: AnyImage) => {
    // 01/坐标串转图产物是 1px 模块小图，×4 最近邻放大后再识别（与通关脚本同口径）
    const scaled = target.width * target.height <= 128 * 128 ? scaleNearest(target, 4) : target;
    const hits = decodeQrCodes(scaled.data as ArrayLike<number>, scaled.width, scaled.height);
    if (hits.length > 0) {
      const joined = hits.map(hit => hit.text).join(' | ');
      setTextResult(`${zh ? '二维码命中' : 'QR hits'}: ${joined}`);
      notifications.show({ message: `${zh ? '二维码：' : 'QR: '}${joined.slice(0, 120)}`, color: 'teal' });
    } else {
      setTextResult(zh ? '未识别出二维码（可试补定位角后再识别）' : 'No QR detected (try adding finder patterns first)');
    }
  };

  return (
    <section id="ff-card-imageops" className="ff-card" aria-label={zh ? '图像运算与转换' : 'Image operations'}>
      <div className="ff-card-head">
        <strong>{zh ? '图像运算与转换' : 'Image operations'}</strong>
        <span className="ff-badge">{image.width}×{image.height}{image.downsampled ? (zh ? '（已降采样）' : ' (downsampled)') : ''}</span>
      </div>
      <div className="ff-tool">
        <span className="ff-label">{zh ? '单图操作' : 'Single image'}</span>
        <div className="ff-row">
          <button type="button" className="ff-button" onClick={() => withImage(flipImage(source, 'horizontal'), 'flipped-h')}>{zh ? '水平翻转' : 'Flip H'}</button>
          <button type="button" className="ff-button" onClick={() => withImage(flipImage(source, 'vertical'), 'flipped-v')}>{zh ? '垂直翻转' : 'Flip V'}</button>
          <button type="button" className="ff-button" onClick={() => withImage(invertImage(source), 'inverted')}>{zh ? '反色' : 'Invert'}</button>
          <button type="button" className="ff-button" onClick={() => { setTextResult(imageToAscii(source)); setResult(null); }}>{zh ? '转字符画' : '→ ASCII'}</button>
          <button type="button" className="ff-button" onClick={() => { setTextResult(imageToRgbText(source, 'dec').split('\n').slice(0, 2000).join('\n')); setResult(null); }}>{zh ? '导出 RGB 串' : '→ RGB text'}</button>
        </div>
      </div>
      <div className="ff-tool">
        <span className="ff-label">{zh ? '双图组合（异或/加减常用于双图隐写）' : 'Combine two images'}</span>
        <div className="ff-row">
          <input
            type="file"
            accept="image/*"
            aria-label={zh ? '第二张图' : 'Second image'}
            onChange={event => {
              const file = event.target.files?.[0];
              if (file === undefined) return;
              void readSecondImage(file).then(
                loaded => setSecond(loaded),
                error => notifications.show({ message: (error as Error).message, color: 'red' }),
              );
            }}
          />
          {second !== null && <span className="ff-badge">{zh ? '已载入' : 'loaded'} {second.width}×{second.height}</span>}
        </div>
        {second !== null && (
          <div className="ff-row">
            {(Object.keys(COMBINE_LABELS) as Array<keyof typeof COMBINE_LABELS>).map(op => (
              <button key={op} type="button" className="ff-button" onClick={() => {
                const outcome = combineImages(source, second, op);
                withImage(outcome.image, `combine-${op}`);
                outcome.notes.forEach(note => notifications.show({ message: note, color: 'yellow' }));
              }}>{COMBINE_LABELS[op][language]}</button>
            ))}
            <button type="button" className="ff-button" onClick={() => withImage(concatImages([source, second], 'h'), 'concat-h')}>{zh ? '横向拼接' : 'Concat H'}</button>
          </div>
        )}
      </div>
      <div className="ff-tool">
        <span className="ff-label">{zh ? '文本转图（0/1 串·坐标·RGB 串，产物常是二维码）' : 'Text → image'}</span>
        <div className="ff-row">
          {([
            ['bits', zh ? '0/1 串' : '0/1 bits'],
            ['coords', zh ? 'XY 坐标' : 'XY coords'],
            ['rgb', 'RGB'],
          ] as const).map(([value, label]) => (
            <button key={value} type="button" className={`ff-button${textMode === value ? ' ff-button-primary' : ''}`} onClick={() => setTextMode(value)}>{label}</button>
          ))}
          <input className="ff-input" style={{ width: 90 }} value={textWidth} aria-label={zh ? '宽度（可留空自动）' : 'Width (optional)'}
            placeholder={zh ? '宽度(自动)' : 'width (auto)'} onChange={event => setTextWidth(event.target.value)} />
          <button type="button" className="ff-button ff-button-primary" onClick={applyText}>{zh ? '生成' : 'Generate'}</button>
          {result !== null && <button type="button" className="ff-button" onClick={() => tryQr(result.image)}>{zh ? '识别二维码' : 'Detect QR'}</button>}
          {textMode === 'bits' && result === null && (
            <button type="button" className="ff-button" onClick={() => {
              const outcome = bitsToBfSource(textInput.replace(/[^01]/g, ''));
              const run = outcome.valid ? runBrainfuck(outcome.source) : null;
              setTextResult(run !== null && run.output !== '' ? `${zh ? 'BF 输出' : 'BF output'}: ${run.output.slice(0, 400)}` : (zh ? '位串按 8bit 转 ASCII 不构成有效 BF 程序' : 'Bit stream is not a valid BF program'));
            }}>{zh ? '按 BF 执行' : 'Run as BF'}</button>
          )}
        </div>
        <textarea
          className="ff-input"
          rows={4}
          value={textInput}
          aria-label={zh ? '文本输入（0/1、x,y 或 RGB 数据）' : 'Text input'}
          placeholder={textMode === 'bits' ? '010101…' : textMode === 'coords' ? '0,0 1,2 …' : '255,0,0 0,255,0 …'}
          onChange={event => setTextInput(event.target.value)}
        />
      </div>
      <div className="ff-tool">
        <span className="ff-label">{zh ? 'flood-fill 掩码 / QR 补定位角' : 'Flood fill / QR finder'}</span>
        <div className="ff-row">
          <input className="ff-input" style={{ width: 60 }} value={fillX} aria-label="X" onChange={event => setFillX(event.target.value)} />
          <input className="ff-input" style={{ width: 60 }} value={fillY} aria-label="Y" onChange={event => setFillY(event.target.value)} />
          <input className="ff-input" style={{ width: 70 }} value={fillTolerance} aria-label={zh ? '容差' : 'Tolerance'} placeholder={zh ? '容差' : 'tol.'} onChange={event => setFillTolerance(event.target.value)} />
          <button type="button" className="ff-button" onClick={() => {
            try {
              const outcome = floodFillMask(source, Number(fillX), Number(fillY), Number(fillTolerance) || 0);
              withImage(outcome.mask, 'flood-mask', `${zh ? '连通域' : 'Region'}: ${outcome.hitCount} ${zh ? '像素' : 'px'}`);
            } catch (error) { notifications.show({ message: (error as Error).message, color: 'red' }); }
          }}>{zh ? '提取同色连通域' : 'Flood fill'}</button>
        </div>
        <div className="ff-row">
          <input className="ff-input" style={{ width: 100 }} value={moduleSize} aria-label={zh ? '模块宽(自动)' : 'Module size (auto)'} placeholder={zh ? '模块宽(自动)' : 'module (auto)'} onChange={event => setModuleSize(event.target.value)} />
          <button type="button" className="ff-button" onClick={() => {
            try {
              const outcome = addQrFinderPatterns(source, moduleSize.trim() === '' ? undefined : { moduleSize: Number(moduleSize) });
              withImage(outcome.image, 'qr-finder', outcome.note);
              tryQr(outcome.image);
            } catch (error) { notifications.show({ message: (error as Error).message, color: 'red' }); }
          }}>{zh ? '补 QR 定位角并识别' : 'Add finder + detect'}</button>
        </div>
      </div>
      {result !== null && <ResultCanvas image={result.image} label={result.label} language={language} />}
      {result === null && textResult !== null && (
        <div className="ff-tool">
          <code className="ff-code"><FlagAutoText text={textResult.slice(0, 4000)} /></code>
          <div className="ff-row">
            <button type="button" className="ff-button" onClick={() => { void copyToClipboard(textResult); }}>{zh ? '复制' : 'Copy'}</button>
            <button type="button" className="ff-button" onClick={() => { void downloadBlob(new Blob([textResult], { type: 'text/plain' }), 'imageops-text.txt'); }}>{zh ? '下载' : 'Download'}</button>
            {textResult.length > 50 && textResult[0] !== '0' && textResult[1] !== '1' && (
              <button type="button" className="ff-button" onClick={() => {
                const restored = asciiToImage(textResult);
                withImage(restored, 'ascii-image');
              }}>{zh ? '字符画转回图片' : 'ASCII → image'}</button>
            )}
          </div>
        </div>
      )}
    </section>
  );
}

export default ImageOpsCard;
