import { useCallback, useRef, useState } from 'react';
import { notifications } from '@mantine/notifications';
import { FlagAutoText } from '../codec/FlagAutoText';
import type { PlaneImage } from './ImagePlanesCard';
import { arnoldInverse, arnoldPeriod, arnoldTransform } from '../../utils/ctf/arnold';
import { rasterCompact, rasterPhasePlan, stereogramDiff, stereogramEstimateOffset } from '../../utils/ctf/rasterStego';
import { blindWatermarkDecode } from '../../utils/ctf/blindWatermark';
import { pixelJihadDecode } from '../../utils/ctf/pixelJihad';
import { runImageProgram } from '../../utils/ctf/esolangs';
import { decodeQrCodes } from '../../utils/ctf/qrDecode';
import { scaleNearest } from '../../utils/ctf/imageOps';
import { downloadBlob } from '../../utils/download';

// 置乱与频域隐写卡（批次 SI·C/B 线）：Arnold 猫脸/光栅相位/Stereogram 偏移差分/盲水印双图提取/
// PixelJihad/Brainloller+Braincopter。全部纯本地运算。
interface ImageStegoCardProps {
  image: PlaneImage;
  language: 'zh' | 'en';
}

type AnyImage = { data: Uint8ClampedArray | ArrayLike<number>; width: number; height: number };

const RASTER_THUMB = 110;

function StegoCanvas({ image, scaleTo, language }: { image: AnyImage; scaleTo: number; language: 'zh' | 'en' }) {
  const ref = useRef<HTMLCanvasElement | null>(null);
  const attach = useCallback(
    (node: HTMLCanvasElement | null) => {
      ref.current = node;
      if (node === null) return;
      const source = document.createElement('canvas');
      source.width = image.width;
      source.height = image.height;
      const sourceCtx = source.getContext('2d');
      if (sourceCtx === null) return;
      const clamped = image.data instanceof Uint8ClampedArray ? image.data : new Uint8ClampedArray(image.data);
      sourceCtx.putImageData(new ImageData(clamped as Uint8ClampedArray<ArrayBuffer>, image.width, image.height), 0, 0);
      const scale = Math.min(1, scaleTo / Math.max(image.width, image.height));
      node.width = Math.max(1, Math.round(image.width * scale));
      node.height = Math.max(1, Math.round(image.height * scale));
      const ctx = node.getContext('2d');
      if (ctx === null) return;
      ctx.imageSmoothingEnabled = false;
      ctx.drawImage(source, 0, 0, node.width, node.height);
    },
    [image, scaleTo],
  );
  const download = useCallback(() => {
    const canvas = document.createElement('canvas');
    canvas.width = image.width;
    canvas.height = image.height;
    const ctx = canvas.getContext('2d');
    if (ctx === null) return;
    const clamped = image.data instanceof Uint8ClampedArray ? image.data : new Uint8ClampedArray(image.data);
    ctx.putImageData(new ImageData(clamped as Uint8ClampedArray<ArrayBuffer>, image.width, image.height), 0, 0);
    void canvas.toBlob(blob => {
      if (blob !== null) void downloadBlob(blob, 'stego-result.png');
    });
  }, [image]);
  void language;
  return (
    <div className="ff-row">
      <canvas ref={attach} className="ff-canvas" aria-label="result" />
      <button type="button" className="ff-button" onClick={download}>PNG</button>
    </div>
  );
}

const readSecondImage = async (file: File): Promise<AnyImage> => {
  const bitmap = await createImageBitmap(file);
  const width = bitmap.width;
  const height = bitmap.height;
  const canvas = document.createElement('canvas');
  canvas.width = width;
  canvas.height = height;
  const ctx = canvas.getContext('2d');
  if (ctx === null) throw new Error('canvas 2d 上下文不可用');
  ctx.drawImage(bitmap, 0, 0);
  bitmap.close();
  if (width * height > 4_000_000) throw new Error(`第二张图 ${width}×${height} 超过 400 万像素上限，请先缩小`);
  return { data: ctx.getImageData(0, 0, width, height).data, width, height };
};

function ImageStegoCard({ image, language }: ImageStegoCardProps) {
  const zh = language === 'zh';
  const source: AnyImage = { data: image.rgba, width: image.width, height: image.height };
  const square = image.width === image.height;
  const [result, setResult] = useState<AnyImage | null>(null);
  const [textOut, setTextOut] = useState<string | null>(null);
  const [arnoldIterations, setArnoldIterations] = useState('1');
  const [arnoldA, setArnoldA] = useState('1');
  const [arnoldB, setArnoldB] = useState('1');
  const [rasterCandidates, setRasterCandidates] = useState<Array<{ axis: string; period: number; phase: number; image: AnyImage }> | null>(null);
  const [stereoOffset, setStereoOffset] = useState('100');
  const [bwSecond, setBwSecond] = useState<AnyImage | null>(null);
  const [bwSeed, setBwSeed] = useState('20160930');
  const [bwAlpha, setBwAlpha] = useState('3');
  const [pjPassword, setPjPassword] = useState('');

  const arnoldOptions = () => {
    const iterations = Math.max(1, Number(arnoldIterations) || 1);
    const a = Number(arnoldA) || 1;
    const b = Number(arnoldB) || 1;
    return { iterations, a, b };
  };

  return (
    <section id="ff-card-imagestego" className="ff-card" aria-label={zh ? '置乱与频域隐写' : 'Scramble & frequency stego'}>
      <div className="ff-card-head">
        <strong>{zh ? '置乱与频域隐写' : 'Scramble & frequency stego'}</strong>
        <span className="ff-badge">{image.width}×{image.height}</span>
      </div>

      <div className="ff-tool">
        <span className="ff-label">{zh ? 'Arnold 猫脸变换（矩阵 [[1,a],[b,ab+1]]，a=b=1 标准）' : 'Arnold cat map'}</span>
        {!square && <p className="ff-note">{zh ? '非方阵图像需先裁成正方形（Arnold 要求 N×N）。' : 'Arnold requires a square image.'}</p>}
        {square && (
          <>
            <div className="ff-row">
              <input className="ff-input" style={{ width: 80 }} value={arnoldIterations} aria-label={zh ? '迭代次数' : 'Iterations'} onChange={event => setArnoldIterations(event.target.value)} />
              <input className="ff-input" style={{ width: 50 }} value={arnoldA} aria-label="a" onChange={event => setArnoldA(event.target.value)} />
              <input className="ff-input" style={{ width: 50 }} value={arnoldB} aria-label="b" onChange={event => setArnoldB(event.target.value)} />
              <button type="button" className="ff-button ff-button-primary" onClick={() => { setResult(arnoldTransform(source, arnoldOptions())); setTextOut(null); }}>{zh ? '置乱' : 'Scramble'}</button>
              <button type="button" className="ff-button" onClick={() => { setResult(arnoldInverse(source, arnoldOptions())); setTextOut(null); }}>{zh ? '还原' : 'Restore'}</button>
              <span className="ff-badge">
                {zh ? `周期 ${arnoldPeriod(image.width, Number(arnoldA) || 1, Number(arnoldB) || 1)}` : `Period ${arnoldPeriod(image.width, Number(arnoldA) || 1, Number(arnoldB) || 1)}`}
              </span>
            </div>
            <p className="ff-note">{zh ? '无迭代次数时按周期穷举：依次试「还原 1..周期-1 次」目检。' : 'Brute-force tip: restore 1..period-1 times and eyeball.'}</p>
          </>
        )}
      </div>

      <div className="ff-tool">
        <span className="ff-label">{zh ? '光栅栅栏图（周期 2-10 相位抽取）' : 'Raster interleaving (period 2-10)'}</span>
        <div className="ff-row">
          <button type="button" className="ff-button" onClick={() => {
            // 元数据先行 + 懒算（reviewer P1：逐候选物化整图在 4M 像素图上瞬时分配 >1GB）
            const plan = rasterPhasePlan(image.width, image.height, 10).slice(0, 60);
            setRasterCandidates(plan.map(item => ({ axis: item.axis, period: item.period, phase: item.phase, image: rasterCompact(source, item.axis, item.period, item.phase) })));
          }}>{zh ? '全相位扫描' : 'Scan all phases'}</button>
          {rasterCandidates !== null && <span className="ff-badge">{rasterCandidates.length} {zh ? '候选' : 'candidates'}</span>}
        </div>
        {rasterCandidates !== null && (
          <div className="ff-row" style={{ flexWrap: 'wrap' }}>
            {rasterCandidates.map(item => (
              <div key={`${item.axis}-${item.period}-${item.phase}`} style={{ textAlign: 'center' }}>
                <StegoCanvas image={item.image} scaleTo={RASTER_THUMB} language={language} />
                <span className="ff-badge">{item.axis === 'x' ? '列' : '行'}p{item.period}·φ{item.phase}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="ff-tool">
        <span className="ff-label">{zh ? 'Stereogram 立体图求解（偏移差分显深度）' : 'Stereogram solver'}</span>
        <div className="ff-row">
          <input className="ff-input" style={{ width: 80 }} value={stereoOffset} aria-label="offset" onChange={event => setStereoOffset(event.target.value)} />
          <button type="button" className="ff-button" onClick={() => { setResult(stereogramDiff(source, Math.max(1, Number(stereoOffset) || 1))); setTextOut(null); }}>{zh ? '差分' : 'Diff'}</button>
          <button type="button" className="ff-button" onClick={() => {
            const estimate = stereogramEstimateOffset(source, 32, 256);
            setStereoOffset(String(estimate.bestOffset));
            setResult(stereogramDiff(source, estimate.bestOffset));
            setTextOut(null);
          }}>{zh ? '自动估周期' : 'Auto offset'}</button>
        </div>
      </div>

      <div className="ff-tool">
        <span className="ff-label">{zh ? '盲水印双图提取（chishaxie FFT 版，需原图+水印图）' : 'Blind watermark (FFT)'}</span>
        <div className="ff-row">
          <input
            type="file"
            accept="image/*"
            aria-label={zh ? '水印图（第二张）' : 'Watermarked image'}
            onChange={event => {
              const file = event.target.files?.[0];
              if (file === undefined) return;
              void readSecondImage(file).then(
                loaded => setBwSecond(loaded),
                error => notifications.show({ message: (error as Error).message, color: 'red' }),
              );
            }}
          />
          {bwSecond !== null && <span className="ff-badge">{bwSecond.width}×{bwSecond.height}</span>}
        </div>
        <div className="ff-row">
          <input className="ff-input" style={{ width: 110 }} value={bwSeed} aria-label="seed" onChange={event => setBwSeed(event.target.value)} />
          <input className="ff-input" style={{ width: 60 }} value={bwAlpha} aria-label="alpha" onChange={event => setBwAlpha(event.target.value)} />
          <button type="button" className="ff-button ff-button-primary" disabled={bwSecond === null} onClick={() => {
            try {
              setResult(blindWatermarkDecode(source, bwSecond!, { seed: Number(bwSeed), alpha: Number(bwAlpha) }));
              setTextOut(null);
            } catch (error) { notifications.show({ message: (error as Error).message, color: 'red' }); }
          }}>{zh ? '提取水印' : 'Extract'}</button>
        </div>
      </div>

      <div className="ff-tool">
        <span className="ff-label">{zh ? 'PixelJihad 提取 / Brainloller·Braincopter 执行' : 'PixelJihad / brainloller·braincopter'}</span>
        <div className="ff-row">
          <input className="ff-input" style={{ width: 130 }} value={pjPassword} aria-label={zh ? '口令（可空）' : 'Password'} placeholder={zh ? '口令(可空)' : 'password'} onChange={event => setPjPassword(event.target.value)} />
          <button type="button" className="ff-button" onClick={() => {
            try {
              setTextOut(`${zh ? 'PixelJihad' : 'PixelJihad'}: ${pixelJihadDecode(source, pjPassword)}`);
              setResult(null);
            } catch (error) { notifications.show({ message: (error as Error).message, color: 'red' }); }
          }}>PixelJihad</button>
          {(['brainloller', 'braincopter'] as const).map(flavor => (
            <button key={flavor} type="button" className="ff-button" onClick={() => {
              const outcome = runImageProgram(source, flavor);
              setTextOut(`${flavor}: ${outcome.run.output !== '' ? outcome.run.output.slice(0, 400) : (outcome.run.error ?? (zh ? '（无输出）' : '(no output)'))}`);
              setResult(null);
            }}>{flavor === 'brainloller' ? 'Brainloller' : 'Braincopter'}</button>
          ))}
        </div>
      </div>

      {result !== null && (
        <div className="ff-tool">
          <StegoCanvas image={result} scaleTo={360} language={language} />
          <button type="button" className="ff-button" onClick={() => {
            const scaled = result.width * result.height <= 128 * 128 ? scaleNearest(result, 4) : result;
            const hits = decodeQrCodes(scaled.data as ArrayLike<number>, scaled.width, scaled.height);
            setTextOut(hits.length > 0 ? `${zh ? '二维码命中' : 'QR hit'}: ${hits.map(hit => hit.text).join(' | ')}` : (zh ? '结果图中未识别出二维码' : 'No QR in result'));
          }}>{zh ? '识别结果图二维码' : 'Detect QR in result'}</button>
        </div>
      )}
      {textOut !== null && <code className="ff-code"><FlagAutoText text={textOut.slice(0, 4000)} /></code>}
    </section>
  );
}

export default ImageStegoCard;
