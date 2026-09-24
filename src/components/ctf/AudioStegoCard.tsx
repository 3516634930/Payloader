import { useEffect, useMemo, useRef, useState } from 'react';
import { notifications } from '@mantine/notifications';
import { FlagAutoText } from '../codec/FlagAutoText';
import { bytesToPreviewText } from '../../utils/ctf/imagePlanes';
import {
  computeSpectrogram,
  dtmfDecode,
  extractWavLsb,
  morseDecodeAudio,
  parseWav,
} from '../../utils/ctf/audioStego';
import { copyToClipboard } from '../../utils/clipboard';

// 音频隐写卡：WAV 直接进纯函数引擎；mp3/flac/ogg 用浏览器 decodeAudioData 解成 PCM 采样后走同一套
// 引擎（LSB 仅对 WAV 有意义——有损压缩重建的采样不保留原始低位，UI 上对非 WAV 隐藏 LSB 区）。
interface AudioStegoCardProps {
  file: File;
  language: 'zh' | 'en';
}

interface DecodedAudio {
  samples: Float64Array;
  sampleRate: number;
  channels: number;
  isWav: boolean;
  bitsPerSample: number | null;
  frames: number;
}

const LSB_PREVIEW_CHARS = 2048;

// 频谱热力色（黑→深蓝→橙→白 的简易插值，亮=能量高）：v∈[0,1]。
const heatColor = (value: number): [number, number, number] => {
  const v = Math.min(1, Math.max(0, value));
  const r = Math.round(255 * Math.min(1, Math.max(0, 2.2 * v - 0.5)));
  const g = Math.round(255 * Math.min(1, Math.max(0, 1.9 * v - 0.75)));
  const b = Math.round(255 * Math.min(1, Math.max(0, v < 0.35 ? 1.15 * v + 0.25 : 1.65 - 3.6 * v)));
  return [r, g, b];
};

function AudioStegoCard({ file, language }: AudioStegoCardProps) {
  const zh = language === 'zh';
  const [decoded, setDecoded] = useState<DecodedAudio | null>(null);
  const [failed, setFailed] = useState<string | null>(null);
  const [dtmf, setDtmf] = useState<string | null>(null);
  const [morse, setMorse] = useState<{ text: string; timeline: string } | null>(null);
  const [lsbChannel, setLsbChannel] = useState(0);
  const [lsbBit, setLsbBit] = useState(0);
  const [lsbText, setLsbText] = useState<string | null>(null);
  const spectroRef = useRef<HTMLCanvasElement | null>(null);

  // 解码是异步副作用：本卡由父层按文件 key remount，state 无跨文件残留。
  useEffect(() => {
    let cancelled = false;
    const decode = async () => {
      try {
        const bytes = new Uint8Array(await file.arrayBuffer());
        try {
          const wav = parseWav(bytes);
          if (!cancelled) setDecoded({
            samples: wav.samples, sampleRate: wav.info.sampleRate, channels: wav.info.channels,
            isWav: true, bitsPerSample: wav.info.bitsPerSample, frames: wav.info.frames,
          });
          return;
        } catch {
          // 非 PCM WAV：交给浏览器解码（mp3/flac/ogg 等压缩格式）
        }
        const AudioCtx = window.AudioContext ?? (window as unknown as { webkitAudioContext: typeof AudioContext }).webkitAudioContext;
        const ctx = new AudioCtx();
        try {
          const buffer = await ctx.decodeAudioData(await file.arrayBuffer());
          const channels = buffer.numberOfChannels;
          const frames = buffer.length;
          const samples = new Float64Array(frames * channels);
          for (let channel = 0; channel < channels; channel += 1) {
            const data = buffer.getChannelData(channel);
            for (let frame = 0; frame < frames; frame += 1) samples[frame * channels + channel] = data[frame];
          }
          if (!cancelled) setDecoded({ samples, sampleRate: buffer.sampleRate, channels, isWav: false, bitsPerSample: null, frames });
        } finally {
          void ctx.close();
        }
      } catch {
        if (!cancelled) setFailed(zh ? '无法解码该音频（浏览器不支持的格式）。' : 'The browser could not decode this audio format.');
      }
    };
    void decode();
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [file]);

  // 第一通道（分析口径与引擎一致：DTMF/摩尔斯/频谱均单声道足够）。
  const mono = useMemo(() => {
    if (!decoded) return null;
    if (decoded.channels === 1) return decoded.samples;
    const out = new Float64Array(decoded.frames);
    for (let frame = 0; frame < decoded.frames; frame += 1) out[frame] = decoded.samples[frame * decoded.channels];
    return out;
  }, [decoded]);

  // 频谱图：引擎算矩阵，这里只做像素映射（y 轴翻转：低频在下）。
  const spectrogram = useMemo(() => (mono && decoded ? computeSpectrogram(mono, decoded.sampleRate) : null), [mono, decoded]);

  useEffect(() => {
    const canvas = spectroRef.current;
    if (!canvas || !spectrogram) return;
    const { matrix, bins, frames } = spectrogram;
    canvas.width = Math.max(1, frames);
    canvas.height = Math.max(1, bins);
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    const image = ctx.createImageData(canvas.width, canvas.height);
    for (let frame = 0; frame < frames; frame += 1) {
      for (let bin = 0; bin < bins; bin += 1) {
        const [r, g, b] = heatColor(matrix[frame * bins + bin]);
        const offset = ((bins - 1 - bin) * frames + frame) * 4;
        image.data[offset] = r;
        image.data[offset + 1] = g;
        image.data[offset + 2] = b;
        image.data[offset + 3] = 255;
      }
    }
    ctx.putImageData(image, 0, 0);
  }, [spectrogram]);

  const runLsb = () => {
    if (!decoded || !decoded.isWav) return;
    const bytes = extractWavLsb({ info: { sampleRate: decoded.sampleRate, channels: decoded.channels, bitsPerSample: decoded.bitsPerSample ?? 16, dataBytes: 0, frames: decoded.frames, formatTag: 1 }, samples: decoded.samples }, { channel: lsbChannel, bit: lsbBit });
    setLsbText(bytesToPreviewText(bytes, LSB_PREVIEW_CHARS));
  };

  const copyText = (text: string) => {
    void copyToClipboard(text).then(ok => {
      if (!ok) notifications.show({ message: zh ? '复制失败，请手动选择文本。' : 'Copy failed; select the text manually.', color: 'red' });
      else notifications.show({ message: zh ? '已复制。' : 'Copied.', color: 'teal', autoClose: 1600 });
    });
  };

  if (failed) {
    return (
      <section id="ff-card-audio" className="ff-card" aria-label={zh ? '音频隐写分析' : 'Audio steganography'}>
        <div className="ff-card-head"><strong>{zh ? '音频隐写分析' : 'Audio steganography'}</strong></div>
        <p className="ff-note">{failed}</p>
      </section>
    );
  }

  return (
    <section id="ff-card-audio" className="ff-card" aria-label={zh ? '音频隐写分析' : 'Audio steganography'}>
      <div className="ff-card-head">
        <strong>{zh ? '音频隐写分析' : 'Audio steganography'}</strong>
        {decoded && (
          <span className="ff-badge">
            {decoded.sampleRate} Hz · {decoded.channels}ch · {(decoded.frames / decoded.sampleRate).toFixed(1)}s{decoded.isWav && decoded.bitsPerSample ? ` · ${decoded.bitsPerSample}bit` : ''}
          </span>
        )}
      </div>
      {!decoded && <p className="ff-note">{zh ? '正在解码音频…' : 'Decoding audio…'}</p>}
      {decoded && mono && (
        <>
          <div className="ff-tool">
            <span className="ff-label">{zh ? '频谱图（隐藏文字/摩尔斯/SSTV 常藏在频谱里；y 轴低频在下，亮色 = 能量高）' : 'Spectrogram (hidden text/Morse/SSTV often live here; low freq at bottom, bright = energy)'}</span>
            {spectrogram && (
              <canvas ref={spectroRef} className="ff-spectrogram" aria-label={zh ? '频谱图' : 'Spectrogram'} />
            )}
          </div>
          <div className="ff-tool">
            <span className="ff-label">{zh ? '信号解码（DTMF 电话拨号音 / 摩尔斯电码）' : 'Signal decoding (DTMF tones / Morse code)'}</span>
            <div className="ff-row">
              <button type="button" className="ff-button" onClick={() => setDtmf(dtmfDecode(mono, decoded.sampleRate) || (zh ? '（未检出 DTMF 按键）' : '(no DTMF digits detected)'))}>
                {zh ? 'DTMF 解码' : 'Decode DTMF'}
              </button>
              <button type="button" className="ff-button" onClick={() => setMorse(morseDecodeAudio(mono, decoded.sampleRate))}>
                {zh ? '摩尔斯解码' : 'Decode Morse'}
              </button>
            </div>
            {dtmf !== null && (
              <code className="ff-code"><FlagAutoText text={dtmf} /></code>
            )}
            {morse && (
              <code className="ff-code">
                {`${zh ? '文本' : 'Text'}: ${morse.text || (zh ? '（空）' : '(empty)')}\n${zh ? '原始点划' : 'Raw timeline'}: ${morse.timeline}`}
              </code>
            )}
          </div>
          {decoded.isWav && (
            <div className="ff-tool">
              <span className="ff-label">{zh ? 'WAV LSB 提取（帧序、高位在前组字节）' : 'WAV LSB extraction (frame order, MSB first)'}</span>
              <div className="ff-row">
                <select className="ff-select" value={lsbChannel} aria-label={zh ? '提取通道' : 'Channel'} onChange={event => setLsbChannel(Number(event.target.value))}>
                  {Array.from({ length: decoded.channels }, (_, index) => index).map(channel => (
                    <option key={channel} value={channel}>{zh ? `通道 ${channel}` : `Channel ${channel}`}</option>
                  ))}
                </select>
                <select className="ff-select" value={lsbBit} aria-label={zh ? '提取位' : 'Bit'} onChange={event => setLsbBit(Number(event.target.value))}>
                  {(decoded.bitsPerSample && decoded.bitsPerSample >= 16 ? [0, 1, 2, 3, 4, 5, 6, 7] : [0, 1, 2, 3]).map(bit => <option key={bit} value={bit}>bit {bit}</option>)}
                </select>
                <button type="button" className="ff-button ff-button-primary" onClick={runLsb}>{zh ? '提取' : 'Extract'}</button>
              </div>
              {lsbText !== null && (
                <>
                  <code className="ff-code"><FlagAutoText text={lsbText} /></code>
                  <div className="ff-row">
                    <button type="button" className="ff-button" onClick={() => copyText(lsbText)}>{zh ? '复制文本' : 'Copy text'}</button>
                  </div>
                </>
              )}
            </div>
          )}
        </>
      )}
    </section>
  );
}

export default AudioStegoCard;
