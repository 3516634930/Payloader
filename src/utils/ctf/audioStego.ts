// 音频信号处理纯函数引擎（misc 域音频隐写四件套）：WAV 解析 / LSB 提取 / DTMF 解码 /
// 摩尔斯音频识别 / 频谱矩阵。全部只读输入、零浏览器依赖（FFT 自写迭代 Cooley-Tukey），
// 可在 node --test 直接跑。mp3/flac/ogg 等压缩格式解码由组件层 decodeAudioData 负责，
// 解出样本后转 Float64 走同一套接口。
// dtmfDecode/morseDecodeAudio/computeSpectrogram 均按单声道设计：多通道 WAV 由调用方
// 先取第一通道再传入（mono 分析足够，LSB 才需要逐通道区分）。

// 交织样本总数上限（内存红线：≈3 分钟 48kHz 立体声；超出后 parseWav 截断解码，
// info 的 frames/dataBytes 按截断后计，避免百 MB 级 Float64Array）。
export const MAX_WAV_SAMPLES = 1 << 24;

export interface WavInfo {
  sampleRate: number;
  channels: number;
  bitsPerSample: number;
  dataBytes: number;
  frames: number;
  formatTag: number;
}

export interface DecodedWav {
  info: WavInfo;
  samples: Float64Array; // 归一到 [-1,1]，多通道按帧交织保留（L,R,L,R,...）
}

const ascii4 = (bytes: Uint8Array, offset: number): string => {
  let out = '';
  for (let index = 0; index < 4; index += 1) out += String.fromCharCode(bytes[offset + index]);
  return out;
};

const u16le = (bytes: Uint8Array, offset: number): number =>
  bytes[offset] | (bytes[offset + 1] << 8);

const u32le = (bytes: Uint8Array, offset: number): number =>
  (bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24)) >>> 0;

// RIFF/WAVE 解析：只认 PCM（formatTag=1）与 WAVE_FORMAT_EXTENSIBLE(0xFFFE) 的 PCM 基础子格式，
// 其余编码（a-law/μ-law/ADPCM 等）抛中文错误提示走组件层 decodeAudioData。
export const parseWav = (bytes: Uint8Array): DecodedWav => {
  if (bytes.length < 12 || ascii4(bytes, 0) !== 'RIFF' || ascii4(bytes, 8) !== 'WAVE') {
    throw new Error('不是有效 WAV 文件（缺少 RIFF/WAVE 头），压缩音频请走组件层 decodeAudioData 解码');
  }
  let fmtTag = -1;
  let channels = 0;
  let sampleRate = 0;
  let bits = 0;
  let dataOffset = -1;
  let dataEnd = -1;
  let pos = 12;
  while (pos + 8 <= bytes.length) {
    const id = ascii4(bytes, pos);
    const size = u32le(bytes, pos + 4);
    const bodyStart = pos + 8;
    const bodyEnd = Math.min(bodyStart + size, bytes.length); // chunk 声称尺寸越过文件尾时按实际截住
    if (id === 'fmt ' && fmtTag === -1) {
      if (bodyEnd - bodyStart < 16) throw new Error('fmt chunk 残缺，无法解析 WAV 参数');
      fmtTag = u16le(bytes, bodyStart);
      if (fmtTag === 0xfffe) {
        // WAVE_FORMAT_EXTENSIBLE：基础子格式在 subFormat GUID 的 data1 低 16 位（fmt 偏移 24）
        if (bodyEnd - bodyStart < 40) throw new Error('WAVE_FORMAT_EXTENSIBLE 的 fmt chunk 残缺');
        fmtTag = u16le(bytes, bodyStart + 24);
      }
      channels = u16le(bytes, bodyStart + 2);
      sampleRate = u32le(bytes, bodyStart + 4);
      bits = u16le(bytes, bodyStart + 14);
    } else if (id === 'data' && dataOffset === -1) {
      dataOffset = bodyStart;
      dataEnd = bodyEnd;
    }
    pos = bodyStart + size + (size & 1); // RIFF chunk 按 2 字节对齐补偶
  }
  if (fmtTag === -1) throw new Error('缺少 fmt chunk，无法解析 WAV 参数');
  if (fmtTag !== 1) {
    throw new Error(`不支持的 WAV 编码 formatTag=${fmtTag}（仅 PCM 8/16/24/32bit），请走组件层 decodeAudioData 解码`);
  }
  if (channels < 1) throw new Error(`无效声道数 ${channels}`);
  if (sampleRate < 1) throw new Error(`无效采样率 ${sampleRate}`);
  if (bits !== 8 && bits !== 16 && bits !== 24 && bits !== 32) {
    throw new Error(`不支持的 PCM 位深 ${bits}bit（仅 8/16/24/32）`);
  }
  const bytesPerSample = bits >> 3;
  const blockAlign = channels * bytesPerSample;
  let frames = Math.floor((dataEnd - dataOffset) / blockAlign);
  if (frames * channels > MAX_WAV_SAMPLES) frames = Math.floor(MAX_WAV_SAMPLES / channels);
  if (frames < 1) throw new Error('data chunk 为空或不足一帧，无可分析样本');
  const samples = new Float64Array(frames * channels);
  const scale = bits === 8 ? 0x80 : bits === 16 ? 0x8000 : bits === 24 ? 0x800000 : 0x80000000;
  let out = 0;
  for (let frame = 0; frame < frames; frame += 1) {
    for (let channel = 0; channel < channels; channel += 1) {
      const base = dataOffset + (frame * channels + channel) * bytesPerSample;
      let value: number;
      if (bits === 8) value = bytes[base] - 0x80; // 8bit PCM 无符号
      else if (bits === 16) value = ((bytes[base] | (bytes[base + 1] << 8)) << 16) >> 16;
      else if (bits === 24) {
        value = bytes[base] | (bytes[base + 1] << 8) | (bytes[base + 2] << 16);
        if (value & 0x800000) value -= 0x1000000; // 24bit 手工符号扩展
      } else {
        value = (bytes[base] | (bytes[base + 1] << 8) | (bytes[base + 2] << 16) | (bytes[base + 3] << 24)) | 0;
      }
      samples[out] = value / scale;
      out += 1;
    }
  }
  return {
    info: { sampleRate, channels, bitsPerSample: bits, dataBytes: frames * blockAlign, frames, formatTag: fmtTag },
    samples,
  };
};

export interface LsbOptions {
  channel: number;
  bit: number;
  // 单次提取字节上限（红线 64KB，避免巨音频全量提取卡 UI）。
  maxBytes?: number;
}

// WAV LSB 提取：指定通道指定位平面，按帧序（音频的"行序"）采样，MSB-first 组字节
// （与图片域 extractLsbBytes 同一口径）。样本先还原回整数再取位——归一化 Float64 与
// 整数在 2 的幂分母下精确互转，位信息不丢失。
export const extractWavLsb = (wav: DecodedWav, options: LsbOptions): Uint8Array => {
  const { channels, bitsPerSample: bits, frames } = wav.info;
  if (options.channel < 0 || options.channel >= channels) {
    throw new Error(`通道 ${options.channel} 越界（该文件共 ${channels} 个声道）`);
  }
  if (options.bit < 0 || options.bit >= bits) {
    throw new Error(`位平面 ${options.bit} 超出 ${bits}bit 样本范围`);
  }
  const maxBytes = options.maxBytes ?? 64 * 1024;
  const count = Math.min(frames, maxBytes * 8);
  const scale = bits === 8 ? 0x80 : bits === 16 ? 0x8000 : bits === 24 ? 0x800000 : 0x80000000;
  const mask = 1 << options.bit;
  const out = new Uint8Array(Math.ceil(count / 8));
  let byte = 0;
  let filled = 0;
  let written = 0;
  for (let frame = 0; frame < count; frame += 1) {
    const sample = wav.samples[frame * channels + options.channel];
    const integer = bits === 8 ? Math.round(sample * scale) + 0x80 : Math.round(sample * scale);
    byte = (byte << 1) | ((integer & mask) === 0 ? 0 : 1);
    filled += 1;
    if (filled === 8) {
      out[written] = byte;
      written += 1;
      byte = 0;
      filled = 0;
    }
  }
  if (filled > 0) out[written] = byte << (8 - filled);
  return out;
};

// ITU Q.23 DTMF 频率表（Goertzel 逐频检测，无需 FFT）。
const DTMF_LOW = [697, 770, 852, 941];
const DTMF_HIGH = [1209, 1336, 1477, 1633];
const DTMF_KEYS = [
  ['1', '2', '3', 'A'],
  ['4', '5', '6', 'B'],
  ['7', '8', '9', 'C'],
  ['*', '0', '#', 'D'],
];

// DTMF 解码：25ms 帧窗 + 10ms 步进；帧 RMS 做自适应静音门（全局长峰值 RMS 的 8%），
// 过门帧对 8 个频率跑 Goertzel 取双频，组内最优/次优功率比 ≥1.25 且双频功率占帧能量
// ≥30% 才判有效（压制跨键混叠帧与噪声误报）；连续同键 ≥2 帧记一次按键，容忍 1 帧毛刺断裂。
export const dtmfDecode = (samples: Float64Array, sampleRate: number): string => {
  if (samples.length === 0 || sampleRate < 1) return '';
  const frameLen = Math.max(64, Math.round(sampleRate * 0.025)); // 最短可分辨低频组 73Hz 间距
  const hop = Math.max(1, Math.round(sampleRate * 0.01));
  const frameCount = Math.floor((samples.length - frameLen) / hop) + 1;
  if (frameCount < 1) return '';
  const rms = new Float64Array(frameCount);
  let maxRms = 0;
  for (let frame = 0; frame < frameCount; frame += 1) {
    const start = frame * hop;
    let acc = 0;
    for (let index = 0; index < frameLen; index += 1) {
      const value = samples[start + index];
      acc += value * value;
    }
    rms[frame] = Math.sqrt(acc / frameLen);
    if (rms[frame] > maxRms) maxRms = rms[frame];
  }
  if (maxRms < 1e-6) return ''; // 全零静音
  const gate = maxRms * 0.08;
  const coeffs = new Float64Array(8);
  for (let index = 0; index < 8; index += 1) {
    const freq = index < 4 ? DTMF_LOW[index] : DTMF_HIGH[index - 4];
    coeffs[index] = (2 * Math.cos((2 * Math.PI * freq) / sampleRate));
  }
  const power = new Float64Array(8);
  const detected: string[] = new Array<string>(frameCount).fill('');
  for (let frame = 0; frame < frameCount; frame += 1) {
    if (rms[frame] < gate) continue;
    const start = frame * hop;
    for (let index = 0; index < 8; index += 1) {
      const coeff = coeffs[index];
      let s1 = 0;
      let s2 = 0;
      for (let i = 0; i < frameLen; i += 1) {
        const s = samples[start + i] + coeff * s1 - s2;
        s2 = s1;
        s1 = s;
      }
      power[index] = s1 * s1 + s2 * s2 - coeff * s1 * s2;
    }
    let lowBest = 0;
    let lowSecond = 0;
    let lowIndex = 0;
    for (let index = 0; index < 4; index += 1) {
      if (power[index] > lowBest) {
        lowSecond = lowBest;
        lowBest = power[index];
        lowIndex = index;
      } else if (power[index] > lowSecond) {
        lowSecond = power[index];
      }
    }
    let highBest = 0;
    let highSecond = 0;
    let highIndex = 4;
    for (let index = 4; index < 8; index += 1) {
      if (power[index] > highBest) {
        highSecond = highBest;
        highBest = power[index];
        highIndex = index;
      } else if (power[index] > highSecond) {
        highSecond = power[index];
      }
    }
    // 双频能量门（量纲对齐）：Goertzel power 是未归一 |X(f)|² ≈ 能量×N/2，乘 2/N 归一后
    // 才与帧能量 rms²×frameLen 同量纲可比（纯音时两者相等）；否则 0.3 阈值等效噪声容忍百倍于信号。
    const energy = rms[frame] * rms[frame] * frameLen;
    if (lowBest > lowSecond * 1.25 && highBest > highSecond * 1.25 && ((lowBest + highBest) * 2) / frameLen > 0.3 * energy) {
      detected[frame] = DTMF_KEYS[lowIndex][highIndex - 4];
    }
  }
  // 按帧折叠成按键序列：同键连续段（容忍 1 帧断裂）计一次，最短 2 帧防单帧噪声
  let result = '';
  let index = 0;
  while (index < frameCount) {
    const key = detected[index];
    if (key === '') {
      index += 1;
      continue;
    }
    let run = 0;
    let gap = 0;
    let cursor = index;
    while (cursor < frameCount) {
      if (detected[cursor] === key) {
        run += 1;
        gap = 0;
        cursor += 1;
      } else if (detected[cursor] === '' && gap === 0) {
        gap = 1;
        cursor += 1;
      } else {
        break;
      }
    }
    if (run >= 2) result += key;
    index = cursor;
  }
  return result;
};

// 国际摩尔斯电码表（含常见标点；未收录序列输出 ? 便于人工核对 timeline）。
const MORSE_TABLE: Record<string, string> = {
  '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F', '--.': 'G',
  '....': 'H', '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N',
  '---': 'O', '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
  '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y', '--..': 'Z',
  '-----': '0', '.----': '1', '..---': '2', '...--': '3', '....-': '4', '.....': '5',
  '-....': '6', '--...': '7', '---..': '8', '----.': '9',
  '.-.-.-': '.', '--..--': ',', '..--..': '?', '-..-.': '/', '-....-': '-', '-.--.': '(',
  '-.--.-': ')', '.----.': "'", '---...': ':', '-.-.-.': ';', '-...-': '=', '.-.-.': '+',
  '..--.-': '_', '.-..-.': '"', '...-..-': '$', '.--.-.': '@',
};

// 摩尔斯音频识别：5ms 能量窗 1ms 步进做包络检波（整流+低通的等价离散实现），
// 峰谷中点自适应阈值二值化 → 交替电平段；最短有效 on 段自适应出 1 单位（点），
// on >2 单位判划，间隔 <2 单位为元素内、2~5 单位为字母间隔、≥5 单位为词间隔。
export const morseDecodeAudio = (samples: Float64Array, sampleRate: number): { text: string; timeline: string } => {
  if (samples.length === 0 || sampleRate < 1) return { text: '', timeline: '' };
  const winLen = Math.max(1, Math.round(sampleRate * 0.005));
  const hop = Math.max(1, Math.round(sampleRate * 0.001));
  const frameCount = Math.max(1, Math.floor((samples.length - winLen) / hop) + 1);
  const env = new Float64Array(frameCount);
  let peak = 0;
  let floorLevel = Infinity;
  for (let frame = 0; frame < frameCount; frame += 1) {
    const start = frame * hop;
    const end = Math.min(start + winLen, samples.length);
    let acc = 0;
    for (let index = start; index < end; index += 1) acc += samples[index] * samples[index];
    env[frame] = Math.sqrt(acc / Math.max(1, end - start));
    if (env[frame] > peak) peak = env[frame];
    if (env[frame] < floorLevel) floorLevel = env[frame];
  }
  if (peak < 1e-6 || peak - floorLevel < 1e-6) return { text: '', timeline: '' }; // 全零/直流静音
  const threshold = floorLevel + (peak - floorLevel) * 0.5;
  const runs: Array<{ on: boolean; len: number }> = [];
  let level = env[0] > threshold;
  let len = 1;
  for (let frame = 1; frame < frameCount; frame += 1) {
    const on = env[frame] > threshold;
    if (on === level) {
      len += 1;
    } else {
      runs.push({ on: level, len });
      level = on;
      len = 1;
    }
  }
  runs.push({ on: level, len });
  // 折叠成有效脉冲与脉冲间隔（<3 窗口的 on 段视为边沿毛刺丢弃，两侧 off 顺延合并）
  const pulses: number[] = [];
  const gaps: number[] = [];
  let pendingOff = 0;
  for (const run of runs) {
    if (run.on) {
      if (run.len >= 3) {
        pulses.push(run.len);
        gaps.push(pendingOff);
        pendingOff = 0;
      }
    } else {
      pendingOff += run.len;
    }
  }
  if (pulses.length === 0) return { text: '', timeline: '' };
  gaps.shift(); // 首脉冲前的静音无意义
  let unit = Infinity;
  for (const pulse of pulses) if (pulse < unit) unit = pulse;
  const parts: string[] = []; // timeline 片段：摩尔斯字母与词分隔 '/'
  let letter = '';
  for (let index = 0; index < pulses.length; index += 1) {
    letter += pulses[index] > unit * 2 ? '-' : '.';
    const gap = index + 1 < pulses.length ? gaps[index] : 0; // 尾脉冲后无间隔概念，不发分隔
    if (gap >= unit * 5) {
      parts.push(letter, '/');
      letter = '';
    } else if (gap >= unit * 2) {
      parts.push(letter);
      letter = '';
    }
  }
  if (letter !== '') parts.push(letter);
  const timeline = parts.join(' ');
  const words: string[] = [];
  let word = '';
  for (const part of parts) {
    if (part === '/') {
      if (word !== '') {
        words.push(word);
        word = '';
      }
    } else {
      word += MORSE_TABLE[part] ?? '?';
    }
  }
  if (word !== '') words.push(word);
  return { text: words.join(' '), timeline };
};

export interface SpectrogramOptions {
  fftSize?: number;
  hop?: number;
  maxFrames?: number;
}

export interface SpectrogramResult {
  matrix: Float64Array; // 行主序 frames×bins，值域 [0,1]（全局峰值=1，-96dB=0）
  bins: number;
  frames: number;
  maxFreq: number;
}

// 迭代 radix-2 Cooley-Tukey FFT：位反转置换 + 蝶形，原位变换（长度须为 2 的幂）。
const fftRadix2 = (re: Float64Array, im: Float64Array): void => {
  const n = re.length;
  for (let i = 1, j = 0; i < n; i += 1) {
    let bit = n >> 1;
    for (; (j & bit) !== 0; bit >>= 1) j ^= bit;
    j |= bit;
    if (i < j) {
      const swapRe = re[i];
      re[i] = re[j];
      re[j] = swapRe;
      const swapIm = im[i];
      im[i] = im[j];
      im[j] = swapIm;
    }
  }
  for (let len = 2; len <= n; len <<= 1) {
    const angle = (-2 * Math.PI) / len;
    const wRe = Math.cos(angle);
    const wIm = Math.sin(angle);
    const half = len >> 1;
    for (let base = 0; base < n; base += len) {
      let curRe = 1;
      let curIm = 0;
      for (let k = 0; k < half; k += 1) {
        const i0 = base + k;
        const i1 = i0 + half;
        const vRe = re[i1] * curRe - im[i1] * curIm;
        const vIm = re[i1] * curIm + im[i1] * curRe;
        re[i1] = re[i0] - vRe;
        im[i1] = im[i0] - vIm;
        re[i0] += vRe;
        im[i0] += vIm;
        const nextRe = curRe * wRe - curIm * wIm;
        curIm = curRe * wIm + curIm * wRe;
        curRe = nextRe;
      }
    }
  }
};

// 频谱矩阵：Hann 加窗分帧 → FFT → 取 [0, fs/2] 幅度谱，全局峰值 dB 归一映射到 [0,1]
// （96dB 动态范围，看 SSTV/隐藏文本类特征够用）。fftSize 默认 1024、hop=fftSize/4、
// maxFrames 默认 600 控内存（600×513 double ≈ 2.5MB）：超长音频只取前 maxFrames 帧不全量扫。
export const computeSpectrogram = (
  samples: Float64Array,
  sampleRate: number,
  options?: SpectrogramOptions,
): SpectrogramResult => {
  const fftSize = options?.fftSize ?? 1024;
  const hop = options?.hop ?? fftSize >> 2;
  const maxFrames = options?.maxFrames ?? 600;
  if (sampleRate < 1) throw new Error(`无效采样率 ${sampleRate}`);
  if (fftSize < 16 || (fftSize & (fftSize - 1)) !== 0) {
    throw new Error(`fftSize 必须为 ≥16 的 2 的幂（收到 ${fftSize}）`);
  }
  if (hop < 1) throw new Error(`hop 必须 ≥1（收到 ${hop}）`);
  const bins = (fftSize >> 1) + 1;
  if (samples.length === 0) {
    return { matrix: new Float64Array(0), bins, frames: 0, maxFreq: sampleRate / 2 };
  }
  const frameCount = Math.min(
    maxFrames,
    samples.length >= fftSize ? Math.floor((samples.length - fftSize) / hop) + 1 : 1, // 短音频零填补一帧
  );
  const window = new Float64Array(fftSize);
  for (let index = 0; index < fftSize; index += 1) {
    window[index] = 0.5 - 0.5 * Math.cos((2 * Math.PI * index) / fftSize); // 周期 Hann（DFT 口径）
  }
  const re = new Float64Array(fftSize);
  const im = new Float64Array(fftSize);
  const matrix = new Float64Array(frameCount * bins);
  let maxMag = 0;
  for (let frame = 0; frame < frameCount; frame += 1) {
    const start = frame * hop;
    for (let index = 0; index < fftSize; index += 1) {
      const raw = start + index < samples.length ? samples[start + index] : 0;
      re[index] = raw * window[index];
      im[index] = 0;
    }
    fftRadix2(re, im);
    const row = frame * bins;
    for (let bin = 0; bin < bins; bin += 1) {
      const mag = Math.sqrt(re[bin] * re[bin] + im[bin] * im[bin]);
      matrix[row + bin] = mag;
      if (mag > maxMag) maxMag = mag;
    }
  }
  if (maxMag < 1e-12) return { matrix, bins, frames: frameCount, maxFreq: sampleRate / 2 }; // 全零样本保持全 0
  for (let index = 0; index < matrix.length; index += 1) {
    const db = Math.max(-96, 20 * Math.log10(matrix[index] / maxMag)); // log10(0)=-Infinity，钳到下界
    matrix[index] = (db + 96) / 96;
  }
  return { matrix, bins, frames: frameCount, maxFreq: sampleRate / 2 };
};
