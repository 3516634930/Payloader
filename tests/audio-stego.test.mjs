// 音频隐写引擎测试：WAV 解析（8/16/24bit、立体声交织、extensible、非 PCM 拒绝、
// 超长截断红线）、LSB 提取（mono/stereo 通道选择性、位平面、maxBytes 截断）、
// DTMF 合成解码（8k/44.1k）、摩尔斯合成识别（text+timeline）、频谱峰值 bin、
// 非 2 幂 fftSize 抛错、空/静音/单样本退化输入。
// 向量全部程序化构造（手写 WAV 头），加载统一走 tests/helpers/compileTsModule.mjs。
import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const { loadModule } = createTsModuleLoader();
const {
  parseWav, extractWavLsb, dtmfDecode, morseDecodeAudio, computeSpectrogram, MAX_WAV_SAMPLES,
} = loadModule(path.join(projectRoot, 'src', 'utils', 'ctf', 'audioStego.ts'));

// ---- 测试工厂 ----

const makePrng = seed => {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) | 0;
    let mixed = Math.imul(state ^ (state >>> 15), 1 | state);
    mixed = (mixed + Math.imul(mixed ^ (mixed >>> 7), 61 | mixed)) ^ mixed;
    return ((mixed ^ (mixed >>> 14)) >>> 0) / 4294967296;
  };
};

// 手写 WAV：RIFF/fmt/data 头 + 按位深编码的整数样本（帧主序交织）。extensible=true 时写 40 字节 fmt。
const buildWav = ({ sampleRate = 8000, channels = 1, bits = 16, formatTag = 1, extensible = false, samplesInt }) => {
  if (samplesInt.length % channels !== 0) throw new Error('样本数必须是通道数整数倍');
  const frames = samplesInt.length / channels;
  const bytesPerSample = bits / 8;
  const blockAlign = channels * bytesPerSample;
  const dataLen = frames * blockAlign;
  const fmtLen = extensible ? 40 : 16;
  const header = Buffer.alloc(12 + 8 + fmtLen + 8);
  header.write('RIFF', 0, 'latin1');
  header.writeUInt32LE(4 + (8 + fmtLen) + (8 + dataLen), 4);
  header.write('WAVE', 8, 'latin1');
  header.write('fmt ', 12, 'latin1');
  header.writeUInt32LE(fmtLen, 16);
  header.writeUInt16LE(formatTag, 20);
  header.writeUInt16LE(channels, 22);
  header.writeUInt32LE(sampleRate, 24);
  header.writeUInt32LE(sampleRate * blockAlign, 28);
  header.writeUInt16LE(blockAlign, 32);
  header.writeUInt16LE(bits, 34);
  if (extensible) {
    header.writeUInt16LE(22, 36); // cbSize
    header.writeUInt16LE(bits, 38); // validBitsPerSample
    header.writeUInt32LE(0x3, 40); // channelMask（引擎不读，占位）
    // subFormat GUID = PCM {00000001-0000-0010-8000-00AA00389B71}，引擎只认前 2 字节
    header.writeUInt32LE(0x00000001, 44);
    header.writeUInt16LE(0x0000, 48);
    header.writeUInt16LE(0x0010, 50);
    header.writeUInt16LE(0x8000, 52);
    header[54] = 0x00; header[55] = 0xaa; header[56] = 0x00; header[57] = 0x38;
    header[58] = 0x9b; header[59] = 0x71;
  }
  const dataOffsetInHeader = 12 + 8 + fmtLen;
  header.write('data', dataOffsetInHeader, 'latin1');
  header.writeUInt32LE(dataLen, dataOffsetInHeader + 4);
  const data = Buffer.alloc(dataLen);
  for (let index = 0; index < samplesInt.length; index += 1) {
    // 手工小端逐字节写无符号补码（避开 Buffer.writeInt16LE 的有符号域校验，位嵌入后可能超域）
    const value = samplesInt[index] >>> 0;
    const offset = index * bytesPerSample;
    for (let byte = 0; byte < bytesPerSample; byte += 1) {
      data[offset + byte] = (value >>> (8 * byte)) & 0xff;
    }
  }
  return new Uint8Array(Buffer.concat([header, data]));
};

const toLatin1 = bytes => {
  let out = '';
  for (let index = 0; index < bytes.length; index += 1) out += String.fromCharCode(bytes[index]);
  return out;
};

const concatFloat64 = parts => {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Float64Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
};

// ---- parseWav ----

test('parseWav 16bit 立体声：info 字段与 L/R 帧交织归一', () => {
  const frames = 100;
  const samplesInt = [];
  for (let frame = 0; frame < frames; frame += 1) samplesInt.push(16000, -16000);
  const { info, samples } = parseWav(buildWav({ sampleRate: 44100, channels: 2, bits: 16, samplesInt }));
  assert.equal(info.sampleRate, 44100);
  assert.equal(info.channels, 2);
  assert.equal(info.bitsPerSample, 16);
  assert.equal(info.frames, frames);
  assert.equal(info.dataBytes, frames * 4);
  assert.equal(info.formatTag, 1);
  assert.equal(samples.length, frames * 2);
  for (let frame = 0; frame < frames; frame += 1) {
    assert.ok(Math.abs(samples[frame * 2] - 16000 / 32768) < 1e-12, `L 帧${frame}=${samples[frame * 2]}`);
    assert.ok(Math.abs(samples[frame * 2 + 1] + 16000 / 32768) < 1e-12, `R 帧${frame}=${samples[frame * 2 + 1]}`);
  }
});

test('parseWav 8bit 无符号 PCM：样本归一到 [-1,1]', () => {
  const { info, samples } = parseWav(buildWav({ bits: 8, samplesInt: [0, 64, 128, 192, 255] }));
  assert.equal(info.bitsPerSample, 8);
  assert.equal(info.frames, 5);
  assert.equal(info.dataBytes, 5);
  const expected = [-1, -0.5, 0, 0.5, 127 / 128];
  for (let index = 0; index < expected.length; index += 1) {
    assert.ok(Math.abs(samples[index] - expected[index]) < 1e-12, `idx=${index} v=${samples[index]}`);
  }
});

test('parseWav 24bit：符号扩展与满幅边界', () => {
  const inputs = [0, 1, -1, 0x7fffff, -0x800000];
  const { info, samples } = parseWav(buildWav({ bits: 24, samplesInt: inputs }));
  assert.equal(info.bitsPerSample, 24);
  assert.equal(info.frames, inputs.length);
  const scale = 0x800000;
  for (let index = 0; index < inputs.length; index += 1) {
    assert.ok(Math.abs(samples[index] - inputs[index] / scale) < 1e-12, `idx=${index} v=${samples[index]}`);
  }
});

test('parseWav WAVE_FORMAT_EXTENSIBLE(0xFFFE) PCM 基础子格式可解析', () => {
  const samplesInt = [12345, -12345];
  const { info, samples } = parseWav(
    buildWav({ channels: 2, bits: 16, formatTag: 0xfffe, extensible: true, samplesInt }));
  assert.equal(info.formatTag, 1); // 解析为基础子格式 PCM
  assert.equal(info.channels, 2);
  assert.equal(info.frames, 1);
  assert.ok(Math.abs(samples[0] - 12345 / 32768) < 1e-12);
  assert.ok(Math.abs(samples[1] + 12345 / 32768) < 1e-12);
});

test('parseWav 非 PCM（a-law）与垃圾输入抛中文错误', () => {
  assert.throws(() => parseWav(buildWav({ bits: 8, formatTag: 6, samplesInt: [128, 130] })), /decodeAudioData/);
  assert.throws(() => parseWav(new Uint8Array(100)), /RIFF/);
  assert.throws(() => parseWav(new Uint8Array(0)), /RIFF/);
});

test('parseWav 文件尾截断：按实际字节收敛帧数不崩溃', () => {
  const full = buildWav({ bits: 16, samplesInt: new Array(1000).fill(0) });
  const chopped = full.subarray(0, full.length - 100); // 砍掉 100 字节（50 帧）
  const { info } = parseWav(chopped);
  assert.equal(info.frames, 950);
  assert.equal(info.dataBytes, 1900);
});

test('parseWav 超过 2^24 交织样本截断到上限（内存红线）', () => {
  const channels = 2;
  const overFrames = Math.floor(MAX_WAV_SAMPLES / channels) + 3;
  const dataLen = overFrames * channels * 2; // 16bit
  const header = Buffer.alloc(44);
  header.write('RIFF', 0, 'latin1');
  header.writeUInt32LE(36 + dataLen, 4);
  header.write('WAVE', 8, 'latin1');
  header.write('fmt ', 12, 'latin1');
  header.writeUInt32LE(16, 16);
  header.writeUInt16LE(1, 20);
  header.writeUInt16LE(channels, 22);
  header.writeUInt32LE(48000, 24);
  header.writeUInt32LE(48000 * 4, 28);
  header.writeUInt16LE(4, 32);
  header.writeUInt16LE(16, 34);
  header.write('data', 36, 'latin1');
  header.writeUInt32LE(dataLen, 40);
  const wav = parseWav(new Uint8Array(Buffer.concat([header, Buffer.alloc(dataLen, 0x11)])));
  assert.equal(wav.info.frames, Math.floor(MAX_WAV_SAMPLES / channels));
  assert.equal(wav.samples.length, MAX_WAV_SAMPLES);
  assert.equal(wav.info.dataBytes, Math.floor(MAX_WAV_SAMPLES / channels) * 4);
});

// ---- extractWavLsb ----

test('extractWavLsb 16bit mono：8K 随机样本 bit0 藏 flag 可找回', () => {
  const prng = makePrng(0xa0d10001);
  const ints = Array.from({ length: 8192 }, () => Math.floor(prng() * 65536) - 32768);
  const flag = 'flag{wav_lsb_hit}';
  for (let bit = 0; bit < flag.length * 8; bit += 1) {
    const byte = flag.charCodeAt(bit >> 3);
    const value = (byte >> (7 - (bit & 7))) & 1;
    ints[bit] = (ints[bit] & 0xfffe) | value;
  }
  const wav = parseWav(buildWav({ sampleRate: 44100, bits: 16, samplesInt: ints }));
  const extracted = toLatin1(extractWavLsb(wav, { channel: 0, bit: 0, maxBytes: 64 }));
  assert.ok(extracted.startsWith(flag), `提取=${extracted.slice(0, 32)}`);
});

test('extractWavLsb 立体声：R 通道(channel=1)命中而 L(channel=0)不命中', () => {
  const prng = makePrng(0xa0d10002);
  const frames = 4096;
  const flag = 'flag{stereo_r_channel}';
  const ints = new Array(frames * 2);
  for (let index = 0; index < ints.length; index += 1) ints[index] = Math.floor(prng() * 65536) - 32768;
  for (let bit = 0; bit < flag.length * 8; bit += 1) {
    const byte = flag.charCodeAt(bit >> 3);
    const value = (byte >> (7 - (bit & 7))) & 1;
    const sampleIndex = bit * 2 + 1; // R 通道 = 每帧第 2 个交织样本
    ints[sampleIndex] = (ints[sampleIndex] & 0xfffe) | value;
  }
  const wav = parseWav(buildWav({ channels: 2, bits: 16, samplesInt: ints }));
  const hit = toLatin1(extractWavLsb(wav, { channel: 1, bit: 0, maxBytes: 128 }));
  const miss = toLatin1(extractWavLsb(wav, { channel: 0, bit: 0, maxBytes: 128 }));
  assert.ok(hit.startsWith(flag), `R=${hit.slice(0, 40)}`);
  assert.ok(!miss.includes('flag{'), `L 不应泄漏：${miss.slice(0, 40)}`);
});

test('extractWavLsb 位平面参数生效与 maxBytes 截断、越界抛错', () => {
  const prng = makePrng(0xa0d10003);
  const ints = Array.from({ length: 4096 }, () => Math.floor(prng() * 65536) - 32768);
  const secret = 'bitplane1';
  for (let bit = 0; bit < secret.length * 8; bit += 1) {
    const byte = secret.charCodeAt(bit >> 3);
    const value = (byte >> (7 - (bit & 7))) & 1;
    ints[bit] = (ints[bit] & 0xfffd) | (value << 1); // 藏进 bit1
  }
  const wav = parseWav(buildWav({ bits: 16, samplesInt: ints }));
  assert.ok(toLatin1(extractWavLsb(wav, { channel: 0, bit: 1, maxBytes: 64 })).startsWith(secret));
  assert.ok(!toLatin1(extractWavLsb(wav, { channel: 0, bit: 0, maxBytes: 64 })).includes(secret));
  const capped = extractWavLsb(wav, { channel: 0, bit: 1, maxBytes: 4 });
  assert.equal(capped.length, 4);
  assert.equal(toLatin1(capped), 'bitp');
  assert.throws(() => extractWavLsb(wav, { channel: 2, bit: 0 }), /通道/);
  assert.throws(() => extractWavLsb(wav, { channel: 0, bit: 16 }), /位平面/);
});

// ---- dtmfDecode ----

const DTMF_FREQS = {
  '1': [697, 1209], '2': [697, 1336], '3': [697, 1477],
  '4': [770, 1209], '5': [770, 1336], '6': [770, 1477],
  '7': [852, 1209], '8': [852, 1336], '9': [852, 1477],
  '*': [941, 1209], '0': [941, 1336], '#': [941, 1477],
  A: [697, 1633], B: [770, 1633], C: [852, 1633], D: [941, 1633],
};

const synthDtmf = (keys, sampleRate = 8000, toneMs = 80, gapMs = 40, amp = 0.25) => {
  const parts = [];
  for (const key of keys) {
    const [low, high] = DTMF_FREQS[key];
    const toneLen = Math.round((sampleRate * toneMs) / 1000);
    const tone = new Float64Array(toneLen);
    for (let index = 0; index < toneLen; index += 1) {
      const t = index / sampleRate;
      tone[index] = amp * Math.sin(2 * Math.PI * low * t) + amp * Math.sin(2 * Math.PI * high * t);
    }
    parts.push(tone, new Float64Array(Math.round((sampleRate * gapMs) / 1000)));
  }
  return concatFloat64(parts);
};

test('dtmfDecode 合成 "1238#A"（80ms 键音 + 40ms 静音）完整还原', () => {
  assert.equal(dtmfDecode(synthDtmf('1238#A'), 8000), '1238#A');
});

test('dtmfDecode 44.1kHz 采样率下同样成立', () => {
  assert.equal(dtmfDecode(synthDtmf('8059B', 44100), 44100), '8059B');
});

test('dtmfDecode 空样本与全零静音返回空串', () => {
  assert.equal(dtmfDecode(new Float64Array(0), 8000), '');
  assert.equal(dtmfDecode(new Float64Array(8000), 8000), '');
});

// ---- morseDecodeAudio ----

const synthMorse = (timeline, sampleRate = 8000, { ditMs = 60, freq = 600, amp = 0.8 } = {}) => {
  // ITU 比例：点=1 单位、划=3 单位、元素内间隔=1 单位、字母间隔=3 单位、词间隔=7 单位
  const parts = [];
  const push = (ms, on) => {
    const len = Math.round((sampleRate * ms) / 1000);
    const buf = new Float64Array(len);
    if (on) {
      for (let index = 0; index < len; index += 1) {
        const sine = Math.sin(2 * Math.PI * freq * (index / sampleRate));
        buf[index] = sine >= 0 ? amp : -amp; // 方波
      }
    }
    parts.push(buf);
  };
  let prevElement = false;
  for (const ch of timeline) {
    if (ch === '.') {
      if (prevElement) push(ditMs, false);
      push(ditMs, true);
      prevElement = true;
    } else if (ch === '-') {
      if (prevElement) push(ditMs, false);
      push(ditMs * 3, true);
      prevElement = true;
    } else if (ch === '/') {
      push(ditMs * 7, false);
      prevElement = false;
    } else if (ch === ' ') {
      push(ditMs * 3, false);
      prevElement = false;
    }
  }
  push(ditMs * 7, false); // 尾部静音收口
  return concatFloat64(parts);
};

// 注：`.... .. / -.. .-` 逐码严格解码为 HI DA（.- = A）；任务描述中的 "HI DE" 对应
// `-.. .`（E=单点），两组向量各断言一次。
test('morseDecodeAudio 合成 ".... .. / -.. .-"（600Hz 方波）：text 与 timeline 原样还原', () => {
  const { text, timeline } = morseDecodeAudio(synthMorse('.... .. / -.. .-'), 8000);
  assert.equal(text, 'HI DA');
  assert.equal(timeline, '.... .. / -.. .-');
});

test('morseDecodeAudio 合成 ".... .. / -.. ."：text=HI DE；44.1kHz 采样率下 SOS 同样成立', () => {
  const hiDe = morseDecodeAudio(synthMorse('.... .. / -.. .'), 8000);
  assert.equal(hiDe.text, 'HI DE');
  assert.equal(hiDe.timeline, '.... .. / -.. .');
  assert.equal(morseDecodeAudio(synthMorse('... --- ...', 44100), 44100).text, 'SOS');
});

test('morseDecodeAudio 空样本与全零静音返回空结果', () => {
  assert.equal(morseDecodeAudio(new Float64Array(0), 8000).text, '');
  assert.equal(morseDecodeAudio(new Float64Array(8000), 8000).timeline, '');
});

// ---- computeSpectrogram ----

test('computeSpectrogram 440Hz 单频：峰值 bin 命中最近 bin（±1 容差）且值域/维度正确', () => {
  const sampleRate = 44100;
  const samples = new Float64Array(Math.round(sampleRate * 0.5));
  for (let index = 0; index < samples.length; index += 1) {
    samples[index] = 0.6 * Math.sin(2 * Math.PI * 440 * (index / sampleRate));
  }
  const { matrix, bins, frames, maxFreq } = computeSpectrogram(samples, sampleRate, { fftSize: 1024, hop: 256 });
  assert.equal(bins, 513);
  assert.equal(maxFreq, sampleRate / 2);
  assert.equal(frames, Math.floor((samples.length - 1024) / 256) + 1);
  assert.equal(matrix.length, frames * bins);
  const expectBin = Math.round(440 / (sampleRate / 1024));
  for (let frame = 0; frame < frames; frame += 1) {
    let bestBin = 0;
    let bestValue = -1;
    for (let bin = 0; bin < bins; bin += 1) {
      const value = matrix[frame * bins + bin];
      assert.ok(Number.isFinite(value) && value >= 0 && value <= 1, `值域越界 frame=${frame} bin=${bin} v=${value}`);
      if (value > bestValue) {
        bestValue = value;
        bestBin = bin;
      }
    }
    assert.ok(Math.abs(bestBin - expectBin) <= 1, `帧${frame} 峰值 bin=${bestBin} 期望=${expectBin}`);
  }
});

test('computeSpectrogram 非 2 幂 fftSize 抛错；空/单样本/全零不崩', () => {
  const samples = new Float64Array(2000).map((_, index) => Math.sin(index * 0.01));
  assert.throws(() => computeSpectrogram(samples, 8000, { fftSize: 1000 }), /2 的幂/);
  assert.throws(() => computeSpectrogram(samples, 8000, { fftSize: 1024, hop: 0 }), /hop/);
  const empty = computeSpectrogram(new Float64Array(0), 8000);
  assert.equal(empty.frames, 0);
  assert.equal(empty.matrix.length, 0);
  assert.equal(empty.maxFreq, 4000);
  const single = computeSpectrogram(new Float64Array([0.5]), 8000, { fftSize: 64, hop: 16 });
  assert.equal(single.frames, 1); // 短音频零填补一帧
  assert.equal(single.matrix.length, single.bins);
  const zero = computeSpectrogram(new Float64Array(4096), 8000, { fftSize: 256, hop: 64 });
  for (let index = 0; index < zero.matrix.length; index += 1) {
    assert.ok(Number.isFinite(zero.matrix[index]), `全零样本不应产生 NaN idx=${index}`);
  }
});
