// GIF 深度解析引擎（杂项取证域，sweep2 缺口 #19）：帧分离、帧延时隐写、注释段/纯文本段提取。
// 纯函数、只读字节、无 DOM/eval/网络；GIF87a/89a 结构（LSD/GCE/Image Descriptor/LZW 子块流/
// Comment 0xFE、PlainText 0x01、Application 0xFF 扩展/Trailer 0x3B）按规范自实现，
// 帧解码用标准迭代 LZW。上限红线：单帧像素 >1600 万抛中文错误拒绝解码；帧数 >2000 只解析前 2000 帧并写入 anomalies。

export const GIF_MAX_PIXELS = 16000000; // 单帧像素红线（≈4K 全屏）
export const GIF_MAX_FRAMES = 2000; // 帧数红线：超出只解析前 2000 帧

export interface GifFrame {
  index: number;
  delayMs: number; // GCE delay（单位 10ms 字段 ×10）
  left: number;
  top: number;
  width: number;
  height: number;
  lzwMinCodeSize: number;
  dataOffset: number; // LZW 子块链起始偏移（含子块长度字节；帧分离下载用）
  dataLength: number; // 子块链整体长度（含终止符 0x00）
  imageData?: Uint8ClampedArray<ArrayBuffer>; // 解码后的 RGBA 像素（惰性可选：decodeGifFrames 时填；ArrayBuffer 变体以匹配 ImageData 构造器）
  // 规范接口之外的超集字段：decodeGifFrame 重入解码所需，缺省按"无"处理。
  localColorTable?: Uint8Array | null;
  interlaced?: boolean;
  transparentIndex?: number; // -1 = 无透明
  disposal?: number;
}

export interface GifInspectResult {
  version: string;
  logicalWidth: number;
  logicalHeight: number;
  globalColorTable: Uint8Array | null; // 768 字节内 RGB 或 null
  loopCount: number; // NETSCAPE2.0 应用扩展的循环次数（0=无限；无该扩展时为 1=播放一次）
  frames: GifFrame[];
  comments: string[]; // Comment Extension 内容（latin1 尽力）
  plainTexts: string[]; // PlainText Extension 原始块
  anomalies: string[]; // 结构异常与人审线索（截断/尾附/延时分布等）
  delayBits: { raw: number[]; asBinary: string; asAscii: string; asSeconds: string } | null;
}

const latin1 = new TextDecoder('latin1');

// 读取子块链：返回各数据块视图与终止符之后的偏移；无终止符或数据块越界（截断流）返回 null。
const readSubBlocks = (bytes: Uint8Array, position: number): { chunks: Uint8Array[]; end: number } | null => {
  const chunks: Uint8Array[] = [];
  let cursor = position;
  while (cursor < bytes.length) {
    const length = bytes[cursor];
    if (length === 0) return { chunks, end: cursor + 1 };
    if (cursor + 1 + length > bytes.length) return null;
    chunks.push(bytes.subarray(cursor + 1, cursor + 1 + length));
    cursor += 1 + length;
  }
  return null;
};

const concatChunks = (chunks: Uint8Array[]): Uint8Array => {
  let total = 0;
  for (const chunk of chunks) total += chunk.length;
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.length;
  }
  return merged;
};

// GCE delay 原始字段值（delayMs / 10 恒为精确整数，双精度下无舍入）。
const rawDelays = (frames: GifFrame[]): number[] => frames.map(frame => frame.delayMs / 10);

// 帧延时隐写三口径并排输出（不赌单一解读）：raw 存原始字段值（单位 1/100 秒），
// asBinary 按字段值 >50 阈值化（题面口径"50"），asAscii 把字段值直接当 ASCII 码，
// asSeconds 把字段值当秒数字符（0-9）。三口径全部基于同一 raw 序列，选手并排判读。
const buildDelayBits = (frames: GifFrame[]): GifInspectResult['delayBits'] => {
  if (frames.length < 2) return null;
  const raw = rawDelays(frames);
  let asBinary = '';
  let asAscii = '';
  let asSeconds = '';
  for (const value of raw) {
    asBinary += value > 50 ? '1' : '0';
    asAscii += value >= 32 && value <= 126 ? String.fromCharCode(value) : '.';
    asSeconds += value >= 0 && value <= 9 ? String.fromCharCode(0x30 + value) : '.';
  }
  return { raw, asBinary, asAscii, asSeconds };
};

// 延时序列人审线索：首帧 0、0 值混杂（0/1 编码形态）、双值分布、连续可打印 ASCII。
const analyzeDelayAnomalies = (frames: GifFrame[], anomalies: string[]): void => {
  if (frames.length < 2) return;
  const raw = rawDelays(frames);
  if (raw[0] === 0) anomalies.push('首帧延时字段为 0（浏览器会按约 100ms 兜底渲染，延时隐写高发位）');
  const zeroCount = raw.filter(value => value === 0).length;
  if (zeroCount === frames.length) anomalies.push(`全部 ${frames.length} 帧延时字段为 0（动画语义异常或延时信息被抹平）`);
  else if (zeroCount > 0) anomalies.push(`${zeroCount} 帧延时字段为 0 且与其余帧混杂，符合按帧 0/1 延时编码形态`);
  const distinct = [...new Set(raw)];
  if (distinct.length === 2) anomalies.push(`延时呈双值分布（${distinct[0]}/${distinct[1]}），符合按帧 0/1 位编码特征`);
  let bestStart = -1;
  let bestLength = 0;
  let runStart = 0;
  let runLength = 0;
  for (let index = 0; index <= raw.length; index += 1) {
    const printable = index < raw.length && raw[index] >= 32 && raw[index] <= 126;
    if (printable) {
      if (runLength === 0) runStart = index;
      runLength += 1;
    } else {
      if (runLength > bestLength) {
        bestLength = runLength;
        bestStart = runStart;
      }
      runLength = 0;
    }
  }
  if (bestLength >= 4) {
    const text = raw.slice(bestStart, bestStart + bestLength).map(value => String.fromCharCode(value)).join('');
    anomalies.push(`第 ${bestStart}-${bestStart + bestLength - 1} 帧延时字段构成连续可打印 ASCII："${text}"`);
  }
};

export const inspectGif = (bytes: Uint8Array): GifInspectResult => {
  if (bytes.length < 13) throw new Error(`不是 GIF 文件：总长 ${bytes.length} 不足以容纳 Header+LSD`);
  if (bytes[0] !== 0x47 || bytes[1] !== 0x49 || bytes[2] !== 0x46 || bytes[3] !== 0x38) {
    throw new Error('不是 GIF 文件：缺少 GIF87a/89a 签名');
  }
  const version = latin1.decode(bytes.subarray(3, 6));
  if (version !== '87a' && version !== '89a') throw new Error(`GIF 版本号异常：${version}（仅支持 87a/89a）`);
  const logicalWidth = bytes[6] | (bytes[7] << 8);
  const logicalHeight = bytes[8] | (bytes[9] << 8);
  const lsdPacked = bytes[10];
  const anomalies: string[] = [];
  if (!logicalWidth || !logicalHeight) anomalies.push(`逻辑屏幕尺寸异常：${logicalWidth}×${logicalHeight}`);

  const gctFlag = (lsdPacked & 0x80) !== 0;
  const gctLength = gctFlag ? 3 << ((lsdPacked & 7) + 1) : 0;
  const frames: GifFrame[] = [];
  const comments: string[] = [];
  const plainTexts: string[] = [];
  let loopCount = 1;
  let pendingGce: { delay: number; transparentIndex: number; disposal: number } | null = null;
  let sawTrailer = false;

  if (13 + gctLength > bytes.length) {
    anomalies.push('数据流在偏移 13 处截断（全局色表不完整）');
    return { version, logicalWidth, logicalHeight, globalColorTable: null, loopCount, frames, comments, plainTexts, anomalies, delayBits: null };
  }
  const globalColorTable = gctFlag ? bytes.slice(13, 13 + gctLength) : null;

  let position = 13 + gctLength;
  while (position < bytes.length) {
    const block = bytes[position];
    // Trailer：其后仍有字节即为尾附数据（binwalk 式嵌入高发位）。
    if (block === 0x3b) {
      sawTrailer = true;
      position += 1;
      if (position < bytes.length) anomalies.push(`Trailer 之后仍有 ${bytes.length - position} 字节尾附数据（binwalk 式嵌入高发位）`);
      break;
    }
    // Extension：label + 子块链，统一先读链再按 label 分派。
    if (block === 0x21) {
      const label = bytes[position + 1];
      const sub = readSubBlocks(bytes, position + 2);
      if (!sub) {
        anomalies.push(`数据流在偏移 ${position} 处截断（扩展块 0x${label.toString(16)} 子块链不完整）`);
        break;
      }
      position = sub.end;
      if (label === 0xf9) {
        const data = sub.chunks.length ? sub.chunks[0] : null;
        if (data && data.length >= 4) {
          const gcePacked = data[0];
          pendingGce = {
            delay: data[1] | (data[2] << 8),
            transparentIndex: gcePacked & 1 ? data[3] : -1,
            disposal: (gcePacked >> 2) & 7,
          };
        } else {
          anomalies.push(`偏移 ${position} 的 GCE 数据块长度异常（期望 4，实际 ${data ? data.length : 0}）`);
        }
      } else if (label === 0xfe) {
        comments.push(latin1.decode(concatChunks(sub.chunks)));
      } else if (label === 0x01) {
        // 首个 12 字节数据块是 Plain Text Header（left/top/w/h/cellW/cellH/fg/bg），其余为文本。
        const body = sub.chunks.length >= 1 && sub.chunks[0].length === 12 ? sub.chunks.slice(1) : sub.chunks;
        plainTexts.push(latin1.decode(concatChunks(body)));
      } else if (label === 0xff) {
        const appId = sub.chunks.length >= 1 && sub.chunks[0].length === 11 ? latin1.decode(sub.chunks[0]) : '';
        const loopBlock = appId.startsWith('NETSCAPE') && sub.chunks.length >= 2 ? sub.chunks[1] : null;
        if (loopBlock && loopBlock.length >= 3 && loopBlock[0] === 1) loopCount = loopBlock[1] | (loopBlock[2] << 8);
      }
      continue;
    }
    // Image Descriptor + 局部色表 + LZW min code size + 数据子块链。
    if (block === 0x2c) {
      if (frames.length >= GIF_MAX_FRAMES) {
        anomalies.push(`帧数达到 ${GIF_MAX_FRAMES} 上限，仅解析前 ${GIF_MAX_FRAMES} 帧`);
        break;
      }
      if (position + 10 > bytes.length) {
        anomalies.push(`数据流在偏移 ${position} 处截断（Image Descriptor 不完整）`);
        break;
      }
      const left = bytes[position + 1] | (bytes[position + 2] << 8);
      const top = bytes[position + 3] | (bytes[position + 4] << 8);
      const width = bytes[position + 5] | (bytes[position + 6] << 8);
      const height = bytes[position + 7] | (bytes[position + 8] << 8);
      const descriptorPacked = bytes[position + 9];
      let cursor = position + 10;
      const lctFlag = (descriptorPacked & 0x80) !== 0;
      const interlaced = (descriptorPacked & 0x40) !== 0;
      const lctLength = lctFlag ? 3 << ((descriptorPacked & 7) + 1) : 0;
      if (cursor + lctLength + 1 > bytes.length) {
        anomalies.push(`数据流在偏移 ${cursor} 处截断（帧 ${frames.length} 的局部色表/LZW 起始不完整）`);
        break;
      }
      const localColorTable = lctFlag ? bytes.slice(cursor, cursor + lctLength) : null;
      cursor += lctLength;
      const lzwMinCodeSize = bytes[cursor];
      cursor += 1;
      const sub = readSubBlocks(bytes, cursor);
      if (!sub) {
        anomalies.push(`数据流在偏移 ${cursor} 处截断（帧 ${frames.length} 的 LZW 子块链不完整）`);
        break;
      }
      const frame: GifFrame = {
        index: frames.length,
        delayMs: (pendingGce ? pendingGce.delay : 0) * 10,
        left,
        top,
        width,
        height,
        lzwMinCodeSize,
        dataOffset: cursor,
        dataLength: sub.end - cursor,
        localColorTable,
        interlaced,
        transparentIndex: pendingGce ? pendingGce.transparentIndex : -1,
        disposal: pendingGce ? pendingGce.disposal : 0,
      };
      if (!pendingGce) anomalies.push(`帧 ${frames.length} 前无 GCE（延时/透明信息缺失，按 delay=0 处理）`);
      if (width * height > GIF_MAX_PIXELS) {
        anomalies.push(`帧 ${frames.length} 像素 ${width}×${height}=${width * height} 超过 1600 万红线，decodeGifFrame 将拒绝解码`);
      }
      pendingGce = null;
      frames.push(frame);
      position = sub.end;
      continue;
    }
    anomalies.push(`未知块标记 0x${block.toString(16).padStart(2, '0')} 于偏移 ${position}，停止解析`);
    break;
  }
  if (!sawTrailer) anomalies.push('数据流截断：未遇到 Trailer (0x3B)');

  analyzeDelayAnomalies(frames, anomalies);
  return {
    version,
    logicalWidth,
    logicalHeight,
    globalColorTable,
    loopCount,
    frames,
    comments,
    plainTexts,
    anomalies,
    delayBits: buildDelayBits(frames),
  };
};

// GIF LZW 解码（标准迭代实现）：clear code 重置、码宽随字典增长递增（上限 12bit）、
// 提前 EOI/数据耗尽/未定义码均按"已解出多少保留多少"终止，字典到 4096 后停止追加条目。
const lzwDecode = (minCodeSize: number, data: Uint8Array, expectedPixels: number): Uint8Array => {
  const clearCode = 1 << minCodeSize;
  const eoiCode = clearCode + 1;
  const prefix = new Int32Array(4096).fill(-1);
  const suffix = new Uint8Array(4096);
  for (let root = 0; root < clearCode; root += 1) suffix[root] = root; // 根条目：码号即色号
  const output = new Uint8Array(expectedPixels);
  const stack = new Uint8Array(4096);
  let codeWidth = minCodeSize + 1;
  let nextCode = eoiCode + 1;
  let outputPosition = 0;
  let bitBuffer = 0;
  let bitCount = 0;
  let bytePosition = 0;
  let previous = -1;
  let lastFirst = 0;
  // 把字典条目沿前缀链展开写入 output；lastFirst 记录该条目首字节（供下一轮拼接新条目）。
  const emit = (code: number): void => {
    let depth = 0;
    let node = code;
    while (node >= 0 && prefix[node] !== -1 && depth < 4096) {
      stack[depth] = suffix[node];
      depth += 1;
      node = prefix[node];
    }
    if (node < 0) return;
    stack[depth] = suffix[node];
    depth += 1;
    lastFirst = stack[depth - 1];
    while (depth > 0 && outputPosition < expectedPixels) {
      depth -= 1;
      output[outputPosition] = stack[depth];
      outputPosition += 1;
    }
  };

  while (outputPosition < expectedPixels) {
    while (bitCount < codeWidth) {
      if (bytePosition >= data.length) break;
      bitBuffer |= data[bytePosition] << bitCount;
      bytePosition += 1;
      bitCount += 8;
    }
    if (bitCount < codeWidth) break;
    const code = bitBuffer & ((1 << codeWidth) - 1);
    bitBuffer >>>= codeWidth;
    bitCount -= codeWidth;
    if (code === clearCode) {
      codeWidth = minCodeSize + 1;
      nextCode = eoiCode + 1;
      previous = -1;
      continue;
    }
    if (code === eoiCode) break;
    if (previous < 0) {
      if (code >= clearCode) break; // clear 后首码必须是根
      emit(code);
      previous = code;
      continue;
    }
    if (code < nextCode) {
      emit(code); // 此后 lastFirst = 本条目首字节
      if (nextCode < 4096) {
        prefix[nextCode] = previous;
        suffix[nextCode] = lastFirst;
        nextCode += 1;
      }
    } else if (code === nextCode) {
      // Km+1 = Km + Km[0]：此刻 lastFirst 仍是上一轮（previous）的首字节
      if (nextCode < 4096) {
        prefix[nextCode] = previous;
        suffix[nextCode] = lastFirst;
        nextCode += 1;
      }
      emit(code);
    } else {
      break; // 字典未定义的码：损坏流，保留已解出部分
    }
    previous = code;
    if (nextCode >= (1 << codeWidth) && codeWidth < 12) codeWidth += 1;
  }
  return output;
};

// 从 dataOffset 起沿子块链收集 LZW 码流（剔除长度字节，遇终止符或越界停）。
const concatSubBlockChain = (bytes: Uint8Array, start: number, length: number): Uint8Array => {
  const end = length > 0 ? Math.min(bytes.length, start + length) : bytes.length;
  const chunks: Uint8Array[] = [];
  let cursor = start;
  while (cursor < end) {
    const blockLength = bytes[cursor];
    if (blockLength === 0) break;
    if (cursor + 1 + blockLength > end) {
      chunks.push(bytes.subarray(cursor + 1, end));
      break;
    }
    chunks.push(bytes.subarray(cursor + 1, cursor + 1 + blockLength));
    cursor += 1 + blockLength;
  }
  return concatChunks(chunks);
};

// GIF 四遍隔行扫描（0/8、4/8、2/4、1/2）还原为行主序。
const deinterlace = (indices: Uint8Array, width: number, height: number): Uint8Array => {
  const ordered = new Uint8Array(indices.length);
  let source = 0;
  const passes: Array<[number, number]> = [[0, 8], [4, 8], [2, 4], [1, 2]];
  for (const [start, step] of passes) {
    for (let row = start; row < height; row += step) {
      for (let column = 0; column < width; column += 1) {
        ordered[row * width + column] = indices[source];
        source += 1;
      }
    }
  }
  return ordered;
};

export const decodeGifFrame = (
  bytes: Uint8Array,
  frame: GifFrame,
  globalColorTable: Uint8Array | null,
): Uint8ClampedArray<ArrayBuffer> => {
  const { width, height, lzwMinCodeSize } = frame;
  const pixelCount = width * height;
  if (pixelCount > GIF_MAX_PIXELS) {
    throw new Error(`GIF 帧像素总数 ${width}×${height}=${pixelCount} 超过 1600 万上限，拒绝解码`);
  }
  if (lzwMinCodeSize < 2 || lzwMinCodeSize > 8) {
    throw new Error(`帧 ${frame.index} LZW min code size ${lzwMinCodeSize} 越界（合法区间 2-8）`);
  }
  if (frame.dataOffset <= 0 || frame.dataOffset >= bytes.length) {
    throw new Error(`帧 ${frame.index} 的 LZW 数据偏移 ${frame.dataOffset} 越界`);
  }
  const stream = concatSubBlockChain(bytes, frame.dataOffset, frame.dataLength);
  const scanIndices = lzwDecode(lzwMinCodeSize, stream, pixelCount);
  const ordered = frame.interlaced ? deinterlace(scanIndices, width, height) : scanIndices;
  const palette = frame.localColorTable ?? globalColorTable;
  if (!palette || palette.length < 3) {
    throw new Error(`帧 ${frame.index} 无可用色表（局部与全局色表均缺失），无法映射 RGBA`);
  }
  const colorCount = Math.floor(palette.length / 3);
  const transparent = frame.transparentIndex ?? -1;
  const rgba = new Uint8ClampedArray(pixelCount * 4);
  for (let pixel = 0; pixel < pixelCount; pixel += 1) {
    const rawIndex = ordered[pixel];
    const colorIndex = rawIndex < colorCount ? rawIndex : colorCount - 1; // 越界索引钳到最后一种颜色（容错）
    const base = pixel * 4;
    rgba[base] = palette[colorIndex * 3];
    rgba[base + 1] = palette[colorIndex * 3 + 1];
    rgba[base + 2] = palette[colorIndex * 3 + 2];
    rgba[base + 3] = rawIndex === transparent ? 0 : 255;
  }
  return rgba;
};

// 批量惰性解码：把前 maxFrames 帧的 RGBA 就地填进 frame.imageData（供缩略图/帧下载）。
// 单帧解码失败即停并写入 anomalies（后续帧大概率同样损坏），返回成功帧数。
// 累计像素总预算：恶意 GIF（声明大尺寸+超短 LZW 流）×64 帧可同步分配数 GB RGBA 卡死页面，
// 超预算截断并记 anomalies（单帧上限 GIF_MAX_PIXELS 之外的第二道防线）。
export const GIF_MAX_TOTAL_PIXELS = 64_000_000;

export const decodeGifFrames = (bytes: Uint8Array, result: GifInspectResult, options: { maxFrames?: number } = {}): number => {
  const maxFrames = options.maxFrames ?? 64;
  let decoded = 0;
  let totalPixels = 0;
  for (const frame of result.frames) {
    if (decoded >= maxFrames) break;
    if (totalPixels + frame.width * frame.height > GIF_MAX_TOTAL_PIXELS) {
      result.anomalies.push(`累计像素达 ${GIF_MAX_TOTAL_PIXELS} 上限：仅解码前 ${decoded} 帧，其余帧可用原始 LZW 流下载后离线分析`);
      break;
    }
    try {
      frame.imageData = decodeGifFrame(bytes, frame, result.globalColorTable);
      totalPixels += frame.width * frame.height;
      decoded += 1;
    } catch (error) {
      result.anomalies.push(`帧 ${frame.index} 解码中止：${error instanceof Error ? error.message : String(error)}`);
      break;
    }
  }
  return decoded;
};
