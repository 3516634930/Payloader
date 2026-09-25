// 文件头修复引擎（BMP/GIF/JPG）：魔数重建、宽高修复、段结构诊断。
// 对齐 fileDetect.ts fixPngDimensions 的 API 习惯（async、返回修复后 bytes + 宽高 + 诊断信息），
// 但允许更丰富的诊断数组；纯本地算法、只读输入（返回副本）、无 eval/网络。
// 尺寸/偏移依据（公开规范，逐条核对）：
// - BMP：Wikipedia "BMP file format"——BITMAPFILEHEADER bfType@0='BM'(2B)/bfSize@2(4B)/bfOffBits@10(4B)；
//   BITMAPINFOHEADER(40B)@14：biWidth@18(有符号 i32)/biHeight@22(有符号 i32，负值=自顶向下)/
//   biPlanes@26(2B)/biBitCount@28(2B)/biCompression@30(4B)；行补齐"rounded up to a multiple of
//   4 bytes"，RowSize=⌈bpp×W/32⌉×4，PixelArraySize=RowSize×|H|（仅未压缩数组成立）。
//   BITMAPCOREHEADER(12B) 为 u16 变体（width@18/height@20/bitCount@24，无压缩字段）。
//   修复思路对照：exscape/BMP(bmp.py) 在改尺寸时同步重建头与文件大小的自建头实践。
// - GIF：Wikipedia "GIF"——Header 6B 'GIF87a'/'GIF89a'；Logical Screen Descriptor：width@6/
//   height@8（u16 LE）/packed@10/bg@11/aspect@12；Image Descriptor：0x2C + left/top/width/height
//   各 u16 LE + packed 1B。帧结构解析复用本仓 gifInspect.inspectGif。
// - JPEG：Wikipedia "JPEG"/"JPEG File Interchange Format"——SOI=FFD8/EOI=FFD9（均无负载）；
//   段=marker(2B)+长度(2B 大端，含长度自身不含 marker)；RST0-7=FFD0-FFD7/TEM=FF01 独立 marker；
//   SOS 后为无长度熵编码数据（0xFF 后填 0x00 去冲突，解码器须跳过）；SOF0=FFC0/SOF2=FFC2，
//   帧头字段序 Lf(2B)+P(1B 精度)+Y(2B 高)+X(2B 宽)+Nf(1B 分量数) 按 ITU-T T.81 §B.2.2。
import { MAX_FILE_BYTES } from './fileDetect';
import { inspectGif } from './gifInspect';

// 任务红线：文件解析限量 20MB，超限入口抛错（与 fileDetect.MAX_FILE_BYTES 同一条红线）。
const assertWithinLimit = (bytes: Uint8Array, format: string): void => {
  if (bytes.length > MAX_FILE_BYTES) {
    throw new Error(`${format} 修复输入 ${bytes.length} 字节超过 ${MAX_FILE_BYTES} 上限，拒绝解析`);
  }
};

export interface FileRepairResult {
  // 识别为本格式时恒为可用副本（含已应用的修复）；识别失败/超出可修复范围时为 undefined。
  bytes?: Uint8Array;
  diagnosis: string[];
  width?: number;
  height?: number;
}

// ---- BMP ----

// 枚举上限：题目要求 (w,h) 均 ≤16384，同时保证枚举 O(16384) 单量级。
const BMP_DIM_LIMIT = 16384;

interface BmpHeaderLayout {
  widthOffset: number;
  heightOffset: number;
  bitCountOffset: number;
  widthIsU16: boolean; // BITMAPCOREHEADER 变体
  compression: number;
  dibSize: number;
}

interface BmpCandidate {
  width: number;
  height: number;
  // 行补齐证据量：w 非 4 字节对齐时每行有 padBytes 个补齐字节，统计"全零补齐行"折算的零字节数
  // （null = 宽为 4 的倍数，无补齐字节可核验）。Wikipedia 注明 "padding bytes are not necessarily
  // zero"，故只作启发式打分不作硬性拒绝；证据量而非比率参与排序——39×1 这类单行伪候选的
  // 3 个零补齐字节赢不了真候选多行累计出的证据。
  padEvidence: number | null;
}

const rowSizeOf = (bitCount: number, width: number): number => ((bitCount * width + 31) >>> 5) << 2;

const bmpHeaderLayout = (view: DataView): BmpHeaderLayout | null => {
  const dibSize = view.getUint32(14, true);
  if (dibSize === 12) {
    return { widthOffset: 18, heightOffset: 20, bitCountOffset: 24, widthIsU16: true, compression: 0, dibSize };
  }
  if (dibSize >= 40) {
    // BITMAPINFOHEADER/V4/V5 共享前 40 字节核心布局（宽高/位深/压缩字段偏移一致）。
    return { widthOffset: 18, heightOffset: 22, bitCountOffset: 28, widthIsU16: false, compression: view.getUint32(30, true), dibSize };
  }
  return null;
};

// 按行补齐核验候选宽度：每行末尾 padBytes 个补齐字节，折算"确认全零"的补齐字节数。
const padEvidenceOf = (bytes: Uint8Array, dataOffset: number, bitCount: number, width: number, height: number): number | null => {
  const rowSize = rowSizeOf(bitCount, width);
  const padBytes = rowSize - Math.ceil((bitCount * width) / 8);
  if (padBytes <= 0) return null;
  let zeroRows = 0;
  for (let row = 0; row < height; row += 1) {
    let allZero = true;
    const rowStart = dataOffset + row * rowSize;
    for (let index = rowSize - padBytes; index < rowSize; index += 1) {
      if (bytes[rowStart + index] !== 0) {
        allZero = false;
        break;
      }
    }
    if (allZero) zeroRows += 1;
  }
  return zeroRows * padBytes;
};

export const repairBmp = async (bytes: Uint8Array): Promise<FileRepairResult> => {
  assertWithinLimit(bytes, 'BMP');
  const diagnosis: string[] = [];
  if (bytes.length < 54) {
    diagnosis.push(`文件仅 ${bytes.length} 字节，不足 14 字节文件头 + 40 字节 BITMAPINFOHEADER 的最小 BMP`);
    return { diagnosis };
  }
  const patched = bytes.slice();
  const view = new DataView(patched.buffer, patched.byteOffset, patched.byteLength);

  // ① 'BM' 魔数重建（bfType@0，Wikipedia BMP：must be "BM" 0x4D42）。
  if (patched[0] !== 0x42 || patched[1] !== 0x4d) {
    patched[0] = 0x42;
    patched[1] = 0x4d;
    diagnosis.push(`魔数损坏（原 0x${bytes[0].toString(16).padStart(2, '0')}${bytes[1].toString(16).padStart(2, '0')}）：已重写为 'BM'`);
  }

  const layout = bmpHeaderLayout(view);
  if (!layout) {
    diagnosis.push(`DIB 头大小字段异常（biSize=${view.getUint32(14, true)}，合法值 12 或 ≥40）：无法定位宽高字段`);
    return { bytes: patched, diagnosis };
  }
  diagnosis.push(`DIB 头：${layout.widthIsU16 ? 'BITMAPCOREHEADER(12B)' : `BITMAPINFOHEADER 系(${layout.dibSize}B)`}`);

  const bitCount = view.getUint16(layout.bitCountOffset, true);
  const declaredWidth = layout.widthIsU16 ? view.getUint16(layout.widthOffset, true) : view.getInt32(layout.widthOffset, true);
  const declaredHeight = layout.widthIsU16 ? view.getUint16(layout.heightOffset, true) : view.getInt32(layout.heightOffset, true);
  if (![1, 4, 8, 16, 24, 32].includes(bitCount)) {
    diagnosis.push(`biBitCount=${bitCount} 不在合法集合 {1,4,8,16,24,32}，按 24 位继续尝试反推（结果需人审）`);
  }

  // bfOffBits@10：像素区起点。损坏时按头结构尺寸兜底重建（含 8bpp 以下调色板无法推断的局限写入诊断）。
  let dataOffset = view.getUint32(10, true);
  const minDataOffset = 14 + layout.dibSize;
  if (dataOffset < minDataOffset || dataOffset > patched.length || (dataOffset === 0 && patched.length > minDataOffset)) {
    diagnosis.push(`bfOffBits=${dataOffset} 越界（合法区间 [${minDataOffset}, ${patched.length}]）：已按 ${minDataOffset} 重建${bitCount <= 8 ? '（调色板条目数无法从损坏头推断，若枚举失败请人工指定 dataOffset）' : ''}`);
    dataOffset = minDataOffset;
    view.setUint32(10, dataOffset, true);
  }

  // 反推目标长度：优先头部声明 bfSize@2（文件尾部常被附加 CTF 数据，实际长度会虚高），无效时退回实际长度。
  const declaredFileSize = view.getUint32(2, true);
  let target = patched.length - dataOffset;
  let targetSource = '实际文件长度';
  if (declaredFileSize >= dataOffset + 1 && declaredFileSize < patched.length) {
    target = declaredFileSize - dataOffset;
    targetSource = '头部 bfSize 声明';
    diagnosis.push(`bfSize(${declaredFileSize}) 小于实际文件长度(${patched.length})：尾部另有 ${patched.length - declaredFileSize} 字节附加数据，宽高按 bfSize 反推`);
  } else if (declaredFileSize > patched.length || (declaredFileSize !== 0 && declaredFileSize < dataOffset + 1)) {
    diagnosis.push(`bfSize(${declaredFileSize}) 与实际文件长度(${patched.length}) 不一致且无法采信：宽高按实际长度反推`);
  }

  const rowSizeOfDeclared = rowSizeOf(bitCount, Math.max(1, Math.abs(declaredWidth)));
  const declaredConsistent =
    declaredWidth > 0 &&
    declaredHeight !== 0 &&
    rowSizeOfDeclared * Math.abs(declaredHeight) === target;
  if (declaredConsistent) {
    diagnosis.push(`宽高 ${declaredWidth}×${Math.abs(declaredHeight)} 与像素区（${target} 字节，按${targetSource}）按 RowSize=⌈${bitCount}×W/32⌉×4 公式一致：无需修复`);
    return { bytes: patched, diagnosis, width: declaredWidth, height: Math.abs(declaredHeight) };
  }

  // 变长压缩（BI_RLE8/4=1/2、BI_JPEG=4、BI_PNG=5）下像素区长度可变，公式反推不成立。
  const fixedRowCompression = layout.compression === 0 || layout.compression === 3 || layout.compression === 11 || layout.compression === 12;
  if (!fixedRowCompression) {
    diagnosis.push(`biCompression=${layout.compression}（RLE/JPEG/PNG 等变长压缩）：像素区尺寸不可反推，宽高修复不支持（当前声明 ${declaredWidth}×${declaredHeight}）`);
    return { bytes: patched, diagnosis, width: declaredWidth > 0 ? declaredWidth : undefined, height: declaredHeight !== 0 ? declaredHeight : undefined };
  }
  if (layout.compression === 3) diagnosis.push('biCompression=3 (BI_BITFIELDS)：行仍为定长，按未压缩公式反推');

  // ② 宽高枚举反推：target = RowSize(w)×|h|，枚举全部合法 (w,h)（≤16384）。
  const candidates: BmpCandidate[] = [];
  for (let width = 1; width <= BMP_DIM_LIMIT; width += 1) {
    const rowSize = rowSizeOf(bitCount, width);
    if (target % rowSize !== 0) continue;
    const height = target / rowSize;
    if (height < 1 || height > BMP_DIM_LIMIT) continue;
    candidates.push({ width, height, padEvidence: padEvidenceOf(patched, dataOffset, bitCount, width, height) });
  }
  if (!candidates.length) {
    diagnosis.push(`按 ${target} 字节像素区（bitCount=${bitCount}）未枚举到任何 ≤${BMP_DIM_LIMIT} 的合法 (宽,高) 组合：损坏超出宽高字段（可能涉及 dataOffset/压缩字段/像素区本身）`);
    return { bytes: patched, diagnosis };
  }
  const shown = candidates.slice(0, 8).map(candidate => `${candidate.width}×${candidate.height}`).join('、');
  diagnosis.push(`枚举出 ${candidates.length} 个候选：${shown}${candidates.length > 8 ? ` 等（共 ${candidates.length} 个，完整列表见下方逐条）` : ''}`);
  for (const candidate of candidates.slice(0, 16)) {
    const padNote = candidate.padEvidence === null
      ? '宽为 4 字节倍数，无补齐字节可核验'
      : `行补齐全零核验折算 ${candidate.padEvidence} 字节零补齐`;
    diagnosis.push(`候选 ${candidate.width}×${candidate.height}（${padNote}）`);
  }

  // 选择：行补齐证据量最大 → 与幸存声明侧匹配 → 更接近方形 → 宽更小（确定性）。
  const padWeight = (candidate: BmpCandidate): number => (candidate.padEvidence === null ? 0.5 : candidate.padEvidence);
  const absDeclaredHeight = Math.abs(declaredHeight);
  const best = candidates
    .map(candidate => ({ candidate, key: [padWeight(candidate), candidate.height === absDeclaredHeight ? 1 : 0, candidate.width === declaredWidth ? 1 : 0, Math.min(candidate.width, candidate.height), -candidate.width] }))
    .sort((left, right) => {
      for (let index = 0; index < left.key.length; index += 1) {
        if (left.key[index] !== right.key[index]) return right.key[index] - left.key[index];
      }
      return 0;
    })[0].candidate;

  const signedHeight = declaredHeight < 0 ? -best.height : best.height;
  if (layout.widthIsU16) {
    view.setUint16(layout.widthOffset, best.width, true);
    view.setUint16(layout.heightOffset, Math.abs(signedHeight), true);
  } else {
    view.setInt32(layout.widthOffset, best.width, true);
    view.setInt32(layout.heightOffset, signedHeight, true);
  }
  diagnosis.push(
    `宽高已按候选 ${best.width}×${best.height} 重写（原声明 ${declaredWidth}×${declaredHeight}${declaredHeight < 0 ? '，负高自顶向下语义保留' : ''}）；若渲染仍异常请对照候选清单人工换选`,
  );
  return { bytes: patched, diagnosis, width: best.width, height: signedHeight };
};

// ---- GIF ----

export interface GifSizeGuess {
  width: number;
  height: number;
  frameCount: number;
  // 单帧且锚定 (0,0) 时描述符尺寸即逻辑屏幕尺寸（精确）；多帧/带偏移时为覆盖包围盒（推断）。
  exact: boolean;
  notes: string[];
}

// 头部自愈：'GIF87a'/'GIF89a'（Wikipedia GIF：Header 固定 6 字节）。87a 合法则保留，其余一律重写为 89a
// （89a 结构是 87a 的超集，扩展块在 87a 语义下按未知块跳过，重写 89a 对解码器更安全）。
const healGifHeader = (source: Uint8Array): { bytes: Uint8Array; healed: boolean } => {
  const bytes = source.slice();
  const valid87 = bytes[0] === 0x47 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x38 && bytes[4] === 0x37 && bytes[5] === 0x61;
  const valid89 = bytes[0] === 0x47 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x38 && bytes[4] === 0x39 && bytes[5] === 0x61;
  if (valid87 || valid89) return { bytes, healed: false };
  bytes.set([0x47, 0x49, 0x46, 0x38, 0x39, 0x61], 0);
  return { bytes, healed: true };
};

// 按图像描述符块交叉推断逻辑屏幕尺寸：屏幕须容纳所有帧 → w=max(left+fw), h=max(top+fh)。
// 结构遍历复用 gifInspect.inspectGif（其 LSD 宽高为 0 时仅记异常不抛错，恰好容纳"宽高被抹"的输入）。
export const guessGifSize = (bytes: Uint8Array): GifSizeGuess | null => {
  if (bytes.length < 13) return null;
  const { bytes: healed } = healGifHeader(bytes);
  let inspected: ReturnType<typeof inspectGif>;
  try {
    inspected = inspectGif(healed);
  } catch {
    return null;
  }
  if (!inspected.frames.length) return null;
  let width = 0;
  let height = 0;
  for (const frame of inspected.frames) {
    width = Math.max(width, frame.left + frame.width);
    height = Math.max(height, frame.top + frame.height);
  }
  if (!width || !height) return null;
  const single = inspected.frames[0];
  return {
    width,
    height,
    frameCount: inspected.frames.length,
    exact: inspected.frames.length === 1 && single.left === 0 && single.top === 0,
    notes: inspected.anomalies,
  };
};

const writeGifLsdSize = (view: DataView, width: number, height: number): void => {
  view.setUint16(6, width, true);
  view.setUint16(8, height, true);
};

export const repairGif = async (bytes: Uint8Array): Promise<FileRepairResult> => {
  assertWithinLimit(bytes, 'GIF');
  const diagnosis: string[] = [];
  if (bytes.length < 13) {
    diagnosis.push(`文件仅 ${bytes.length} 字节，不足 Header(6)+LSD(7)=13 字节的最小 GIF`);
    return { diagnosis };
  }
  const { bytes: patched, healed } = healGifHeader(bytes);
  if (healed) diagnosis.push(`头部损坏（原 0x${Array.from(bytes.subarray(0, 6)).map(byte => byte.toString(16).padStart(2, '0')).join(' ')}）：已重写为 'GIF89a'`);
  const view = new DataView(patched.buffer, patched.byteOffset, patched.byteLength);
  const declaredWidth = view.getUint16(6, true);
  const declaredHeight = view.getUint16(8, true);

  const guess = guessGifSize(patched);
  if (!guess) {
    diagnosis.push(`未解析到任何图像描述符（结构遍历失败）：无法推断尺寸（当前 LSD 声明 ${declaredWidth}×${declaredHeight}），可手工指定宽高调用 repairGifWithSize`);
    return { bytes: patched, diagnosis, width: declaredWidth || undefined, height: declaredHeight || undefined };
  }
  diagnosis.push(`按 ${guess.frameCount} 个图像描述符${guess.exact ? '（单帧锚定 0,0，推断即精确值）' : '（多帧覆盖包围盒推断）'}得到逻辑屏幕 ${guess.width}×${guess.height}；帧内偏移细节：${guess.notes.length ? guess.notes.join('；') : '无异常'}`);

  if (!declaredWidth || !declaredHeight) {
    writeGifLsdSize(view, guess.width, guess.height);
    diagnosis.push(`LSD 宽高为 0（原声明 ${declaredWidth}×${declaredHeight}）：已按推断值 ${guess.width}×${guess.height} 重写`);
  } else if (declaredWidth < guess.width || declaredHeight < guess.height) {
    writeGifLsdSize(view, guess.width, guess.height);
    diagnosis.push(`LSD 声明 ${declaredWidth}×${declaredHeight} 容不下帧覆盖区 ${guess.width}×${guess.height}（经典"改小宽高"损坏）：已扩写为 ${guess.width}×${guess.height}；若原图确为更大画布，请用 repairGifWithSize 手工指定`);
  } else {
    diagnosis.push(`LSD 宽高 ${declaredWidth}×${declaredHeight} ≥ 帧覆盖区 ${guess.width}×${guess.height}：画布可容纳全部帧，未改动（GIF 允许画布大于帧，是否被改大请结合题目判断）`);
  }
  return { bytes: patched, diagnosis, width: view.getUint16(6, true), height: view.getUint16(8, true) };
};

// 手工指定模式：宽高已从题面（如渲染比例/像素统计）得知时的确定性重写。
export const repairGifWithSize = async (bytes: Uint8Array, width: number, height: number): Promise<FileRepairResult> => {
  assertWithinLimit(bytes, 'GIF');
  if (!Number.isInteger(width) || !Number.isInteger(height) || width < 1 || height < 1 || width > 0xffff || height > 0xffff) {
    throw new Error(`GIF 宽高必须是 1-65535 的整数（LSD 为 u16 LE）：当前 ${width}×${height}`);
  }
  const diagnosis: string[] = [];
  const { bytes: patched, healed } = healGifHeader(bytes);
  if (healed) diagnosis.push(`头部损坏：已重写为 'GIF89a'`);
  const view = new DataView(patched.buffer, patched.byteOffset, patched.byteLength);
  view.setUint16(6, width, true);
  view.setUint16(8, height, true);
  diagnosis.push(`LSD 宽高已重写为 ${width}×${height}`);
  return { bytes: patched, diagnosis, width, height };
};

// ---- JPEG ----

export interface JpgSegment {
  offset: number;
  marker: number;
  name: string;
  // length=null 表示独立 marker（无长度字段）；熵编码数据另记 entropyBytes。
  length: number | null;
  entropyBytes?: number;
}

export interface JpgSofInfo {
  marker: number;
  name: string;
  offset: number;
  precision: number;
  height: number;
  width: number;
  components: number;
}

export interface JpgRepairResult extends FileRepairResult {
  segments: JpgSegment[];
  sofFrames: JpgSofInfo[];
  repairedSoi: boolean;
  repairedEoi: boolean;
}

const JPG_STANDALONE = (marker: number): boolean => marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7);
const JPG_SOF_MARKERS = new Set([0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf]);

const jpgMarkerName = (marker: number): string => {
  if (JPG_SOF_MARKERS.has(marker)) return `SOF${({ 0xc0: 0, 0xc1: 1, 0xc2: 2, 0xc3: 3, 0xc5: 5, 0xc6: 6, 0xc7: 7, 0xc9: 9, 0xca: 10, 0xcb: 11, 0xcd: 13, 0xce: 14, 0xcf: 15 })[marker] ?? -1}`;
  if (marker === 0xc4) return 'DHT';
  if (marker === 0xc8) return 'JPG';
  if (marker === 0xcc) return 'DAC';
  if (marker === 0xd8) return 'SOI';
  if (marker === 0xd9) return 'EOI';
  if (marker === 0xda) return 'SOS';
  if (marker === 0xdb) return 'DQT';
  if (marker === 0xdc) return 'DNL';
  if (marker === 0xdd) return 'DRI';
  if (marker === 0xde) return 'DHP';
  if (marker === 0xdf) return 'EXP';
  if (marker >= 0xd0 && marker <= 0xd7) return `RST${marker - 0xd0}`;
  if (marker === 0x01) return 'TEM';
  if (marker >= 0xe0 && marker <= 0xef) return `APP${marker - 0xe0}`;
  if (marker === 0xfe) return 'COM';
  return 'RES';
};

interface JpgWalkResult {
  segments: JpgSegment[];
  sofFrames: JpgSofInfo[];
  notes: string[];
  reachedEoi: boolean;
  eoiOffset: number | null;
  truncated: boolean;
}

// 段结构枚举：SOI 后逐 marker 前进。SOS 后进入熵编码扫描——0xFF00 为字节填充须跳过、
// 连续 0xFF 为填充字节、RSTn 独立 marker 跨过继续扫熵数据，直到下一个真实 marker（Wikipedia JPEG：
// "after any 0xFF byte, a 0x00 byte is inserted by the encoder"、"Decoders must skip this 0x00 byte"）。
const walkJpgSegments = (bytes: Uint8Array): JpgWalkResult => {
  const segments: JpgSegment[] = [];
  const sofFrames: JpgSofInfo[] = [];
  const notes: string[] = [];
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let position = 2;
  let reachedEoi = false;
  let eoiOffset: number | null = null;
  let truncated = false;

  segments.push({ offset: 0, marker: 0xd8, name: 'SOI', length: null });
  while (position < bytes.length) {
    if (bytes[position] !== 0xff) {
      notes.push(`偏移 ${position} 期望 marker 前缀 0xFF，实际 0x${bytes[position].toString(16).padStart(2, '0')}：段结构在此损坏（其后内容不可信）`);
      break;
    }
    while (position + 1 < bytes.length && bytes[position + 1] === 0xff) position += 1; // 填充 FF 序列
    if (position + 1 >= bytes.length) {
      truncated = true;
      notes.push(`文件在偏移 ${position} 处截断（marker 未写完）`);
      break;
    }
    const marker = bytes[position + 1];
    const markerOffset = position;
    position += 2;
    if (marker === 0x00) {
      notes.push(`偏移 ${markerOffset} 出现非法 marker FF00（熵数据内未填充的 0xFF）：段结构在此损坏`);
      break;
    }
    if (marker === 0xd9) {
      segments.push({ offset: markerOffset, marker, name: 'EOI', length: null });
      reachedEoi = true;
      eoiOffset = markerOffset;
      break;
    }
    if (JPG_STANDALONE(marker)) {
      segments.push({ offset: markerOffset, marker, name: jpgMarkerName(marker), length: null });
      continue;
    }
    if (marker === 0xda) {
      const sosLength = markerOffset + 4 <= bytes.length ? view.getUint16(markerOffset + 2) : -1;
      if (sosLength < 2 || markerOffset + 2 + sosLength > bytes.length) {
        notes.push(`偏移 ${markerOffset} 的 SOS 段长度异常（${sosLength}）：段结构在此损坏`);
        truncated = true;
        break;
      }
      const sosSegment: JpgSegment = { offset: markerOffset, marker, name: 'SOS', length: sosLength };
      segments.push(sosSegment);
      position = markerOffset + 2 + sosLength;
      const entropyStart = position;
      for (;;) {
        while (position + 1 < bytes.length && bytes[position] !== 0xff) position += 1;
        if (position + 1 >= bytes.length) {
          truncated = true;
          notes.push(`熵编码数据在偏移 ${position} 处截断（未等到后续 marker/EOI）：尾部截断，可补 EOI 修复`);
          break;
        }
        const next = bytes[position + 1];
        if (next === 0x00) {
          position += 2; // 字节填充
          continue;
        }
        if (next === 0xff) {
          position += 1; // 填充 FF
          continue;
        }
        if (next >= 0xd0 && next <= 0xd7) {
          segments.push({ offset: position, marker: next, name: jpgMarkerName(next), length: null });
          position += 2; // RST 独立 marker，其后继续熵数据
          continue;
        }
        break;
      }
      sosSegment.entropyBytes = position - entropyStart;
      if (truncated) break;
      continue;
    }
    if (markerOffset + 4 > bytes.length) {
      notes.push(`偏移 ${markerOffset} 的 ${jpgMarkerName(marker)} 段长度字段不完整（文件截断）`);
      segments.push({ offset: markerOffset, marker, name: jpgMarkerName(marker), length: null });
      truncated = true;
      break;
    }
    const length = view.getUint16(markerOffset + 2);
    if (length < 2 || markerOffset + 2 + length > bytes.length) {
      notes.push(`偏移 ${markerOffset} 的 ${jpgMarkerName(marker)} 段长度字段异常（${length}，越界到 ${markerOffset + 2 + length} > ${bytes.length}）：段结构在此损坏`);
      segments.push({ offset: markerOffset, marker, name: jpgMarkerName(marker), length });
      truncated = true;
      break;
    }
    segments.push({ offset: markerOffset, marker, name: jpgMarkerName(marker), length });
    if (JPG_SOF_MARKERS.has(marker)) {
      // SOF 帧头（ITU-T T.81 §B.2.2）：Lf(2B)+P(1B)+Y 高(2B BE)+X 宽(2B BE)+Nf(1B)。
      sofFrames.push({
        marker,
        name: jpgMarkerName(marker),
        offset: markerOffset,
        precision: bytes[markerOffset + 4],
        height: view.getUint16(markerOffset + 5),
        width: view.getUint16(markerOffset + 7),
        components: bytes[markerOffset + 9],
      });
    }
    position = markerOffset + 2 + length;
  }
  if (!reachedEoi && !truncated) notes.push('段遍历到文件尾仍未遇到 EOI：缺少结束标记');
  return { segments, sofFrames, notes, reachedEoi, eoiOffset, truncated };
};

export const repairJpg = async (bytes: Uint8Array): Promise<JpgRepairResult> => {
  assertWithinLimit(bytes, 'JPEG');
  const diagnosis: string[] = [];
  if (bytes.length < 4) {
    diagnosis.push(`文件仅 ${bytes.length} 字节，不足以容纳 SOI + 任一段`);
    return { segments: [], sofFrames: [], diagnosis, repairedSoi: false, repairedEoi: false };
  }

  // ① SOI 重建：优先定位文件内（含前导垃圾剥除），完全缺失时重写前 2 字节并要求后续段结构自洽。
  let patched = bytes.slice();
  let repairedSoi = false;
  if (bytes[0] !== 0xff || bytes[1] !== 0xd8) {
    // 外层条件已排除 found===0；全文件首个 FFD8 即为剥除目标。
    const found = bytes.findIndex((byte, index) => index + 1 < bytes.length && byte === 0xff && bytes[index + 1] === 0xd8);
    if (found > 0) {
      patched = bytes.slice(found);
      diagnosis.push(`首 2 字节非 FFD8 且在偏移 ${found} 找到 SOI：已剥除 ${found} 字节前导垃圾`);
      repairedSoi = true;
    } else {
      patched = bytes.slice();
      patched[0] = 0xff;
      patched[1] = 0xd8;
      diagnosis.push(`首 2 字节非 FFD8（原 0x${bytes[0].toString(16).padStart(2, '0')}${bytes[1].toString(16).padStart(2, '0')}）且全文件无其它 FFD8：已按"仅头部 2 字节被覆写"假设重写 SOI（若头部垃圾超过 2 字节需先手工剥除）`);
      repairedSoi = true;
    }
  }

  const walk = walkJpgSegments(patched);
  if (walk.segments.length <= 1) {
    diagnosis.push('SOI 后未解析到任何有效段：不是 JPEG 或损坏超出可修复范围');
    return { segments: walk.segments, sofFrames: [], diagnosis, repairedSoi, repairedEoi: false };
  }

  // ② EOI 重建：尾部截断（无任何 FFD9）补 FFD9；EOI 后有尾附数据只提示不截断（尾附常是 CTF 载荷）。
  let repairedEoi = false;
  if (!walk.reachedEoi) {
    // 大文件下展开运算符会拷贝两份数组（20MB 输入约 160MB 尖峰），手写扩容。
    const grown = new Uint8Array(patched.length + 2);
    grown.set(patched, 0);
    grown[patched.length] = 0xff;
    grown[patched.length + 1] = 0xd9;
    patched = grown;
    repairedEoi = true;
    diagnosis.push(walk.truncated ? '尾部截断（遍历至文件尾无 EOI）：已补写 FFD9' : '缺少 EOI：已补写 FFD9');
  } else if (walk.eoiOffset !== null && walk.eoiOffset + 2 < patched.length) {
    diagnosis.push(`EOI 之后仍有 ${patched.length - walk.eoiOffset - 2} 字节尾附数据（binwalk 式嵌入高发位）：保留未截断，请另做尾附分析`);
  }

  // ③ 段结构枚举诊断：逐段列出 marker+长度，定位损坏点。
  diagnosis.push(`段结构（共 ${walk.segments.length} 项）：${walk.segments.slice(0, 24).map(segment => `${segment.name}@${segment.offset}${segment.length === null ? '' : `(${segment.length}B)`}${segment.entropyBytes !== undefined ? `[熵数据 ${segment.entropyBytes}B]` : ''}`).join('、')}${walk.segments.length > 24 ? ` …等 ${walk.segments.length} 项` : ''}`);
  diagnosis.push(...walk.notes);

  // ④ SOF 宽高读取诊断：只检测读出不改写——JPG 宽高写死在熵编码的 MCU 排布里，
  // 改 SOF 尺寸与霍夫曼/重启间隔流不一致，图像必然花屏（与 PNG IHDR+CRC 可爆破修复本质不同）。
  for (const sof of walk.sofFrames) {
    diagnosis.push(`${sof.name}@${sof.offset}：精度 ${sof.precision} 位，真实尺寸 ${sof.width}×${sof.height}，${sof.components} 分量（只读诊断：宽高改写会破坏熵编码流，不提供爆破改写）`);
  }
  const firstSof = walk.sofFrames[0];
  if (walk.sofFrames.length > 1) {
    const consistent = walk.sofFrames.every(sof => sof.width === firstSof.width && sof.height === firstSof.height);
    diagnosis.push(consistent ? `文件含 ${walk.sofFrames.length} 个 SOF，尺寸一致（${firstSof.width}×${firstSof.height}）` : `文件含 ${walk.sofFrames.length} 个 SOF 且尺寸不一致：首个为 ${firstSof.width}×${firstSof.height}，缩略图 SOF 与主图并存属正常，逐个核对上表`);
  }
  return {
    bytes: patched,
    diagnosis,
    width: firstSof?.width,
    height: firstSof?.height,
    segments: walk.segments,
    sofFrames: walk.sofFrames,
    repairedSoi,
    repairedEoi,
  };
};
