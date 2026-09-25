// JPEG DCT 系数读取层（批次 SI·A 线第一步）：消费 vendor 的 eugeneware/jpeg-js
// 解码器（src/vendor/jpegjs-decoder.ts）收集熵解码后的量化系数。F5/outguess 等
// 系数域工具后续消费同一 JpegCoefficientData 接口——这是本层存在的唯一理由。
import { parseJpegCoefficientsInternal } from '../../vendor/jpegjs-decoder';

export interface JpegCoefficientData {
  components: Array<{
    blocks: Int32Array; // 块数×64，块内 natural order，块行主序（MCU 对齐块网格）
    widthInBlocks: number;
    heightInBlocks: number;
    h: number;
    v: number;
  }>;
  mcuOrderCoefficients: Int32Array; // MCU 交织顺序展平的全部系数（jsteg/F5 遍历用，含 DC）
  mcuOrderComponentIndex: Uint8Array | null; // 与 mcuOrderCoefficients 等长：系数所属分量下标（单分量图像为 null）
  width: number;
  height: number;
}

// jpeg-js 的 dctZigZag 常量（复制自 vendor）：JPEG_ZIGZAG[zigzag 序号 k] = natural order 块内下标。
// jsteg/F5 语义按 zigzag 序遍历，而块存储是 natural order，用本表换算。
export const JPEG_ZIGZAG = new Int32Array([
  0,
  1, 8,
  16, 9, 2,
  3, 10, 17, 24,
  32, 25, 18, 11, 4,
  5, 12, 19, 26, 33, 40,
  48, 41, 34, 27, 20, 13, 6,
  7, 14, 21, 28, 35, 42, 49, 56,
  57, 50, 43, 36, 29, 22, 15,
  23, 30, 37, 44, 51, 58,
  59, 52, 45, 38, 31,
  39, 46, 53, 60,
  61, 54, 47,
  62, 55,
  63,
]);

// vendor 解码器的消费面结构（vendor 整体 @ts-nocheck，导出为 any，此处只收窄用到的字段）
interface InternalComponent {
  h: number;
  v: number;
  coefficients: Int32Array;
  widthInBlocks: number;
  heightInBlocks: number;
}

interface InternalFrame {
  componentsOrder: number[];
  components: Record<number, InternalComponent>;
  maxH: number;
  maxV: number;
  mcusPerLine: number;
  mcusPerColumn: number;
  scanComponentOrder?: InternalComponent[];
}

interface InternalDecoder {
  width: number;
  height: number;
  frame: InternalFrame;
}

// vendor 内部错误 → 面向用户的中文错误（渐进式/20MB 两条已是中文，原样透传）
const translateJpegError = (error: unknown): Error => {
  const message = error instanceof Error ? error.message : String(error);
  if (message.includes('渐进式') || message.includes('20MB')) {
    return error instanceof Error ? error : new Error(message);
  }
  if (/SOI not found/.test(message)) {
    return new Error('不是有效的 JPEG 文件（未找到 SOI 标记）');
  }
  if (/marker was not found|unexpected marker|invalid huffman|Could not recreate/.test(message)) {
    return new Error(`JPEG 数据被截断或熵编码段损坏：${message}`);
  }
  return new Error(`JPEG 解析失败：${message}`);
};

// MCU 交织序：按扫描分量顺序、每 MCU 内分量 h×v 个块、每块 64 系数。
// 交错扫描（常规 baseline 彩色）下与熵位流块序一致；单分量图像退化为块光栅序。
// 罕见的非交错多扫描顺序式文件按 SOF 分量序近似重建（每分量块数据本身仍精确）。
const buildMcuOrder = (
  components: Array<{ blocks: Int32Array; widthInBlocks: number; h: number; v: number }>,
  scanOrderIndices: number[],
  frame: InternalFrame,
): { mcuOrderCoefficients: Int32Array; mcuOrderComponentIndex: Uint8Array | null } => {
  let blocksPerMcu = 0;
  for (const index of scanOrderIndices) {
    const component = components[index];
    if (!component) throw new Error('JPEG 解析失败：扫描分量不在帧内');
    blocksPerMcu += component.h * component.v;
  }
  const totalBlocks = frame.mcusPerLine * frame.mcusPerColumn * blocksPerMcu;
  const mcuOrderCoefficients = new Int32Array(totalBlocks * 64);
  const mcuOrderComponentIndex =
    components.length > 1 ? new Uint8Array(totalBlocks * 64) : null;
  let cursor = 0;
  for (let mcuRow = 0; mcuRow < frame.mcusPerColumn; mcuRow += 1) {
    for (let mcuCol = 0; mcuCol < frame.mcusPerLine; mcuCol += 1) {
      for (const componentIndex of scanOrderIndices) {
        const component = components[componentIndex];
        for (let j = 0; j < component.v; j += 1) {
          for (let k = 0; k < component.h; k += 1) {
            const blockRow = mcuRow * component.v + j;
            const blockCol = mcuCol * component.h + k;
            const source = (blockRow * component.widthInBlocks + blockCol) * 64;
            mcuOrderCoefficients.set(
              component.blocks.subarray(source, source + 64),
              cursor,
            );
            if (mcuOrderComponentIndex !== null) {
              mcuOrderComponentIndex.fill(componentIndex, cursor, cursor + 64);
            }
            cursor += 64;
          }
        }
      }
    }
  }
  return { mcuOrderCoefficients, mcuOrderComponentIndex };
};

export const readJpegCoefficients = (bytes: Uint8Array): JpegCoefficientData => {
  let decoder: InternalDecoder;
  try {
    decoder = parseJpegCoefficientsInternal(bytes) as InternalDecoder;
  } catch (error) {
    throw translateJpegError(error);
  }
  const { frame } = decoder;
  const components = Array.from(frame.componentsOrder, (id: number) => {
    const component = frame.components[id];
    return {
      blocks: component.coefficients,
      widthInBlocks: component.widthInBlocks,
      heightInBlocks: component.heightInBlocks,
      h: component.h,
      v: component.v,
    };
  });
  // 扫描分量顺序优先取 SOS 实际顺序（可不同于 SOF 声明序）；不完整时退回 SOF 序
  const scan = frame.scanComponentOrder;
  let scanOrderIndices: number[] | null = null;
  if (Array.isArray(scan) && scan.length === components.length) {
    scanOrderIndices = scan.map((component) =>
      components.findIndex((entry) => entry.blocks === component.coefficients),
    );
    if (scanOrderIndices.some((index) => index < 0)) scanOrderIndices = null;
  }
  const order = scanOrderIndices ?? components.map((_, index) => index);
  const { mcuOrderCoefficients, mcuOrderComponentIndex } = buildMcuOrder(
    components,
    order,
    frame,
  );
  return {
    components,
    mcuOrderCoefficients,
    mcuOrderComponentIndex,
    width: decoder.width,
    height: decoder.height,
  };
};
