// 光栅栅栏图与立体图求解器（批次 SI·C 线）：
// - 光栅（随波逐流"光栅图隐写提取"，AabyssZG/Raster-Terminator 算法）：单图按 行%period / 列%period
//   交织了多个条带帧，按相位抽取重组即可显影——周期枚举（默认 2..10，仅保留整除对应维度的值），
//   每相位输出一张候选图。
// - Stereogram（随波逐流"Stereogram Solver"，StegSolve/piellardj 同款思路）：autostereogram 是
//   水平纹理重复，与自身偏移 offset 的副本做逐像素差——命中真实周期处 diff≈0（黑），深度边缘亮，
//   差分图即隐藏文字/轮廓；offset 滑杆 + 全局差值和曲线自动估背景周期。
// 纯 rgba 层运算，零依赖。
import type { RgbaImage } from './imageOps';

export interface RasterCandidate {
  axis: 'x' | 'y'; // x=纵向光栅（列相位抽取，周期整除宽度）/ y=横向光栅（行相位抽取，周期整除高度）
  period: number;
  phase: number;
  image: RgbaImage;
}

// 只枚举 (axis, period, phase) 组合不物化图像（reviewer P1：全相位扫描逐候选物化整图在 4M 像素
// 图上瞬时分配 >1GB；UI 应先枚举元数据、渲染缩略时再逐个 rasterCompact 懒算）
export const rasterPhasePlan = (width: number, height: number, maxPeriod = 10): Array<{ axis: 'x' | 'y'; period: number; phase: number }> => {
  const plan: Array<{ axis: 'x' | 'y'; period: number; phase: number }> = [];
  for (let period = 2; period <= maxPeriod; period += 1) {
    if (width % period === 0) {
      for (let phase = 0; phase < period; phase += 1) plan.push({ axis: 'x', period, phase });
    }
    if (height % period === 0) {
      for (let phase = 0; phase < period; phase += 1) plan.push({ axis: 'y', period, phase });
    }
  }
  return plan;
};

// 全参数扫描（保留引擎兼容）：需要全部候选图像时使用；UI 场景优先 rasterPhasePlan + 懒算
export const rasterRevealAll = (image: RgbaImage, maxPeriod = 10): RasterCandidate[] => {
  return rasterPhasePlan(image.width, image.height, maxPeriod).map(plan => ({
    ...plan,
    image: extractPhase(image, plan.axis, plan.period, plan.phase),
  }));
};

// 单相位抽取：x 轴=只保留 列%period===phase 的列（其余白），画布不变，便于目检叠加帧
const extractPhase = (image: RgbaImage, axis: 'x' | 'y', period: number, phase: number): RgbaImage => {
  const { data, width, height } = image;
  const out = new Uint8ClampedArray(width * height * 4).fill(255);
  if (axis === 'x') {
    for (let x = phase; x < width; x += period) {
      for (let y = 0; y < height; y += 1) {
        const source = (y * width + x) * 4;
        const target = source;
        out[target] = data[source];
        out[target + 1] = data[source + 1];
        out[target + 2] = data[source + 2];
        out[target + 3] = 255;
      }
    }
    return { data: out, width, height };
  }
  for (let y = phase; y < height; y += period) {
    for (let x = 0; x < width; x += 1) {
      const source = (y * width + x) * 4;
      const target = source;
      out[target] = data[source];
      out[target + 1] = data[source + 1];
      out[target + 2] = data[source + 2];
      out[target + 3] = 255;
    }
  }
  return { data: out, width, height };
};

// 压缩重组（可选形态）：把相位条带抽出来拼成紧凑图（无白隔条）——显影帧的实际宽高 = 维度/period
export const rasterCompact = (image: RgbaImage, axis: 'x' | 'y', period: number, phase: number): RgbaImage => {
  const { data, width, height } = image;
  if (axis === 'x') {
    const columns: number[] = [];
    for (let x = phase; x < width; x += period) columns.push(x);
    const out = new Uint8ClampedArray(columns.length * height * 4);
    columns.forEach((sourceX, targetX) => {
      for (let y = 0; y < height; y += 1) {
        const source = (y * width + sourceX) * 4;
        const target = (y * columns.length + targetX) * 4;
        out[target] = data[source];
        out[target + 1] = data[source + 1];
        out[target + 2] = data[source + 2];
        out[target + 3] = 255;
      }
    });
    return { data: out, width: columns.length, height };
  }
  const rows: number[] = [];
  for (let y = phase; y < height; y += period) rows.push(y);
  const out = new Uint8ClampedArray(width * rows.length * 4);
  rows.forEach((sourceY, targetY) => {
    for (let x = 0; x < width; x += 1) {
      const source = (sourceY * width + x) * 4;
      const target = (targetY * width + x) * 4;
      out[target] = data[source];
      out[target + 1] = data[source + 1];
      out[target + 2] = data[source + 2];
      out[target + 3] = 255;
    }
  });
  return { data: out, width, height: rows.length };
};

// ---- Stereogram Solver ----

// 偏移差分：diff(x,y) = |灰度(x,y) − 灰度(x−offset,y)| 归一化放大 → 深度图
export const stereogramDiff = (image: RgbaImage, offset: number): RgbaImage => {
  const { data, width, height } = image;
  const out = new Uint8ClampedArray(width * height * 4);
  const grayOf = (index: number) => 0.299 * data[index * 4] + 0.587 * data[index * 4 + 1] + 0.114 * data[index * 4 + 2];
  for (let y = 0; y < height; y += 1) {
    for (let x = 0; x < width; x += 1) {
      const index = y * width + x;
      const diff =
        x - offset >= 0
          ? Math.min(255, Math.round(Math.abs(grayOf(index) - grayOf(index - offset)) * 4)) // ×4 归一化放大微差
          : 255;
      out[index * 4] = diff;
      out[index * 4 + 1] = diff;
      out[index * 4 + 2] = diff;
      out[index * 4 + 3] = 255;
    }
  }
  return { data: out, width, height };
};

// 背景周期自动估计：offset∈[min,max] 的全局差值和曲线取最小值（背景平面重复处差值最低）
export const stereogramEstimateOffset = (
  image: RgbaImage,
  minOffset = 32,
  maxOffset = 256,
): { bestOffset: number; curve: Array<{ offset: number; totalDiff: number }> } => {
  const { data, width, height } = image;
  const grayOf = (index: number) => 0.299 * data[index * 4] + 0.587 * data[index * 4 + 1] + 0.114 * data[index * 4 + 2];
  const curve: Array<{ offset: number; totalDiff: number }> = [];
  const strideY = Math.max(1, Math.floor(height / 128)); // 采样降本
  const strideX = Math.max(1, Math.floor(width / 256));
  let bestOffset = minOffset;
  let bestTotal = Number.POSITIVE_INFINITY;
  for (let offset = minOffset; offset <= Math.min(maxOffset, width - 1); offset += 1) {
    let total = 0;
    for (let y = 0; y < height; y += strideY) {
      for (let x = offset; x < width; x += strideX) {
        total += Math.abs(grayOf(y * width + x) - grayOf(y * width + x - offset));
      }
    }
    if (total < bestTotal) {
      bestTotal = total;
      bestOffset = offset;
    }
    curve.push({ offset, totalDiff: total });
  }
  return { bestOffset, curve };
};
