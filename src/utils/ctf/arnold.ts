// Arnold 猫脸变换（批次 SI·C 线）：N×N 图像置乱/还原（随波逐流"Arnold cat face transform encryption/decryption"对标）。
// 参数化矩阵 [[1,a],[b,a·b+1]] mod N（EBCTFCodeBox/社区惯例，det=1 保证可逆；a=b=1 即标准猫脸 [[1,1],[1,2]]）：
// 正向 x'=(x+a·y)%N, y'=(b·x+(a·b+1)·y)%N；逆向用逆矩阵 [[a·b+1,-a],[-b,1]]。
// 周期性质：N=2^m 时为 3·2^(m-2)（128→96、256→192）；非 2 幂无封闭式，运行时按双基点归位判定（M^k≡I）。
// 纯 rgba 层像素置换，零依赖；迭代次数与周期枚举供无密钥爆破。
import type { RgbaImage } from './imageOps';

export interface ArnoldOptions {
  iterations?: number; // 迭代次数（默认 1；解密方向传置乱时用的次数）
  a?: number; // 参数 a（默认 1）
  b?: number; // 参数 b（默认 1）
}

const shufflexy = (x: number, y: number, n: number, a: number, b: number): { x: number; y: number } => ({
  x: (x + a * y) % n,
  y: (b * x + (a * b + 1) * y) % n,
});

const inversexy = (x: number, y: number, n: number, a: number, b: number): { x: number; y: number } => {
  // 逆矩阵 [[a·b+1, -a], [-b, 1]]（det=1）
  const rawX = ((a * b + 1) * x - a * y) % n;
  const rawY = (-b * x + y) % n;
  return { x: (rawX + n) % n, y: (rawY + n) % n };
};

const permuteImage = (image: RgbaImage, forward: boolean, a: number, b: number): RgbaImage => {
  const { data, width, height } = image;
  if (width !== height) throw new Error(`Arnold 变换要求方阵图像，当前 ${width}×${height}：请先裁剪或补边为正方形`);
  const n = width;
  const out = new Uint8ClampedArray(width * height * 4);
  for (let y = 0; y < n; y += 1) {
    for (let x = 0; x < n; x += 1) {
      const mapped = forward ? shufflexy(x, y, n, a, b) : inversexy(x, y, n, a, b);
      const source = (y * n + x) * 4;
      const target = (mapped.y * n + mapped.x) * 4;
      out[target] = data[source];
      out[target + 1] = data[source + 1];
      out[target + 2] = data[source + 2];
      out[target + 3] = data[source + 3];
    }
  }
  return { data: out, width, height };
};

export const ARNOLD_MAX_ITERATIONS = 10_000; // 迭代上限（reviewer P2：无界迭代在大图上小时级冻结）

export const arnoldTransform = (image: RgbaImage, options: ArnoldOptions = {}): RgbaImage => {
  const iterations = Math.min(ARNOLD_MAX_ITERATIONS, Math.max(1, options.iterations ?? 1));
  const a = options.a ?? 1;
  const b = options.b ?? 1;
  let current: RgbaImage = image;
  for (let index = 0; index < iterations; index += 1) {
    current = permuteImage(current, true, a, b);
  }
  return current;
};

export const arnoldInverse = (image: RgbaImage, options: ArnoldOptions = {}): RgbaImage => {
  const iterations = Math.min(ARNOLD_MAX_ITERATIONS, Math.max(1, options.iterations ?? 1));
  const a = options.a ?? 1;
  const b = options.b ?? 1;
  let current: RgbaImage = image;
  for (let index = 0; index < iterations; index += 1) {
    current = permuteImage(current, false, a, b);
  }
  return current;
};

// 周期：从原图迭代置乱直到回到原图的最少步数（标准 Arnold 周期因 N 而异，如 N=2→3、N=128→96、N=240→60）。
// 用于"不知迭代次数"的爆破上限（不超过周期 × 保守系数）与题解提示。
// 判定=两个基点 (1,0)/(0,1) 同时归位：变换是线性的，M^k 作用在基上还原 ⟺ M^k≡I (mod N) ⟺ 整图还原
// （只盯单点会得到该点轨道周期，可能小于矩阵周期）。
export const arnoldPeriod = (size: number, a = 1, b = 1, maxIterations = 100000): number => {
  let x1 = 1;
  let y1 = 0;
  let x2 = 0;
  let y2 = 1;
  for (let step = 1; step <= maxIterations; step += 1) {
    const mapped1 = shufflexy(x1, y1, size, a, b);
    x1 = mapped1.x;
    y1 = mapped1.y;
    const mapped2 = shufflexy(x2, y2, size, a, b);
    x2 = mapped2.x;
    y2 = mapped2.y;
    if (x1 === 1 && y1 === 0 && x2 === 0 && y2 === 1) return step;
  }
  return -1; // 超上限（异常参数）
};
