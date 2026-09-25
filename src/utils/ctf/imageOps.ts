// 图像隐写工具箱（批次 SI·D 线）：随波逐流"图片隐写"菜单的图像运算与转换族——
// 双图组合 / 翻转反色拼接 / 01 串·XY 坐标·RGB 串⇄图像 / 字符画(Novel_In_Image 形态) /
// flood-fill 掩码提取 / QR 定位角补全。全部 rgba(ArrayLike<number>) 层运算，纯本地、零依赖。
// CTF 场景约定：01/XY/RGB 串的产物常是二维码，卡层负责接 qrDecode 复检。
export interface RgbaImage {
  data: Uint8ClampedArray | ArrayLike<number>;
  width: number;
  height: number;
}

export type CombineOp = 'xor' | 'and' | 'or' | 'add' | 'sub' | 'mul';

export const COMBINE_LABELS: Record<CombineOp, { zh: string; en: string }> = {
  xor: { zh: '异或 XOR', en: 'XOR' },
  and: { zh: '与 AND', en: 'AND' },
  or: { zh: '或 OR', en: 'OR' },
  add: { zh: '加 ADD（灰度差见隐藏图）', en: 'ADD' },
  sub: { zh: '减 SUB（A−B 差值）', en: 'SUB' },
  mul: { zh: '乘 MUL', en: 'MUL' },
};

// 双图逐像素运算（RGB 三通道，alpha 取 255）。尺寸不一致取交集（左上对齐），备注说明裁剪量。
export const combineImages = (
  first: RgbaImage,
  second: RgbaImage,
  op: CombineOp,
): { image: RgbaImage; notes: string[] } => {
  const width = Math.min(first.width, second.width);
  const height = Math.min(first.height, second.height);
  const notes: string[] = [];
  if (first.width !== second.width || first.height !== second.height) {
    notes.push(
      `两图尺寸不同（${first.width}×${first.height} 与 ${second.width}×${second.height}），按交集 ${width}×${height} 左上对齐运算`,
    );
  }
  const out = new Uint8ClampedArray(width * height * 4);
  for (let index = 0; index < width * height; index += 1) {
    const aBase = index * 4;
    const bBase = index * 4;
    for (let channel = 0; channel < 3; channel += 1) {
      const a = first.data[aBase + channel];
      const b = second.data[bBase + channel];
      let value: number;
      switch (op) {
        case 'xor':
          value = (a ^ b) & 0xff;
          break;
        case 'and':
          value = (a & b) & 0xff;
          break;
        case 'or':
          value = (a | b) & 0xff;
          break;
        case 'add':
          value = Math.min(255, a + b);
          break;
        case 'sub':
          value = Math.max(0, a - b);
          break;
        default:
          value = Math.min(255, Math.round((a * b) / 255));
          break;
      }
      out[aBase + channel] = value;
    }
    out[aBase + 3] = 255;
  }
  return { image: { data: out, width, height }, notes };
};

// 翻转（水平/垂直镜像）与反色（RGB 取补，alpha 不动）
export const flipImage = (image: RgbaImage, direction: 'horizontal' | 'vertical'): RgbaImage => {
  const { data, width, height } = image;
  const out = new Uint8ClampedArray(width * height * 4);
  for (let y = 0; y < height; y += 1) {
    for (let x = 0; x < width; x += 1) {
      const source = (y * width + x) * 4;
      const tx = direction === 'horizontal' ? width - 1 - x : x;
      const ty = direction === 'vertical' ? height - 1 - y : y;
      const target = (ty * width + tx) * 4;
      out[target] = data[source];
      out[target + 1] = data[source + 1];
      out[target + 2] = data[source + 2];
      out[target + 3] = data[source + 3];
    }
  }
  return { data: out, width, height };
};

export const invertImage = (image: RgbaImage): RgbaImage => {
  const { data, width, height } = image;
  const out = new Uint8ClampedArray(width * height * 4);
  for (let index = 0; index < width * height; index += 1) {
    const base = index * 4;
    out[base] = 255 - data[base];
    out[base + 1] = 255 - data[base + 1];
    out[base + 2] = 255 - data[base + 2];
    out[base + 3] = data[base + 3];
  }
  return { data: out, width, height };
};

// 多图拼接（横向/纵向）。尺寸不齐按最大画布、白底（CTF 拼帧惯例）居顶/居左对齐。
export const concatImages = (images: RgbaImage[], direction: 'h' | 'v'): RgbaImage => {
  if (images.length === 0) throw new Error('拼接至少需要一张图');
  if (direction === 'h') {
    const height = Math.max(...images.map(item => item.height));
    const width = images.reduce((sum, item) => sum + item.width, 0);
    const out = new Uint8ClampedArray(width * height * 4).fill(255);
    let offsetX = 0;
    for (const item of images) {
      for (let y = 0; y < item.height; y += 1) {
        for (let x = 0; x < item.width; x += 1) {
          const source = (y * item.width + x) * 4;
          const target = (y * width + offsetX + x) * 4;
          out[target] = item.data[source];
          out[target + 1] = item.data[source + 1];
          out[target + 2] = item.data[source + 2];
          out[target + 3] = item.data[source + 3];
        }
      }
      offsetX += item.width;
    }
    return { data: out, width, height };
  }
  const width = Math.max(...images.map(item => item.width));
  const height = images.reduce((sum, item) => sum + item.height, 0);
  const out = new Uint8ClampedArray(width * height * 4).fill(255);
  let offsetY = 0;
  for (const item of images) {
    for (let y = 0; y < item.height; y += 1) {
      for (let x = 0; x < item.width; x += 1) {
        const source = (y * item.width + x) * 4;
        const target = ((offsetY + y) * width + x) * 4;
        out[target] = item.data[source];
        out[target + 1] = item.data[source + 1];
        out[target + 2] = item.data[source + 2];
        out[target + 3] = item.data[source + 3];
      }
    }
    offsetY += item.height;
  }
  return { data: out, width, height };
};

// ---- 文本 ⇄ 图像 ----

export interface BitsImageResult {
  image: RgbaImage;
  bitCount: number;
  widthGuess: string;
}

// 01 串转黑白图（CTF 高频：txt 全是 0/1 → 画成二维码）。
// 宽度推断：有换行且行长一致 → 行宽；总数为完全平方数 → √n；否则需调用方指定。
// 1=黑（二维码暗模块），0=白。
export const bitsToImage = (text: string, forcedWidth?: number): BitsImageResult => {
  const lines = text.split(/\r?\n/).map(line => line.replace(/[^01]/g, '')).filter(line => line.length > 0);
  let bits: string;
  let widthGuess: string;
  let width: number;
  if (lines.length >= 2 && new Set(lines.map(line => line.length)).size === 1) {
    width = lines[0].length;
    bits = lines.join('');
    widthGuess = `按行宽 ${width}（${lines.length} 行）`;
  } else {
    bits = (lines.length === 1 ? lines[0] : text.replace(/[^01]/g, ''));
    const root = Math.sqrt(bits.length);
    if (Number.isInteger(root) && root > 0) {
      width = root;
      widthGuess = `总数 ${bits.length} 为完全平方，取 ${root}×${root}`;
    } else if (forcedWidth !== undefined && forcedWidth > 0) {
      width = forcedWidth;
      widthGuess = `指定宽 ${forcedWidth}`;
    } else {
      throw new Error(`0/1 总数 ${bits.length} 既不构成矩形文本行，也不是完全平方数：请在参数里指定宽度`);
    }
  }
  if (forcedWidth !== undefined && forcedWidth > 0 && width !== forcedWidth) {
    width = forcedWidth;
    widthGuess = `指定宽 ${forcedWidth}（覆盖自动推断）`;
  }
  const height = Math.ceil(bits.length / width);
  if (width * height > 4_000_000) {
    throw new Error(`0/1 串画布 ${width}×${height} 超过 400 万像素上限：内容过长或宽度设置异常`);
  }
  const out = new Uint8ClampedArray(width * height * 4).fill(255);
  for (let index = 0; index < bits.length; index += 1) {
    if (bits[index] !== '1') continue;
    const base = index * 4;
    out[base] = 0;
    out[base + 1] = 0;
    out[base + 2] = 0;
    out[base + 3] = 255;
  }
  return { image: { data: out, width, height }, bitCount: bits.length, widthGuess };
}

// XY 坐标串转散点图（黑底白点，QR 模块形态）：支持 "x,y"、"x y"、"(x,y)"、制表符分隔，行内逗号或空白均可
export const coordsToImage = (text: string): { image: RgbaImage; pointCount: number } => {
  const points: Array<{ x: number; y: number }> = [];
  const seen = new Set<number>(); // 复合键去重（reviewer P1：O(n²) 线性扫在 10 万点时分钟级冻结）
  const pattern = /\(?(-?\d+)[,;\s]+(-?\d+)\)?/g;
  for (const match of text.matchAll(pattern)) {
    const x = Number(match[1]);
    const y = Number(match[2]);
    const key = (x + 1_000_000) * 4_000_007 + (y + 1_000_000);
    if (seen.has(key)) continue;
    seen.add(key);
    points.push({ x, y });
  }
  if (points.length === 0) throw new Error('未解析出任何 (x,y) 坐标对：每行应为 "x,y" 或 "x y" 形式');
  const minX = Math.min(...points.map(point => point.x));
  const minY = Math.min(...points.map(point => point.y));
  const maxX = Math.max(...points.map(point => point.x));
  const maxY = Math.max(...points.map(point => point.y));
  const width = maxX - minX + 1;
  const height = maxY - minY + 1;
  if (width * height > 4_000_000) {
    throw new Error(`坐标画布 ${width}×${height} 超过 400 万像素上限（坐标跨度异常，请检查解析结果）`);
  }
  const out = new Uint8ClampedArray(width * height * 4).fill(0);
  for (let index = 0; index < width * height; index += 1) out[index * 4 + 3] = 255;
  for (const point of points) {
    const base = ((point.y - minY) * width + (point.x - minX)) * 4;
    out[base] = 255;
    out[base + 1] = 255;
    out[base + 2] = 255;
  }
  return { image: { data: out, width, height }, pointCount: points.length };
}

export interface RgbTextResult {
  image: RgbaImage;
  pixelCount: number;
  format: 'dec' | 'hex';
}

// RGB 数据串转图：十进制三元组（R,G,B 空格/逗号/换行分隔）或 6 位 hex 连串（RRGGBB×N）
export const rgbTextToImage = (text: string, forcedWidth?: number): RgbTextResult => {
  const cleaned = text.replace(/#[rR][gG][bB]?\(/gi, ' ').replace(/[()]/g, ' ');
  const decimals = cleaned.match(/-?\d+/g);
  const compactHex = cleaned.replace(/[^0-9a-fA-F]/g, '');
  let pixels: Array<[number, number, number]>;
  let format: 'dec' | 'hex';
  if (decimals !== null && decimals.length >= 3 && decimals.length % 3 === 0 && decimals.length / 3 <= compactHex.length / 6 + 2) {
    format = 'dec';
    pixels = [];
    for (let index = 0; index < decimals.length; index += 3) {
      pixels.push([Number(decimals[index]), Number(decimals[index + 1]), Number(decimals[index + 2])]);
    }
  } else if (compactHex.length >= 6 && compactHex.length % 6 === 0) {
    format = 'hex';
    pixels = [];
    for (let index = 0; index < compactHex.length; index += 6) {
      pixels.push([
        parseInt(compactHex.slice(index, index + 2), 16),
        parseInt(compactHex.slice(index + 2, index + 4), 16),
        parseInt(compactHex.slice(index + 4, index + 6), 16),
      ]);
    }
  } else {
    throw new Error('无法识别 RGB 数据形态：需要 "R,G,B" 十进制三元组序列（总数为 3 的倍数）或连续 6 位 hex（总数为 6 的倍数）');
  }
  const count = pixels.length;
  let width: number;
  const root = Math.sqrt(count);
  if (forcedWidth !== undefined && forcedWidth > 0) {
    width = forcedWidth;
  } else if (Number.isInteger(root) && root > 0) {
    width = root;
  } else if (count % 500 === 0) {
    width = 500;
  } else if (count % 250 === 0) {
    width = 250;
  } else if (count % 100 === 0) {
    width = 100;
  } else {
    throw new Error(`像素数 ${count} 无法推断宽度（非完全平方、也非 100/250/500 整倍）：请在参数里指定宽度`);
  }
  const height = Math.ceil(count / width);
  if (width * height > 4_000_000) {
    throw new Error(`RGB 像素画布 ${width}×${height} 超过 400 万像素上限：内容过长或宽度设置异常`);
  }
  const out = new Uint8ClampedArray(width * height * 4).fill(255);
  pixels.forEach((pixel, index) => {
    const base = index * 4;
    out[base] = Math.max(0, Math.min(255, pixel[0]));
    out[base + 1] = Math.max(0, Math.min(255, pixel[1]));
    out[base + 2] = Math.max(0, Math.min(255, pixel[2]));
    out[base + 3] = 255;
  });
  return { image: { data: out, width, height }, pixelCount: count, format };
};

// 图片转 RGB 串（dec：每像素 "R,G,B" 换行；hex：每像素 6 位 hex）
export const imageToRgbText = (image: RgbaImage, format: 'dec' | 'hex'): string => {
  const { data, width, height } = image;
  const parts: string[] = [];
  for (let index = 0; index < width * height; index += 1) {
    const base = index * 4;
    if (format === 'hex') {
      const hex = ((data[base] << 16) | (data[base + 1] << 8) | data[base + 2]).toString(16).padStart(6, '0');
      parts.push(hex);
    } else {
      parts.push(`${data[base]},${data[base + 1]},${data[base + 2]}`);
    }
  }
  return parts.join('\n');
};

// ---- 字符画（Novel_In_Image 形态） ----

export const ASCII_RAMP = '@%#*+=-:. ';

// 图片→字符画：亮度映射到 charset（默认 10 级灰阶坡），文本即"小说"载体——flag 常藏在这种长文本里
export const imageToAscii = (image: RgbaImage, charset = ASCII_RAMP): string => {
  const { data, width, height } = image;
  const lines: string[] = [];
  for (let y = 0; y < height; y += 1) {
    let line = '';
    for (let x = 0; x < width; x += 1) {
      const base = (y * width + x) * 4;
      const luminance = 0.299 * data[base] + 0.587 * data[base + 1] + 0.114 * data[base + 2];
      line += charset[Math.min(charset.length - 1, Math.floor((luminance / 256) * charset.length))];
    }
    lines.push(line);
  }
  return lines.join('\n');
};

// 字符画→图片：按字符在 charset 中的序位还原灰度（imageToAscii 的逆）
export const asciiToImage = (text: string, charset = ASCII_RAMP): RgbaImage => {
  const lines = text.replace(/\r/g, '').split('\n').filter(line => line.length > 0);
  if (lines.length === 0) throw new Error('字符画文本为空');
  const width = Math.max(...lines.map(line => line.length));
  const height = lines.length;
  const out = new Uint8ClampedArray(width * height * 4);
  for (let y = 0; y < height; y += 1) {
    for (let x = 0; x < width; x += 1) {
      const char = lines[y][x] ?? ' ';
      const position = charset.indexOf(char);
      const gray = position < 0 ? 255 : Math.round((position / (charset.length - 1)) * 255);
      const base = (y * width + x) * 4;
      out[base] = gray;
      out[base + 1] = gray;
      out[base + 2] = gray;
      out[base + 3] = 255;
    }
  }
  return { data: out, width, height };
}

// 最近邻整数放大（QR 识别链专用）：1px 模块的小图（01 串/坐标串转图产物）直接喂解码器
// 不稳定，×4 放大后命中；alpha 保留源值，放大区不足整块按最近邻复制。
export const scaleNearest = (image: RgbaImage, factor: number): RgbaImage => {
  if (!Number.isInteger(factor) || factor < 1) {
    throw new Error(`放大倍数必须为 ≥1 的整数，当前 ${factor}`);
  }
  if (factor === 1) return image;
  const { data, width, height } = image;
  const outWidth = width * factor;
  const outHeight = height * factor;
  const out = new Uint8ClampedArray(outWidth * outHeight * 4);
  for (let y = 0; y < outHeight; y += 1) {
    for (let x = 0; x < outWidth; x += 1) {
      const source = (Math.floor(y / factor) * width + Math.floor(x / factor)) * 4;
      const target = (y * outWidth + x) * 4;
      out[target] = data[source];
      out[target + 1] = data[source + 1];
      out[target + 2] = data[source + 2];
      out[target + 3] = data[source + 3];
    }
  }
  return { data: out, width: outWidth, height: outHeight };
};

// ---- flood-fill 掩码提取 ----

export interface FloodFillResult {
  mask: RgbaImage; // 命中区红高亮、其余半透明灰
  hitCount: number;
}

// 从种子点泛洪同色连通域（tolerance 容差），提取为高亮掩码——CTF 用于"同色块区域藏着差异内容"场景
export const floodFillMask = (image: RgbaImage, seedX: number, seedY: number, tolerance = 0): FloodFillResult => {
  const { data, width, height } = image;
  if (seedX < 0 || seedY < 0 || seedX >= width || seedY >= height) {
    throw new Error(`种子坐标 (${seedX},${seedY}) 超出图像范围 ${width}×${height}`);
  }
  const seedBase = (seedY * width + seedX) * 4;
  const target = [data[seedBase], data[seedBase + 1], data[seedBase + 2]];
  const visited = new Uint8Array(width * height);
  const out = new Uint8ClampedArray(width * height * 4);
  const queue: number[] = [seedY * width + seedX];
  visited[seedY * width + seedX] = 1;
  let hitCount = 0;
  while (queue.length > 0) {
    const index = queue.pop() as number;
    const base = index * 4;
    if (
      Math.abs(data[base] - target[0]) <= tolerance &&
      Math.abs(data[base + 1] - target[1]) <= tolerance &&
      Math.abs(data[base + 2] - target[2]) <= tolerance
    ) {
      hitCount += 1;
      out[base] = 255;
      out[base + 1] = 40;
      out[base + 2] = 40;
      out[base + 3] = 255;
      const x = index % width;
      const y = (index - x) / width;
      const neighbors = [
        x > 0 ? index - 1 : -1,
        x < width - 1 ? index + 1 : -1,
        y > 0 ? index - width : -1,
        y < height - 1 ? index + width : -1,
      ];
      for (const neighbor of neighbors) {
        if (neighbor >= 0 && visited[neighbor] === 0) {
          visited[neighbor] = 1;
          queue.push(neighbor);
        }
      }
    }
  }
  return { mask: { data: out, width, height }, hitCount };
}

// ---- QR 定位角补全 ----

// 画一个 7×7 模块定位角：外 1 模块黑环 + 1 模块白环 + 3×3 黑心（白环显式绘制——
// 残缺角若遗留黑像素，跳过白环会产出损坏定位角，reviewer P2）
const drawFinder = (out: Uint8ClampedArray, width: number, moduleX: number, moduleY: number, moduleSize: number): void => {
  for (let my = 0; my < 7; my += 1) {
    for (let mx = 0; mx < 7; mx += 1) {
      const ring = mx === 0 || mx === 6 || my === 0 || my === 6;
      const core = mx >= 2 && mx <= 4 && my >= 2 && my <= 4;
      const value = ring || core ? 0 : 255;
      const pixelX = (moduleX + mx) * moduleSize;
      const pixelY = (moduleY + my) * moduleSize;
      for (let dy = 0; dy < moduleSize; dy += 1) {
        for (let dx = 0; dx < moduleSize; dx += 1) {
          const base = ((pixelY + dy) * width + pixelX + dx) * 4;
          out[base] = value;
          out[base + 1] = value;
          out[base + 2] = value;
          out[base + 3] = 255;
        }
      }
    }
  }
};

// QR 补定位角：三角（左上/右上/左下）各画 7×7 定位角。moduleSize=单模块像素宽（自动=黑像素游程众数），
// margin=quiet zone 模块数（默认 1）。补完直接交给 qrDecode 复检。
export const addQrFinderPatterns = (
  image: RgbaImage,
  options?: { moduleSize?: number; margin?: number },
): { image: RgbaImage; moduleSize: number; note: string } => {
  const { data, width, height } = image;
  let moduleSize = options?.moduleSize ?? 0;
  if (moduleSize <= 0) {
    // 自动估模块宽：扫描前几行黑像素的水平游程，取众数
    const runs: number[] = [];
    let run = 0;
    for (let y = 0; y < Math.min(height, 40); y += 1) {
      run = 0;
      for (let x = 0; x < width; x += 1) {
        const base = (y * width + x) * 4;
        const dark = data[base] < 128 && data[base + 1] < 128 && data[base + 2] < 128;
        if (dark) run += 1;
        else {
          if (run > 0) runs.push(run);
          run = 0;
        }
      }
      if (run > 0) runs.push(run);
    }
    if (runs.length === 0) throw new Error('图像中无黑色像素，无法估算 QR 模块宽度：请手动指定 moduleSize');
    const counts = new Map<number, number>();
    for (const value of runs) counts.set(value, (counts.get(value) ?? 0) + 1);
    moduleSize = [...counts.entries()].sort((left, right) => right[1] - left[1])[0][0];
  }
  const marginModules = options?.margin ?? 1;
  const moduleCountX = Math.floor(width / moduleSize);
  const moduleCountY = Math.floor(height / moduleSize);
  if (Math.min(moduleCountX, moduleCountY) < 21) {
    throw new Error(`模块数 ${moduleCountX}×${moduleCountY} 小于最小 QR 版本（21×21）：模块宽 ${moduleSize}px 对 ${width}×${height} 图像过大`);
  }
  const out = new Uint8ClampedArray(width * height * 4).fill(255);
  // 二值化重画原图（清掉残缺角遗留像素）
  for (let index = 0; index < width * height; index += 1) {
    const base = index * 4;
    const luminance = 0.299 * data[base] + 0.587 * data[base + 1] + 0.114 * data[base + 2];
    const value = luminance < 128 ? 0 : 255;
    out[base] = value;
    out[base + 1] = value;
    out[base + 2] = value;
    out[base + 3] = 255;
  }
  const topLeft = marginModules;
  const topRight = moduleCountX - marginModules - 7;
  const bottomLeft = moduleCountY - marginModules - 7;
  drawFinder(out, width, topLeft, topLeft, moduleSize);
  drawFinder(out, width, topRight, topLeft, moduleSize);
  drawFinder(out, width, topLeft, bottomLeft, moduleSize);
  return {
    image: { data: out, width, height },
    moduleSize,
    note: `已在三个角落补画 7×7 定位角（模块 ${moduleSize}px，quiet zone ${marginModules} 模块）`,
  };
};
