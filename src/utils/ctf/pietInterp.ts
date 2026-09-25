// Piet esolang 解释器（批次 SI·C 线）：esolangs.org/wiki/Piet 规范。
// 18 指令色 = 6 hue（红黄绿青蓝洋红循环）× 3 light（浅/正常/深循环），加黑（阻隔、触发滑动规则）
// 与白（可穿越；穿越期间不执行指令，进入下一色块时按"进入白区前最后离开的色块"结算指令）。
// codel 块 = 同色四连通；程序从 (0,0) 所在块起步，DP 初始右、CC 初始 left；
// 目标为黑或出界时滑动：先翻 CC 重试、再顺时针转 DP，8 种 (DP,CC) 组合穷尽即程序正常终止。
// 纯本地、零依赖；步数上限防 CTF 恶意题死循环。

export interface PietRunResult {
  output: string;
  steps: number;
  terminated: boolean;
  timedOut: boolean;
  error: string | null;
  stackTop: number[];
}

export const PIET_DEFAULT_MAX_STEPS = 2_000_000;

const COLOR_TOLERANCE = 2;
const WHITE = -1;
const BLACK = -2;
const NO_PENDING = -1;

// 标准 20 色表（wiki）：行序 hue 红/黄/绿/青/蓝/洋红、列序 light 浅/正常/深；colorId = hue*3 + light。
// 表外色（±2 容差外）按黑处理；半透明像素按白处理（浏览器解码透明 PNG 后其 RGB 不可靠）。
const PIET_COLOR_TABLE: ReadonlyArray<readonly [number, number, number]> = [
  [0xff, 0xc0, 0xc0], [0xff, 0x00, 0x00], [0xc0, 0x00, 0x00],
  [0xff, 0xff, 0xc0], [0xff, 0xff, 0x00], [0xc0, 0xc0, 0x00],
  [0xc0, 0xff, 0xc0], [0x00, 0xff, 0x00], [0x00, 0xc0, 0x00],
  [0xc0, 0xff, 0xff], [0x00, 0xff, 0xff], [0x00, 0xc0, 0xc0],
  [0xc0, 0xc0, 0xff], [0x00, 0x00, 0xff], [0x00, 0x00, 0xc0],
  [0xff, 0xc0, 0xff], [0xff, 0x00, 0xff], [0xc0, 0x00, 0xc0],
];

// DP 顺时针序（屏幕坐标 y 向下）：右→下→左→上；CC=left 为面朝 DP 方向的左手侧
const DP_VECTORS: ReadonlyArray<readonly [number, number]> = [[1, 0], [0, 1], [-1, 0], [0, -1]];
const CC_LEFT_VECTORS: ReadonlyArray<readonly [number, number]> = [[0, -1], [1, 0], [0, 1], [-1, 0]];

// 指令矩阵（wiki 6×3）：行 = hue 差 0..5、列 = light 差 0..2，下标 dh*3+dl
const INSTRUCTIONS: ReadonlyArray<string> = [
  'none', 'push', 'pop',
  'add', 'sub', 'mul',
  'div', 'mod', 'not',
  'greater', 'pointer', 'switch',
  'dup', 'roll', 'inNum',
  'outNum', 'outChar', 'inChar',
];

interface PietBlock {
  colorId: number;
  size: number;
  exits: Int32Array; // exits[dp*2+cc]：该 (DP,CC) 组合下选出的边缘退出 codel 索引
}

const classifyColor = (r: number, g: number, b: number): number => {
  // 白/黑不在 18 色表内：白须显式判（否则落进"表外→黑"分支，白区会被当成阻隔）
  if (Math.abs(r - 0xff) <= COLOR_TOLERANCE && Math.abs(g - 0xff) <= COLOR_TOLERANCE && Math.abs(b - 0xff) <= COLOR_TOLERANCE) {
    return WHITE;
  }
  for (let id = 0; id < PIET_COLOR_TABLE.length; id += 1) {
    const [cr, cg, cb] = PIET_COLOR_TABLE[id];
    if (Math.abs(r - cr) <= COLOR_TOLERANCE && Math.abs(g - cg) <= COLOR_TOLERANCE && Math.abs(b - cb) <= COLOR_TOLERANCE) {
      return id;
    }
  }
  return BLACK;
};

// 预计算块在全部 8 种 (DP,CC) 组合下的边缘退出 codel：
// 先取 DP 方向最远的边缘（主键），再在该边缘上取 CC 方向最远者（次键），两键字典序取最大。
const makeBlock = (colorId: number, codels: number[], cols: number): PietBlock => {
  const exits = new Int32Array(8);
  for (let dp = 0; dp < 4; dp += 1) {
    const [dx, dy] = DP_VECTORS[dp];
    const [lx, ly] = CC_LEFT_VECTORS[dp];
    for (let cc = 0; cc < 2; cc += 1) {
      const cx = cc === 0 ? lx : -lx;
      const cy = cc === 0 ? ly : -ly;
      let best = codels[0];
      let bestPrimary = Number.NEGATIVE_INFINITY;
      let bestSecondary = Number.NEGATIVE_INFINITY;
      for (const idx of codels) {
        const x = idx % cols;
        const y = (idx / cols) | 0;
        const primary = x * dx + y * dy;
        const secondary = x * cx + y * cy;
        if (primary > bestPrimary || (primary === bestPrimary && secondary > bestSecondary)) {
          best = idx;
          bestPrimary = primary;
          bestSecondary = secondary;
        }
      }
      exits[dp * 2 + cc] = best;
    }
  }
  return { colorId, size: codels.length, exits };
};

export const runPiet = (
  rgba: ArrayLike<number>,
  width: number,
  height: number,
  options: { input?: string; maxSteps?: number; codelSize?: number } = {},
): PietRunResult => {
  if (!Number.isInteger(width) || !Number.isInteger(height) || width <= 0 || height <= 0) {
    throw new Error(`图像尺寸非法：${width}×${height}（须为正整数）`);
  }
  if (rgba.length < width * height * 4) {
    throw new Error(`RGBA 数据长度 ${rgba.length} 小于 ${width}×${height}×4`);
  }
  const input = options.input ?? '';
  const maxSteps = options.maxSteps ?? PIET_DEFAULT_MAX_STEPS;
  const codelSize = options.codelSize ?? 1;
  if (!Number.isInteger(codelSize) || codelSize <= 0) {
    throw new Error(`codelSize 非法：${codelSize}（须为正整数）`);
  }
  if (!Number.isInteger(maxSteps) || maxSteps <= 0) {
    throw new Error(`maxSteps 非法：${maxSteps}（须为正整数）`);
  }

  const cols = Math.ceil(width / codelSize);
  const rows = Math.ceil(height / codelSize);
  const colorGrid = new Int16Array(cols * rows);
  for (let cy = 0; cy < rows; cy += 1) {
    for (let cx = 0; cx < cols; cx += 1) {
      const base = (cy * codelSize * width + cx * codelSize) * 4;
      colorGrid[cy * cols + cx] = rgba[base + 3] < 0x80
        ? WHITE
        : classifyColor(rgba[base], rgba[base + 1], rgba[base + 2]);
    }
  }

  // 四连通分块：只给 18 指令色建块；黑直接查 colorGrid（无需块结构），白按位置滑行不建块
  const blockId = new Int32Array(cols * rows).fill(-1);
  const blocks: PietBlock[] = [];
  const flood: number[] = [];
  for (let start = 0; start < cols * rows; start += 1) {
    const color = colorGrid[start];
    if (color < 0 || blockId[start] !== -1) continue;
    const id = blocks.length;
    const codels: number[] = [];
    flood.push(start);
    blockId[start] = id;
    while (flood.length > 0) {
      const idx = flood.pop();
      if (idx === undefined) break;
      codels.push(idx);
      const x = idx % cols;
      const y = (idx / cols) | 0;
      if (x + 1 < cols) {
        const n = idx + 1;
        if (blockId[n] === -1 && colorGrid[n] === color) { blockId[n] = id; flood.push(n); }
      }
      if (x > 0) {
        const n = idx - 1;
        if (blockId[n] === -1 && colorGrid[n] === color) { blockId[n] = id; flood.push(n); }
      }
      if (y + 1 < rows) {
        const n = idx + cols;
        if (blockId[n] === -1 && colorGrid[n] === color) { blockId[n] = id; flood.push(n); }
      }
      if (y > 0) {
        const n = idx - cols;
        if (blockId[n] === -1 && colorGrid[n] === color) { blockId[n] = id; flood.push(n); }
      }
    }
    blocks.push(makeBlock(color, codels, cols));
  }

  const stack: number[] = [];
  let output = '';
  let steps = 0;
  let dp = 0;
  let cc = 0; // 0=left 1=right
  let inputCursor = 0;
  let error: string | null = null;
  let terminated = false;
  let timedOut = false;

  // 白区穿越状态：滑行位置 + 待结算的"进入白区前最后离开的色块"（颜色与 codel 数）
  let inWhite = false;
  let whitePos = 0;
  let pendingColor = NO_PENDING;
  let pendingSize = 0;
  let current: PietBlock | null = null;

  if (colorGrid[0] === BLACK) {
    terminated = true; // 起步块即黑：立即终止
  } else if (colorGrid[0] === WHITE) {
    inWhite = true; // 从白区滑行起步：进入首个色块时不执行指令
  } else {
    current = blocks[blockId[0]];
  }

  const popValue = (what: string): number => {
    const top = stack.pop();
    if (top === undefined) {
      error = `${what} 栈下溢（当前栈为空）`;
      return 0;
    }
    return top;
  };

  const execute = (fromColor: number, fromSize: number, toColor: number): void => {
    const dh = (((toColor / 3) | 0) - ((fromColor / 3) | 0) + 6) % 6;
    const dl = ((toColor % 3) - (fromColor % 3) + 3) % 3;
    switch (INSTRUCTIONS[dh * 3 + dl]) {
      case 'push':
        stack.push(fromSize); // push 压入的是"被退出的块"的 codel 数
        break;
      case 'pop':
        popValue('pop');
        break;
      case 'add': {
        const a = popValue('add');
        if (error === null) {
          const b = popValue('add');
          if (error === null) stack.push(b + a);
        }
        break;
      }
      case 'sub': {
        const a = popValue('sub');
        if (error === null) {
          const b = popValue('sub');
          if (error === null) stack.push(b - a); // 次栈顶减栈顶
        }
        break;
      }
      case 'mul': {
        const a = popValue('mul');
        if (error === null) {
          const b = popValue('mul');
          if (error === null) stack.push(b * a);
        }
        break;
      }
      case 'div': {
        const a = popValue('div');
        if (error === null) {
          if (a === 0) error = 'div 除数为 0';
          else {
            const b = popValue('div');
            if (error === null) stack.push(Math.trunc(b / a));
          }
        }
        break;
      }
      case 'mod': {
        const a = popValue('mod');
        if (error === null) {
          if (a === 0) error = 'mod 除数为 0';
          else {
            const b = popValue('mod');
            if (error === null) stack.push(b % a); // 截断取余（与 npiet/C 一致，余数符号随被除数）
          }
        }
        break;
      }
      case 'not': {
        const top = stack[stack.length - 1];
        if (top === undefined) error = 'not 栈下溢（当前栈为空）';
        else stack[stack.length - 1] = top === 0 ? 1 : 0;
        break;
      }
      case 'greater': {
        const a = popValue('greater');
        if (error === null) {
          const b = popValue('greater');
          if (error === null) stack.push(b > a ? 1 : 0); // 次栈顶 > 栈顶
        }
        break;
      }
      case 'pointer': {
        const n = popValue('pointer');
        if (error === null) dp = ((dp + n) % 4 + 4) % 4; // 负数即逆时针
        break;
      }
      case 'switch': {
        const n = popValue('switch');
        if (error === null && ((n % 2) + 2) % 2 === 1) cc ^= 1;
        break;
      }
      case 'dup': {
        const top = stack[stack.length - 1];
        if (top === undefined) error = 'dup 栈下溢（当前栈为空）';
        else stack.push(top);
        break;
      }
      case 'roll': {
        const x = popValue('roll');
        if (error === null) {
          const y = popValue('roll');
          if (error === null) {
            if (y < 0) error = `roll 旋转深度为负（${y}）`;
            else {
              // 深度超出栈深时钳制到整栈（npiet 容忍语义）；负旋转次数按模规范化为反向
              const depth = Math.min(y, stack.length);
              if (depth > 1) {
                const count = ((x % depth) + depth) % depth;
                if (count > 0) {
                  const win = stack.splice(stack.length - depth);
                  stack.push(...win.slice(win.length - count), ...win.slice(0, win.length - count));
                }
              }
            }
          }
        }
        break;
      }
      case 'inNum': {
        let i = inputCursor;
        while (i < input.length && /\s/.test(input[i])) i += 1;
        let j = i;
        const head = j < input.length ? input[j] : '';
        if (head === '+' || head === '-') j += 1;
        const digitStart = j;
        while (j < input.length && input[j] >= '0' && input[j] <= '9') j += 1;
        if (j === digitStart) {
          error = `in(number) 输入中无可读的十进制数字（剩余 "${input.slice(inputCursor, inputCursor + 8)}"）`;
        } else {
          stack.push(parseInt(input.slice(i, j), 10));
          inputCursor = j;
        }
        break;
      }
      case 'inChar': {
        if (inputCursor >= input.length) error = 'in(char) 输入已耗尽';
        else {
          stack.push(input.charCodeAt(inputCursor));
          inputCursor += 1;
        }
        break;
      }
      case 'outNum':
        output += String(popValue('out(number)'));
        break;
      case 'outChar':
        output += String.fromCharCode(popValue('out(char)'));
        break;
      default:
        break; // none：同色差为 0，跨白区回到同色块等场景
    }
  };

  // 尝试进入 (nx,ny)：出界/黑返回 false（触发滑动规则）；白区则挂起/保留 pending；
  // 有色则结算指令（直接来自色块用其颜色，跨白区用挂起色）。fromColor < 0 表示当前正处于白区。
  const enterCell = (nx: number, ny: number, fromColor: number, fromSize: number): boolean => {
    if (nx < 0 || ny < 0 || nx >= cols || ny >= rows) return false;
    const nextIdx = ny * cols + nx;
    const color = colorGrid[nextIdx];
    if (color === BLACK) return false;
    if (color === WHITE) {
      if (fromColor >= 0) {
        pendingColor = fromColor;
        pendingSize = fromSize;
      }
      inWhite = true;
      whitePos = nextIdx;
      return true;
    }
    const settleColor = fromColor >= 0 ? fromColor : pendingColor;
    const settleSize = fromColor >= 0 ? fromSize : pendingSize;
    if (settleColor >= 0) execute(settleColor, settleSize, color);
    pendingColor = NO_PENDING;
    current = blocks[blockId[nextIdx]];
    inWhite = false;
    return true;
  };

  // 主循环：一次迭代 = 一次块间转移（含至多 8 次滑动尝试）或一次白区单格滑行；
  // 滑动序为 (DP,CC) → (DP,CC̄) → (DP⁺¹,CC̄) → (DP⁺¹,CC) → …（先翻 CC 再顺时针转 DP，8 组合穷尽即终止）
  while (!terminated && !timedOut && error === null) {
    if (steps >= maxSteps) {
      timedOut = true;
      break;
    }
    steps += 1;
    let moved = false;
    for (let attempt = 0; attempt < 8 && !moved; attempt += 1) {
      if (attempt > 0) {
        if (attempt % 2 === 1) cc ^= 1;
        else dp = (dp + 1) % 4;
      }
      const [dx, dy] = DP_VECTORS[dp];
      if (inWhite) {
        const wx = whitePos % cols;
        const wy = (whitePos / cols) | 0;
        moved = enterCell(wx + dx, wy + dy, NO_PENDING, 0);
      } else if (current !== null) {
        const exitIdx = current.exits[dp * 2 + cc];
        moved = enterCell((exitIdx % cols) + dx, ((exitIdx / cols) | 0) + dy, current.colorId, current.size);
      }
    }
    if (!moved) terminated = true;
  }

  return { output, steps, terminated, timedOut, error, stackTop: stack.slice(-16) };
};
