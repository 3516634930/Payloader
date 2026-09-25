// Piet esolang 解释器（批次 SI·C 线）：esolangs.org/wiki/Piet + 原始规范（dangermouse.net/esoteric/piet.html）双重核实。
// 18 指令色 = 6 hue（红→黄→绿→青→蓝→洋红循环）× 3 lightness（浅→正→深循环），
// 加黑（阻隔、触发滑动规则）与白（可穿越；进出白块均不执行指令——原始规范：
// "Sliding across white blocks into a new colour does not cause a command to be executed"）。
// codel 块 = 同色四连通；程序从 (0,0) 所在块起步，DP 初始右、CC 初始 left；
// 跨块受阻（黑/出界）时先翻 CC 重试、再顺时针转 DP，8 个 (DP,CC) 组合穷尽即程序正常终止
//（规范：全堵是 Piet 唯一终止方式——注意出口取最远边缘上按 CC 的角点 codel，彩色邻块只贴边中部不贴角点时照样算堵死）。
// 每像素一 codel（codelSize 聚合由调用方缩放后传入）；色匹配 ±2 抗有损重编码，未命中任何标准色的像素（如灰）按黑处理。
// 纯本地、零依赖；步数上限防 CTF 恶意题死循环。运行期异常（栈下溢/除零/输入耗尽）以 error 字段中文报错停机，不静默跳过。

export interface PietRunResult {
  output: string;
  steps: number; // 主循环迭代数：一次跨块尝试（含至多 8 次滑动重试）或白区内前进一格
  terminated: boolean;
  timedOut: boolean;
  error: string | null;
  stackTop: number[]; // 停机时数栈顶部快照（最多 16 个，底→顶）
}

export const PIET_DEFAULT_MAX_STEPS = 2_000_000;

const COLOR_TOLERANCE = 2;
const PIET_WHITE = -1;
const PIET_BLACK = -2;
const NO_PENDING = -1;

// 标准 18 色表（esolangs wiki 色环，行序 lightness 浅/正/深、行内按 hue 红→黄→绿→青→蓝→洋红）。
// colorId = lightness*6 + hue，(hue, light) 可由 id 直接导出参与循环差运算。
const PIET_COLOR_TABLE: ReadonlyArray<readonly [number, number, number]> = [
  [0xff, 0xc0, 0xc0], [0xff, 0xff, 0xc0], [0xc0, 0xff, 0xc0], [0xc0, 0xff, 0xff], [0xc0, 0xc0, 0xff], [0xff, 0xc0, 0xff],
  [0xff, 0x00, 0x00], [0xff, 0xff, 0x00], [0x00, 0xff, 0x00], [0x00, 0xff, 0xff], [0x00, 0x00, 0xff], [0xff, 0x00, 0xff],
  [0xc0, 0x00, 0x00], [0xc0, 0xc0, 0x00], [0x00, 0xc0, 0x00], [0x00, 0xc0, 0xc0], [0x00, 0x00, 0xc0], [0xc0, 0x00, 0xc0],
];

// 指令矩阵（wiki 6×3）：行 = hue 差 0..5、列 = lightness 差 0..2，下标 dh*3+dl。
// 锚点：红→暗红 = (0,1) = push；红→黄 = (1,0) = add；hue 差 5 行 = in(char)/out(number)/out(char)。
const INSTRUCTIONS: ReadonlyArray<string> = [
  'none', 'push', 'pop',
  'add', 'sub', 'mul',
  'div', 'mod', 'not',
  'greater', 'pointer', 'switch',
  'dup', 'roll', 'inNum',
  'inChar', 'outNum', 'outChar',
];

// DP 顺时针序（屏幕坐标 y 向下）：右→下→左→上；CC=left 为面朝 DP 方向的左手侧
const DP_VECTORS: ReadonlyArray<readonly [number, number]> = [[1, 0], [0, 1], [-1, 0], [0, -1]];
// 各 DP 朝向下 CC=left 的方向向量（右朝向左手=北(0,-1)，下=东(1,0)，左=南(0,1)，上=西(-1,0)）
const CC_LEFT_VECTORS: ReadonlyArray<readonly [number, number]> = [[0, -1], [1, 0], [0, 1], [-1, 0]];

interface PietBlock {
  colorId: number;
  size: number;
  exits: Int32Array; // exits[dp*2+cc]：该 (DP,CC) 组合下选中的最远边缘角点 codel 索引
}

const classifyColor = (r: number, g: number, b: number): number => {
  // 白不在 18 色表内须显式判，否则会落进"表外→黑"分支、把白区误当阻隔
  if (Math.abs(r - 0xff) <= COLOR_TOLERANCE && Math.abs(g - 0xff) <= COLOR_TOLERANCE && Math.abs(b - 0xff) <= COLOR_TOLERANCE) {
    return PIET_WHITE;
  }
  for (let id = 0; id < PIET_COLOR_TABLE.length; id += 1) {
    const [cr, cg, cb] = PIET_COLOR_TABLE[id];
    if (Math.abs(r - cr) <= COLOR_TOLERANCE && Math.abs(g - cg) <= COLOR_TOLERANCE && Math.abs(b - cb) <= COLOR_TOLERANCE) {
      return id;
    }
  }
  return PIET_BLACK;
};

// 预计算块在全部 8 种 (DP,CC) 下的边缘角点：主键 = DP 方向投影最远，次键 = CC 方向投影最远（字典序取最大）。
// 图不变故无失效问题；只对 18 指令色建块（黑按格查、白直线滑行均不需要块结构）。
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
  options?: { input?: string; maxSteps?: number },
): PietRunResult => {
  const halted = (error: string): PietRunResult => ({ output: '', steps: 0, terminated: false, timedOut: false, error, stackTop: [] });
  if (!Number.isInteger(width) || !Number.isInteger(height) || width <= 0 || height <= 0) {
    return halted(`图像尺寸非法：${width}×${height}（须为正整数）`);
  }
  if (rgba.length !== width * height * 4) {
    return halted(`rgba 长度 ${rgba.length} 与 ${width}×${height}×4 不符`);
  }
  const input = options?.input ?? '';
  const maxSteps = options?.maxSteps ?? PIET_DEFAULT_MAX_STEPS;

  const classify = new Int16Array(width * height);
  for (let i = 0; i < width * height; i += 1) {
    classify[i] = classifyColor(rgba[i * 4], rgba[i * 4 + 1], rgba[i * 4 + 2]);
  }

  // 四连通分块（迭代泛洪防大图递归爆栈）
  const blockId = new Int32Array(width * height).fill(-1);
  const blocks: PietBlock[] = [];
  const flood: number[] = [];
  for (let seed = 0; seed < width * height; seed += 1) {
    const color = classify[seed];
    if (color < 0 || blockId[seed] !== -1) continue;
    const id = blocks.length;
    const codels: number[] = [];
    flood.push(seed);
    blockId[seed] = id;
    while (flood.length > 0) {
      const idx = flood.pop();
      if (idx === undefined) break;
      codels.push(idx);
      const x = idx % width;
      const y = (idx / width) | 0;
      const visit = (n: number): void => {
        if (blockId[n] === -1 && classify[n] === color) {
          blockId[n] = id;
          flood.push(n);
        }
      };
      if (x + 1 < width) visit(idx + 1);
      if (x > 0) visit(idx - 1);
      if (y + 1 < height) visit(idx + width);
      if (y > 0) visit(idx - width);
    }
    blocks.push(makeBlock(color, codels, width));
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

  let inWhite = classify[0] === PIET_WHITE;
  let whitePos = 0;
  let current: PietBlock | null = classify[0] >= 0 ? blocks[blockId[0]] : null;

  if (classify[0] === PIET_BLACK) {
    // 起步 codel 即黑：8 态天然全堵，零步终止
    return { output: '', steps: 0, terminated: true, timedOut: false, error: null, stackTop: [] };
  }

  // 弹栈失败即置错误停机（npiet 同样在栈下溢时中止；不静默吞掉）
  const popChecked = (what: string): number | null => {
    const top = stack.pop();
    if (top === undefined) {
      error = `${what} 栈下溢（当前栈为空）`;
      return null;
    }
    return top;
  };

  // 执行"退出色→进入色"循环差对应的指令；push 压入的是退出块的 codel 数
  const execute = (fromColor: number, fromSize: number, toColor: number): void => {
    // colorId = lightness*6 + hue：hue 差取 %6、lightness 差取 /6
    const dh = ((toColor % 6) - (fromColor % 6) + 6) % 6;
    const dl = (((toColor / 6) | 0) - ((fromColor / 6) | 0) + 3) % 3;
    const command = INSTRUCTIONS[dh * 3 + dl];
    switch (command) {
      case 'push':
        stack.push(fromSize);
        break;
      case 'pop':
        popChecked('pop');
        break;
      case 'add':
      case 'sub':
      case 'mul':
      case 'div':
      case 'mod':
      case 'greater': {
        const a = popChecked(command);
        if (a === null) break;
        const b = popChecked(command);
        if (b === null) break;
        if (command === 'add') stack.push(b + a);
        else if (command === 'sub') stack.push(b - a); // 次栈顶 − 栈顶
        else if (command === 'mul') stack.push(b * a);
        else if (command === 'greater') stack.push(b > a ? 1 : 0);
        else if (a === 0) error = `${command} 除数为 0`;
        else if (command === 'div') stack.push(Math.trunc(b / a)); // 截断向零（C/npiet 语义）
        else stack.push(b % a); // 截断型余数，符号随被除数
        break;
      }
      case 'not': {
        const top = stack[stack.length - 1];
        if (top === undefined) error = 'not 栈下溢（当前栈为空）';
        else stack[stack.length - 1] = top === 0 ? 1 : 0;
        break;
      }
      case 'pointer': {
        const n = popChecked('pointer');
        if (n !== null) dp = ((dp + n) % 4 + 4) % 4; // 负值即逆时针
        break;
      }
      case 'switch': {
        const n = popChecked('switch');
        if (n !== null && ((n % 2) + 2) % 2 === 1) cc ^= 1;
        break;
      }
      case 'dup': {
        const top = stack[stack.length - 1];
        if (top === undefined) error = 'dup 栈下溢（当前栈为空）';
        else stack.push(top);
        break;
      }
      case 'roll': {
        const x = popChecked('roll');
        if (x === null) break;
        const y = popChecked('roll');
        if (y === null) break;
        // 原始规范：单次 roll = "把栈顶值埋到深度 y 处"（wiki 原例 [1,2,3] roll(1,3) → [3,1,2]，即滚动段右移）；
        // 负次数反向；负深度忽略；深度超栈深为实现自由项、规范建议忽略（此处从简：no-op）
        if (y > 0 && y <= stack.length) {
          const count = ((x % y) + y) % y;
          if (count > 0) {
            const segment = stack.splice(stack.length - y);
            const rotated = segment.slice(segment.length - count).concat(segment.slice(0, segment.length - count));
            for (const value of rotated) stack.push(value);
          }
        }
        break;
      }
      case 'inNum': {
        // 十进制整数：跳过前导空白，可选符号 + 数字串；无数字可读即报错停机
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
          stack.push(Number.parseInt(input.slice(i, j), 10));
          inputCursor = j;
        }
        break;
      }
      case 'inChar': {
        if (inputCursor >= input.length) {
          error = 'in(char) 输入已耗尽';
          break;
        }
        const code = input.codePointAt(inputCursor);
        if (code === undefined) stack.push(0);
        else {
          stack.push(code);
          inputCursor += String.fromCodePoint(code).length;
        }
        break;
      }
      case 'outNum': {
        const value = popChecked('out(number)');
        if (value !== null) output += String(value);
        break;
      }
      case 'outChar': {
        const value = popChecked('out(char)');
        // 非法码点（负数/超平面）跳过，不让一次坏输出击穿整个取证流程
        if (value !== null && Number.isInteger(value) && value >= 0 && value <= 0x10ffff) {
          output += String.fromCodePoint(value);
        }
        break;
      }
      default:
        break; // none：同色差 (0,0) 只可能出现在跨白区回到同色块等场景
    }
  };

  // 尝试从 (px,py) 沿 dir 前进一格：出界/黑 → false（触发滑动规则）；白 → 白区滑行（无指令）；
  // 彩色 → 结算指令并切换当前块。进出白块均不执行指令（原始规范明文）。
  const enterCell = (px: number, py: number, dir: number, fromColor: number, fromSize: number): boolean => {
    const [dx, dy] = DP_VECTORS[dir];
    const nx = px + dx;
    const ny = py + dy;
    if (nx < 0 || ny < 0 || nx >= width || ny >= height) return false;
    const nextIdx = ny * width + nx;
    const color = classify[nextIdx];
    if (color === PIET_BLACK) return false;
    if (color === PIET_WHITE) {
      inWhite = true;
      whitePos = nextIdx;
      return true;
    }
    if (fromColor >= 0) execute(fromColor, fromSize, color);
    current = blocks[blockId[nextIdx]];
    inWhite = false;
    return true;
  };

  // 主循环。滑动序：(DP,CC) → (DP,CC̄) → (DP⁺¹,CC̄) → (DP⁺¹,CC) → …（先翻 CC、再顺时针转 DP，8 组合穷尽即终止）。
  // 白区内受阻沿用同一套 8 态滑动（npiet 行为；原始规范的"白区路径回溯检测"不实现，环形白区死循环交给 maxSteps 兜底）。
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
      if (inWhite) {
        const wx = whitePos % width;
        const wy = (whitePos / width) | 0;
        moved = enterCell(wx, wy, dp, NO_PENDING, 0);
      } else if (current !== null) {
        const exitIdx = current.exits[dp * 2 + cc];
        moved = enterCell(exitIdx % width, (exitIdx / width) | 0, dp, current.colorId, current.size);
      }
    }
    if (!moved) terminated = true;
  }

  return { output, steps, terminated, timedOut, error, stackTop: stack.slice(-16) };
};
