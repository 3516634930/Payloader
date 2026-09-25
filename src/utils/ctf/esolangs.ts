// esolang 解释器集合（批次 SI·C 线）：随波逐流"bftools"/"npiet"对标。
// Brainfuck：8 指令栈机（esolangs.org/wiki/Brainfuck 标准）。
// Brainloller：PNG 每像素一指令的色表方言（mbikovitsky/BrainTools BFLib/CommandColors.cs 逐色核实），
//   在 BF 之外增加指令指针转向（↻ 顺时针 / ↺ 逆时针）。
// Braincopter：把 BF+转向指令嵌进任意图片：(65536·R + 256·G + B) % 11（BrainTools BFLib/Braincopter.cs 核实），
//   0-7=BF 八指令、8=右转、9=左转、10=终止填充。
// 解码出的指令流按"方向行走"模型执行（从 (0,0) 向东，转向指令改变行走方向，出界/色表外=nop 不停走）。
// 纯本地、零依赖；步数上限防 CTF 恶意题死循环。
export interface BfRunResult {
  output: string; // latin1 文本
  steps: number;
  timedOut: boolean;
  error: string | null;
}

export const BF_DEFAULT_MAX_STEPS = 20_000_000;
const BF_TAPE_SIZE = 30_000;

// 执行 Brainfuck 源码。input 为 `,` 读入的 latin1 缓冲（一次性预载，读尽后 `,` 不推进输出）。
export const runBrainfuck = (source: string, input = '', maxSteps = BF_DEFAULT_MAX_STEPS): BfRunResult => {
  const commands = source.replace(/[^><+\-.,[\]]/g, '');
  // 括号配对预解析（失配早报，避免运行期栈错位）
  const jump = new Int32Array(commands.length).fill(-1);
  const stack: number[] = [];
  for (let index = 0; index < commands.length; index += 1) {
    const command = commands[index];
    if (command === '[') stack.push(index);
    else if (command === ']') {
      const open = stack.pop();
      if (open === undefined) return { output: '', steps: 0, timedOut: false, error: `第 ${index + 1} 个字符 ']' 缺少配对的 '['` };
      jump[open] = index;
      jump[index] = open;
    }
  }
  if (stack.length > 0) {
    return { output: '', steps: 0, timedOut: false, error: `'[' 缺少配对的 ']'（首个未闭合位于第 ${stack[0] + 1} 个有效字符）` };
  }
  const tape = new Uint8Array(BF_TAPE_SIZE);
  let pointer = 0;
  let programCounter = 0;
  let inputCursor = 0;
  let steps = 0;
  let output = '';
  while (programCounter < commands.length) {
    if (steps >= maxSteps) return { output, steps, timedOut: true, error: null };
    steps += 1;
    const command = commands[programCounter];
    switch (command) {
      case '>':
        pointer += 1;
        if (pointer >= BF_TAPE_SIZE) return { output, steps, timedOut: false, error: `指针越界：'>' 超出磁带 ${BF_TAPE_SIZE} 单元` };
        break;
      case '<':
        pointer -= 1;
        if (pointer < 0) return { output, steps, timedOut: false, error: "指针越界：'<' 越过磁带起点" };
        break;
      case '+':
        tape[pointer] = (tape[pointer] + 1) & 0xff;
        break;
      case '-':
        tape[pointer] = (tape[pointer] - 1) & 0xff;
        break;
      case '.':
        output += String.fromCharCode(tape[pointer]);
        break;
      case ',':
        tape[pointer] = inputCursor < input.length ? input.charCodeAt(inputCursor++) & 0xff : 0;
        break;
      case '[':
        if (tape[pointer] === 0) programCounter = jump[programCounter];
        break;
      default:
        if (tape[pointer] !== 0) programCounter = jump[programCounter];
        break;
    }
    programCounter += 1;
  }
  return { output, steps, timedOut: false, error: null };
};

// 图片→BF 指令串：黑白像素块（暗=指令明=分隔？CTF 惯例=每黑块一个指令字符）。
// 实际做法：把图像二值化后按行扫描，黑像素游程映射到指令集（bftools 形态：黑块=BF 字符，白=分隔）。
// 这里采用最通用的形态：黑像素→'1' 白→'0' 得到位串，位串按 8 位一组转 ASCII 字符——若结果含
// BF 指令字符即为源码；另一常见形态是像素亮度直接就是字符画（走 strings/字符画工具）。
export const bitsToBfSource = (bits: string): { source: string; valid: boolean } => {
  const clean = bits.replace(/[^01]/g, '');
  if (clean.length < 8) return { source: '', valid: false };
  let source = '';
  for (let index = 0; index + 8 <= clean.length; index += 8) {
    source += String.fromCharCode(parseInt(clean.slice(index, index + 8), 2));
  }
  const bfChars = source.replace(/[^><+\-.,[\]]/g, '');
  return { source, valid: bfChars.length >= 4 && bfChars.length >= source.length * 0.5 };
};

// ---- Brainloller / Braincopter（mbikovitsky/BrainTools 规范） ----

import type { RgbaImage } from './imageOps';

// Brainloller 色表：精确 RGB → 指令（±2 容差应对有损重编码）
const BRAINLOLLER_TABLE: Array<{ color: [number, number, number]; command: string }> = [
  { color: [0xff, 0x00, 0x00], command: '>' },
  { color: [0x80, 0x00, 0x00], command: '<' },
  { color: [0x00, 0xff, 0x00], command: '+' },
  { color: [0x00, 0x80, 0x00], command: '-' },
  { color: [0x00, 0x00, 0xff], command: '.' },
  { color: [0x00, 0x00, 0x80], command: ',' },
  { color: [0xff, 0xff, 0x00], command: '[' },
  { color: [0x80, 0x80, 0x00], command: ']' },
  { color: [0x00, 0xff, 0xff], command: 'R' }, // 指令指针顺时针
  { color: [0x00, 0x80, 0x80], command: 'L' }, // 指令指针逆时针
];

export interface WalkedProgram {
  commands: string; // 依行走方向收集的指令序列（R/L 转向已消费，不入序列）
  path: Array<{ x: number; y: number }>;
  terminated: boolean; // 出界终止
}

// Brainloller：按色表逐像素映射（±容差），非命令色=nop（空格，不进入指令序列）
export const decodeBrainloller = (image: RgbaImage, tolerance = 2): WalkedProgram => {
  const { data, width, height } = image;
  const commandAt = (x: number, y: number): string | null => {
    const base = (y * width + x) * 4;
    const r = data[base];
    const g = data[base + 1];
    const b = data[base + 2];
    for (const entry of BRAINLOLLER_TABLE) {
      if (
        Math.abs(r - entry.color[0]) <= tolerance &&
        Math.abs(g - entry.color[1]) <= tolerance &&
        Math.abs(b - entry.color[2]) <= tolerance
      ) {
        return entry.command;
      }
    }
    return null;
  };
  return walkProgram(commandAt, width, height);
};

// Braincopter：(65536·R + 256·G + B) % 11 → 0-7 BF 指令 / 8 右转 / 9 左转 / 10 终止
const BRAINCOPTER_COMMANDS = ['>', '<', '+', '-', '.', ',', '[', ']', 'R', 'L', 'X'];

export const decodeBraincopter = (image: RgbaImage): WalkedProgram & { terminatedByMarker: boolean } => {
  const { data, width, height } = image;
  const commandAt = (x: number, y: number): string | null => {
    const base = (y * width + x) * 4;
    return BRAINCOPTER_COMMANDS[(65536 * data[base] + 256 * data[base + 1] + data[base + 2]) % 11];
  };
  const walked = walkProgram(commandAt, width, height, new Set(['X']));
  return { ...walked, terminatedByMarker: walked.terminated && walked.terminatedBy === 'marker' } as WalkedProgram & { terminatedByMarker: boolean };
};

// 方向行走模型：从 (0,0) 向东，R/L 转向（含走回头路的 1 步回退），nop 直行，出界终止。
// stopAt：遇到即终止的指令（Braincopter 的 'X'）。
function walkProgram(
  commandAt: (x: number, y: number) => string | null,
  width: number,
  height: number,
  stopAt?: Set<string>,
): WalkedProgram & { terminatedBy: string | null } {
  const directions: Array<[number, number]> = [[1, 0], [0, 1], [-1, 0], [0, -1]]; // 东南西北（顺时针）
  let direction = 0;
  let x = 0;
  let y = 0;
  const maxSteps = width * height * 4; // 转向环路兜底
  let steps = 0;
  let commands = '';
  const path: Array<{ x: number; y: number }> = [];
  let terminatedBy: string | null = 'edge';
  while (x >= 0 && y >= 0 && x < width && y < height) {
    if (steps >= maxSteps) {
      terminatedBy = 'loop';
      break;
    }
    steps += 1;
    const command = commandAt(x, y);
    path.push({ x, y });
    if (command === 'R') {
      direction = (direction + 1) % 4;
      x += directions[direction][0];
      y += directions[direction][1];
      continue;
    }
    if (command === 'L') {
      direction = (direction + 3) % 4;
      x += directions[direction][0];
      y += directions[direction][1];
      continue;
    }
    if (command !== null && stopAt?.has(command)) {
      terminatedBy = 'marker';
      break;
    }
    if (command !== null && command !== ' ') commands += command;
    x += directions[direction][0];
    y += directions[direction][1];
  }
  return { commands, path, terminated: true, terminatedBy };
}

// 组合入口：Brainloller/Braincopter 解码 → 直接执行（BF 指令流）
export const runImageProgram = (
  image: RgbaImage,
  flavor: 'brainloller' | 'braincopter',
  input = '',
  maxSteps = BF_DEFAULT_MAX_STEPS,
): { program: WalkedProgram; run: BfRunResult } => {
  const program = flavor === 'brainloller' ? decodeBrainloller(image) : decodeBraincopter(image);
  const run = runBrainfuck(program.commands, input, maxSteps);
  return { program, run };
};
