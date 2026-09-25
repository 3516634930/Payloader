// Piet 解释器测试（批次 SI·C 线）：全部程序图程序化构造（codel 网格直建 rgba），不依赖外部图片与编解码。
// 预期输出/栈 = 按 esolangs wiki + 原始规范（dangermouse.net/esoteric/piet.html）指令矩阵手推的自洽向量（测试即规格）。
// 指令矩阵锚点（hue 差 × light 差）：(0,1)=push（红→暗红）、(4,0)=dup、(1,0)=add、(5,1)=out(number)、
// (5,2)=out(char)（暗红→洋红）、(4,2)=in(number)、(5,0)=in(char)、(3,1)=pointer、(3,2)=switch、(4,1)=roll。
// 终止结构（墓园）：程序链末块 B 正下方白 W、W 正下方 3 宽死路块 F——入口只触 F 中段，F 的 4 个角点出口
// 全被黑/出界封死（Piet 唯一终止方式 = 8 个 (DP,CC) 角点出口全堵，彩色邻块贴中段不贴角点不影响）。
// 加载统一走 tests/helpers/compileTsModule.mjs；沙箱返回数组断言前先 Array.from 转主 realm（AGENTS.md 踩坑记录）。
import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const srcDir = path.join(projectRoot, 'src');
const { loadModule } = createTsModuleLoader();
const { runPiet } = loadModule(path.join(srcDir, 'utils', 'ctf', 'pietInterp.ts'));

// ---- codel 网格工厂（格值 = 色名或 [r,g,b] 原色数组）----

const NAMED_COLORS = {
  lightred: [255, 192, 192], red: [255, 0, 0], darkred: [192, 0, 0],
  lightyellow: [255, 255, 192], yellow: [255, 255, 0], darkyellow: [192, 192, 0],
  lightgreen: [192, 255, 192], green: [0, 255, 0], darkgreen: [0, 192, 0],
  lightcyan: [192, 255, 255], cyan: [0, 255, 255], darkcyan: [0, 192, 192],
  lightblue: [192, 192, 255], blue: [0, 0, 255], darkblue: [0, 0, 192],
  lightmagenta: [255, 192, 255], magenta: [255, 0, 255], darkmagenta: [192, 0, 192],
  white: [255, 255, 255], black: [0, 0, 0],
};
const HUE = { red: 0, yellow: 1, green: 2, cyan: 3, blue: 4, magenta: 5 };
const BASES = ['red', 'yellow', 'green', 'cyan', 'blue', 'magenta'];

const toHL = (name) => {
  const light = name.startsWith('light') ? 0 : name.startsWith('dark') ? 2 : 1;
  return [HUE[name.replace(/^light|^dark/, '')], light];
};
const fromHL = (hue, light) => (light === 0 ? 'light' : light === 2 ? 'dark' : '') + BASES[hue];
const advance = (name, [dh, dl]) => {
  const [h, l] = toHL(name);
  return fromHL((h + dh) % 6, (l + dl) % 3);
};

// 指令 → (hue 差, light 差)，与实现的 6×3 矩阵同源（wiki 核实：hue 差 5 行 = in(char)/out(number)/out(char)）
const DELTA = {
  none: [0, 0], push: [0, 1], pop: [0, 2],
  add: [1, 0], sub: [1, 1], mul: [1, 2],
  div: [2, 0], mod: [2, 1], not: [2, 2],
  greater: [3, 0], pointer: [3, 1], switch: [3, 2],
  dup: [4, 0], roll: [4, 1], inNum: [4, 2],
  inChar: [5, 0], outNum: [5, 1], outChar: [5, 2],
};

const makeGrid = (width, height) => Array.from({ length: height }, () => Array.from({ length: width }, () => 'black'));
const rectCells = (x, y, w, h) => {
  const cells = [];
  for (let dy = 0; dy < h; dy += 1) for (let dx = 0; dx < w; dx += 1) cells.push([x + dx, y + dy]);
  return cells;
};
const paintCells = (grid, cells, color) => {
  for (const [x, y] of cells) grid[y][x] = color;
};

const gridToRgba = (grid) => {
  const height = grid.length;
  const width = grid[0].length;
  const data = new Uint8ClampedArray(width * height * 4);
  for (let y = 0; y < height; y += 1) {
    for (let x = 0; x < width; x += 1) {
      const [r, g, b] = typeof grid[y][x] === 'string' ? NAMED_COLORS[grid[y][x]] : grid[y][x];
      const base = (y * width + x) * 4;
      data[base] = r;
      data[base + 1] = g;
      data[base + 2] = b;
      data[base + 3] = 255;
    }
  }
  return { data, width, height };
};

const runGrid = (grid, options = {}) => {
  const { data, width, height } = gridToRgba(grid);
  return runPiet(data, width, height, options);
};

// 线性程序链（行 0 左→右直行，块宽 = sizes[i]，非零色差保证相邻块不合并）+ 标准墓园收尾：
//   行 1 在末块正下方放白 W，行 2 在 W 正下方放 3 宽红 F —— 末块右墙撞黑后 DP 顺滑到下、入白、
//   直线滑入 F 中段（进出白均无指令），F 四角全封 → 8 态穷尽真终止。
// deltas[i] = 离开块 i 的色差（即块 i→i+1 转移执行的指令）；sizes.length === deltas.length + 1（末块须 1 宽）。
const chainImage = (startName, deltas, sizes) => {
  assert.equal(sizes.length, deltas.length + 1);
  assert.equal(sizes[sizes.length - 1], 1, '末块须为 1 宽才能命中墓园入口');
  const names = [startName];
  for (const delta of deltas) names.push(advance(names[names.length - 1], delta));
  const m = sizes.reduce((sum, size) => sum + size, 0);
  const grid = makeGrid(m + 1, 3);
  let x = 0;
  names.forEach((name, i) => {
    paintCells(grid, rectCells(x, 0, sizes[i], 1), name);
    x += sizes[i];
  });
  grid[1][m - 1] = 'white';
  paintCells(grid, rectCells(m - 2, 2, 3, 1), 'red');
  return grid;
};

const chainRun = (startName, deltas, sizes, options = {}) => runGrid(chainImage(startName, deltas, sizes), options);

// ---- 1. push + out(char)：红→暗红 = (0,1) push 压退出块大小；暗红→洋红 = (5,2) out(char) ----

test('push/out(char)：65 codel 红块压 65、暗红→洋红 out(char) 输出 "A"；±2 偏色仍按红识别输出 "B"', () => {
  const a = chainRun('red', [DELTA.push, DELTA.outChar], [65, 1, 1]);
  assert.equal(a.output, 'A');
  assert.equal(a.terminated, true);
  assert.equal(a.timedOut, false);
  assert.equal(a.error, null);
  assert.deepEqual(Array.from(a.stackTop), []);
  assert.ok(a.steps >= 3 && a.steps <= 6, `steps 应为个位数，实际 ${a.steps}`);

  // 偏色 254,1,0（红 ±2 内）× 66 codel：抗重编码容差仍压 66 → 输出 'B'
  const grid = makeGrid(69, 3);
  paintCells(grid, rectCells(0, 0, 66, 1), [254, 1, 0]);
  paintCells(grid, rectCells(66, 0, 1, 1), 'darkred');
  paintCells(grid, rectCells(67, 0, 1, 1), 'magenta');
  grid[1][67] = 'white';
  paintCells(grid, rectCells(66, 2, 3, 1), 'red');
  const b = runGrid(grid);
  assert.equal(b.output, 'B');
  assert.equal(b.terminated, true);
  assert.equal(b.error, null);
});

// ---- 2. push/dup/add + out(number)：3 dup add = 6 ----

test('push/dup/add/out(number)：红 3 codel → push 3 → dup → add → out(number) 输出 "6"', () => {
  // 红→暗红 (0,1)=push 3；暗红→暗蓝 (4,0)=dup；暗蓝→暗洋红 (1,0)=add；暗洋红→浅蓝 (5,1)=out(number)
  const result = chainRun('red', [DELTA.push, DELTA.dup, DELTA.add, DELTA.outNum], [3, 1, 1, 1, 1]);
  assert.equal(result.output, '6');
  assert.equal(result.terminated, true);
  assert.equal(result.error, null);
  assert.deepEqual(Array.from(result.stackTop), []);
});

// ---- 3. 黑块阻隔 + 8 态穷尽终止 ----

test('黑块阻隔：孤块四向全堵一步终止；1×1 图同样穷尽 8 组合', () => {
  const grid = makeGrid(3, 3);
  paintCells(grid, [[0, 0]], 'red');
  const result = runGrid(grid);
  assert.equal(result.output, '');
  assert.equal(result.terminated, true);
  assert.equal(result.timedOut, false);
  assert.equal(result.error, null);
  assert.equal(result.steps, 1);
  assert.deepEqual(Array.from(result.stackTop), []);

  const single = runGrid([['red']]);
  assert.equal(single.terminated, true);
  assert.equal(single.steps, 1);
});

// ---- 4. 白块滑行：进出白均无指令（原始规范锚点）----

test('白区滑行：红→暗红 push 6 后穿 2 格白再 out(number) "6"；跨白进色不结算待定指令', () => {
  // (a) 穿白链：red6 → darkred(push 6) → white×2 → darkred(白→彩无指令) → lightmagenta(5,1)=out(number) "6"
  const cross = makeGrid(12, 3);
  paintCells(cross, rectCells(0, 0, 6, 1), 'red');
  paintCells(cross, rectCells(6, 0, 1, 1), 'darkred');
  paintCells(cross, rectCells(7, 0, 2, 1), 'white');
  paintCells(cross, rectCells(9, 0, 1, 1), 'darkred');
  paintCells(cross, rectCells(10, 0, 1, 1), 'lightmagenta');
  cross[1][10] = 'white';
  paintCells(cross, rectCells(9, 2, 3, 1), 'red');
  const a = runGrid(cross);
  assert.equal(a.output, '6');
  assert.equal(a.terminated, true);
  assert.equal(a.error, null);
  assert.deepEqual(Array.from(a.stackTop), []);

  // (b) 反"跨白结算"锚点：red2 → darkred(push 2) → white → lightred。
  // 若错误地把 暗红→浅红=(0,1)=push 1 结算在穿白之后，栈变 [2,1]、out(number) 会打 "1"；
  // 规范（"Sliding across white blocks into a new colour does not cause a command to be executed"）应打 "2"。
  const settle = makeGrid(7, 3);
  paintCells(settle, rectCells(0, 0, 2, 1), 'red');
  paintCells(settle, rectCells(2, 0, 1, 1), 'darkred');
  paintCells(settle, rectCells(3, 0, 1, 1), 'white');
  paintCells(settle, rectCells(4, 0, 1, 1), 'lightred');
  paintCells(settle, rectCells(5, 0, 1, 1), 'magenta');
  settle[1][5] = 'white';
  paintCells(settle, rectCells(4, 2, 3, 1), 'red');
  const b = runGrid(settle);
  assert.equal(b.output, '2');
  assert.equal(b.terminated, true);
  assert.deepEqual(Array.from(b.stackTop), []);
});

// ---- 5. roll：wiki 原例 [1,2,3] roll(1,3) → [3,1,2]（顶值绕回滚动段底）；负次数反向 ----

test('roll：wiki 原例 1,2,3 + roll(1,3) 输出 "213"；roll(-1,3) 反向输出 "132"', () => {
  const deltas = [DELTA.inNum, DELTA.inNum, DELTA.inNum, DELTA.inNum, DELTA.inNum, DELTA.roll, DELTA.outNum, DELTA.outNum, DELTA.outNum];
  const sizes = Array.from({ length: deltas.length + 1 }, () => 1);

  const positive = chainRun('red', deltas, sizes, { input: '1 2 3 3 1' });
  assert.equal(positive.terminated, true);
  assert.equal(positive.error, null);
  assert.equal(positive.output, '213'); // [1,2,3,3,1] → roll 弹 x=1,y=3 → [1,2,3]→[3,1,2] → 依栈顶输出 2,1,3
  assert.deepEqual(Array.from(positive.stackTop), []);

  const negative = chainRun('red', deltas, sizes, { input: '1 2 3 3 -1' });
  assert.equal(negative.terminated, true);
  assert.equal(negative.error, null);
  assert.equal(negative.output, '132'); // roll(-1,3) 反向：[1,2,3]→[2,3,1] → 输出 1,3,2
  assert.deepEqual(Array.from(negative.stackTop), []);
});

// ---- 6. 超时防护 ----

test('死循环防护：红/暗红两块 push-pop 永久往复，恰在 maxSteps 截停', () => {
  const result = runGrid([['red', 'darkred']], { maxSteps: 1000 });
  assert.equal(result.timedOut, true);
  assert.equal(result.terminated, false);
  assert.equal(result.error, null);
  assert.equal(result.steps, 1000);
  assert.equal(result.output, '');
});

// ---- 7. 未匹配色（灰）按黑处理 ----

test('灰 #808080 按黑阻隔：起点即灰零步终止；灰墙把红块封死一步穷尽终止', () => {
  const gray = [128, 128, 128];
  const start = runGrid([[gray, gray, gray]]);
  assert.equal(start.terminated, true);
  assert.equal(start.steps, 0);
  assert.equal(start.output, '');

  const blocked = runGrid([['red', 'red', gray]]);
  assert.equal(blocked.terminated, true);
  assert.equal(blocked.steps, 1);
  assert.equal(blocked.output, '');
  assert.deepEqual(Array.from(blocked.stackTop), []); // 永远没能跨块，push 未执行
});

// ---- 8. 算术/比较 + in(number) 全覆盖：add/sub/mul/div/mod/not/greater ----

test('算术链 in(number)×2+op+out(number)：9/5/14/3/1/1/1/0 → "951431110"', () => {
  const in2 = [DELTA.inNum, DELTA.inNum];
  const deltas = [
    ...in2, DELTA.add, DELTA.outNum,      // 7+2=9
    ...in2, DELTA.sub, DELTA.outNum,      // 7-2=5
    ...in2, DELTA.mul, DELTA.outNum,      // 7*2=14
    ...in2, DELTA.div, DELTA.outNum,      // trunc(7/2)=3
    ...in2, DELTA.mod, DELTA.outNum,      // 7%2=1（余数符号随被除数）
    DELTA.inNum, DELTA.not, DELTA.outNum, // not 0=1
    ...in2, DELTA.greater, DELTA.outNum,  // 7>2=1
    ...in2, DELTA.greater, DELTA.outNum,  // 2>7=0
  ];
  const sizes = Array.from({ length: deltas.length + 1 }, () => 1);
  const result = chainRun('red', deltas, sizes, { input: '7 2 7 2 7 2 7 2 7 2 0 7 2 2 7' });
  assert.equal(result.output, '951431110');
  assert.equal(result.terminated, true);
  assert.equal(result.error, null);
  assert.deepEqual(Array.from(result.stackTop), []);
});

// ---- 9. in(char)/out(char)：逐字符消费，LIFO 输出倒序 ----

test('in(char)/out(char)：读 "AB" 两次 out(char) 依 LIFO 输出 "BA"', () => {
  // 红→洋红 (5,0)=in(char)；洋红→蓝 (5,0)=in(char)；蓝→浅青 (5,2)=out(char)；浅青→暗绿 (5,2)=out(char)
  const result = chainRun('red', [DELTA.inChar, DELTA.inChar, DELTA.outChar, DELTA.outChar],
    [1, 1, 1, 1, 1], { input: 'AB' });
  assert.equal(result.output, 'BA');
  assert.equal(result.terminated, true);
  assert.equal(result.error, null);
  assert.deepEqual(Array.from(result.stackTop), []);
});

// ---- 10. pointer：弹 65 → DP 右转 (0+65)%4=1 次成下，从顶部块拐进下方输出块 ----

test('pointer：push 65 → dup → pointer 消费 65 转 DP 向下，out(char) 输出 "A"（65%4 非零转向）', () => {
  const grid = makeGrid(69, 3);
  paintCells(grid, rectCells(0, 0, 65, 1), 'red');        // 65 codel 红
  paintCells(grid, rectCells(65, 0, 1, 1), 'darkred');    // (0,1) push 65
  paintCells(grid, rectCells(66, 0, 1, 1), 'darkblue');   // (4,0) dup → [65,65]
  paintCells(grid, rectCells(67, 0, 1, 1), 'lightyellow'); // (3,1) pointer：弹 65，DP=(0+65)%4=1（下）
  paintCells(grid, rectCells(67, 1, 1, 1), 'darkred');    // (5,2) out(char) 'A'，栈剩 [65]
  paintCells(grid, rectCells(66, 2, 3, 1), 'lightred');   // 死路 F：从中部上方进入，入口指令 darkred→lightred=(0,1) push 1 无害
  const result = runGrid(grid);
  assert.equal(result.output, 'A');
  assert.equal(result.terminated, true);
  assert.equal(result.error, null);
  assert.deepEqual(Array.from(result.stackTop), [1]);
});

// ---- 11. switch：翻 CC 改变 2×2 块的角点出口（min-y → max-y）----

test('switch：弹 1 翻 CC 后，2×2 块取 (4,1) 角点出口而非 (4,0)，输出 "1" 且正常终止', () => {
  // 行 0：red → darkred(push 1) → cyan(switch 弹 1 → CC=right) → 2×2 darkcyan(上排)
  // 行 1：2×2 darkcyan(下排) → lightgreen(5,1) out(number) → 白 W(6,1)
  // 行 2：白竖井 W(6,2)；行 3：3 宽死路 F(5..7,3) 四角全封 → 终止。
  // 离开 cyan(1px) 进 2×2 时 push 压的是退出块大小 1，out(number) 打 "1"；
  // 若 switch 未翻 CC：初始 CC=left 角点 (4,0) → 白(5,0) 滑落后逆行触发 mul 空栈下溢报错、无输出。
  const grid = makeGrid(9, 4);
  paintCells(grid, rectCells(0, 0, 1, 1), 'red');
  paintCells(grid, rectCells(1, 0, 1, 1), 'darkred');
  paintCells(grid, rectCells(2, 0, 1, 1), 'cyan');
  paintCells(grid, rectCells(3, 0, 2, 2), 'darkcyan');   // 2×2：cyan→darkcyan = (0,1) push（压退出块 cyan 的 1）
  paintCells(grid, rectCells(5, 0, 1, 1), 'white');      // CC=left 误路的缓冲白
  paintCells(grid, rectCells(5, 1, 1, 1), 'lightgreen'); // darkcyan→lightgreen = (5,1) out(number)
  grid[1][6] = 'white';
  grid[2][6] = 'white';
  paintCells(grid, rectCells(5, 3, 3, 1), 'red');        // 死路 F，白 (6,2) 正下方中段进入
  const result = runGrid(grid);
  assert.equal(result.output, '1');
  assert.equal(result.terminated, true);
  assert.equal(result.timedOut, false);
  assert.equal(result.error, null);
  assert.deepEqual(Array.from(result.stackTop), []);
});

// ---- 12. 运行期错误：栈下溢 / 除零 / 输入耗尽（中文报错、不计正常终止）----

test('错误路径：空栈 pop 报下溢；div 除零报错；in(number)/in(char) 输入耗尽报错', () => {
  const underflow = chainRun('red', [DELTA.pop], [1, 1]); // 红→浅红 (0,2)=pop 空栈
  assert.equal(underflow.error !== null && /下溢/.test(underflow.error), true);
  assert.equal(underflow.terminated, false);
  assert.equal(underflow.steps, 1);
  assert.equal(underflow.output, '');

  // push7 dup sub → 0；push9 dup sub → 0；div 0/0 → 除零
  const divZero = chainRun('red',
    [DELTA.push, DELTA.dup, DELTA.sub, DELTA.push, DELTA.dup, DELTA.sub, DELTA.div],
    [7, 1, 1, 9, 1, 1, 1, 1], { input: '' });
  assert.equal(divZero.error !== null && /除数为 0/.test(divZero.error), true);
  assert.equal(divZero.terminated, false);

  const noNumber = chainRun('red', [DELTA.inNum], [1, 1], { input: '   xyz' });
  assert.equal(noNumber.error !== null && /十进制/.test(noNumber.error), true);

  const noChar = chainRun('red', [DELTA.inChar], [1, 1], { input: '' });
  assert.equal(noChar.error !== null && /耗尽/.test(noChar.error), true);
});

// ---- 13. 参数校验（error 字段返回，不抛异常）----

test('参数校验：rgba 长度不符与非法宽高以中文 error 返回', () => {
  const short = runPiet(new Uint8ClampedArray(8), 3, 1);
  assert.equal(short.error !== null && /不符/.test(short.error), true);
  assert.equal(short.terminated, false);

  const badSize = runPiet(new Uint8ClampedArray(0), 0, 1);
  assert.equal(badSize.error !== null && /正整数/.test(badSize.error), true);
});
