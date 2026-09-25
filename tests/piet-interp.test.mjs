// Piet 解释器测试（批次 SI·C 线）：全部程序图程序化构造（codel 网格直建 rgba），不依赖外部图片。
// 预期输出/栈 = 构造时按 esolangs wiki 指令矩阵手推的自洽向量（测试即规格，替代本机没有的 npiet 对拍）。
// 加载统一走 tests/helpers/compileTsModule.mjs；沙箱返回数组断言前先 Array.from 转主 realm。
import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const srcDir = path.join(projectRoot, 'src');
const { loadModule } = createTsModuleLoader();
const { runPiet } = loadModule(path.join(srcDir, 'utils', 'ctf', 'pietInterp.ts'));

// ---- codel 网格工厂（格值 = 色名或 [r,g,b] 原色）----

const NAMED_COLORS = {
  lightred: [255, 192, 192], red: [255, 0, 0], darkred: [192, 0, 0],
  lightyellow: [255, 255, 192], yellow: [255, 255, 0], darkyellow: [192, 192, 0],
  lightgreen: [192, 255, 192], green: [0, 255, 0], darkgreen: [0, 192, 0],
  lightcyan: [192, 255, 255], cyan: [0, 255, 255], darkcyan: [0, 192, 192],
  lightblue: [192, 192, 255], blue: [0, 0, 255], darkblue: [0, 0, 192],
  lightmagenta: [255, 192, 255], magenta: [255, 0, 255], darkmagenta: [192, 0, 192],
  white: [255, 255, 255], black: [0, 0, 0],
};

// colorId → 色名（hue*3+light 编码同实现）
const COLOR_NAMES = [
  'lightred', 'red', 'darkred', 'lightyellow', 'yellow', 'darkyellow',
  'lightgreen', 'green', 'darkgreen', 'lightcyan', 'cyan', 'darkcyan',
  'lightblue', 'blue', 'darkblue', 'lightmagenta', 'magenta', 'darkmagenta',
];
const RED_ID = 1;

// 指令 → (hue 差, light 差)，wiki 6×3 指令矩阵（行 hue 差 0..5、列 light 差 0..2）
const DELTA = {
  none: [0, 0], push: [0, 1], pop: [0, 2],
  add: [1, 0], sub: [1, 1], mul: [1, 2],
  div: [2, 0], mod: [2, 1], not: [2, 2],
  greater: [3, 0], pointer: [3, 1], switch: [3, 2],
  dup: [4, 0], roll: [4, 1], inNum: [4, 2],
  outNum: [5, 0], outChar: [5, 1], inChar: [5, 2],
};

const applyDelta = (colorId, [dh, dl]) => {
  const hue = ((Math.floor(colorId / 3) + dh) % 6 + 6) % 6;
  const light = ((colorId % 3) + dl) % 3;
  return hue * 3 + light;
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

// 构造自检：同一 18 指令色相邻但分属两个"程序块"，会被四连通静默合并、令构造意图跑偏 → 提前失败。
// 黑/白/未登记格（阻隔区）不查：同色合并对它们无语义影响。
const checkBlockAdjacency = (grid, blocks) => {
  const owner = new Map();
  blocks.forEach((cells, index) => {
    for (const [x, y] of cells) owner.set(`${x},${y}`, index);
  });
  const height = grid.length;
  const width = grid[0].length;
  for (let y = 0; y < height; y += 1) {
    for (let x = 0; x < width; x += 1) {
      const a = grid[y][x];
      if (typeof a !== 'string' || a === 'black' || a === 'white') continue;
      for (const [nx, ny] of [[x + 1, y], [x, y + 1]]) {
        if (nx >= width || ny >= height || grid[ny][nx] !== a) continue;
        if (owner.get(`${x},${y}`) !== owner.get(`${nx},${ny}`)) {
          assert.fail(`相邻同色 ${a} 分属不同程序块：(${x},${y}) 与 (${nx},${ny})`);
        }
      }
    }
  }
};

const gridToRgba = (grid, scale = 1) => {
  const height = grid.length;
  const width = grid[0].length;
  const data = new Uint8ClampedArray(width * scale * height * scale * 4);
  for (let y = 0; y < height; y += 1) {
    for (let x = 0; x < width; x += 1) {
      const [r, g, b] = typeof grid[y][x] === 'string' ? NAMED_COLORS[grid[y][x]] : grid[y][x];
      for (let dy = 0; dy < scale; dy += 1) {
        for (let dx = 0; dx < scale; dx += 1) {
          const base = ((y * scale + dy) * width * scale + (x * scale + dx)) * 4;
          data[base] = r; data[base + 1] = g; data[base + 2] = b; data[base + 3] = 255;
        }
      }
    }
  }
  return { data, width: width * scale, height: height * scale };
};

const runGrid = (grid, options = {}, scale = 1) => {
  const { data, width, height } = gridToRgba(grid, scale);
  return runPiet(data, width, height, options);
};

// 线性程序模板（左→右直行）：
//   B0 = 含 (0,0) 的 3 行高起始块（尺寸 3w+e，余数 e 挂在 (0,3)/(0,4)，可用尺寸 = 3 或 ≥6）；
//   B1..B_{n-1} = 行 2 上的单行横条（宽度 = 尺寸，任意 ≥1）；
//   F  = 最右 1×4 高柱终止块（从行 2 中部进入，四向被黑/出界围死）。
// 起步时 (R,L) 出口 (w0-1,0) 撞黑 → 翻 CC 后从 (w0-1,2) 入 B1，此后 CC=right 沿行 2 直行。
// instrs[i] = 离开 B_i 的转移指令（末条 = B_{n-1}→F，进入终止块也会执行一条指令）；
// sizes[i] = B_i 的 codel 数（push 时即压栈值）；instrs.length === sizes.length。
const buildLinearGrid = (instrs, sizes) => {
  const n = instrs.length;
  assert.equal(sizes.length, n);
  assert.ok(sizes[0] === 3 || sizes[0] >= 6, `起始块尺寸 ${sizes[0]} 需为 3 或 ≥6`);
  const w0 = Math.floor(sizes[0] / 3);
  const extra = sizes[0] % 3;
  const width = w0 + sizes.slice(1).reduce((a, b) => a + b, 0) + 1;
  const grid = makeGrid(width, extra === 2 ? 6 : 5);
  const blocks = [];
  const b0 = rectCells(0, 0, w0, 3);
  if (extra >= 1) b0.push([0, 3]);
  if (extra === 2) b0.push([0, 4]);
  blocks.push(b0);
  paintCells(grid, b0, 'red');
  let color = RED_ID;
  let x = w0;
  for (let i = 1; i < n; i += 1) {
    color = applyDelta(color, DELTA[instrs[i - 1]]);
    const cells = rectCells(x, 2, sizes[i], 1);
    blocks.push(cells);
    paintCells(grid, cells, COLOR_NAMES[color]);
    x += sizes[i];
  }
  color = applyDelta(color, DELTA[instrs[n - 1]]);
  const f = rectCells(x, 0, 1, 4);
  blocks.push(f);
  paintCells(grid, f, COLOR_NAMES[color]);
  checkBlockAdjacency(grid, blocks);
  return grid;
};

// ---- 1. 经典输出：红→暗红 push 72、暗红→浅洋红 out(char) 输出 "Hi" ----

test('经典输出向量：push 72/out(char) 与 push 105/out(char) 输出 "Hi"；codelSize=2 放大图同结果', () => {
  // 手工着色（锚定指令矩阵，不走链式推导）：B0 红 24×3=72 codel；B2 浅洋红横条 105 codel。
  const grid = makeGrid(132, 5);
  const blocks = [
    rectCells(0, 0, 24, 3),   // B0：72 codel 红
    rectCells(24, 2, 1, 1),   // B1 暗红：B0→B1 同 hue 暗 1 级 = push 72
    rectCells(25, 2, 105, 1), // B2 浅洋红：B1→B2 hue+5、light+1 = out(char) 'H'
    rectCells(130, 2, 1, 1),  // B3 洋红：B2→B3 同 hue 亮 1 级 = push 105
    rectCells(131, 0, 1, 4),  // F 暗蓝：B3→F = out(char) 'i' 后终止
  ];
  paintCells(grid, blocks[0], 'red');
  paintCells(grid, blocks[1], 'darkred');
  paintCells(grid, blocks[2], 'lightmagenta');
  paintCells(grid, blocks[3], 'magenta');
  paintCells(grid, blocks[4], 'darkblue');
  checkBlockAdjacency(grid, blocks);

  const result = runGrid(grid);
  assert.equal(result.output, 'Hi');
  assert.equal(result.terminated, true);
  assert.equal(result.timedOut, false);
  assert.equal(result.error, null);
  assert.deepEqual(Array.from(result.stackTop), []);

  // 每 codel 放大为 2×2 像素 + codelSize=2：push 压的是 codel 数（72）而非像素数（288）
  const scaled = runGrid(grid, { codelSize: 2 }, 2);
  assert.equal(scaled.output, 'Hi');
  assert.deepEqual(Array.from(scaled.stackTop), []);
});

// ---- 2. push/dup/mul 大数栈操作 ----

test('push/dup/mul：12 dup mul = 144，out(number) 打印后清栈', () => {
  const grid = makeGrid(8, 5);
  const blocks = [
    rectCells(0, 0, 4, 3),  // B0：12 codel 红
    rectCells(4, 2, 1, 1),  // push 12（红→暗红）
    rectCells(5, 2, 1, 1),  // dup（暗红→暗蓝：hue+4 同 light）→ [12,12]
    rectCells(6, 2, 1, 1),  // mul（暗蓝→洋红：hue+1、light+2）→ [144]
    rectCells(7, 0, 1, 4),  // out(number) "144"（洋红→蓝：hue+5 同 light）后终止
  ];
  paintCells(grid, blocks[0], 'red');
  paintCells(grid, blocks[1], 'darkred');
  paintCells(grid, blocks[2], 'darkblue');
  paintCells(grid, blocks[3], 'magenta');
  paintCells(grid, blocks[4], 'blue');
  checkBlockAdjacency(grid, blocks);

  const result = runGrid(grid);
  assert.equal(result.output, '144');
  assert.equal(result.terminated, true);
  assert.equal(result.error, null);
  assert.deepEqual(Array.from(result.stackTop), []);
});

// ---- 3. 黑块阻隔与 DP 滑动旋转 ----

test('黑块阻隔 + 滑动规则：翻 CC、顺时针转 DP 后向下入块，再被黑围死正常终止', () => {
  // L 形起步块 {(0,0),(1,0),(1,1)}：(R,L)/(R,R) 出口均撞黑 → 转 DP=down：
  // (D,R) 出口 (0,0) 下方 (0,1) 为黑仍阻 → 翻回 (D,L) 从 (1,1) 下方 (1,2) 入暗红块（push 3）。
  // 暗红块四向 8 组合全黑/出界 → 终止。
  const grid = makeGrid(4, 5);
  const blocks = [
    [[0, 0], [1, 0], [1, 1]],
    rectCells(0, 2, 3, 2),
  ];
  paintCells(grid, blocks[0], 'red');
  paintCells(grid, blocks[1], 'darkred');
  checkBlockAdjacency(grid, blocks);
  const result = runGrid(grid);
  assert.equal(result.output, '');
  assert.equal(result.terminated, true);
  assert.equal(result.timedOut, false);
  assert.equal(result.error, null);
  assert.deepEqual(Array.from(result.stackTop), [3]);
  assert.equal(result.steps, 2); // 一次成功转移 + 一次穷尽 8 组合的终止迭代
});

// ---- 4. 白块滑行 ----

test('白区滑行：穿越白不执行指令，进入色块按"离开前的色块"结算 push（压 5 而非白区大小）', () => {
  // B0 = {(0,0),(0,1),(0,2),(1,1),(1,2)}（5 codel），东缘北端 (1,1) 右侧是白：
  // 沿 DP=right 直线滑过 (2,1),(3,1) 两格白，从 (4,1) 进暗红块，结算 红→暗红 = push |B0| = 5。
  const grid = makeGrid(6, 5);
  const blocks = [
    [[0, 0], [0, 1], [0, 2], [1, 1], [1, 2]],
    rectCells(4, 0, 2, 4), // 2 宽终止块：从中部 (4,1) 列进入，四向黑/出界
  ];
  paintCells(grid, blocks[0], 'red');
  paintCells(grid, [[2, 1], [3, 1]], 'white');
  paintCells(grid, blocks[1], 'darkred');
  checkBlockAdjacency(grid, blocks);
  const result = runGrid(grid);
  assert.equal(result.output, '');
  assert.equal(result.terminated, true);
  assert.equal(result.error, null);
  assert.deepEqual(Array.from(result.stackTop), [5]);
});

// ---- 5. roll 指令栈旋转（正向 + 负向取模） ----

test('roll：[6,1,2] 顶 3 个滚 1 次 → [2,6,1]；roll 负次数 -1 取模反向 → [1,2,6]', () => {
  // A：push6 push1 push2 push3 push1 roll → [6,1,2,3,1] → 弹 x=1,y=3 → [6,1,2] → [2,6,1]
  // 末块→F 用 out(number) 打印旋转后的栈顶 1，栈剩 [2,6]
  const gridA = buildLinearGrid(
    ['push', 'push', 'push', 'push', 'push', 'roll', 'outNum'],
    [6, 1, 2, 3, 1, 1, 1],
  );
  const a = runGrid(gridA);
  assert.equal(a.terminated, true);
  assert.equal(a.error, null);
  assert.equal(a.output, '1');
  assert.deepEqual(Array.from(a.stackTop), [2, 6]);

  // B：用 push1 push1 sub 造 0、再 push1 sub 造 -1：[6,1,2,3,-1] → roll(x=-1,y=3) → [1,2,6]
  const gridB = buildLinearGrid(
    ['push', 'push', 'push', 'push', 'push', 'push', 'sub', 'push', 'sub', 'roll', 'outNum'],
    [6, 1, 2, 3, 1, 1, 1, 1, 1, 1, 1],
  );
  const b = runGrid(gridB);
  assert.equal(b.terminated, true);
  assert.equal(b.error, null);
  assert.equal(b.output, '6');
  assert.deepEqual(Array.from(b.stackTop), [1, 2]);
});

// ---- 5b. roll 计数移位经输出可观测 ----

test('roll 计数循环移位：push [3,1,2] + roll(1,3) 后连续 out(number) 依栈顶输出 "132"', () => {
  const grid = buildLinearGrid(
    ['push', 'push', 'push', 'push', 'push', 'roll', 'outNum', 'outNum', 'outNum', 'push', 'push'],
    [3, 1, 2, 3, 1, 1, 1, 1, 1, 1, 1],
  );
  const result = runGrid(grid);
  assert.equal(result.terminated, true);
  assert.equal(result.error, null);
  assert.equal(result.output, '132');
  assert.deepEqual(Array.from(result.stackTop), [1, 1]); // 清栈后两条收尾 push 各压 1
});

// ---- 6. 计数循环：环形赛道 + pointer 四角转向 + 分支指针倒计时 ----

test('计数循环：push3 起步，环形程序 dup/out/sub/not/pointer 倒计时输出 "321" 后经分支指针出环终止', () => {
  // 环形赛道（顺时针）：S(含 (0,0)) → 顶行右行 → 右缘下行 → 底行左行 → 左缘上行回环首。
  // 指令流：body 7 条 [dup outN push1 sub dup not pointer(v)] + 四角各 [push1 pointer]
  //（第 4 角的 pointer 即闭环转移），其余槽位用栈中性填充，并搜索组合使色差环和 ≡ (0,0) mod (6,3)
  //——否则闭环转移的颜色回不到起点，环在几何上闭合而语义断裂。
  const baseInstrs = [
    'dup', 'outNum', 'push', 'sub', 'dup', 'not', 'pointer',
    'push', 'pointer', 'push', 'pointer', 'push', 'pointer', 'push', 'pointer',
  ];
  // 栈中性填充单元：(dup,pop)、dup（栈底留 1 个垃圾，不影响只看栈顶的循环体）、
  // (dup,dup,pop,pop)、(dup,dup,greater,pop)（等值比较得 0 再弹掉；色差 (5,2) 提供奇 hue 分量）
  const sumDelta = (names) => names.reduce(([h, l], n) => [h + DELTA[n][0], l + DELTA[n][1]], [0, 0]);
  let plan = null;
  for (let X = 11; X <= 14 && !plan; X += 1) {
    for (let R = 5; R <= 8 && !plan; R += 1) {
      const N = 2 * X + 2 * R - 2;
      const padSlots = N - baseInstrs.length;
      for (let pairs = 0; pairs <= 5 && !plan; pairs += 1) {
        for (let dups = 0; dups <= 6 && !plan; dups += 1) {
          for (let quads = 0; quads <= 3 && !plan; quads += 1) {
            for (let cmps = 0; cmps <= 2 && !plan; cmps += 1) {
              if (2 * pairs + dups + 4 * quads + 4 * cmps !== padSlots) continue;
              const pads = [];
              for (let i = 0; i < pairs; i += 1) pads.push('dup', 'pop');
              for (let i = 0; i < quads; i += 1) pads.push('dup', 'dup', 'pop', 'pop');
              for (let i = 0; i < cmps; i += 1) pads.push('dup', 'dup', 'greater', 'pop');
              for (let i = 0; i < dups; i += 1) pads.push('dup');
              const total = sumDelta([...baseInstrs, ...pads]);
              if (total[0] % 6 === 0 && total[1] % 3 === 0) plan = { X, R, N, pads };
            }
          }
        }
      }
    }
  }
  assert.ok(plan, '存在使色环闭合的填充组合');

  const { X, R, N, pads } = plan;
  const cells = [];
  for (let x = 1; x <= X; x += 1) cells.push([x, 0]);
  for (let y = 1; y <= R; y += 1) cells.push([X, y]);
  for (let x = X - 1; x >= 1; x -= 1) cells.push([x, R]);
  for (let y = R - 1; y >= 1; y -= 1) cells.push([1, y]);
  assert.equal(cells.length, N);

  // slot[i] = 进入 cells[i] 触发的指令；slot[0] = 闭环转移（cells[N-1]→cells[0]）
  const slot = new Array(N).fill(null);
  ['dup', 'outNum', 'push', 'sub', 'dup', 'not'].forEach((name, i) => { slot[i + 1] = name; });
  slot[7] = 'pointer';                                           // 分支：v=0 直行续环 / v=1 转下出环
  slot[X - 2] = 'push'; slot[X - 1] = 'pointer';                 // 角1：右→下
  slot[X + R - 2] = 'push'; slot[X + R - 1] = 'pointer';         // 角2：下→左
  slot[2 * X + R - 3] = 'push'; slot[2 * X + R - 2] = 'pointer'; // 角3：左→上
  slot[N - 1] = 'push'; slot[0] = 'pointer';                     // 角4（闭环）：上→右
  let padCursor = 0;
  for (let i = 0; i < N; i += 1) if (slot[i] === null) slot[i] = pads[padCursor++];
  assert.equal(padCursor, pads.length, '填充指令恰好用尽');

  const colorIds = [applyDelta(RED_ID, DELTA.push)]; // S(红,3 codel)→环首 = push 3
  for (let i = 1; i < N; i += 1) colorIds.push(applyDelta(colorIds[i - 1], DELTA[slot[i]]));
  assert.deepEqual(applyDelta(colorIds[N - 1], DELTA[slot[0]]), colorIds[0], '色环闭合：末块→首块色差仍指向 pointer');

  const grid = makeGrid(X + 1, R + 1);
  const blocks = [rectCells(0, 0, 1, 3)]; // S：3 codel 红起步块
  paintCells(grid, blocks[0], 'red');
  cells.forEach(([x, y], i) => {
    blocks.push([[x, y]]);
    paintCells(grid, [[x, y]], COLOR_NAMES[colorIds[i]]);
  });
  // 出环路径：分支块 (8,0) 下方 X1=(8,1)（进入时 pop 清掉 not 留下的 0），
  // 再入 3×2 终止块 (7..9, 2..3)（进入时 push 1），从其中部列进入、四向黑/出界 → 终止。
  const x1Color = applyDelta(colorIds[7], DELTA.pop);
  blocks.push([[8, 1]]);
  paintCells(grid, [[8, 1]], COLOR_NAMES[x1Color]);
  blocks.push(rectCells(7, 2, 3, 2));
  paintCells(grid, rectCells(7, 2, 3, 2), COLOR_NAMES[applyDelta(x1Color, DELTA.push)]);
  checkBlockAdjacency(grid, blocks);

  const result = runGrid(grid);
  assert.equal(result.output, '321');
  assert.equal(result.terminated, true);
  assert.equal(result.timedOut, false);
  assert.equal(result.error, null);
});

// ---- 7. 超时防护 ----

test('死循环防护：红/暗红双柱 push-pop 永久往复，在 maxSteps 截停且不计为错误', () => {
  // A 右行入 B（push 4）→ B 右/下全阻 → 滑动转 DP=left 回 A（pop）→ A 左/上出界、下行黑 → 转 DP=right 又入 B……
  const grid = makeGrid(2, 5);
  const blocks = [rectCells(0, 0, 1, 4), rectCells(1, 0, 1, 4)];
  paintCells(grid, blocks[0], 'red');
  paintCells(grid, blocks[1], 'darkred');
  const result = runGrid(grid, { maxSteps: 100 });
  assert.equal(result.timedOut, true);
  assert.equal(result.terminated, false);
  assert.equal(result.error, null);
  assert.equal(result.steps, 100);
  assert.equal(result.output, '');
});

// ---- 8. 非法色与容差 ----

test('非法色与容差：灰 (#808080) 按黑阻隔立即终止；±2 内偏色仍按标准色执行', () => {
  // 灰柱/灰行把红块右、下封死，左、上出界 → 8 组合穷尽，零指令终止
  const gray = [128, 128, 128];
  const grid = makeGrid(5, 5);
  paintCells(grid, rectCells(0, 0, 3, 3), 'red');
  for (let y = 0; y < 3; y += 1) grid[y][3] = gray;
  for (let x = 0; x < 3; x += 1) grid[3][x] = gray;
  const blocked = runGrid(grid);
  assert.equal(blocked.terminated, true);
  assert.equal(blocked.timedOut, false);
  assert.deepEqual(Array.from(blocked.stackTop), []);
  assert.equal(blocked.steps, 1);

  // 偏色 ±2（抗重编码）：253,2,1≈红、191,1,1≈暗红、254,193,254≈浅洋红，push 72 + out(char) 照常
  const jitter = makeGrid(26, 5);
  paintCells(jitter, rectCells(0, 0, 24, 3), [253, 2, 1]);
  paintCells(jitter, rectCells(24, 2, 1, 1), [191, 1, 1]);
  paintCells(jitter, rectCells(25, 0, 1, 4), [254, 193, 254]);
  const tolerant = runGrid(jitter);
  assert.equal(tolerant.output, 'H');
  assert.equal(tolerant.terminated, true);
  assert.equal(tolerant.error, null);
});

// ---- 9. 输入指令：in(number) / in(char) 消费调用方传入的 input 串 ----

test('in(number)/in(char)：数字跳前导空白解析、字符逐个消费，输入耗尽报中文错误', () => {
  // 红→浅蓝 = in(number)（hue+4、light+2），浅蓝→浅青 = out(number)
  const numGrid = makeGrid(3, 5);
  paintCells(numGrid, rectCells(0, 0, 1, 3), 'red');
  paintCells(numGrid, rectCells(1, 2, 1, 1), 'lightblue');
  paintCells(numGrid, rectCells(2, 0, 1, 4), 'lightcyan');
  assert.equal(runGrid(numGrid, { input: '42' }).output, '42');
  assert.equal(runGrid(numGrid, { input: '  17abc' }).output, '17'); // 跳过前导空白，停在首个非数字
  const starved = runGrid(numGrid, { input: '' });
  assert.equal(starved.terminated, false);
  assert.equal(starved.error !== null && /输入/.test(starved.error), true);

  // 红→浅洋红 = in(char)（hue+5、light+2），浅洋红→蓝 = out(char)
  const charGrid = makeGrid(3, 5);
  paintCells(charGrid, rectCells(0, 0, 1, 3), 'red');
  paintCells(charGrid, rectCells(1, 2, 1, 1), 'lightmagenta');
  paintCells(charGrid, rectCells(2, 0, 1, 4), 'blue');
  assert.equal(runGrid(charGrid, { input: 'Z' }).output, 'Z');
  const emptyChar = runGrid(charGrid, { input: '' });
  assert.equal(emptyChar.error !== null && /输入/.test(emptyChar.error), true);
});

// ---- 10. 算术与比较指令（手工着色锚定 div/mod/greater/add/not 的矩阵位置） ----

test('div/mod/greater/add/not/out(number)：20÷6、20%6、5>9、4+8、not 1 → 输出 "320120"', () => {
  const colors = [
    'red', 'darkred', 'lightred', 'lightgreen', 'lightyellow', 'yellow', 'darkyellow',
    'lightcyan', 'lightgreen', 'green', 'darkgreen', 'darkmagenta', 'darkblue',
    'lightblue', 'blue', 'magenta', 'blue', 'darkblue', 'lightblue', 'darkred',
    'darkmagenta', 'lightmagenta',
  ];
  const widths = [20, 6, 1, 1, 20, 6, 1, 1, 5, 9, 1, 1, 4, 8, 1, 1, 1, 1, 1, 1, 2];
  assert.equal(colors.length, widths.length + 1); // 21 个程序块 + 终止块 F
  const grid = makeGrid(widths.reduce((a, b) => a + b, 0) + 1, 6);
  const blocks = [];
  const b0 = rectCells(0, 0, 6, 3); // B0：3 行高 6 宽 = 18
  b0.push([0, 3], [0, 4]);         // +2 个尾部 codel（挂在 (0,3)/(0,4)，不在东缘）凑 20
  blocks.push(b0);
  paintCells(grid, b0, colors[0]);
  let x = 6;
  for (let i = 1; i < widths.length; i += 1) {
    const cells = rectCells(x, 2, widths[i], 1);
    blocks.push(cells);
    paintCells(grid, cells, colors[i]);
    x += widths[i];
  }
  const f = rectCells(x, 0, 1, 4);
  blocks.push(f);
  paintCells(grid, f, colors[colors.length - 1]);
  checkBlockAdjacency(grid, blocks);

  const result = runGrid(grid);
  assert.equal(result.output, '320120');
  assert.equal(result.terminated, true);
  assert.equal(result.error, null);
  assert.deepEqual(Array.from(result.stackTop), [1, 2]); // not 只翻转栈顶：留下首个 1，末块 push 2 压顶
});

// ---- 11. 栈下溢错误 ----

test('栈下溢：空栈执行 pop 以中文错误停机，不计为正常终止', () => {
  const grid = makeGrid(3, 5);
  const blocks = [rectCells(0, 0, 1, 3), rectCells(1, 2, 1, 1), rectCells(2, 0, 1, 4)];
  paintCells(grid, blocks[0], 'red');
  paintCells(grid, blocks[1], 'lightred'); // 红→浅红：同 hue 亮 2 级 = pop（空栈）
  paintCells(grid, blocks[2], 'darkred');
  checkBlockAdjacency(grid, blocks);
  const result = runGrid(grid);
  assert.equal(result.error !== null && /下溢/.test(result.error), true);
  assert.equal(result.terminated, false);
  assert.equal(result.timedOut, false);
  assert.equal(result.steps, 1);
  assert.equal(result.output, '');
});
