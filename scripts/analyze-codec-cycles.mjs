// codec 模块循环依赖检测（T5/T6 验收工具）：对 src/utils/codec/*.ts 建运行时 import 图并 DFS 找环。
// 构图口径：只计运行时边（import/export-from 语句），type-only import 编译后擦除不计入。
// 用法：node scripts/analyze-codec-cycles.mjs
import fs from 'node:fs';
import path from 'node:path';

const codecDir = path.join(process.cwd(), 'src', 'utils', 'codec');
const files = fs.readdirSync(codecDir).filter(f => f.endsWith('.ts')).sort();

const graph = new Map();
for (const file of files) {
  const source = fs.readFileSync(path.join(codecDir, file), 'utf8');
  const deps = new Set();
  const patterns = [
    /(?:^|\n)\s*import\s+(?!type\b)[^;]*?from\s+['"]\.\/([^'"]+)['"]/g,
    /(?:^|\n)\s*import\s+['"]\.\/([^'"]+)['"]/g,
    /(?:^|\n)\s*export\s+(?:\{[^}]*\}|\*)\s*from\s+['"]\.\/([^'"]+)['"]/g,
  ];
  for (const pattern of patterns) {
    for (const match of source.matchAll(pattern)) {
      const target = match[1].replace(/\.ts$/, '');
      if (files.includes(`${target}.ts`) && target !== file.replace(/\.ts$/, '')) deps.add(target);
    }
  }
  graph.set(file.replace(/\.ts$/, ''), [...deps]);
}

// 极简 DFS 列出全部基础环（去重：同一环的旋转/反向视为一个）
const cycles = [];
const seen = new Set();
const visit = (node, stack, inStack) => {
  stack.push(node);
  inStack.add(node);
  for (const next of graph.get(node) ?? []) {
    if (!inStack.has(next)) {
      visit(next, stack, inStack);
    } else {
      const index = stack.indexOf(next);
      const cycle = stack.slice(index);
      const key = [...cycle].sort().join('|');
      if (!seen.has(key)) {
        seen.add(key);
        cycles.push(cycle);
      }
    }
  }
  stack.pop();
  inStack.delete(node);
};
for (const node of graph.keys()) visit(node, [], new Set());

console.log(`codec 模块图：${graph.size} 个模块，${[...graph.values()].flat().length} 条运行时边`);
if (cycles.length === 0) {
  console.log('未发现循环依赖。');
} else {
  console.log(`发现 ${cycles.length} 个循环：`);
  for (const cycle of cycles) console.log(`  ${[...cycle, cycle[0]].join(' → ')}`);
}
