// 全库内容质量终审 dump：payload 全中文内容 + 工具命令，按分支分组、体积切 片。
// 只导 zh（en 已停更不审）+ 命令原文。输出 output/content-audit/qa-pack-p##.md / qa-pack-t##.md
import { DatabaseSync } from 'node:sqlite';
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const outDir = path.join(root, 'output', 'content-audit');
mkdirSync(outDir, { recursive: true });

const SLICE = parseInt(process.argv[2] || '62000', 10);
const db = new DatabaseSync('data/payloader.sqlite', { readOnly: true });

const zh = v => (v && typeof v === 'object' ? (v.zh || '') : String(v || ''));
const ind = (s, pad) => String(s || '').split('\n').map(l => pad + l).join('\n');

// ── payload dump ──
const payloads = db.prepare('SELECT data FROM payloads').all().map(r => JSON.parse(r.data));
const byBranch = new Map();
for (const p of payloads) {
  const cat = zh(p.category) || '未分类';
  if (!byBranch.has(cat)) byBranch.set(cat, []);
  byBranch.get(cat).push(p);
}

const payloadBlock = p => {
  const L = [];
  L.push(`###### ${p.id} | ${zh(p.name)}`);
  L.push(`[分类] ${zh(p.category)} / ${zh(p.subCategory)}`);
  L.push(`[描述] ${zh(p.description)}`);
  if (p.prerequisites?.length) L.push(`[前置] ${p.prerequisites.map((x, i) => `(${i})${zh(x)}`).join(' ')}`);
  if (p.execution?.length) {
    L.push('[执行]');
    p.execution.forEach((e, i) => {
      L.push(`  (${i}) ${zh(e.title)}`);
      L.push(ind(e.command, '      CMD: ').replace(/^ {6}CMD: /, '      CMD: '));
      L.push(`      判据: ${zh(e.description)}`);
    });
  }
  if (p.wafBypass?.length) {
    L.push('[WAF绕过]');
    p.wafBypass.forEach((w, i) => {
      L.push(`  (${i}) ${zh(w.title)} — ${zh(w.description)}`);
      L.push(ind(w.command, '      CMD: '));
    });
  }
  if (p.attackChain?.length) {
    L.push('[攻击链]');
    p.attackChain.forEach((c, i) => {
      L.push(`  (${i}) ${zh(c.title)} | 锚: ${c.payload ? String(c.payload).split('\n')[0].slice(0, 80) : '§空'}`);
      L.push(`      ${zh(c.description)}`);
    });
  }
  L.push(`[分析] ${zh(p.analysis)}`);
  if (p.opsecTips?.length) L.push(`[OPSEC] ${p.opsecTips.map((x, i) => `(${i})${zh(x)}`).join(' ')}`);
  const t = p.tutorial || {};
  if (zh(t.overview)) L.push(`[教程-总览] ${zh(t.overview)}`);
  if (zh(t.vulnerability)) L.push(`[教程-原理] ${zh(t.vulnerability)}`);
  if (zh(t.exploitation)) L.push(`[教程-利用] ${zh(t.exploitation)}`);
  if (zh(t.mitigation)) L.push(`[教程-缓解] ${zh(t.mitigation)}`);
  L.push('');
  return L.join('\n');
};

const blockSize = b => b.length;
let fileIdx = 0, cur = [], curSize = 0, curBranches = new Set();
const flushP = () => {
  if (!cur.length) return;
  fileIdx += 1;
  const name = `qa-pack-p${String(fileIdx).padStart(2, '0')}.md`;
  writeFileSync(path.join(outDir, name), `# 内容质量终审 pack p${fileIdx}（分支: ${[...curBranches].join(' / ')}；${cur.length} 条）\n\n${cur.join('\n')}`);
  cur = []; curSize = 0; curBranches = new Set();
};
for (const [cat, list] of [...byBranch.entries()].sort((a, b) => b[1].length - a[1].length)) {
  const blocks = list.map(payloadBlock);
  const catSize = blocks.reduce((a, b) => a + blockSize(b), 0);
  if (catSize <= SLICE && curSize + catSize <= SLICE) {
    cur.push(...blocks); curSize += catSize; curBranches.add(cat);
  } else if (catSize <= SLICE) {
    flushP(); cur.push(...blocks); curSize = catSize; curBranches.add(cat);
  } else {
    // 大分支单独切：先冲掉当前片保持分支不跨片
    flushP();
    for (const b of blocks) {
      if (curSize + blockSize(b) > SLICE) flushP();
      cur.push(b); curSize += blockSize(b); curBranches.add(cat);
    }
  }
}
flushP();
console.log(`payload packs: ${fileIdx}`);

// ── tools dump ──
const tools = db.prepare('SELECT data FROM tools').all().map(r => JSON.parse(r.data));
const tByCat = new Map();
for (const t of tools) {
  const cat = zh(t.category) || '未分类';
  if (!tByCat.has(cat)) tByCat.set(cat, []);
  tByCat.get(cat).push(t);
}
const toolBlock = t => {
  const L = [];
  L.push(`###### ${t.id} | ${zh(t.name)}`);
  L.push(`[类别] ${zh(t.category)}`);
  L.push(`[描述] ${zh(t.description)}`);
  if (t.commands?.length) {
    L.push('[命令]');
    t.commands.forEach((c, i) => {
      L.push(`  (${i}) ${zh(c.name)} — ${zh(c.description)}`);
      L.push(ind(c.command, '      CMD: '));
      if (c.examples?.length) L.push(`      示例: ${c.examples.join(' ⏎ ')}`);
      if (c.platform) L.push(`      平台: ${Array.isArray(c.platform) ? c.platform.join(',') : c.platform}`);
    });
  }
  L.push('');
  return L.join('\n');
};
let tIdx = 0; cur = []; curSize = 0; curBranches = new Set();
const flushT = () => {
  if (!cur.length) return;
  tIdx += 1;
  const name = `qa-pack-t${String(tIdx).padStart(2, '0')}.md`;
  writeFileSync(path.join(outDir, name), `# 工具命令终审 pack t${tIdx}（类别: ${[...curBranches].join(' / ')}；${cur.length} 个工具）\n\n${cur.join('\n')}`);
  cur = []; curSize = 0; curBranches = new Set();
};
for (const [cat, list] of [...tByCat.entries()].sort((a, b) => b[1].length - a[1].length)) {
  const blocks = list.map(toolBlock);
  const catSize = blocks.reduce((a, b) => a + b.length, 0);
  if (catSize <= SLICE && curSize + catSize <= SLICE) { cur.push(...blocks); curSize += catSize; curBranches.add(cat); }
  else if (catSize <= SLICE) { flushT(); cur.push(...blocks); curSize = catSize; curBranches.add(cat); }
  else {
    flushT();
    for (const b of blocks) { if (curSize + b.length > SLICE) flushT(); cur.push(b); curSize += b.length; curBranches.add(cat); }
  }
}
flushT();
console.log(`tool packs: ${tIdx}`);
db.close();
