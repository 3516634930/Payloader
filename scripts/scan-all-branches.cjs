#!/usr/bin/env node
/**
 * 全库审计扫描（除 sqli 外全部分支）：
 * A. 模板腔命名（边界/可见性/能力边界/语义/验证 结尾或含"边界"）
 * B. 单命令弱组（execution 仅 1 条且 wafBypass 空/1）
 * C. 混堆子分支（名称含"与/和"连接两个技术族）+ 子分支组数失衡
 * D. wafBypass/execution 变量字面量（已知全局变量名无花括号）
 * E. waf 与 exec 逐字节重复行 ≥50%
 * F. 同子分支组名近似（首 6 字相同）
 * 输出 output/content-audit/global-scan-findings.txt
 */
const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');
const ROOT = path.resolve(__dirname, '..');
const db = new DatabaseSync(path.join(ROOT, 'data/payloader.sqlite'), { readOnly: true });

const trees = db.prepare("SELECT id, tree FROM navigation_nodes WHERE id IN ('web','intranet')").all()
  .map(r => JSON.parse(r.tree));
const payloads = db.prepare('SELECT data FROM payloads').all().map(r => JSON.parse(r.data));
const byId = new Map(payloads.map(p => [p.id, p]));
db.close();

const zh = o => (o && typeof o === 'object' ? o.zh : o) || '';
const cmds = p => {
  const ex = Array.isArray(p.execution) ? p.execution : [];
  return ex.map(e => String(typeof e === 'string' ? e : (e?.command || '')));
};
const wafs = p => (Array.isArray(p.wafBypass) ? p.wafBypass : []).map(w => String(typeof w === 'string' ? w : (w?.command || '')));
const GLOBAL_VARS = ['TARGET_TABLE','DATABASE_NAME','ATTACKER_HOST','WEB_ROOT','SHELL_NAME','FILE_PATH','TARGET_URL','TARGET_IP','TARGET_DOMAIN','USERNAME','PASSWORD','CMD','LAB_OAST','LAB_APP','LISTENER_IP','LISTENER_PORT','SHARE_PATH','DOMAIN','LHOST','LPORT'];

const out = [];
const push = s => out.push(s);

// ── 遍历树 ──
const leaves = []; // {branch, sub, node, payload}
for (const tree of trees) {
  for (const branch of (tree.children || [])) {
    for (const sub of (branch.children || [])) {
      for (const g of (sub.children || [])) {
        if (g.payloadId) leaves.push({ branch: zh(branch.name), sub: zh(sub.name), subId: sub.id, g: zh(g.name), id: g.payloadId });
      }
    }
  }
}
push(`# 全库扫描：${leaves.length} 组（sqli 除外 ${leaves.filter(l => l.branch.includes('SQL')).length} 组已审）`);
push('');

// A. 模板腔命名
push('## A. 模板腔命名');
for (const l of leaves) {
  if (/(边界|可见性)$/.test(l.g) || /能力边界|会话缓冲边界|写入边界/.test(l.g)) push(`  [${l.branch} / ${l.sub}] ${l.g} {${l.id}}`);
}
push('');

// B. 单命令弱组
push('## B. 单命令弱组（exec=1 且 waf≤1）');
for (const l of leaves) {
  const p = byId.get(l.id); if (!p) continue;
  const e = cmds(p), w = wafs(p);
  if (e.length === 1 && w.length <= 1 && String(e[0]).split('\n').length <= 3) push(`  [${l.branch} / ${l.sub}] ${l.g} {${l.id}} cmd: ${String(e[0]).slice(0, 70).replace(/\n/g, ' ')}`);
}
push('');

// C. 混堆子分支 + 组数
push('## C. 子分支清单（含混堆嫌疑"与/和"，组数标注）');
const subCount = new Map();
for (const l of leaves) { const k = l.branch + ' / ' + l.sub; subCount.set(k, (subCount.get(k) || 0) + 1); }
for (const [k, n] of [...subCount.entries()].sort()) {
  const flag = /[^\s]{2,}(与|和|、)[^\s]{2,}/.test(k.split(' / ')[1] || '') ? ' ←混堆嫌疑' : '';
  push(`  ${k} [${n} 组]${flag}`);
}
push('');

// D. 变量字面量
push('## D. 变量字面量（无花括号全局变量名）');
for (const l of leaves) {
  const p = byId.get(l.id); if (!p) continue;
  const hits = [];
  for (const [arr, area] of [[cmds(p), 'exec'], [wafs(p), 'waf']]) {
    arr.forEach((c, i) => {
      for (const v of GLOBAL_VARS) {
        const re = new RegExp(`(^|[^{\\w])${v}([^}\\w]|$)`);
        if (re.test(c) && !c.includes(`{${v}}`)) hits.push(`${area}[${i}]:${v}`);
      }
    });
  }
  if (hits.length) push(`  [${l.sub}] ${l.g} {${l.id}} → ${[...new Set(hits)].slice(0, 4).join(', ')}`);
}
push('');

// E. waf 与 exec 逐字节重复行 ≥50%
push('## E. waf 条目与 exec 行重复 ≥50%');
for (const l of leaves) {
  const p = byId.get(l.id); if (!p) continue;
  const execLines = new Set(cmds(p).join('\n').split('\n').map(s => s.trim()).filter(Boolean));
  wafs(p).forEach((w, i) => {
    const lines = w.split('\n').map(s => s.trim()).filter(Boolean);
    if (!lines.length) return;
    const dup = lines.filter(x => execLines.has(x)).length;
    if (dup / lines.length >= 0.5 && lines.length >= 3) push(`  [${l.sub}] ${l.g} {${l.id}} waf[${i}] ${dup}/${lines.length} 行重复`);
  });
}
push('');

// F. 同子分支组名近似（前 6 字相同）
push('## F. 同子分支近似组名（前 5 字相同）');
const bySub = new Map();
for (const l of leaves) { if (!bySub.has(l.subId)) bySub.set(l.subId, []); bySub.get(l.subId).push(l); }
for (const [sid, ls] of bySub) {
  for (let i = 0; i < ls.length; i++) for (let j = i + 1; j < ls.length; j++) {
    const a = ls[i].g, b = ls[j].g;
    if (a.slice(0, 5) === b.slice(0, 5) && a !== b) push(`  [${ls[i].sub}] "${a}" ↔ "${b}"`);
  }
}
push('');

const f = path.join(ROOT, 'output', 'content-audit', 'global-scan-findings.txt');
fs.mkdirSync(path.dirname(f), { recursive: true });
fs.writeFileSync(f, out.join('\n'));
console.log('written', f, '| lines:', out.length, '| leaves:', leaves.length);
