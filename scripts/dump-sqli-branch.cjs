#!/usr/bin/env node
/**
 * 调研脚本 v2：SQL/NoSQL注入 分支全量导出（组→payloadId→条目详情）
 * 每组输出：名称 / payload 名称 / 描述首句 / execution 全部命令行 / wafBypass 首行 / tags
 */
const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');
const ROOT = path.resolve(__dirname, '..');
const db = new DatabaseSync(path.join(ROOT, 'data', 'payloader.sqlite'), { readOnly: true });

const tree = JSON.parse(db.prepare("SELECT tree FROM navigation_nodes WHERE tree LIKE '%SQL/NoSQL%'").get().tree);
const pmap = new Map(db.prepare('SELECT data FROM payloads').all().map(r => {
  const p = JSON.parse(r.data); return [p.id, p];
}));

const find = (n, id) => { if (n.id === id) return n; for (const k of (n.children || [])) { const r = find(k, id); if (r) return r; } return null; };
const branch = find(tree, 'sqli');
if (!branch) { console.log('branch sqli not found'); db.close(); process.exit(1); }

let out = [];
const walk = (node, depth) => {
  const nm = node.name?.zh || node.name || node.id;
  if (node.payloadId) {
    const p = pmap.get(node.payloadId);
    out.push('  '.repeat(depth) + '## ' + nm + '  {g:' + node.id + ' → p:' + node.payloadId + '}');
    if (!p) { out.push('  '.repeat(depth) + '  !! payload missing'); return; }
    out.push('  '.repeat(depth) + '  name: ' + p.name);
    const desc = (p.description && (p.description.zh || p.description)) || '';
    out.push('  '.repeat(depth) + '  desc: ' + String(desc).slice(0, 160).replace(/\n/g, ' '));
    const exec = p.execution || [];
    const lines = Array.isArray(exec) ? exec : [exec];
    out.push('  '.repeat(depth) + '  execution[' + lines.length + ']:');
    for (const c of lines) {
      const cmd = typeof c === 'string' ? c : (c.command || c.title || '');
      out.push('  '.repeat(depth) + '    | ' + String(cmd).slice(0, 150));
    }
    const wf = p.wafBypass || [];
    if (wf.length) out.push('  '.repeat(depth) + '  waf[' + wf.length + '] first: ' + String(typeof wf[0] === 'string' ? wf[0] : (wf[0].command || '')).slice(0, 120));
    out.push('');
  } else {
    out.push('  '.repeat(depth) + '# ' + nm + ' {' + node.id + '}');
    for (const k of (node.children || [])) walk(k, depth + 1);
  }
};
walk(branch, 0);
const f = path.join(ROOT, 'output', 'content-audit', 'sqli-branch-full.txt');
fs.writeFileSync(f, out.join('\n'));
console.log('written', f, out.length, 'lines');
db.close();
