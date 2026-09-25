#!/usr/bin/env node
/** 链步清理：doc attackChain 中 payload 文本在自身 execution/wafBypass 命令集找不到的步骤删除。参数=ids。 */
const fs = require('fs');
const path = require('path');
const ROOT = path.resolve(__dirname, '..');
const CR = p => path.join(ROOT, 'content-review', p);
const ids = new Set(process.argv.slice(2));
if (!ids.size) { console.log('用法: node prune-chain-steps.cjs id...'); process.exit(1); }
const manifest = JSON.parse(fs.readFileSync(CR('manifest.json'), 'utf8'));
let n = 0;
for (const f of [...(manifest.overrideFiles || []), ...(manifest.collectionSplitFiles || [])]) {
  const full = CR(f);
  if (!fs.existsSync(full)) continue;
  const doc = JSON.parse(fs.readFileSync(full, 'utf8'));
  let hit = false;
  const walk = o => {
    if (Array.isArray(o)) return o.forEach(walk);
    if (!o || typeof o !== 'object') return;
    if (typeof o.id === 'string' && ids.has(o.id) && Array.isArray(o.attackChain)) {
      const cmds = new Set();
      for (const area of ['execution', 'wafBypass']) for (const e of (o[area] || [])) {
        const c = String(typeof e === 'string' ? e : (e?.command || ''));
        if (c) c.split('\n').forEach(l => l.trim() && cmds.add(l.trim()));
        if (c) cmds.add(c.trim());
      }
      const b = o.attackChain.length;
      o.attackChain = o.attackChain.filter(step => {
        const pl = String(step?.payload ?? '').trim();
        if (!pl) return true;
        return cmds.has(pl) || [...cmds].some(c => c.includes(pl) || pl.includes(c));
      });
      if (o.attackChain.length !== b) { n += b - o.attackChain.length; hit = true; }
    }
    for (const k of Object.keys(o)) walk(o[k]);
  };
  walk(doc);
  if (hit) fs.writeFileSync(full, JSON.stringify(doc, null, 2) + '\n');
}
console.log('链步清理', n, '步');
