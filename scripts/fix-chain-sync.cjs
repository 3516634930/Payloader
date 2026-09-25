#!/usr/bin/env node
/** 修复对账误删链锚补丁导致的 DANGLING/MISSING_CHAIN_PAYLOAD：doc 条目 attackChain ← DB 现值。 */
const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');
const ROOT = path.resolve(__dirname, '..');
const CR = p => path.join(ROOT, 'content-review', p);
const db = new DatabaseSync(path.join(ROOT, 'data/payloader.sqlite'), { readOnly: true });
const byId = new Map(db.prepare('SELECT data FROM payloads').all().map(r => { const p = JSON.parse(r.data); return [p.id, p]; }));
db.close();
const ids = process.argv.slice(2);
if (!ids.length) { console.log('用法: node fix-chain-sync.cjs id1 id2 ...'); process.exit(1); }
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
    if (typeof o.id === 'string' && ids.includes(o.id) && o.attackChain !== undefined) {
      const p = byId.get(o.id);
      if (p && Array.isArray(p.attackChain)) { o.attackChain = p.attackChain; n++; hit = true; }
    }
    for (const k of Object.keys(o)) walk(o[k]);
  };
  walk(doc);
  if (hit) fs.writeFileSync(full, JSON.stringify(doc, null, 2) + '\n');
}
console.log('attackChain 同步', n, '处');
