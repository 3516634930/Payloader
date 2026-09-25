#!/usr/bin/env node
/** 清理被 wafFix 文档改写致死的补丁：生效数组 = override 文档携带的 wafBypass（若无则 seed）。 */
const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');
const ROOT = path.resolve(__dirname, '..');
const CR = p => path.join(ROOT, 'content-review', p);
const db = new DatabaseSync(path.join(ROOT, 'data/payloader.sqlite'), { readOnly: true });
const seedById = new Map(db.prepare('SELECT data FROM payloads').all().map(r => { const p = JSON.parse(r.data); return [p.id, p]; }));
db.close();
const manifest = JSON.parse(fs.readFileSync(CR('manifest.json'), 'utf8'));
// override 文档携带的 wafBypass（id → 数组）
const docWaf = new Map();
for (const f of [...(manifest.overrideFiles || []), ...(manifest.collectionSplitFiles || [])]) {
  const full = CR(f);
  if (!fs.existsSync(full)) continue;
  const walk = o => {
    if (Array.isArray(o)) return o.forEach(walk);
    if (!o || typeof o !== 'object') return;
    if (typeof o.id === 'string' && Array.isArray(o.wafBypass) && !docWaf.has(o.id)) docWaf.set(o.id, o.wafBypass);
    for (const k of Object.keys(o)) walk(o[k]);
  };
  walk(JSON.parse(fs.readFileSync(full, 'utf8')));
}
let dropped = 0, reanchored = 0;
for (const f of manifest.payloadCommandOverrideFiles || []) {
  const full = CR(f);
  const doc = JSON.parse(fs.readFileSync(full, 'utf8'));
  let dirty = false;
  for (const entry of doc.entries) {
    const seedP = seedById.get(entry.id);
    const arr = (entry.patches[0]?.area === 'execution' ? seedP?.execution : (docWaf.get(entry.id) || seedP?.wafBypass)) || [];
    const out = [];
    for (const patch of entry.patches) {
      const a = patch.area === 'execution' ? (seedP?.execution || []) : (docWaf.get(entry.id) || seedP?.wafBypass || []);
      const cur = String(a[patch.index]?.command ?? '');
      if (cur && cur === String(patch.command ?? '')) {
        const expA = String(patch.expectedCommand ?? '');
        if (!(Array.isArray(entry.attackChain) && entry.attackChain.some(s => s?.payload === expA))) { dropped++; dirty = true; continue; }
        out.push(patch); continue; // 已应用但链仍引用，保留
      }
      const exp = String(patch.expectedCommand ?? '');
      const idx = a.findIndex(e => String(e?.command ?? '') === exp);
      if (idx >= 0) { if (idx !== patch.index) { patch.index = idx; reanchored++; dirty = true; } out.push(patch); continue; }
      if (patch.command === undefined && cur) { out.push(patch); continue; } // 元数据补丁
      // 链保护：expectedCommand 仍被 attackChain 引用的补丁保留（链解析依赖）
      if (Array.isArray(entry.attackChain) && entry.attackChain.some(s => s?.payload === exp)) { out.push(patch); continue; }
      dropped++; dirty = true;
    }
    entry.patches = out;
    if (!out.length) entry.__x = true;
  }
  doc.entries = doc.entries.filter(e => !e.__x);
  if (dirty) fs.writeFileSync(full, JSON.stringify(doc, null, 2) + '\n');
}
console.log(`死锚清理：丢弃 ${dropped}｜重锚 ${reanchored}`);
