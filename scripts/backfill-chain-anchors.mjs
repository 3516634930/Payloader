// 第二波-A（幂等版）：空锚链回填 + doc 命令区与 runtime 同步（防整组替换错位悬挂）。
import { DatabaseSync } from 'node:sqlite';
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const db = new DatabaseSync(path.join(root, 'data/payloader.sqlite'), { readOnly: true });
const rows = db.prepare('SELECT data FROM payloads').all().map(r => JSON.parse(r.data));
db.close();

const manifest = JSON.parse(readFileSync(path.join(root, 'content-review/manifest.json'), 'utf8'));
const docCache = new Map();
const loadDoc = f => {
  if (!docCache.has(f)) docCache.set(f, JSON.parse(readFileSync(path.join(root, 'content-review', f), 'utf8')));
  return docCache.get(f);
};
const owner = new Map();
for (const f of manifest.overrideFiles) for (const e of (loadDoc(f).entries || [])) owner.set(e.id, f);

const touched = new Set();
let syncCmd = 0, backfill = 0;
const newEntries = [];
for (const p of rows) {
  const f = owner.get(p.id);
  const pool = [...(p.execution || []), ...(p.wafBypass || [])].map(c => String(c?.command || '')).filter(Boolean);
  let entry = null;
  if (f) entry = (loadDoc(f).entries || []).find(e => e.id === p.id) || null;
  if (!entry) {
    const chain = p.attackChain || [];
    if (!chain.length || chain.some(s => String(s?.payload || '').trim()) || !pool.length) continue;
    newEntries.push({
      id: p.id, name: p.name, description: p.description, category: p.category, subCategory: p.subCategory,
      tags: p.tags, prerequisites: p.prerequisites, execution: p.execution, analysis: p.analysis,
      opsecTips: p.opsecTips, wafBypass: p.wafBypass,
      attackChain: chain.map((s, i) => ({ ...s, payload: pool[Math.min(i, pool.length - 1)] })),
      references: p.references, tutorial: p.tutorial,
      review: { decision: 'payload', reason: 'qa-final-2026-09 空锚链回填（第二波）' },
    });
    continue;
  }
  let changed = false;
  // 命令区同步：doc 携带版必须与 runtime 一致，否则整组替换造成锚错位/内容回退
  if (JSON.stringify(entry.execution) !== JSON.stringify(p.execution)) { entry.execution = p.execution; changed = true; syncCmd++; }
  if (JSON.stringify(entry.wafBypass) !== JSON.stringify(p.wafBypass)) { entry.wafBypass = p.wafBypass; changed = true; syncCmd++; }
  // doc 链全空锚 → 回填
  const chain = entry.attackChain || [];
  if (chain.length && chain.every(s => !String(s?.payload || '').trim()) && pool.length) {
    entry.attackChain = chain.map((s, i) => ({ ...s, payload: pool[Math.min(i, pool.length - 1)] }));
    changed = true; backfill++;
  }
  if (changed) touched.add(f);
}
for (const f of touched) writeFileSync(path.join(root, 'content-review', f), JSON.stringify(docCache.get(f), null, 1) + '\n');
const newFile = 'overrides-qa-chain-backfill-2026-09.json';
if (newEntries.length) {
  writeFileSync(path.join(root, 'content-review', newFile), JSON.stringify({ schemaVersion: 1, contentStandard: 3, sourceIds: newEntries.map(e => e.id), entries: newEntries }, null, 1));
  if (!manifest.overrideFiles.includes(newFile)) manifest.overrideFiles.push(newFile);
} else {
  manifest.overrideFiles = manifest.overrideFiles.filter(x => x !== newFile);
}
writeFileSync(path.join(root, 'content-review/manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
console.log('doc cmd-area syncs:', syncCmd, '/ chain backfills:', backfill, '/ new-doc entries:', newEntries.length, '/ touched files:', touched.size);
