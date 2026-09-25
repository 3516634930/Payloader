// 死锚剔除：expectedCommand ≠ runtime 现值 且 command ≠ runtime 现值（无法重锚）的 patch 删除；
// 链守卫：runtime 链锚引用该槽位命令时保留并告警。
import { DatabaseSync } from 'node:sqlite';
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const db = new DatabaseSync(path.join(root, 'data/payloader.sqlite'), { readOnly: true });
const byId = new Map(db.prepare('SELECT data FROM payloads').all().map(r => { const p = JSON.parse(r.data); return [p.id, p]; }));
db.close();
const manifest = JSON.parse(readFileSync(path.join(root, 'content-review/manifest.json'), 'utf8'));
let dropped = 0, guarded = 0;
for (const f of manifest.payloadCommandOverrideFiles) {
  const file = path.join(root, 'content-review', f);
  const doc = JSON.parse(readFileSync(file, 'utf8'));
  let dirty = false;
  for (const entry of (doc.entries || [])) {
    const p = byId.get(entry.id);
    if (!p) continue;
    const before = entry.patches?.length || 0;
    entry.patches = (entry.patches || []).filter(patch => {
      const cur = p?.[patch.area]?.[patch.index]?.command;
      if (cur === undefined) return true;
      const stale = String(patch.expectedCommand ?? '') !== String(cur) && patch.command !== undefined;
      const applied = String(patch.command ?? '') === String(cur);
      if (!stale || applied) return true; // 健康 或 已应用（重锚后）
      // 死锚：链守卫
      const chainUses = (p.attackChain || []).some(s => String(s?.payload || '') === String(patch.command || '') && String(patch.command || '').trim());
      if (chainUses) { guarded++; return true; }
      dropped++;
      return false;
    });
    if ((entry.patches?.length || 0) !== before) dirty = true;
    if (entry.patches && entry.patches.length === 0) delete entry.patches;
  }
  doc.entries = (doc.entries || []).filter(e => (e.patches?.length || 0) > 0);
  if (dirty) writeFileSync(file, JSON.stringify(doc, null, 1) + '\n');
}
console.log('dropped dead patches:', dropped, '/ chain-guarded kept:', guarded);
