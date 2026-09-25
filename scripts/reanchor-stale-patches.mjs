// 已应用 patch（runtime command === patch.command）的 expectedCommand 重锚到 runtime 现值
import { DatabaseSync } from 'node:sqlite';
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const db = new DatabaseSync(path.join(root, 'data/payloader.sqlite'), { readOnly: true });
const byId = new Map(db.prepare('SELECT data FROM payloads').all().map(r => { const p = JSON.parse(r.data); return [p.id, p]; }));
db.close();
const manifest = JSON.parse(readFileSync(path.join(root, 'content-review/manifest.json'), 'utf8'));
let n = 0;
for (const f of manifest.payloadCommandOverrideFiles) {
  const file = path.join(root, 'content-review', f);
  const doc = JSON.parse(readFileSync(file, 'utf8'));
  let dirty = false;
  for (const entry of (doc.entries || [])) {
    const p = byId.get(entry.id);
    if (!p) continue;
    for (const patch of (entry.patches || [])) {
      const cur = p?.[patch.area]?.[patch.index]?.command;
      if (cur === undefined) continue;
      if (String(patch.expectedCommand ?? '') !== String(cur) && String(patch.command ?? '') === String(cur)) {
        patch.expectedCommand = String(cur);
        n++; dirty = true;
      }
    }
  }
  if (dirty) writeFileSync(file, JSON.stringify(doc, null, 1) + '\n');
}
console.log('reanchored:', n);
