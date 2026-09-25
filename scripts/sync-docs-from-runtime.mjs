// 全量同步：所有 override doc 的 entry 内容字段 ← runtime 真相（doc=runtime 全等后 apply 幂等归零）。
// 文案改文已随第一波 apply 写入 runtime，本同步不丢任何策展成果。
import { DatabaseSync } from 'node:sqlite';
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const db = new DatabaseSync(path.join(root, 'data/payloader.sqlite'), { readOnly: true });
const byId = new Map(db.prepare('SELECT data FROM payloads').all().map(r => { const p = JSON.parse(r.data); return [p.id, p]; }));
db.close();

const FIELDS = ['name', 'description', 'category', 'subCategory', 'tags', 'prerequisites', 'execution', 'analysis', 'opsecTips', 'wafBypass', 'attackChain', 'references', 'tutorial'];
const manifest = JSON.parse(readFileSync(path.join(root, 'content-review/manifest.json'), 'utf8'));
let synced = 0, touchedFiles = 0;
for (const f of manifest.overrideFiles) {
  const file = path.join(root, 'content-review', f);
  const doc = JSON.parse(readFileSync(file, 'utf8'));
  let dirty = false;
  for (const e of (doc.entries || [])) {
    const p = byId.get(e.id);
    if (!p) continue;
    for (const fl of FIELDS) {
      if (JSON.stringify(e[fl]) !== JSON.stringify(p[fl])) { e[fl] = p[fl]; synced++; dirty = true; }
    }
  }
  if (dirty) { writeFileSync(file, JSON.stringify(doc, null, 1) + '\n'); touchedFiles++; }
}
console.log('field syncs:', synced, '/ files:', touchedFiles);
