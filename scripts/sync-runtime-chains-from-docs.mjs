// 第二波-A2：runtime 空锚链 ← 归属 doc 已回填锚 直写（doc 为真相源；机械同步非策展决策）。
// 走 curate 管线无法落地：legacy contentStandard doc 的 applied 判定不含 attackChain，entry 被幂等剔除。
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const manifest = JSON.parse(readFileSync(path.join(root, 'content-review/manifest.json'), 'utf8'));
const docChain = new Map();
for (const f of manifest.overrideFiles) {
  const d = JSON.parse(readFileSync(path.join(root, 'content-review', f), 'utf8'));
  for (const e of (d.entries || [])) {
    const chain = e.attackChain || [];
    if (chain.length && chain.some(s => String(s?.payload || '').trim())) docChain.set(e.id, chain);
  }
}
const db = new DatabaseSync(path.join(root, 'data/payloader.sqlite'));
const rows = db.prepare('SELECT id, data FROM payloads').all();
const update = db.prepare('UPDATE payloads SET data = ?, updated_at = ? WHERE id = ?');
const now = new Date().toISOString();
let n = 0;
for (const row of rows) {
  const p = JSON.parse(row.data);
  const chain = p.attackChain || [];
  if (!chain.length || chain.some(s => String(s?.payload || '').trim())) continue;
  const docVersion = docChain.get(p.id);
  if (!docVersion) continue;
  const merged = chain.map((s, i) => String(s?.payload || '').trim() ? s : (docVersion[i] && String(docVersion[i]?.payload || '').trim() ? { ...s, payload: docVersion[i].payload } : s));
  if (!merged.some(s => String(s?.payload || '').trim())) continue;
  p.attackChain = merged;
  update.run(JSON.stringify(p), now, p.id);
  n++;
}
console.log('runtime chains updated from doc:', n);
db.close();
