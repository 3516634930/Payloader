import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
const db = new DatabaseSync('data/payloader.sqlite');
const trans = JSON.parse(readFileSync('scripts/translations.json', 'utf8'));
const sel = db.prepare('SELECT data FROM payloads WHERE id=?');
const upd = db.prepare("UPDATE payloads SET data=?, updated_at=datetime('now') WHERE id=?");
let count = 0;
for (const t of trans) {
  const row = sel.get(t.id);
  if (!row) continue;
  const p = JSON.parse(row.data);
  if (!p.tutorial) continue;
  const tu = p.tutorial;
  if (t.ov_en) tu.overview = { zh: tu.overview?.zh||'', en: t.ov_en };
  if (t.vu_en) tu.vulnerability = { zh: tu.vulnerability?.zh||'', en: t.vu_en };
  if (t.ex_en) tu.exploitation = { zh: tu.exploitation?.zh||'', en: t.ex_en };
  if (t.mi_en) tu.mitigation = { zh: tu.mitigation?.zh||'', en: t.mi_en };
  upd.run(JSON.stringify(p), t.id);
  count++;
}
db.close();
console.log(JSON.stringify({ updated: count }));
