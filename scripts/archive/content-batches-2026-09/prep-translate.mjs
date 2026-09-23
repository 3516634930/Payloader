import { DatabaseSync } from 'node:sqlite';
import { writeFileSync } from 'node:fs';
const db = new DatabaseSync('data/payloader.sqlite');
const rows = db.prepare('SELECT id, data FROM payloads').all();
const chRe = /[一-鿿]/;
const out = rows
  .map(r => ({ id: r.id, p: JSON.parse(r.data) }))
  .filter(({ p }) => p.tutorial && ['overview','vulnerability','exploitation','mitigation'].some(k => chRe.test(p.tutorial[k]?.en || '')))
  .map(({ id, p }) => ({ id, ov:p.tutorial.overview?.zh||'', vu:p.tutorial.vulnerability?.zh||'', ex:p.tutorial.exploitation?.zh||'', mi:p.tutorial.mitigation?.zh||'' }));
writeFileSync('scripts/translate-input.json', JSON.stringify(out));
db.close();
console.log(JSON.stringify({ count: out.length, path: 'scripts/translate-input.json' }));
