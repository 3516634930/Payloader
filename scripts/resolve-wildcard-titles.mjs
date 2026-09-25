// 通配 title 字段解析：用现文文本在 runtime 对应数组中反查真实索引，修 findings2.json
import { DatabaseSync } from 'node:sqlite';
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const db = new DatabaseSync(path.join(root, 'data/payloader.sqlite'), { readOnly: true });
const byId = new Map(db.prepare('SELECT data FROM payloads').all().map(r => { const p = JSON.parse(r.data); return [p.id, p]; }));
db.close();

const file = path.join(root, 'output/content-audit/findings2.json');
const { findings } = JSON.parse(readFileSync(file, 'utf8'));
let resolved = 0, failed = 0;
for (const f of findings) {
  const m = f.field.match(/^(execution|wafBypass)\[i\]\.title$/);
  if (!m) continue;
  const p = byId.get(f.id);
  const arr = p?.[m[1]] || [];
  // 现文格式可能是 "（执行步 0~3 同款模板题名）"这类描述，用 rewrite 或 cur 里的关键短语匹配
  const target = (f.cur || '').replace(/（.*?）/g, '').trim() || f.rewrite;
  let idx = arr.findIndex(e => (e?.title?.zh || '') === (f.cur.match(/^[^（]+/)?.[0] || '').trim());
  if (idx < 0) {
    // 退化：按 title.zh 包含 "清理后命令"/"校正命令" 的顺序，与补写报告的条目序对齐
    const tplIdx = arr.map((e, i) => ({ i, t: e?.title?.zh || '' })).filter(x => /清理后命令|校正命令|命令 ?\d*$/.test(x.t));
    // 从 rewrite 猜步骤号（补写代理可能没给序）——取第一个未处理模板位
    idx = tplIdx[0]?.i ?? -1;
  }
  if (idx >= 0) { f.field = `${m[1]}[${idx}].title`; resolved++; }
  else { f.field = '__UNRESOLVED__'; failed++; console.log('UNRESOLVED', f.id, f.field, '|', f.cur.slice(0, 50), '| rewrite:', f.rewrite.slice(0, 40)); }
}
writeFileSync(file, JSON.stringify({ stats: { total: findings.length }, findings }, null, 1));
console.log('resolved:', resolved, '/ failed:', failed);
