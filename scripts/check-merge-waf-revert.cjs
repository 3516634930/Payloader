#!/usr/bin/env node
/** 合并目标 carried 回盖检查：runtime waf 数 < 备份即被回盖 → 从备份提取 carried 版回写所有权文档并提示 re-apply。 */
const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');
const ROOT = path.resolve(__dirname, '..');
const CR = p => path.join(ROOT, 'content-review', p);
const plan = JSON.parse(fs.readFileSync(path.join(ROOT, 'output/content-audit/plan-round3.json'), 'utf8'));
const BAK = process.argv[2];
if (!BAK) { console.log('用法: node check-merge-waf-revert.cjs <备份路径>'); process.exit(1); }

const get = (db, id) => {
  for (const r of db.prepare('SELECT data FROM payloads').all()) { const p = JSON.parse(r.data); if (p.id === id) return p; }
  return null;
};
const bak = new DatabaseSync(path.isAbsolute(BAK) ? BAK : path.join(ROOT, BAK), { readOnly: true });
const cur = new DatabaseSync(path.join(ROOT, 'data/payloader.sqlite'), { readOnly: true });

const targets = [...new Set(plan.merges.map(([, t]) => t))];
const reverted = [];
for (const t of targets) {
  const b = get(bak, t), c = get(cur, t);
  if (!b || !c) continue;
  const bn = (b.wafBypass || []).length, cn = (c.wafBypass || []).length;
  if (cn < bn) reverted.push({ id: t, from: bn, to: cn, waf: b.wafBypass });
}
bak.close(); cur.close();
console.log(`合并目标 ${targets.length} 个｜被回盖 ${reverted.length} 个`);

if (reverted.length) {
  const manifest = JSON.parse(fs.readFileSync(CR('manifest.json'), 'utf8'));
  const files = [...(manifest.overrideFiles || []), ...(manifest.collectionSplitFiles || [])];
  for (const r of reverted) {
    let wrote = 0;
    for (const f of files) {
      const full = CR(f);
      if (!fs.existsSync(full)) continue;
      const doc = JSON.parse(fs.readFileSync(full, 'utf8'));
      let hit = false;
      const walk = o => {
        if (Array.isArray(o)) return o.forEach(walk);
        if (!o || typeof o !== 'object') return;
        if (o.id === r.id && Array.isArray(o.wafBypass)) { o.wafBypass = JSON.parse(JSON.stringify(r.waf)); hit = true; }
        for (const k of Object.keys(o)) walk(o[k]);
      };
      walk(doc);
      if (hit) { fs.writeFileSync(full, JSON.stringify(doc, null, 2) + '\n'); wrote++; }
    }
    console.log(`  回写 ${r.id}: ${r.from}→${r.to}（命中 ${wrote} 文档）`);
  }
  console.log('— 请再次运行 apply --apply 持久化 carried 版 —');
}
