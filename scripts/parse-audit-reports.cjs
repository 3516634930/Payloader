#!/usr/bin/env node
/** 解析 audit-pack*.md → 候选清单（供主会话裁决成 plan-round3.json）。 */
const fs = require('fs');
const path = require('path');
const ROOT = path.resolve(__dirname, '..');
const packs = fs.readdirSync(path.join(ROOT, 'output/content-audit')).filter(f => /^audit-pack\d\.md$/.test(f)).sort().map(f => 'output/content-audit/' + f);
const out = { rename: [], merge: [], mismatch: [], content: [], split: [], keep: 0 };
for (const f of packs) {
  if (!fs.existsSync(path.join(ROOT, f))) { console.log('skip', f); continue; }
  const sec = {};
  let cur = null;
  for (const line of fs.readFileSync(path.join(ROOT, f), 'utf8').split('\n')) {
    const m = line.match(/^## (RENAME|MERGE|SPLIT|MISMATCH|CONTENT|KEEP)/);
    if (m) { cur = m[1]; continue; }
    if (!cur) continue;
    if (cur === 'KEEP') { if (/^- /.test(line.trim())) out.keep++; continue; }
    if (!/^- /.test(line.trim())) continue;
    const t = line.trim().replace(/^- /, '').replace(/^\{p:/, '').replace(/\}$/, '').replace(/\} \|/, ' |').replace(/\} →/, ' →').replace(/→ \{p:/, '→ ');
    if (cur === 'RENAME') {
      const m2 = t.match(/^([a-z0-9][a-z0-9._-]*) \| (.+?) → (.+?) \|/);
      if (m2) { const zhEn = m2[3]; const em = zhEn.match(/^(.*) \(([^()]*)\)$/); out.rename.push({ id: m2[1], old: m2[2], zh: em ? em[1] : zhEn, en: em ? em[2] : '' }); }
      else out.rename.push({ id: t.slice(0, 60), parseFail: true });
    } else if (cur === 'MERGE') {
      const m2 = t.match(/^([a-z0-9][a-z0-9._-]*) → \{?(?:p:)?([a-z0-9][a-z0-9._-]*)\}? \|(.*)$/);
      if (m2) out.merge.push({ s: m2[1], t: m2[2], ev: m2[3].trim().slice(0, 60) });
      else out.merge.push({ raw: t.slice(0, 100), parseFail: true });
    } else if (cur === 'MISMATCH') {
      const m2 = t.match(/^([a-z0-9][a-z0-9._-]*) \|/);
      out.mismatch.push({ id: m2 ? m2[1] : '?', text: t.slice(0, 160) });
    } else if (cur === 'CONTENT') {
      out.content.push({ text: t.slice(0, 170) });
    } else if (cur === 'SPLIT') {
      if (!/无|未发现/.test(t)) out.split.push({ text: t.slice(0, 140) });
    }
  }
}
console.log('== RENAME', out.rename.length, '(解析失败', out.rename.filter(r => r.parseFail).length, ')');
for (const r of out.rename) console.log(r.parseFail ? '  ✗ ' + r.id : `  ${r.id} | ${r.zh} (${r.en})`);
console.log('== MERGE', out.merge.length, '(解析失败', out.merge.filter(r => r.parseFail).length, ')');
for (const r of out.merge) console.log(r.parseFail ? '  ✗ ' + r.raw : `  ${r.s} → ${r.t}  (${r.ev})`);
console.log('== SPLIT'); out.split.forEach(s => console.log('  ' + s.text));
console.log('== MISMATCH', out.mismatch.length);
for (const m of out.mismatch) console.log('  ' + m.text);
console.log('== CONTENT', out.content.length);
for (const c of out.content) console.log('  ' + c.text);
console.log('== KEEP', out.keep);
fs.writeFileSync(path.join(ROOT, 'output/content-audit/candidates.json'), JSON.stringify(out, null, 1));
