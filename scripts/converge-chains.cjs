#!/usr/bin/env node
/** 链修复收敛循环：validate → 对 MISSING/DANGLING 链 id 回填锚/清死步 → 重复。 */
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const { DatabaseSync } = require('node:sqlite');
const ROOT = path.resolve(__dirname, '..');
const CR = p => path.join(ROOT, 'content-review', p);
const rt = new DatabaseSync(path.join(ROOT, 'data/payloader.sqlite'), { readOnly: true });
const byId = new Map(rt.prepare('SELECT data FROM payloads').all().map(r => { const p = JSON.parse(r.data); return [p.id, p]; }));
rt.close();
const manifest = JSON.parse(fs.readFileSync(CR('manifest.json'), 'utf8'));
const oFiles = [...(manifest.overrideFiles || []), ...(manifest.collectionSplitFiles || [])];

const validate = () => {
  try { return execFileSync('node', [path.join(ROOT, 'scripts/apply-payload-curation.mjs')], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }); }
  catch (e) { return String(e.stdout || '') + String(e.stderr || ''); }
};

for (let round = 1; round <= 30; round++) {
  const out = validate();
  const chainErrs = [...out.matchAll(/(?:MISSING_CHAIN_PAYLOAD|DANGLING_CHAIN_PAYLOAD|DANGLING_CHAIN_PAYLOAD_REF|AMBIGUOUS_CHAIN_PAYLOAD):([a-z0-9][a-z0-9._-]*)/g)].map(m => m[1]);
  const otherErr = /Error:/.test(out) && !chainErrs.length;
  if (!chainErrs.length) {
    if (otherErr) { console.log('非链错误待处理:', out.match(/Error[^\n]{0,110}/)?.[0]); process.exit(1); }
    console.log('链修复完成 ✓');
    console.log((out.match(/dry-run: (ready|blocked)|Invalid review items: \d+|"pass":\w+|Planned changes.*/g) || []).join('\n'));
    break;
  }
  const ids = [...new Set(chainErrs)];
  let acted = 0;
  for (const id of ids) {
    const p = byId.get(id);
    const execC = (p?.execution || []).map(e => String(typeof e === 'string' ? e : (e?.command || ''))).filter(Boolean);
    const wafC = (p?.wafBypass || []).map(e => String(typeof e === 'string' ? e : (e?.command || ''))).filter(Boolean);
    for (const f of oFiles) {
      const full = CR(f);
      if (!fs.existsSync(full)) continue;
      const doc = JSON.parse(fs.readFileSync(full, 'utf8'));
      let hit = false;
      const walk = o => {
        if (Array.isArray(o)) return o.forEach(walk);
        if (!o || typeof o !== 'object') return;
        if (o.id === id && Array.isArray(o.attackChain)) {
          const cmdSet = new Set();
          for (const area of ['execution', 'wafBypass']) for (const e of (o[area] || [])) {
            const c = String(typeof e === 'string' ? e : (e?.command || ''));
            if (c) cmdSet.add(c);
          }
          const anchors = [...execC, ...wafC];
          let ai = 0;
          for (const s of o.attackChain) {
            if (s.payloadRef !== undefined) { delete s.payloadRef; acted++; hit = true; }
            if (s.payload && !cmdSet.has(String(s.payload))) { s.payload = ''; acted++; hit = true; }
            if (!s.payload && anchors[ai]) { s.payload = anchors[ai]; ai++; acted++; hit = true; }
          }
        }
        for (const k of Object.keys(o)) walk(o[k]);
      };
      walk(doc);
      if (hit) fs.writeFileSync(full, JSON.stringify(doc, null, 2) + '\n');
    }
  }
  console.log('第', round, '轮：', ids.length, 'id /', acted, '处');
  if (!acted) { console.log('✗ 无法继续修复'); process.exit(1); }
}
