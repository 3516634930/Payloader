#!/usr/bin/env node
/** 收敛循环：validate → 解析补丁错误 id → 按"生效数组=文档副本后者胜"修复（对齐/删除/去重）→ 重复。 */
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const { DatabaseSync } = require('node:sqlite');
const ROOT = path.resolve(__dirname, '..');
const CR = p => path.join(ROOT, 'content-review', p);
const seed = new DatabaseSync(path.join(ROOT, 'server/default-seed.sqlite'), { readOnly: true });
const byId = new Map(seed.prepare('SELECT data FROM payloads').all().map(r => { const q = JSON.parse(r.data); return [q.id, q]; }));
seed.close();
const manifest = JSON.parse(fs.readFileSync(CR('manifest.json'), 'utf8'));
const overrideFiles = [...(manifest.overrideFiles || []), ...(manifest.collectionSplitFiles || [])];
const cmdFiles = (manifest.payloadCommandOverrideFiles || []).map(f => CR(f));

const validate = () => {
  try { return execFileSync('node', [path.join(ROOT, 'scripts/apply-payload-curation.mjs')], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }); }
  catch (e) { return String(e.stdout || '') + String(e.stderr || ''); }
};
// 生效 waf 数组：文档副本按 manifest 顺序遍历，后者覆盖
const effectiveWaf = id => {
  let waf = null;
  for (const f of overrideFiles) {
    const full = CR(f);
    if (!fs.existsSync(full)) continue;
    const doc = JSON.parse(fs.readFileSync(full, 'utf8'));
    const walk = o => {
      if (Array.isArray(o)) return o.forEach(walk);
      if (!o || typeof o !== 'object') return;
      if (o.id === id && Array.isArray(o.wafBypass)) waf = o.wafBypass;
      for (const k of Object.keys(o)) walk(o[k]);
    };
    walk(doc);
  }
  return waf;
};

for (let round = 1; round <= 25; round++) {
  const out = validate();
  if (!/Invalid payload command override document/.test(out)) {
    console.log('第', round - 1, '轮修复后通过 ✓');
    console.log(out.match(/Invalid review items: \d+|"pass":\w+|Planned changes.*/g)?.join('\n') || '(validate ok)');
    break;
  }
  const ids = [...new Set([...out.matchAll(/(?:STALE_COMMAND|INVALID_PATCH_TARGET|DUPLICATE_PATCH_TARGET|MISSING_PATCH|EMPTY_COMMAND|NOOP_COMMAND):([a-z0-9][a-z0-9._-]*)/g)].map(m => m[1]))];
  let acted = 0;
  for (const id of ids) {
    const p = byId.get(id);
    const waf = p ? (effectiveWaf(id) || p.wafBypass || []) : [];
    for (const full of cmdFiles) {
      const d = JSON.parse(fs.readFileSync(full, 'utf8'));
      const e = d.entries.find(x => x.id === id);
      if (!e) continue;
      let dirty = false;
      const seen = new Set();
      e.patches = e.patches.filter(pa => {
        const key = pa.area + '.' + pa.index;
        if (seen.has(key)) { dirty = true; acted++; return false; }
        seen.add(key);
        const arr = pa.area === 'wafBypass' ? waf : (p?.[pa.area] || []);
        const cur = String(arr[pa.index]?.command ?? '');
        const exp = String(pa.expectedCommand ?? '');
        if (pa.command !== undefined) {
          if (!cur) { dirty = true; acted++; return false; } // 越界
          if (exp !== cur) { pa.expectedCommand = cur; dirty = true; acted++; }
          return true;
        }
        // metadata 补丁
        if (!cur) { dirty = true; acted++; return false; }
        if (exp !== cur && !(e.attackChain || []).some(s => s?.payload === exp && exp)) { pa.expectedCommand = cur; dirty = true; acted++; }
        return true;
      });
      if (!e.patches.length) d.entries = d.entries.filter(x => x !== e);
      if (dirty) fs.writeFileSync(full, JSON.stringify(d, null, 2) + '\n');
    }
  }
  console.log('第', round, '轮：修复', acted, '处（ids:', ids.slice(0, 5).join(','), ids.length > 5 ? '…' : '', '）');
  if (!acted) { console.log('✗ 无可修复项但仍报错——需人工'); process.exit(1); }
}
