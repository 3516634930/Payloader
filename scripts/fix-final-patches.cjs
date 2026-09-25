#!/usr/bin/env node
/** 定向修复剩余 6 处补丁错误（对齐/去重），失败即报不静默。 */
const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');
const ROOT = path.resolve(__dirname, '..');
const CR = p => path.join(ROOT, 'content-review', p);
const seed = new DatabaseSync(path.join(ROOT, 'server/default-seed.sqlite'), { readOnly: true });
const byId = new Map(seed.prepare('SELECT data FROM payloads').all().map(r => { const q = JSON.parse(r.data); return [q.id, q]; }));
seed.close();
const manifest = JSON.parse(fs.readFileSync(CR('manifest.json'), 'utf8'));
const docWaf = new Map();
for (const f of [...(manifest.overrideFiles || []), ...(manifest.collectionSplitFiles || [])]) {
  const full = CR(f);
  if (!fs.existsSync(full)) continue;
  const walk = o => {
    if (Array.isArray(o)) return o.forEach(walk);
    if (!o || typeof o !== 'object') return;
    if (typeof o.id === 'string' && Array.isArray(o.wafBypass) && !docWaf.has(o.id)) docWaf.set(o.id, o.wafBypass);
    for (const k of Object.keys(o)) walk(o[k]);
  };
  walk(JSON.parse(fs.readFileSync(full, 'utf8')));
}
const TARGETS = ['httpbypass-iis-cgi-double-encoded-traversal', 'rce-command-injection', 'sqli-mysql-server-file-write', 'sqli2-union-extraction-lexical-encodings', 'webshell-php'];
for (const f of manifest.payloadCommandOverrideFiles || []) {
  const full = CR(f);
  const d = JSON.parse(fs.readFileSync(full, 'utf8'));
  let dirty = false;
  for (const e of d.entries) {
    if (!TARGETS.includes(e.id)) continue;
    const p = byId.get(e.id);
    if (!p) { console.log('skip', e.id, '(不在 seed)'); continue; }
    // 1) 去重同 area.index
    const seen = new Map();
    e.patches = e.patches.filter(pa => {
      const key = pa.area + '.' + pa.index;
      if (seen.has(key)) { dirty = true; console.log(e.id, '去重', key); return false; }
      seen.set(key, pa); return true;
    });
    // 2) 锚对齐（生效数组 = docWaf 优先）
    for (const pa of e.patches) {
      const arr = pa.area === 'wafBypass' ? (docWaf.get(e.id) || p.wafBypass || []) : (p[pa.area] || []);
      const cur = String(arr[pa.index]?.command ?? '');
      if (cur && String(pa.expectedCommand ?? '') !== cur) { pa.expectedCommand = cur; dirty = true; console.log(e.id, pa.area + '[' + pa.index + '] 锚对齐'); }
    }
  }
  if (dirty) fs.writeFileSync(full, JSON.stringify(d, null, 2) + '\n');
}
console.log('done');
