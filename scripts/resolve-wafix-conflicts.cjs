#!/usr/bin/env node
/** wafFix 冲突终解：doc 剪除类→删被标记补丁；doc 去重类→回退 doc 改 seed 原文+改走补丁（exp=seed 旧文，command=去重文）。 */
const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');
const ROOT = path.resolve(__dirname, '..');
const CR = p => path.join(ROOT, 'content-review', p);
const seed = new DatabaseSync(path.join(ROOT, 'server/default-seed.sqlite'), { readOnly: true });
const byId = new Map(seed.prepare('SELECT data FROM payloads').all().map(r => { const q = JSON.parse(r.data); return [q.id, q]; }));
seed.close();
const plan = JSON.parse(fs.readFileSync(path.join(ROOT, 'output/content-audit/plan-round3.json'), 'utf8'));
const manifest = JSON.parse(fs.readFileSync(CR('manifest.json'), 'utf8'));
const overrideFiles = [...(manifest.overrideFiles || []), ...(manifest.collectionSplitFiles || [])];

const REMOVED = new Set(); // id → 有 removeIndex（doc 剪除保持）
for (const [pid, fixes] of Object.entries(plan.wafFix || {})) if (fixes.some(f => f.removeIndex !== undefined && f.area !== 'execution')) REMOVED.add(pid);

let reverted = 0, patched = 0, deleted = 0;
// 1) 纯去重类：doc 副本回退 seed 数组
for (const [pid, fixes] of Object.entries(plan.wafFix || {})) {
  if (REMOVED.has(pid) || fixes.some(f => f.area === 'execution')) continue;
  const seedWaf = byId.get(pid)?.wafBypass;
  if (!Array.isArray(seedWaf)) continue;
  for (const f of overrideFiles) {
    const full = CR(f);
    if (!fs.existsSync(full)) continue;
    const doc = JSON.parse(fs.readFileSync(full, 'utf8'));
    let hit = false;
    const walk = o => {
      if (Array.isArray(o)) return o.forEach(walk);
      if (!o || typeof o !== 'object') return;
      if (o.id === pid && Array.isArray(o.wafBypass) && JSON.stringify(o.wafBypass) !== JSON.stringify(seedWaf)) { o.wafBypass = JSON.parse(JSON.stringify(seedWaf)); hit = true; }
      for (const k of Object.keys(o)) walk(o[k]);
    };
    walk(doc);
    if (hit) { fs.writeFileSync(full, JSON.stringify(doc, null, 2) + '\n'); reverted++; }
  }
}
// 2) 补丁：去重类加 replace 补丁（exp=seed 文本）；删条目类删除被标记补丁
const FLAGGED = JSON.parse(fs.readFileSync(path.join(ROOT, 'output/content-audit/flagged-patches.json'), 'utf8')); // [{id, area, index}]
for (const fl of FLAGGED) {
  const pid = fl.id;
  const fixes = (plan.wafFix[pid] || []).filter(f => f.area !== 'execution');
  if (REMOVED.has(pid)) continue; // 第 3 步统一删
  const seedP = byId.get(pid);
  const expCmd = String(seedP?.wafBypass?.[fl.index]?.command ?? '');
  const intent = fixes.find(f => f.index === fl.index);
  if (!expCmd || !intent) continue;
  // 并入宿主或新文档
  let host = null;
  for (const f of manifest.payloadCommandOverrideFiles || []) {
    const d = JSON.parse(fs.readFileSync(CR(f), 'utf8'));
    if (d.entries.some(x => x.id === pid)) { host = { file: CR(f), doc: d }; break; }
  }
  const patch = { area: 'wafBypass', index: fl.index, expectedCommand: expCmd, command: intent.command };
  if (host) {
    const e = host.doc.entries.find(x => x.id === pid);
    const same = e.patches.find(q => q.area === 'wafBypass' && q.index === fl.index);
    if (same) { same.expectedCommand = expCmd; same.command = intent.command; }
    else e.patches.push(patch);
    fs.writeFileSync(host.file, JSON.stringify(host.doc, null, 2) + '\n');
  } else {
    const name = 'payload-command-overrides-round3-2026-09.json';
    const p = CR(name);
    const d = fs.existsSync(p) ? JSON.parse(fs.readFileSync(p, 'utf8')) : { schemaVersion: 1, entries: [] };
    let e = d.entries.find(x => x.id === pid);
    if (!e) { e = { id: pid, patches: [] }; d.entries.push(e); }
    e.patches.push(patch);
    fs.writeFileSync(p, JSON.stringify(d, null, 2) + '\n');
    if (!(manifest.payloadCommandOverrideFiles || []).includes(name)) { manifest.payloadCommandOverrideFiles = [...(manifest.payloadCommandOverrideFiles || []), name]; fs.writeFileSync(CR('manifest.json'), JSON.stringify(manifest, null, 2) + '\n'); }
  }
  patched++;
}
// 3) 删条目类：删除全部被标记补丁（doc 剪除状态保持）
for (const fl of FLAGGED) {
  if (!REMOVED.has(fl.id)) continue;
  for (const f of manifest.payloadCommandOverrideFiles || []) {
    const full = CR(f);
    const d = JSON.parse(fs.readFileSync(full, 'utf8'));
    const e = d.entries.find(x => x.id === fl.id);
    if (!e) continue;
    const b = e.patches.length;
    e.patches = e.patches.filter(p2 => !(p2.area === fl.area && p2.index === fl.index));
    if (e.patches.length !== b) { if (!e.patches.length) d.entries = d.entries.filter(x => x !== e); fs.writeFileSync(full, JSON.stringify(d, null, 2) + '\n'); deleted += b - e.patches.length; }
  }
}
console.log(`doc 回退 ${reverted}｜补丁新增/改写 ${patched}｜删条目类补丁删除 ${deleted}`);
