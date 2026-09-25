#!/usr/bin/env node
/**
 * 补丁对账：以 seed 快照为基准重对齐所有 command-override 补丁。
 * 规则：expectedCommand 在目标数组中找到 → 更新 index；当前条目已等于 patch.command → 丢弃（已应用）；
 *      找不到且未应用 → 丢弃并记 dead（锚失效）。
 */
const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');
const ROOT = path.resolve(__dirname, '..');
const CR = p => path.join(ROOT, 'content-review', p);
const seed = new DatabaseSync(path.join(ROOT, 'server/default-seed.sqlite'), { readOnly: true });
const byId = new Map(seed.prepare('SELECT data FROM payloads').all().map(r => { const p = JSON.parse(r.data); return [p.id, p]; }));
seed.close();
const manifest = JSON.parse(fs.readFileSync(CR('manifest.json'), 'utf8'));
let fixed = 0, dropped = 0, kept = 0;
for (const f of manifest.payloadCommandOverrideFiles || []) {
  const full = CR(f);
  const doc = JSON.parse(fs.readFileSync(full, 'utf8'));
  let dirty = false;
  for (const entry of doc.entries) {
    const p = byId.get(entry.id);
    if (!p) { entry.patches = entry.patches.filter(() => false) && (dropped += entry.patches.length, entry.patches = []); dirty = true; continue; }
    const out = [];
    for (const patch of entry.patches) {
      const arr = Array.isArray(p[patch.area]) ? p[patch.area] : [];
      const cur = arr[patch.index];
      const curCmd = String(cur?.command ?? (typeof cur === 'string' ? cur : ''));
      const ok = curCmd && curCmd === String(patch.command ?? '');
      // 已应用
      if (ok) { dropped++; dirty = true; continue; }
      // index 失效或锚不符：按 expectedCommand 找新位置
      const exp = String(patch.expectedCommand ?? '');
      if (exp) {
        const idx = arr.findIndex(e => String(e?.command ?? (typeof e === 'string' ? e : '')) === exp);
        if (idx >= 0) { if (idx !== patch.index) { patch.index = idx; fixed++; dirty = true; } out.push(patch); kept++; continue; }
      }
      // 找不到锚：若 title/desc-only（无 command）保留元数据补丁在合法 index 上
      if (patch.command === undefined && cur) { out.push(patch); kept++; continue; }
      dropped++; dirty = true; console.log(`  drop dead: ${f} :: ${entry.id} ${patch.area}[${patch.index}]`);
    }
    entry.patches = out;
    if (!out.length) entry.__drop = true;
  }
  doc.entries = doc.entries.filter(e => !e.__drop);
  if (dirty) fs.writeFileSync(full, JSON.stringify(doc, null, 2) + '\n');
}
console.log(`对账完成：重锚 ${fixed}｜丢弃(已应用/死锚) ${dropped}｜保留 ${kept}`);
