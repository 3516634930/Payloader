#!/usr/bin/env node
/**
 * SB 补丁落库：合并 5 个子代理产出的 sb*.json → 校验 expectedCommand 与 DB 现值逐字一致 →
 * 生成 command-override 文档（带 id 搬迁防 DUPLICATE）→ 注册 manifest。
 * 用法：node scripts/apply-sb-patches-2026-09.cjs [--dry]
 */
const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');
const ROOT = path.resolve(__dirname, '..');
const CR = p => path.join(ROOT, 'content-review', p);
const OUT = p => path.join(ROOT, 'output/content-audit', p);

const dry = process.argv.includes('--dry');
const db = new DatabaseSync(path.join(ROOT, 'data/payloader.sqlite'), { readOnly: true });
const all = db.prepare('SELECT id, data FROM payloads').all().map(r => JSON.parse(r.data));
db.close();
const byId = new Map(all.map(p => [p.id, p]));

// 1) 收集产出
const packs = ['out-pack1', 'out-pack2', 'out-pack3', 'out-pack4b', 'out-ai', 'out-rest'];
const patchesById = new Map();
let dropped = [];
for (const pack of packs) {
  const dir = OUT(pack);
  if (!fs.existsSync(dir)) { console.log('跳过（不存在）:', pack); continue; }
  for (const f of fs.readdirSync(dir).filter(x => /^sb.*\.json$/.test(x))) {
    const parsed = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'));
    if (!Array.isArray(parsed)) { console.log('跳过非数组文件:', pack + '/' + f); continue; }
    for (const pa of parsed) {
      // 校验：id 存在、区域/索引有效、expectedCommand byte-match、SB 结构合法、en 无中文
      const p = byId.get(pa.id);
      const step = p && (p[pa.area] || [])[pa.index];
      if (!p || !step) { dropped.push(`${pa.id} ${pa.area}[${pa.index}] 目标不存在`); continue; }
      if (step.command !== pa.expectedCommand) { dropped.push(`${pa.id} ${pa.area}[${pa.index}] expectedCommand 不匹配（锚定失败）`); continue; }
      if ((step.syntaxBreakdown || []).length) continue; // 已有 SB 的跳过（子代理应只报空缺）
      const sb = (pa.syntaxBreakdown || []).filter(s => s && typeof s.part === 'string' && s.part.length
        && s.explanation && typeof s.explanation.zh === 'string' && s.explanation.zh.length
        && typeof s.explanation.en === 'string' && s.explanation.en.length && !/[\u4e00-\u9fff]/.test(s.explanation.en)
        && typeof s.type === 'string' && s.type.length);
      if (!sb.length) { dropped.push(`${pa.id} ${pa.area}[${pa.index}] SB 结构非法或为空`); continue; }
      if (!patchesById.has(pa.id)) patchesById.set(pa.id, []);
      patchesById.get(pa.id).push({ area: pa.area, index: pa.index, expectedCommand: pa.expectedCommand, syntaxBreakdown: sb });
    }
  }
}

console.log(`收集 ${patchesById.size} 条 / ${[...patchesById.values()].reduce((s, v) => s + v.length, 0)} 个补丁｜丢弃 ${dropped.length}`);
if (dropped.length) console.log(dropped.slice(0, 20).join('\n'));
if (dry) process.exit(0);

// 2) id 搬迁：已在其他 command-override 文档的 entry 整体搬入本文档（同目标合并 SB）
const DOC = 'payload-command-overrides-sb-2026-09.json';
const manifest = JSON.parse(fs.readFileSync(CR('manifest.json'), 'utf8'));
const others = manifest.payloadCommandOverrideFiles
  .filter(f => f !== DOC)
  .map(f => ({ file: f, doc: JSON.parse(fs.readFileSync(CR(f), 'utf8')) }));
const entries = [];
let moved = 0, merged = 0;
const touched = new Map();
for (const [id, patches] of patchesById) {
  const src = others.find(o => (o.doc.entries || []).some(e => e.id === id));
  if (!src) { entries.push({ id, patches }); continue; }
  const orig = src.doc.entries.find(e => e.id === id);
  const idx = src.doc.entries.indexOf(orig);
  src.doc.entries.splice(idx, 1);
  touched.set(src.file, src.doc);
  moved++;
  const byKey = new Map(orig.patches.map(pa => [`${pa.area}|${pa.index}`, { ...pa }]));
  for (const my of patches) {
    const k = `${my.area}|${my.index}`;
    if (byKey.has(k)) {
      const o = byKey.get(k);
      if (o.expectedCommand !== my.expectedCommand) { dropped.push(`${id} ${k} 搬迁合并锚不一致，跳过该补丁`); continue; }
      byKey.set(k, { ...o, syntaxBreakdown: my.syntaxBreakdown });
      merged++;
    } else byKey.set(k, my);
  }
  orig.patches = [...byKey.values()];
  entries.push(orig);
}
// 保留现有 DOC 中本轮未涉及的 entry（活配置完整性：已 applied 补丁重放时自动跳过）
if (fs.existsSync(CR(DOC))) {
  const prev = JSON.parse(fs.readFileSync(CR(DOC), 'utf8'));
  const handled = new Set(entries.map(e => e.id));
  for (const e of prev.entries || []) if (!handled.has(e.id)) entries.push(e);
}
fs.writeFileSync(CR(DOC), JSON.stringify({ schemaVersion: 1, entries }, null, 2) + '\n');
for (const [f, doc] of touched) fs.writeFileSync(CR(f), JSON.stringify(doc, null, 2) + '\n');
if (!manifest.payloadCommandOverrideFiles.includes(DOC)) {
  manifest.payloadCommandOverrideFiles.push(DOC);
  manifest.payloadCommandOverrideFiles.sort();
  fs.writeFileSync(CR('manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
}
console.log(`写入 ${DOC}：${entries.length} 条（搬迁 ${moved}，同目标合并 ${merged}）｜manifest 已注册`);
