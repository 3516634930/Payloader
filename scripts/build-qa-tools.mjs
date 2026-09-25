// tools 审计落地：qa-report-t*.md → tool-overrides patch doc（en 保留合成）
import { DatabaseSync } from 'node:sqlite';
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const dir = path.join(root, 'output/content-audit');
const db = new DatabaseSync(path.join(root, 'data/payloader.sqlite'), { readOnly: true });
const toolById = new Map(db.prepare('SELECT data FROM tools').all().map(r => { const t = JSON.parse(r.data); return [t.id, t]; }));
db.close();

const FIELD_RE = /^(name|description|commands\[(\d+)\]\.(name|command|description|platform)|commands\[(\d+)\]\.examples\[(\d+)\]|installation|category)$/;
const files = readdirSync(dir).filter(f => /^qa-report-t\d+\.md$/.test(f)).sort();
const findings = [];
for (const f of files) {
  const text = readFileSync(path.join(dir, f), 'utf8');
  for (const raw of text.split(/^## F /m).slice(1)) {
    const lines = raw.split('\n');
    const id = lines[0].trim().replace(/`/g, '');
    const kv = {};
    for (const l of lines.slice(1)) {
      const m = l.match(/^- (字段|类型|现文|问题|改文):\s?(.*)$/);
      if (m) kv[m[1]] = m[2].trim();
    }
    if (id && kv['字段'] && kv['类型']) findings.push({ id, field: kv['字段'], type: kv['类型'], cur: kv['现文'] || '', issue: kv['问题'] || '', rewrite: kv['改文'] || '' });
  }
}
const stripFence = s => s.replace(/^```[a-z]*\n?/, '').replace(/\n?```$/, '').trim();
const stripCmdPrefix = s => {
  if (!s.startsWith('CMD: ')) return s;
  const ls = s.split('\n');
  if (ls.length > 1 && ls.every(l => !l.trim() || l.startsWith('CMD: '))) return ls.map(l => l.replace(/^CMD: /, '')).join('\n');
  return s.slice(5);
};
// 聚合 per-tool patches
const byTool = new Map();
let dropped = 0;
for (const f of findings) {
  if (f.type === 'VERIFY' || !f.rewrite) { dropped++; continue; }
  let rw = stripCmdPrefix(stripFence(f.rewrite));
  if (rw.length < 4 || /<整段|该行替换为/.test(rw)) { dropped++; continue; }
  const t = toolById.get(f.id);
  if (!t) { dropped++; continue; }
  const m = f.field.match(FIELD_RE);
  if (!m) { dropped++; continue; }
  if (!byTool.has(f.id)) byTool.set(f.id, []);
  byTool.get(f.id).push({ field: f.field, rw });
}
// 生成 patch doc：路径映射 + en 保留
const readPath = (t, field) => {
  const m = field.match(FIELD_RE);
  if (field === 'name') return { path: 'name', zh: t.name?.zh, en: t.name?.en };
  if (field === 'description') return { path: 'description', zh: t.description?.zh, en: t.description?.en };
  if (field === 'installation') return { path: 'installation', zh: t.installation?.zh, en: t.installation?.en };
  if (field === 'category') return { path: 'category', zh: t.category?.zh, en: t.category?.en };
  if (m[2] !== undefined) {
    const i = parseInt(m[2], 10), prop = m[3];
    const c = t.commands?.[i];
    if (!c) return null;
    if (prop === 'command') return { path: `commands.${i}.command`, raw: String(c.command || '') };
    if (prop === 'platform') return { path: `commands.${i}.platform` };
    return { path: `commands.${i}.${prop}`, zh: c[prop]?.zh, en: c[prop]?.en };
  }
  if (m[4] !== undefined) {
    const i = parseInt(m[4], 10), j = parseInt(m[5], 10);
    if (!t.commands?.[i]?.examples?.[j]) return null;
    return { path: `commands.${i}.examples.${j}` };
  }
  return null;
};
const entries = [];
for (const [id, list] of byTool) {
  const t = toolById.get(id);
  const patches = [];
  const seen = new Set();
  for (const { field, rw } of list) {
    const loc = readPath(t, field);
    if (!loc || seen.has(loc.path)) continue;
    seen.add(loc.path);
    let value;
    if (loc.raw !== undefined) value = rw; // command 纯文本
    else if (loc.path.endsWith('.platform')) value = ['all', 'linux', 'windows'].includes(rw) ? rw : null;
    else if (loc.path.endsWith('.examples') || /\.examples\.\d+$/.test(loc.path)) value = rw;
    else {
      const fallbackEn = loc.path.includes('description') ? 'Reviewed revision; Chinese text is authoritative for this update.' : 'Reviewed';
      value = { zh: rw, en: (loc.en && loc.en.length >= 3) ? loc.en : fallbackEn };
    }
    if (value === null) continue;
    patches.push({ path: loc.path, value });
  }
  if (patches.length) entries.push({ id, patches });
}
writeFileSync(path.join(root, 'content-review/tool-overrides-qa-final-2026-09.json'), JSON.stringify({ schemaVersion: 1, entries }, null, 1));
const manifest = JSON.parse(readFileSync(path.join(root, 'content-review/manifest.json'), 'utf8'));
if (!manifest.toolOverrideFiles.includes('tool-overrides-qa-final-2026-09.json')) manifest.toolOverrideFiles.push('tool-overrides-qa-final-2026-09.json');
writeFileSync(path.join(root, 'content-review/manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
console.log('tools findings:', findings.length, '/ patched tools:', entries.length, '/ patches:', entries.reduce((a, e) => a + e.patches.length, 0), '/ dropped:', dropped);
