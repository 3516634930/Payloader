// 链锚收敛循环 v3：以子进程 apply 的 DIAG 输出为准（同源数据）
import { readFileSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
process.chdir(root);
const ck = s => String(s || '').replace(/\r\n?/g, '\n').trim();
const APPLY = path.join(root, 'scripts/apply-payload-curation.mjs');
const manifest = JSON.parse(readFileSync(path.join(root, 'content-review/manifest.json'), 'utf8'));
const runApply = () => {
  try {
    const out = execFileSync('node', [APPLY, '--apply'], { stdio: ['ignore', 'pipe', 'pipe'] });
    return { ok: true, diag: '', out: out.toString() };
  } catch (err) {
    return { ok: false, diag: String(err.stderr || ''), out: String(err.stdout || '') };
  }
};
const runDiag = () => {
  const out = runApply();
  const m = out.diag.match(/DIAG-E: (.*)/);
  return { ok: out.ok, lists: m ? JSON.parse(m[1]) : { m: [], p: [], d: [] }, out };
};
for (let round = 1; round <= 6; round++) {
  const { ok, lists, out } = runDiag();
  console.log(`round ${round}: dangling=${lists.d.length} mixed=${lists.m.length} prose=${lists.p.length}`);
  if (ok) { console.log(out.split('\n').filter(l => /Planned/.test(l)).join(' | ')); console.log('CONVERGED'); break; }
  if (!lists.d.length && !lists.m.length && !lists.p.length) { console.log('block 非 editorial，放弃循环'); console.log(out.slice(0, 300)); break; }
  // snapshot 命令集：用 runtime + 从 seed 快照不可得——直接用「runtime 命令 + doc patch 新命令」近似（悬挂锚的相似匹配）
  const { DatabaseSync } = await import('node:sqlite');
  const db = new DatabaseSync(path.join(root, 'data/payloader.sqlite'), { readOnly: true });
  const byId = new Map(db.prepare('SELECT data FROM payloads').all().map(r => { const p = JSON.parse(r.data); return [p.id, p]; }));
  db.close();
  const docCache = new Map();
  const owner = new Map();
  const loadDoc = f => {
    if (!docCache.has(f)) docCache.set(f, JSON.parse(readFileSync(path.join(root, 'content-review', f), 'utf8')));
    return docCache.get(f);
  };
  for (const f of manifest.overrideFiles) for (const e of (loadDoc(f).entries || [])) owner.set(e.id, f);
  // patch 新命令池
  const patchPool = new Map();
  for (const f of manifest.payloadCommandOverrideFiles) {
    const d = JSON.parse(readFileSync(path.join(root, 'content-review', f), 'utf8'));
    for (const e of (d.entries || [])) for (const p of (e.patches || [])) {
      const c = ck(p?.command);
      if (c) { if (!patchPool.has(e.id)) patchPool.set(e.id, []); patchPool.get(e.id).push(c); }
    }
  }
  const touched = new Set();
  let fixed = 0;
  const fixIds = [...new Set([...lists.d, ...lists.m, ...lists.p])];
  for (const id of fixIds) {
    const p = byId.get(id);
    const f = owner.get(id);
    if (!p || !f) continue;
    const entry = (loadDoc(f).entries || []).find(e => e.id === id);
    if (!entry) continue;
    const cmds = [...(p.execution || []), ...(p.wafBypass || [])].map(c => ck(c?.command)).concat(patchPool.get(id) || []);
    for (const step of (entry.attackChain || [])) {
      const a = ck(step?.payload || '');
      if (!a || cmds.includes(a)) continue;
      const head = a.split('\n')[0].trim().slice(0, 25);
      const hit = cmds.find(c => c.startsWith(head) || c.includes(head)) || cmds.find(c => head.includes(c.split('\n')[0].trim().slice(0, 20)));
      if (hit) { step.payload = hit; fixed++; touched.add(f); }
    }
    if (lists.m.includes(id) || lists.p.includes(id)) { entry.execution = p.execution; entry.wafBypass = p.wafBypass; touched.add(f); }
  }
  if (!touched.size) { console.log('no progress'); break; }
  for (const f of touched) writeFileSync(path.join(root, 'content-review', f), JSON.stringify(docCache.get(f), null, 1) + '\n');
  console.log(`  fixed ${fixed} anchors across ${touched.size} docs`);
}
