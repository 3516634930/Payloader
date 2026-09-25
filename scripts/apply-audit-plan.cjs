#!/usr/bin/env node
/**
 * 第三轮全库治理通用执行器：吃 output/content-audit/plan-round3.json，一次落库。
 * 机制全部来自 SQL 轮实证：
 *  - 声明层：payloadSubBranches 改名/删/增 + payloadMerges 追加（titlePrefix 空）
 *  - 文档链 walker：name/description/subCategory 双写（obj 与 payloadOverrides）跨 manifest 全文档
 *  - wafFix：优先改 override 文档条目的 wafBypass（会重放）；payload 只在 collection-splits
 *    replacement 携带 wafBypass 时改 replacement；两者皆无则生成命令补丁（含 DUPLICATE_ID 并入宿主）
 *  - 子分支排序：两库树 children 重排
 * 用法：node scripts/apply-audit-plan.cjs [--no-apply]（默认执行后跑 apply --apply）
 */
const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');
const ROOT = path.resolve(__dirname, '..');
const CR = p => path.join(ROOT, 'content-review', p);
const plan = JSON.parse(fs.readFileSync(path.join(ROOT, 'output/content-audit/plan-round3.json'), 'utf8'));
const log = (...a) => console.log(...a);

const rt = new DatabaseSync(path.join(ROOT, 'data/payloader.sqlite'), { readOnly: true });
const rtById = new Map(rt.prepare('SELECT data FROM payloads').all().map(r => { const p = JSON.parse(r.data); return [p.id, p]; }));
rt.close();
const allIds = new Set(rtById.keys());
const mustExist = ids => { const bad = ids.filter(i => !allIds.has(i)); if (bad.length) { log('✗ id 不存在:', bad.join(',')); process.exit(1); } };

// ── 1) 声明层 ──
const tdPath = CR('tool-decisions.json');
const td = JSON.parse(fs.readFileSync(tdPath, 'utf8'));
let n = 0;
for (const b of td.payloadSubBranches) if (plan.subBranchRenames?.[b.id]) { b.name = { zh: plan.subBranchRenames[b.id][0], en: plan.subBranchRenames[b.id][1] }; n++; }
if (plan.subBranchRemovals?.length) td.payloadSubBranches = td.payloadSubBranches.filter(b => !plan.subBranchRemovals.includes(b.id));
for (const a of plan.subBranchAdds || []) if (!td.payloadSubBranches.some(b => b.id === a.id)) td.payloadSubBranches.push({ parentBranchId: a.parentBranchId, id: a.id, name: { zh: a.name[0], en: a.name[1] } });
const existMerge = new Set(td.payloadMerges.map(m => m.sourceId));
for (const [s, t] of plan.merges || []) {
  mustExist([s, t]);
  if (!existMerge.has(s)) { td.payloadMerges.push({ sourceId: s, targetPayloadId: t }); existMerge.add(s); }
}
fs.writeFileSync(tdPath, JSON.stringify(td, null, 2) + '\n');
log(`声明：子分支改名 ${n}｜删 ${(plan.subBranchRemovals || []).length}｜增 ${(plan.subBranchAdds || []).length}｜合并 ${(plan.merges || []).length}`);

// ── 2) 文档链 walker ──
const nameFix = plan.nameFix || {}, descFix = plan.descFix || {}, subcatFix = plan.subcatFix || {};
mustExist([...Object.keys(nameFix), ...Object.keys(descFix), ...Object.keys(subcatFix)]);
const manifest = JSON.parse(fs.readFileSync(CR('manifest.json'), 'utf8'));
const files = [...(manifest.overrideFiles || []), ...(manifest.collectionSplitFiles || []), 'tool-decisions.json'];
let wn = 0; const hit = new Set();
const rewrite = obj => {
  if (Array.isArray(obj)) return obj.forEach(rewrite);
  if (!obj || typeof obj !== 'object') return;
  const id = typeof obj.id === 'string' ? obj.id : null;
  if (id && (nameFix[id] || descFix[id] || subcatFix[id])) {
    if (nameFix[id] && obj.name !== undefined) { obj.name = { zh: nameFix[id][0], en: nameFix[id][1] }; wn++; }
    if (descFix[id] && obj.description !== undefined) { obj.description = { zh: descFix[id][0], en: descFix[id][1] }; wn++; }
    if (subcatFix[id] && obj.subCategory !== undefined) { obj.subCategory = { zh: subcatFix[id][0], en: subcatFix[id][1] }; wn++; }
    const po = obj.payloadOverrides;
    if (po) {
      if (nameFix[id] && po.name !== undefined) { po.name = { zh: nameFix[id][0], en: nameFix[id][1] }; wn++; }
      if (subcatFix[id] && po.subCategory !== undefined) { po.subCategory = { zh: subcatFix[id][0], en: subcatFix[id][1] }; wn++; }
    }
    hit.add(id);
  }
  for (const k of Object.keys(obj)) rewrite(obj[k]);
};
for (const f of files) {
  const full = CR(f);
  if (!fs.existsSync(full)) continue;
  const doc = JSON.parse(fs.readFileSync(full, 'utf8'));
  const b = wn; rewrite(doc);
  if (wn > b) fs.writeFileSync(full, JSON.stringify(doc, null, 2) + '\n');
}
log(`文档链 name/desc/subcat 改写 ${wn} 处｜未承载:`, [...new Set([...Object.keys(nameFix), ...Object.keys(descFix), ...Object.keys(subcatFix)])].filter(i => !hit.has(i)).join(',') || '无');

// ── 3) wafFix/execFix：改 override/replacement 携带的 wafBypass；execution 一律走命令补丁（文档不承载，补丁对快照后置生效）──
let wfn = 0; const wafPatchDoc = {};
for (const [pid, fixes] of Object.entries(plan.wafFix || {})) {
  mustExist([pid]);
  const cur = rtById.get(pid);
  let docHit = 0;
  const needsPatch = fixes.some(fx => fx.command !== undefined && (fx.area === 'execution' || fx.forcePatch));
  if (!needsPatch) {
    for (const f of files) {
      const full = CR(f);
      if (!fs.existsSync(full)) continue;
      const doc = JSON.parse(fs.readFileSync(full, 'utf8'));
      let hitDoc = false;
      const walk = o => {
        if (Array.isArray(o)) return o.forEach(walk);
        if (!o || typeof o !== 'object') return;
        if (o.id === pid && Array.isArray(o.wafBypass)) {
          for (const fx of fixes) {
            if (fx.removeIndex !== undefined) { if (o.wafBypass.length > fx.removeIndex) { o.wafBypass.splice(fx.removeIndex, 1); wfn++; hitDoc = true; } continue; }
            const cur2 = o.wafBypass[fx.index];
            if (!cur2) continue;
            if (fx.expectedCommand !== undefined && String(cur2.command || '') !== fx.expectedCommand) { log(`✗ wafFix 锚不匹配 ${pid}[${fx.index}]（doc ${f}）——跳过该文档`); continue; }
            if (fx.command !== undefined) { cur2.command = fx.command; wfn++; hitDoc = true; }
          }
        }
        for (const k of Object.keys(o)) walk(o[k]);
      };
      walk(doc);
      if (hitDoc) { fs.writeFileSync(full, JSON.stringify(doc, null, 2) + '\n'); docHit++; }
    }
  }
  if ((!docHit || needsPatch) && fixes.some(fx => fx.command !== undefined)) {
    // 无文档承载 / exec 类 → 命令补丁（锚 = runtime 现值）
    wafPatchDoc[pid] = fixes.filter(fx => fx.command !== undefined).map(fx => ({
      area: fx.area || 'wafBypass', index: fx.index,
      expectedCommand: fx.expectedCommand !== undefined ? fx.expectedCommand : String((fx.area === 'execution' ? cur.execution : cur.wafBypass)?.[fx.index]?.command || ''),
      command: fx.command,
    }));
  }
}
log(`wafFix 文档改写 ${wfn} 处｜需命令补丁的 payload: ${Object.keys(wafPatchDoc).length}`);
if (Object.keys(wafPatchDoc).length) {
  // DUPLICATE_ID 防护：同 id 已有补丁的并入宿主文档（同 area.index 扩展，否则追加）
  const entries = Object.entries(wafPatchDoc).map(([id, patches]) => ({ id, patches }));
  for (const e of entries) {
    let host = null;
    for (const f of manifest.payloadCommandOverrideFiles || []) {
      const d = JSON.parse(fs.readFileSync(CR(f), 'utf8'));
      if (d.entries.some(x => x.id === e.id)) { host = { file: f, doc: d }; break; }
    }
    if (host) {
      const ent = host.doc.entries.find(x => x.id === e.id);
      for (const p of e.patches) {
        const same = ent.patches.find(q => q.area === p.area && q.index === p.index);
        if (same) { same.expectedCommand = p.expectedCommand; same.command = p.command; }
        else ent.patches.push(p);
      }
      fs.writeFileSync(CR(host.file), JSON.stringify(host.doc, null, 2) + '\n');
      log(`  补丁并入宿主 ${host.file}: ${e.id}`);
    } else {
      const name = 'payload-command-overrides-round3-2026-09.json';
      const p = CR(name);
      const doc = fs.existsSync(p) ? JSON.parse(fs.readFileSync(p, 'utf8')) : { schemaVersion: 1, entries: [] };
      doc.entries.push(e);
      fs.writeFileSync(p, JSON.stringify(doc, null, 2) + '\n');
      if (!(manifest.payloadCommandOverrideFiles || []).includes(name)) {
        manifest.payloadCommandOverrideFiles = [...(manifest.payloadCommandOverrideFiles || []), name];
        fs.writeFileSync(CR('manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
      }
      log(`  新补丁文档 + 注册: ${e.id}`);
    }
  }
}

// ── 4) 子分支排序（两库树）──
if (plan.subOrder) {
  for (const rel of ['data/payloader.sqlite', 'server/default-seed.sqlite']) {
    const dbPath = path.join(ROOT, rel);
    const db = new DatabaseSync(dbPath);
    const rows = db.prepare("SELECT id, tree FROM navigation_nodes WHERE id IN ('web','intranet')").all()
      .map(r => ({ id: r.id, tree: JSON.parse(r.tree) }));
    const find = (nd, id) => { if (nd.id === id) return nd; for (const k of (nd.children || [])) { const r = find(k, id); if (r) return r; } return null; };
    for (const row of rows) {
      let dirty = false;
      for (const [branchId, order] of Object.entries(plan.subOrder)) {
        const br = find(row.tree, branchId);
        if (!br) continue;
        const byId = new Map(br.children.map(c => [c.id, c]));
        const miss = order.filter(i => !byId.has(i));
        if (miss.length) { log(`✗ subOrder 缺失 ${branchId}: ${miss.join(',')}`); continue; }
        br.children = [...order.map(i => byId.get(i)), ...br.children.filter(c => !order.includes(c.id))];
        dirty = true;
      }
      if (dirty) db.prepare('UPDATE navigation_nodes SET tree = ? WHERE id = ?').run(JSON.stringify(row.tree), row.id);
    }
    db.close();
  }
  log('子分支排序完成（两库两树）');
}

if (!process.argv.includes('--no-apply')) {
  log('— 请运行: node scripts/apply-payload-curation.mjs --apply —');
}
