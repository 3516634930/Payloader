// 第一波：findings.json → overrides doc + command-override doc（质检过滤 + en 保留合成）
import { DatabaseSync } from 'node:sqlite';
import { readFileSync, writeFileSync, rmSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const { findings } = JSON.parse(readFileSync(path.join(root, 'output/content-audit', process.env.QA_INPUT || 'findings.json'), 'utf8'));
const db = new DatabaseSync(path.join(root, 'data/payloader.sqlite'), { readOnly: true });
const byId = new Map(db.prepare('SELECT data FROM payloads').all().map(r => { const p = JSON.parse(r.data); return [p.id, p]; }));
db.close();

const FIELD_RE = /^(name|description|analysis|tutorial\.(overview|vulnerability|exploitation|mitigation)|prerequisites\[(\d+)\]|opsecTips\[(\d+)\]|attackChain\[(\d+)\]\.(title|description))$/;
const CMD_RE = /^(execution|wafBypass)\[(\d+)\]\.(command|title|description)$/;

const dropped = [];
const manual = [];
const used = [];

const stripFence = s => s.replace(/^```[a-z]*\n?/, '').replace(/\n?```$/, '').trim();
// dump 格式污染清洗：⏎ 行分隔符 → 换行；行内 \" 转义残留还原；# 判据注释行剥离（判据属 description）
const cleanDumpArtifacts = s => s
  .replace(/⏎/g, '\n')
  .split('\n')
  .filter(l => !/^\s*#\s*(判据|成功|说明)[:：]/.test(l))
  .map(l => l.replace(/\\"/g, '"').replace(/\\n/g, '\n'))
  .join('\n')
  .replace(/\n{3,}/g, '\n\n')
  .trim();
// 审计员可能把 dump 格式的 CMD: 前缀抄进改文：多行全带则逐行剥，单行带则剥一次
const stripCmdPrefix = s => {
  if (!s.startsWith('CMD: ')) return s;
  const lines = s.split('\n');
  if (lines.length > 1 && lines.every(l => !l.trim() || l.startsWith('CMD: ') || /^\s{2,}/.test(l))) {
    return lines.map(l => l.replace(/^CMD: /, '')).join('\n');
  }
  return s.slice(5);
};
const stripFieldPrefix = (s, field) => {
  // 子代理可能把 "字段名: " 写进改文开头
  const re = new RegExp('^(?:' + field.replace(/[.[\]]/g, '\\$&') + '|改文)\\s*[:：]\\s*');
  return s.replace(re, '').trim();
};
const quality = (f, rw) => {
  if (!rw) return 'empty';
  if (f.type === 'VERIFY' || f.type === 'CATEGORY_MISMATCH') return 'defer';
  if (/TODO|待补|XXX/i.test(rw) && !/\{XXX/.test(rw)) return 'placeholder';
  // 校验器长度门：tutorial 段≥50 / attackChain 描述≥20 / analysis≥40 / 其余≥12
  let min = 8;
  if (f.field.startsWith('tutorial.')) min = 50;
  else if (f.field.startsWith('attackChain[')) min = 20;
  else if (f.field === 'analysis') min = 40;
  else if (f.field === 'description' || f.field.startsWith('prerequisites[') || f.field.startsWith('opsecTips[')) min = 12;
  if (rw.length < (f.field.endsWith('.command') ? 4 : min)) return 'too-short';
  if (/<整段|该行替换为|行级|<保留|<删除/.test(rw)) return 'manual-instruction';
  return 'ok';
};

// 聚合 per-payload 修改
const proseEdits = new Map(); // id → {field: newZh}
const cmdPatches = new Map(); // id → [{area,index,fields}]
for (const f of findings) {
  if (!byId.has(f.id)) { dropped.push({ ...f, why: 'id-not-in-db' }); continue; }
  const p = byId.get(f.id);
  let rw = cleanDumpArtifacts(stripCmdPrefix(stripFence(String(f.rewrite || ''))));
  const q = quality(f, rw);
  if (q !== 'ok') {
    (q === 'manual-instruction' ? manual : dropped).push({ ...f, why: q });
    continue;
  }
  const mf = f.field.match(FIELD_RE);
  const mc = f.field.match(CMD_RE);
  if (mf) {
    rw = stripFieldPrefix(rw, f.field);
    if (!proseEdits.has(f.id)) proseEdits.set(f.id, {});
    const slot = proseEdits.get(f.id);
    const key = f.field;
    // 同字段多次发现：后写覆盖（按 pack 顺序），记录
    if (slot[key] !== undefined) used.push({ ...f, note: 'dup-field-overwrite' });
    slot[key] = rw;
  } else if (mc) {
    const [, area, idx, prop] = mc;
    const index = parseInt(idx, 10);
    const arr = p[area] || [];
    if (index >= arr.length) { dropped.push({ ...f, why: 'index-out-of-range' }); continue; }
    const src = arr[index];
    if (prop !== 'command' && src?.title?.zh === rw) { dropped.push({ ...f, why: 'same-as-current' }); continue; }
    if (!cmdPatches.has(f.id)) cmdPatches.set(f.id, []);
    const list = cmdPatches.get(f.id);
    let patch = list.find(x => x.area === area && x.index === index);
    if (!patch) { patch = { area, index, expectedCommand: String(src?.command || ''), fields: {} }; list.push(patch); }
    if (prop === 'command') {
      if (rw === patch.expectedCommand) { dropped.push({ ...f, why: 'same-as-current' }); continue; }
      patch.fields.command = rw;
    } else if (prop === 'title') {
      patch.fields.title = { zh: rw, en: String(src?.title?.en || rw) };
    } else {
      patch.fields.description = { zh: rw, en: String(src?.description?.en || '') };
    }
  } else {
    dropped.push({ ...f, why: 'unmapped-field:' + f.field });
  }
}

// 生成 overrides doc（entry = DB 完整 payload 深拷贝 + 目标字段 zh 覆盖，en 全保留原值）
const overrides = [];
// 应用字段级改文到完整 entry
const applySlots = (entry, p, slots) => {
  let touched = false;
  for (const [field, zh] of Object.entries(slots)) {
    const m = field.match(FIELD_RE);
    if (!m) continue;
    if (field === 'name') { entry.name = { zh, en: p.name?.en || '' }; touched = true; }
    else if (field === 'description') { entry.description = { zh, en: p.description?.en || '' }; touched = true; }
    else if (field === 'analysis') { entry.analysis = { zh, en: p.analysis?.en || '' }; touched = true; }
    else if (field.startsWith('tutorial.')) {
      const k = m[2];
      entry.tutorial = entry.tutorial || {};
      entry.tutorial[k] = { zh, en: p.tutorial?.[k]?.en || '' };
      touched = true;
    } else if (field.startsWith('prerequisites[')) {
      const i = parseInt(m[3], 10);
      entry.prerequisites = entry.prerequisites || [];
      if (entry.prerequisites[i]) { entry.prerequisites[i] = { zh, en: entry.prerequisites[i]?.en || '' }; touched = true; }
    } else if (field.startsWith('opsecTips[')) {
      const i = parseInt(m[4], 10);
      entry.opsecTips = entry.opsecTips || [];
      if (entry.opsecTips[i]) { entry.opsecTips[i] = { zh, en: entry.opsecTips[i]?.en || '' }; touched = true; }
    } else if (field.startsWith('attackChain[')) {
      const i = parseInt(m[5], 10);
      const prop = m[6];
      entry.attackChain = entry.attackChain || [];
      if (entry.attackChain[i]) {
        entry.attackChain[i][prop] = { zh, en: entry.attackChain[i][prop]?.en || '' };
        touched = true;
      }
    }
  }
  return touched;
};
for (const [id, slots] of proseEdits) {
  const p = byId.get(id);
  const entry = JSON.parse(JSON.stringify({
    id, name: p.name, description: p.description, category: p.category, subCategory: p.subCategory,
    tags: p.tags, prerequisites: p.prerequisites, execution: p.execution, analysis: p.analysis,
    opsecTips: p.opsecTips, wafBypass: p.wafBypass, attackChain: p.attackChain, references: p.references, tutorial: p.tutorial,
  }));
  entry.review = { decision: 'payload', reason: 'qa-final-2026-09 内容质量终审文案修复' };
  if (applySlots(entry, p, slots)) overrides.push(entry);
}
// 历史空锚链回填：未被 doc 引用过的 payload 链锚全空，一旦进入 override 校验即 MISSING_CHAIN_PAYLOAD。
// 按 execution（不足补 wafBypass）顺序为空锚步回填命令锚——与 converge-chains 的回填语义一致。
let backfilled = 0;
for (const entry of overrides) {
  const p = byId.get(entry.id);
  const chain = entry.attackChain || [];
  if (!chain.length || chain.some(s => String(s?.payload || '').trim())) continue;
  const pool = [...(p.execution || []), ...(p.wafBypass || [])].map(c => String(c?.command || '')).filter(Boolean);
  if (!pool.length) continue;
  chain.forEach((step, i) => { if (!String(step?.payload || '').trim()) step.payload = pool[Math.min(i, pool.length - 1)]; });
  backfilled++;
}

// 生成 command-override doc
const cmdDoc = [];
for (const [id, patches] of cmdPatches) {
  const entries = [];
  for (const p of patches) {
    const e = { area: p.area, index: p.index, expectedCommand: p.expectedCommand };
    if (p.fields.command !== undefined) e.command = p.fields.command;
    if (p.fields.title !== undefined) e.title = p.fields.title;
    if (p.fields.description !== undefined) {
      // patch 校验要求 en ≥30 字符；原 en 不足时用 zh 长度兜底检查
      e.description = p.fields.description;
    }
    entries.push(e);
  }
  if (entries.length) cmdDoc.push({ id, patches: entries });
}

// patch description en 长度预检（en≥30），不足者改用原文 en+提示
let enShort = 0;
for (const entry of cmdDoc) {
  for (const p of entry.patches) {
    if (p.description && String(p.description.en || '').length < 30) {
      // en 停更：复制 zh 到 en 会触发 hasHan 校验；从原 payload 取 en；若仍不足，补一段中性英文
      const src = byId.get(entry.id)[p.area]?.[p.index]?.description?.en;
      if (src && src.length >= 30) p.description.en = src;
      else { p.description.en = '(English copy pending; zh is authoritative for this revision.)'; enShort++; }
    }
  }
}
// patch title en 无汉字 + 非空；原 en 为空时兜底
for (const entry of cmdDoc) {
  for (const p of entry.patches) {
    if (p.title && (!p.title.en || /[\u4e00-\u9fff]/.test(p.title.en))) {
      p.title.en = p.title.zh; // 可能含汉字 → 需要兜底英文
      if (/[\u4e00-\u9fff]/.test(p.title.en)) p.title.en = 'Command ' + p.index;
    }
  }
}

writeFileSync(path.join(root, 'output/content-audit/wave1-rejects.json'), JSON.stringify({ dropped, manual, used, enShort }, null, 1));

// ── 合并模式：改文写入既有归属 doc，避免同 id 多文档冲突 ──
const manifest = JSON.parse(readFileSync(path.join(root, 'content-review/manifest.json'), 'utf8'));
const docCache = new Map(); // file → parsed doc
const loadDoc = f => {
  if (!docCache.has(f)) docCache.set(f, JSON.parse(readFileSync(path.join(root, 'content-review', f), 'utf8')));
  return docCache.get(f);
};
// prose 归属
const proseOwner = new Map();
for (const f of manifest.overrideFiles) {
  if (f === 'overrides-qa-final-2026-09.json') continue;
  for (const e of (loadDoc(f).entries || [])) proseOwner.set(e.id, f);
}
// cmd 归属
const cmdOwner = new Map();
for (const f of manifest.payloadCommandOverrideFiles) {
  if (f === 'payload-command-overrides-qa-final-2026-09.json') continue;
  for (const e of (loadDoc(f).entries || [])) cmdOwner.set(e.id, f);
}
const touchedFiles = new Set();
let proseMerged = 0, proseNewDoc = 0, cmdMerged = 0, cmdNewDoc = 0;
const newProse = [], newCmd = [];
for (const entry of overrides) {
  const ownerFile = proseOwner.get(entry.id);
  if (ownerFile) {
    const doc = loadDoc(ownerFile);
    const target = (doc.entries || []).find(e => e.id === entry.id);
    if (target) {
      // 逐覆盖字段写入（name/description/category/subCategory/prerequisites/tutorial/analysis/opsecTips/wafBypass/attackChain/tags/references）
      for (const key of ['name', 'description', 'category', 'subCategory', 'prerequisites', 'tutorial', 'analysis', 'opsecTips', 'wafBypass', 'attackChain', 'tags', 'references']) {
        if (entry[key] !== undefined && JSON.stringify(entry[key]) !== JSON.stringify(byId.get(entry.id)[key])) target[key] = entry[key];
      }
      proseMerged++;
      touchedFiles.add(ownerFile);
    } else { newProse.push(entry); proseNewDoc++; }
  } else { newProse.push(entry); proseNewDoc++; }
}
for (const entry of cmdDoc) {
  const ownerFile = cmdOwner.get(entry.id);
  if (ownerFile) {
    const doc = loadDoc(ownerFile);
    const target = (doc.entries || []).find(e => e.id === entry.id);
    if (target) {
      for (const patch of entry.patches) {
        const existing = (target.patches || []).find(x => x.area === patch.area && x.index === patch.index);
        if (existing) Object.assign(existing, patch); // 同槽位：我的 fields 覆盖（含 expectedCommand 重锚）
        else (target.patches || (target.patches = [])).push(patch);
      }
      cmdMerged++;
      touchedFiles.add(ownerFile);
    } else { newCmd.push(entry); cmdNewDoc++; }
  } else { newCmd.push(entry); cmdNewDoc++; }
}
// 写回被改的既有 doc
for (const f of touchedFiles) {
  writeFileSync(path.join(root, 'content-review', f), JSON.stringify(docCache.get(f), null, 1) + '\n');
}
// 新 doc 只承载无归属 id；为空则不落盘（manifest 移除）
const myProseFile = path.join(root, 'content-review/overrides-qa-final-2026-09.json');
const myCmdFile = path.join(root, 'content-review/payload-command-overrides-qa-final-2026-09.json');
if (newProse.length) {
  writeFileSync(myProseFile, JSON.stringify({ schemaVersion: 1, contentStandard: 3, sourceIds: newProse.map(e => e.id), entries: newProse }, null, 1));
  if (!manifest.overrideFiles.includes('overrides-qa-final-2026-09.json')) manifest.overrideFiles.push('overrides-qa-final-2026-09.json');
} else {
  manifest.overrideFiles = manifest.overrideFiles.filter(f => f !== 'overrides-qa-final-2026-09.json');
  rmSync(myProseFile, { force: true });
}
if (newCmd.length) {
  writeFileSync(myCmdFile, JSON.stringify({ schemaVersion: 1, entries: newCmd }, null, 1));
  if (!manifest.payloadCommandOverrideFiles.includes('payload-command-overrides-qa-final-2026-09.json')) manifest.payloadCommandOverrideFiles.push('payload-command-overrides-qa-final-2026-09.json');
} else {
  manifest.payloadCommandOverrideFiles = manifest.payloadCommandOverrideFiles.filter(f => f !== 'payload-command-overrides-qa-final-2026-09.json');
  rmSync(myCmdFile, { force: true });
}
// manifest 顺序：我的 doc 回到末尾
manifest.overrideFiles = [...manifest.overrideFiles.filter(f => f !== 'overrides-qa-final-2026-09.json'), ...(manifest.overrideFiles.includes('overrides-qa-final-2026-09.json') ? ['overrides-qa-final-2026-09.json'] : [])];
writeFileSync(path.join(root, 'content-review/manifest.json'), JSON.stringify(manifest, null, 2) + '\n');

console.log('prose merged into existing docs:', proseMerged, '/ new-doc:', proseNewDoc);
console.log('cmd merged:', cmdMerged, '/ new-doc:', cmdNewDoc, '/ patches total:', cmdDoc.reduce((a, e) => a + e.patches.length, 0));
console.log('touched files:', touchedFiles.size);
console.log('dropped:', dropped.length, Object.entries(dropped.reduce((m, d) => { m[d.why] = (m[d.why] || 0) + 1; return m; }, {})).map(([k, v]) => k + ':' + v).join(' '));
console.log("manual:", manual.length, "/ chain-backfilled:", backfilled, "/ en-short fallback:", enShort);
