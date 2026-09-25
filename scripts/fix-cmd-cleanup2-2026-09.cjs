#!/usr/bin/env node
/**
 * 清理轮 2：
 * 1) 24 处"真实命令; Write-Output "PAYLOADER_..."“同行尾拼接剥除（cleanup 文档追加 patch；
 *    entry 已在 cleanup 文档的合入，不在的也进 cleanup——cleanup 现在是唯一 command 补丁入口，
 *    但 id 若在其他文档仍需搬迁逻辑。实测这些 id 多已在 cleanup（轮 1 搬迁过）。
 * 2) ai2-7/ai2-9 编号标题：在 ux 文档原有 patch 上补 title 字段（不动 expectedCommand/command，避开 chain 锚）。
 */
const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');
const CR = p => path.join(process.cwd(), 'content-review', p);

const db = new DatabaseSync('data/payloader.sqlite', { readOnly: true });
const all = db.prepare('SELECT id, data FROM payloads').all().map(r => JSON.parse(r.data));
db.close();
const byId = new Map(all.map(p => [p.id, p]));

const inlineWO = cmd => cmd
  .split('\n').map(line => line
    .replace(/\s*;\s*Write-Output\s+"PAYLOADER[^"]*"\s*(;.*)?\s*$/, '')
    .replace(/\s*&\s*Write-Output\s+"PAYLOADER[^"]*"\s*$/, ''))
  .join('\n').replace(/\n{3,}/g, '\n\n').trim();

// ── 1) cleanup 文档追加行内 WO 剥除 patch ──
const CLEANUP = 'payload-command-overrides-cleanup-2026-09.json';
const cleanupDoc = JSON.parse(fs.readFileSync(CR(CLEANUP), 'utf8'));
const manifest = JSON.parse(fs.readFileSync(CR('manifest.json'), 'utf8'));
const otherDocs = manifest.payloadCommandOverrideFiles
  .filter(f => f !== CLEANUP)
  .map(f => ({ file: f, doc: JSON.parse(fs.readFileSync(CR(f), 'utf8')) }));

let added = 0;
const touchedOthers = new Set();
for (const p of all) {
  for (const [i, step] of (p.execution || []).entries()) {
    const cmd = step.command || '';
    if (!/;\s*Write-Output\s+"PAYLOADER|&\s*Write-Output\s+"PAYLOADER/.test(cmd)) continue;
    const next = inlineWO(cmd);
    if (!next || next === cmd) continue;
    const patch = { area: 'execution', index: i, expectedCommand: cmd, command: next };
    const mine = cleanupDoc.entries.find(e => e.id === p.id);
    if (mine) { mine.patches.push(patch); added++; continue; }
    const other = otherDocs.find(o => (o.doc.entries || []).some(e => e.id === p.id));
    if (other) {
      const target = other.doc.entries.find(e => e.id === p.id);
      const dup = target.patches.some(pa => pa.area === 'execution' && pa.index === i);
      if (dup) { console.log('⚠️ 同目标 patch 已存在，跳过:', p.id, i); continue; }
      target.patches.push(patch); added++; touchedOthers.add(other.file);
    } else {
      cleanupDoc.entries.push({ id: p.id, patches: [patch] }); added++;
    }
  }
}
fs.writeFileSync(CR(CLEANUP), JSON.stringify(cleanupDoc, null, 2) + '\n');
for (const o of otherDocs) if (touchedOthers.has(o.file)) fs.writeFileSync(CR(o.file), JSON.stringify(o.doc, null, 2) + '\n');
console.log('轮2 行内 WO 剥除 patch:', added, '个');

// ── 2) ux 文档 ai2-7/9 标题去编号 ──
const UX = 'payload-command-overrides-ux-2026-09.json';
const uxDoc = JSON.parse(fs.readFileSync(CR(UX), 'utf8'));
const titleFix = {
  'ai2-7-ssrf-via-llm': { zh: 'SSRF via LLM', en: 'SSRF via LLM' },
  'ai2-9-prompt-indirect-injection': { zh: '间接 Prompt 注入', en: 'Indirect Prompt Injection' },
};
let t2 = 0;
for (const [id, title] of Object.entries(titleFix)) {
  const e = uxDoc.entries.find(x => x.id === id);
  if (!e) { console.log('⚠️ ux 无 entry:', id); continue; }
  for (const pa of e.patches) {
    if (pa.area === 'execution' && pa.index === 0 && pa.title === undefined) { pa.title = title; t2++; }
  }
}
fs.writeFileSync(CR(UX), JSON.stringify(uxDoc, null, 2) + '\n');
console.log('轮2 ux 标题修复:', t2, '个');
